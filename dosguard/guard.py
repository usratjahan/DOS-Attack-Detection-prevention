"""DosGuard: detection + automatic prevention for SYN flood, HTTP flood and Slowloris.

Every second it reads what the server saw (SYNs, completed handshakes, requests per source IP,
open connections) and applies *attack-specific signatures*:

  SYN_FLOOD        many SYNs, almost none complete the handshake, backlog filling up
  HTTP_FLOOD       one IP sends >= ip_rps_limit requests/s for several seconds
  GLOBAL_OVERLOAD  total request rate near server capacity (catches distributed floods)
  SLOWLORIS        one IP holds many connections that never finish their request headers
  CONN_EXHAUSTION  connection table nearly full (context alert)

Prevention (mode="protect"): hardening at start-up, then per-attack responses:
  SYN flood  -> SYN cookies (stateless handshake) + block non-spoofed sources
  HTTP flood -> temporary IP ban (auto-expires) ; overload -> max-min fair-share rate limit
  Slowloris  -> block IP + kill its connections ; hardening = header deadline + per-IP connection cap
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .server import Server

SEVERITY = {"INFO": 0, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Alert:
    ts: float
    rule: str
    severity: str
    ip: Optional[str]
    detail: str


def fair_share(demands: Dict[str, float], budget: float) -> float:
    """Max-min fairness: the per-source cap such that sources under the cap keep their full demand."""
    vals = sorted(demands.values())
    remaining = budget
    for i, d in enumerate(vals):
        level = remaining / (len(vals) - i)
        if d <= level:
            remaining -= d
        else:
            return level
    return float("inf")


class DosGuard:
    def __init__(self, server: Server, mode: str = "protect", log: Optional[Callable[[str, str], None]] = None,
                 ban_seconds: float = 30.0, ip_rps_limit: float = 50.0, ip_rps_ticks: int = 2,
                 syn_min_rate: float = 100.0, completion_ratio: float = 0.3, ip_syn_rate: float = 50.0,
                 overload_frac: float = 0.9, conn_per_ip_limit: int = 20, partial_age: float = 3.0,
                 partial_count: int = 10, header_deadline: float = 5.0):
        assert mode in ("monitor", "protect")
        self.server, self.mode, self.log = server, mode, log or (lambda k, m: None)
        self.ban_seconds, self.ip_rps_limit, self.ip_rps_ticks = ban_seconds, ip_rps_limit, ip_rps_ticks
        self.syn_min_rate, self.completion_ratio, self.ip_syn_rate = syn_min_rate, completion_ratio, ip_syn_rate
        self.overload_frac, self.partial_age, self.partial_count = overload_frac, partial_age, partial_count
        self.syn, self.hs, self.req = Counter(), Counter(), Counter()
        self.hot: Counter = Counter()
        self.offenses: Counter = Counter()
        self.good_ticks: Counter = Counter()            # calm seconds in which an IP behaved normally (reputation)
        self.reputation_ticks = 3
        self.over = self.calm_req = self.calm_syn = 0
        self.alerts: List[Alert] = []
        self.actions: List[tuple] = []                  # (ts, description)
        self.blocked_history: List[tuple] = []          # (ts, ip)
        self.first_alert_ts: Optional[float] = None
        self.first_mitigation_ts: Optional[float] = None
        self._last: Dict[tuple, float] = {}
        self.active = True
        server.obs = self
        if mode == "protect":                           # hardening: costs legit users nothing
            server.header_deadline = header_deadline
            server.per_ip_conn_limit = conn_per_ip_limit
            self._act(f"hardening: header deadline {header_deadline:.0f}s, max {conn_per_ip_limit} connections per IP", hardening=True)
        server.sim.at(1.0, self._tick)

    # ---- observer hooks (called by the server) -----------------------------
    def on_syn(self, ip: str, t: float) -> None:
        self.syn[ip] += 1

    def on_handshake(self, ip: str, t: float) -> None:
        self.hs[ip] += 1

    def on_request(self, ip: str, t: float) -> None:
        self.req[ip] += 1

    # ---- helpers ------------------------------------------------------------
    @property
    def _protect(self) -> bool:
        return self.mode == "protect"

    def _alert(self, rule: str, sev: str, ip: Optional[str], detail: str) -> None:
        now = self.server.sim.now
        if now - self._last.get((rule, ip), -1e9) < 5.0:
            return
        self._last[(rule, ip)] = now
        self.alerts.append(Alert(now, rule, sev, ip, detail))
        if self.first_alert_ts is None:
            self.first_alert_ts = now
        self.log("guard", f"ALERT [{sev}] {rule}: {detail}")

    def _act(self, desc: str, hardening: bool = False) -> None:
        now = self.server.sim.now
        self.actions.append((now, desc))
        if not hardening and self.first_mitigation_ts is None:
            self.first_mitigation_ts = now
        self.log("guard", "ACTION " + desc)

    def _block(self, ip: str, why: str) -> None:
        if not self._protect or self.server.is_blocked(ip):
            return
        self.offenses[ip] += 1                          # repeat offenders get exponentially longer bans (max 5 min)
        secs = min(self.ban_seconds * 2 ** (self.offenses[ip] - 1), 300.0)
        self.server.block(ip, secs)
        self.server.rate_exempt.discard(ip)
        self.good_ticks[ip] = 0
        self.blocked_history.append((self.server.sim.now, ip))
        self._act(f"BLOCK {ip} for {secs:.0f}s ({why}; offence #{self.offenses[ip]})")

    def stop(self) -> None:
        """Switch the guard off at runtime: detach, and undo every protection it had turned on."""
        self.active = False
        s = self.server
        s.obs = None
        s.header_deadline, s.per_ip_conn_limit, s.syn_cookies, s.ip_rate_limit = None, None, False, None
        s.rate_exempt.clear()
        s.blocked.clear()

    # ---- the detector ---------------------------------------------------------
    def _tick(self) -> None:
        if not self.active:
            return
        s = self.server
        syn_total, hs_total, req_total = sum(self.syn.values()), sum(self.hs.values()), sum(self.req.values())

        # 1) SYN flood: lots of SYNs, few completed handshakes, backlog under pressure
        pressured = len(s.half_open) >= 0.5 * s.backlog or s.syn_cookies
        if syn_total >= self.syn_min_rate and hs_total < self.completion_ratio * syn_total and pressured:
            self.calm_syn = 0
            self._alert("SYN_FLOOD", "CRITICAL", None,
                        f"{syn_total} SYN/s but only {hs_total} completed handshakes; half-open {len(s.half_open)}/{s.backlog}")
            if self._protect and not s.syn_cookies:
                s.syn_cookies = True
                self._act("SYN cookies ON (stateless handshake; spoofed SYNs now cost nothing)")
            for ip, n in list(self.syn.items()):         # non-spoofed attackers repeat the same source IP
                if n >= self.ip_syn_rate and self.hs[ip] < 0.2 * n:
                    self._alert("SYN_FLOOD", "CRITICAL", ip, f"{ip} sent {n} SYN/s, {self.hs[ip]} completed")
                    self._block(ip, "SYN flood source")
        elif s.syn_cookies and self._protect:
            self.calm_syn = self.calm_syn + 1 if syn_total < self.syn_min_rate else 0
            if self.calm_syn >= 8:
                s.syn_cookies = False
                self._act("SYN cookies OFF (attack over for 8 s)")

        # 2) HTTP flood: a single IP far above any human request rate
        for ip in [i for i in self.hot if i not in self.req]:
            del self.hot[ip]
        for ip, n in list(self.req.items()):
            self.hot[ip] = self.hot[ip] + 1 if n >= self.ip_rps_limit else 0
            if self.hot[ip] >= self.ip_rps_ticks and not s.is_blocked(ip):
                self._alert("HTTP_FLOOD", "HIGH", ip, f"{ip} sent {n} requests/s for {self.hot[ip]} s")
                self._block(ip, "HTTP flood")

        # 3) distributed floods: total load near capacity -> max-min fair-share limit per IP
        if req_total >= self.overload_frac * s.capacity:
            self.over, self.calm_req = self.over + 1, 0
        else:
            self.over = 0
            self.calm_req = self.calm_req + 1 if req_total < 0.5 * s.capacity else 0
        calm = req_total < 0.5 * s.capacity and syn_total < self.syn_min_rate and not s.ip_rate_limit
        if calm and self._protect:                      # reputation: remember IPs that behave in calm periods
            for ip in self.req:
                self.good_ticks[ip] += 1
                if self.good_ticks[ip] >= self.reputation_ticks and not s.is_blocked(ip):
                    s.rate_exempt.add(ip)
        if self.over >= 2:
            self._alert("GLOBAL_OVERLOAD", "MEDIUM", None, f"{req_total} req/s vs capacity {s.capacity:.0f} req/s from {len(self.req)} IPs")
            if self._protect:
                known = sum(n for ip, n in self.req.items() if ip in s.rate_exempt)
                demands = {ip: n for ip, n in self.req.items() if ip not in s.rate_exempt}
                level = max(2.0, fair_share(demands, max(0.2 * s.capacity, 0.8 * s.capacity - known)))
                if s.ip_rate_limit is None or abs(level - s.ip_rate_limit) > 0.2 * s.ip_rate_limit:
                    s.ip_rate_limit = level
                    self._act(f"fair-share rate limit {level:.1f} req/s per new/unknown IP ({len(s.rate_exempt)} known-good IPs exempt)")
        elif s.ip_rate_limit is not None and self._protect and self.calm_req >= 5:
            s.ip_rate_limit = None
            self._act("fair-share rate limit OFF (load normal for 5 s)")

        # 4) Slowloris: connections that stay open without ever finishing their request
        now = s.sim.now
        partial: Counter = Counter()
        for c in s.conns.values():
            if not c.got_request and now - c.opened >= self.partial_age:
                partial[c.ip] += 1
        for ip, n in partial.items():
            if n >= self.partial_count and not s.is_blocked(ip):
                self._alert("SLOWLORIS", "HIGH", ip, f"{ip} holds {n} connections with unfinished request headers")
                self._block(ip, "Slowloris")
        if len(s.conns) >= 0.8 * s.max_conns:
            self._alert("CONN_EXHAUSTION", "MEDIUM", None, f"{len(s.conns)}/{s.max_conns} connection slots in use")

        self.syn.clear(); self.hs.clear(); self.req.clear()
        s.sim.at(1.0, self._tick)
