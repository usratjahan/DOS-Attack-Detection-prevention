"""A deliberately *default-configured* web server model.

It reproduces the three resource limits that denial-of-service attacks exhaust:

  1. SYN backlog        (half-open TCP connections)  -> SYN flood
  2. CPU / worker queue (requests per second)        -> HTTP flood
  3. Connection slots   (max concurrent connections) -> Slowloris

Defaults are like an untuned Apache/nginx: no per-IP limits, no SYN cookies, no
strict header deadline. DosGuard later switches those protections on.
"""
from __future__ import annotations

from collections import Counter, deque
from typing import Callable, Optional

from .sim import Sim

HALF_RTT = 0.005


class Conn:
    __slots__ = ("cid", "ip", "opened", "last_byte", "got_request")

    def __init__(self, cid: int, ip: str, now: float):
        self.cid, self.ip, self.opened, self.last_byte, self.got_request = cid, ip, now, now, False


class Server:
    def __init__(self, sim: Sim, backlog: int = 64, syn_timeout: float = 8.0, max_conns: int = 250,
                 workers: int = 4, service_time: float = 0.010, queue_limit: int = 100, idle_timeout: float = 30.0):
        self.sim = sim
        self.backlog, self.syn_timeout, self.max_conns = backlog, syn_timeout, max_conns
        self.workers, self.service_time, self.queue_limit, self.idle_timeout = workers, service_time, queue_limit, idle_timeout
        # protections (all OFF by default = vulnerable)
        self.syn_cookies = False
        self.header_deadline: Optional[float] = None     # absolute seconds allowed to send full request headers
        self.per_ip_conn_limit: Optional[int] = None
        self.ip_rate_limit: Optional[float] = None       # requests/second per source IP
        self.rate_exempt: set = set()                    # reputation: IPs with a clean history skip the rate limit
        self.blocked: dict = {}                          # ip -> expiry time (firewall DROP)
        # state
        self.half_open: dict = {}                        # cid -> (ip, t)
        self.conns: dict = {}                            # cid -> Conn
        self.ip_conns, self.ip_half = Counter(), Counter()
        self.queue: deque = deque()
        self.busy = 0
        self.buckets: dict = {}
        self.obs = None                                  # observer (DosGuard) hooks
        self.stats: Counter = Counter()
        self.counters: Counter = Counter()               # raw arrivals (before any firewall): 'syn', 'req' -> live rates
        self.access_log: list = []                       # (t, ip, status)
        self._secret = 0x5EC12E7
        sim.at(1.0, self._sweep)

    @property
    def capacity(self) -> float:
        return self.workers / self.service_time

    # ------------------------------------------------------------ firewall --
    def is_blocked(self, ip: str) -> bool:
        exp = self.blocked.get(ip)
        if exp is None:
            return False
        if exp <= self.sim.now:
            del self.blocked[ip]
            return False
        return True

    def block(self, ip: str, seconds: float) -> None:
        self.blocked[ip] = self.sim.now + seconds
        self.kill_ip(ip)

    def kill_ip(self, ip: str) -> None:
        for cid in [c.cid for c in self.conns.values() if c.ip == ip]:
            self.close(cid)
        for cid in [c for c, (i, _) in self.half_open.items() if i == ip]:
            self.half_open.pop(cid)
            self.ip_half[ip] -= 1

    def _cookie(self, ip: str, cid: int) -> int:
        return hash((ip, cid, self._secret))            # stands in for the kernel's keyed hash

    # ----------------------------------------------------------- TCP layer --
    def syn(self, ip: str, cid: int, on_synack: Callable) -> None:
        now = self.sim.now
        self.counters["syn"] += 1
        if self.is_blocked(ip):
            self.stats["fw_drop"] += 1
            return
        if self.obs:
            self.obs.on_syn(ip, now)
        if self.per_ip_conn_limit and self.ip_conns[ip] + self.ip_half[ip] >= self.per_ip_conn_limit:
            self.stats["connlimit_drop"] += 1
            return
        if self.syn_cookies:                             # stateless: nothing is stored for this SYN
            self.sim.at(HALF_RTT, on_synack, self._cookie(ip, cid))
            return
        if len(self.half_open) >= self.backlog:
            self.stats["syn_dropped"] += 1
            return
        self.half_open[cid] = (ip, now)
        self.ip_half[ip] += 1
        self.sim.at(HALF_RTT, on_synack, None)

    def ack(self, ip: str, cid: int, cookie, on_established: Callable) -> None:
        if self.is_blocked(ip):
            return
        if cid in self.half_open:
            i, _ = self.half_open.pop(cid)
            self.ip_half[i] -= 1
        elif cookie is None or cookie != self._cookie(ip, cid):
            self.stats["ack_invalid"] += 1
            on_established(False)
            return
        if len(self.conns) >= self.max_conns:
            self.stats["conn_refused"] += 1
            on_established(False)
            return
        self.conns[cid] = Conn(cid, ip, self.sim.now)
        self.ip_conns[ip] += 1
        if self.obs:
            self.obs.on_handshake(ip, self.sim.now)
        on_established(True)

    def close(self, cid: int) -> None:
        c = self.conns.pop(cid, None)
        if c:
            self.ip_conns[c.ip] -= 1

    def trickle(self, cid: int) -> bool:
        """Client sends one more byte of a (never finished) request header."""
        c = self.conns.get(cid)
        if c is None:
            return False
        c.last_byte = self.sim.now
        return True

    # ----------------------------------------------------------- HTTP layer --
    def _take_token(self, ip: str) -> bool:
        rate, now = self.ip_rate_limit, self.sim.now
        b = self.buckets.get(ip)
        burst = max(3.0, rate)
        if b is None:
            b = self.buckets[ip] = [burst, now]
        b[0] = min(burst, b[0] + (now - b[1]) * rate)
        b[1] = now
        if b[0] >= 1.0:
            b[0] -= 1.0
            return True
        return False

    def request(self, cid: int, ip: str, on_response: Callable, close: bool = True) -> None:
        now = self.sim.now
        self.counters["req"] += 1
        c = self.conns.get(cid)
        if c is None:
            on_response(False, "no_conn")
            return
        if self.is_blocked(ip):
            self.close(cid)
            on_response(False, "blocked")
            return
        if self.obs:
            self.obs.on_request(ip, now)
        c.got_request, c.last_byte = True, now
        if self.ip_rate_limit and ip not in self.rate_exempt and not self._take_token(ip):
            self.stats["rate_limited"] += 1
            self.access_log.append((now, ip, 429))
            if close:
                self.close(cid)
            on_response(False, "429")
            return
        if len(self.queue) >= self.queue_limit:
            self.stats["overload_503"] += 1
            self.access_log.append((now, ip, 503))
            if close:
                self.close(cid)
            on_response(False, "503")
            return
        self.queue.append((now, cid, ip, on_response, close))
        self._dispatch()

    def _dispatch(self) -> None:
        while self.busy < self.workers and self.queue:
            item = self.queue.popleft()
            self.busy += 1
            self.sim.at(self.service_time, self._done, item)

    def _done(self, item) -> None:
        arrived, cid, ip, cb, close = item
        self.busy -= 1
        self.access_log.append((self.sim.now, ip, 200))
        self.stats["served"] += 1
        if close:
            self.close(cid)
        cb(True, self.sim.now - arrived)
        self._dispatch()

    # --------------------------------------------------------------- timers --
    def _sweep(self) -> None:
        now = self.sim.now
        for cid in [c for c, (_, t) in self.half_open.items() if now - t > self.syn_timeout]:
            ip, _ = self.half_open.pop(cid)
            self.ip_half[ip] -= 1
        for c in list(self.conns.values()):
            if now - c.last_byte > self.idle_timeout:
                self.close(c.cid)
                self.stats["idle_closed"] += 1
            elif self.header_deadline and not c.got_request and now - c.opened > self.header_deadline:
                self.close(c.cid)
                self.stats["slow_killed"] += 1
        self.sim.at(1.0, self._sweep)
