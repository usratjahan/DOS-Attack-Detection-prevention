"""Real-time engine for the web dashboard.

Runs the same server model, legitimate users, attackers and DosGuard as the offline experiments,
but paced by the wall clock (1 simulated second = 1 real second at 1x speed) and controllable while
it runs: start/stop attacks, switch protection mode, change speed, reset.

Thread model: one background thread advances the simulation; HTTP handler threads call the
public methods, all guarded by one lock. Each ~0.5 s of simulated time a JSON snapshot is published.
"""
from __future__ import annotations

import json
import random
import threading
import time
from collections import deque
from typing import Dict, List, Optional

from .guard import DosGuard
from .server import Server
from .sim import Sim
from .traffic import HttpBot, LegitClient, Slowloris, SynFlood

ATTACK_NAMES = ["syn_flood", "http_flood", "slowloris", "http_distributed"]
MODES = ["off", "monitor", "protect"]
SPEEDS = [1.0, 2.0, 4.0]
FAR = 1e12
SNAP_EVERY = 0.5          # simulated seconds between published snapshots
WINDOW = 4.0              # availability / latency are computed over the last 4 simulated seconds


class LiveSim:
    def __init__(self, seed: int = 1):
        self.lock = threading.RLock()
        self.cond = threading.Condition()
        self.version = 0
        self.latest = ""
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.reset(seed)

    # ---------------------------------------------------------------- setup --
    def reset(self, seed: Optional[int] = None) -> None:
        with self.lock:
            self.seed = seed if seed is not None else random.randrange(1, 10**6)
            self.rnd = random.Random(self.seed)
            self.sim = Sim()
            self.server = Server(self.sim)
            self.server.access_log = deque(maxlen=500)
            self.metrics: deque = deque(maxlen=30000)           # (t_start, ok, latency, ip) of real users' requests
            self.mode, self.guard, self.speed = "off", None, 1.0
            self.feed: deque = deque(maxlen=300)
            self.seq = 0
            self.history: deque = deque(maxlen=240)             # 120 s of snapshots at 0.5 s
            self.attacks: Dict[str, dict] = {}
            self._last = {"t": 0.0, "syn": 0, "req": 0, "served": 0}
            self._next_snap = SNAP_EVERY
            self.sim.log = self._log                            # all components log through us
            clients = [LegitClient(self.sim, self.server, f"10.0.0.{i + 1}", 0.5, self.metrics, self.rnd) for i in range(40)]
            clients.append(LegitClient(self.sim, self.server, "10.0.1.1", 15.0, self.metrics, self.rnd))   # shared-IP office
            clients.append(LegitClient(self.sim, self.server, "10.0.2.1", 8.0, self.metrics, self.rnd))    # power user
            for c in clients:
                c.start(self.rnd.random())
            self._log("info", "server online - 40 visitors + an office (15 req/s) + a power user (8 req/s) browsing normally")

    def _log(self, kind: str, msg: str) -> None:
        self.seq += 1
        self.feed.append({"seq": self.seq, "t": round(self.sim.now, 1), "kind": kind, "msg": msg})

    # -------------------------------------------------------------- controls --
    def start_attack(self, name: str) -> bool:
        if name not in ATTACK_NAMES:
            raise ValueError("unknown attack")
        with self.lock:
            if name in self.attacks:
                return False
            s, r = self.sim, self.rnd
            if name == "syn_flood":
                objs, ips = [SynFlood(s, self.server, 600, r, 0.0, FAR)], []
            elif name == "http_flood":
                ips = [f"198.51.100.{i + 1}" for i in range(15)]
                objs = [HttpBot(s, self.server, ip, 100.0, r, 0.0, FAR) for ip in ips]
                self._log("attack", "HTTP flood started: 15 bots x 100 req/s = 1500 req/s (capacity 400)")
            elif name == "http_distributed":
                ips = [f"203.{i // 250}.{i % 250}.{r.randrange(1, 255)}" for i in range(200)]
                objs = [HttpBot(s, self.server, ip, 6.0, r, 0.0, FAR) for ip in ips]
                self._log("attack", "Distributed HTTP flood started: 200 bots x 6 req/s = 1200 req/s")
            else:
                ips = [f"192.0.2.{i + 1}" for i in range(5)]
                objs = [Slowloris(s, self.server, ips, 60, r, 0.0, FAR)]
                self._log("attack", "Slowloris started: 5 IPs x 60 half-finished requests (250 slots)")
            self.attacks[name] = {"objs": objs, "ips": ips, "since": s.now}
            return True

    def stop_attack(self, name: str) -> bool:
        if name not in ATTACK_NAMES:
            raise ValueError("unknown attack")
        with self.lock:
            a = self.attacks.pop(name, None)
            if a is None:
                return False
            for o in a["objs"]:
                o.stop = self.sim.now                            # attacker goes quiet
            for ip in a["ips"]:
                self.server.kill_ip(ip)                          # ...and its connections are gone
            self._log("attack", f"{name} stopped by the attacker")
            return True

    def set_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise ValueError("unknown mode")
        with self.lock:
            if mode == self.mode:
                return
            if self.guard:
                self.guard.stop()
                self.guard = None
            if mode != "off":
                self.guard = DosGuard(self.server, mode, log=self._log)
            self.mode = mode
            self._log("info", f"protection mode -> {mode}")

    def set_speed(self, speed: float) -> None:
        if speed not in SPEEDS:
            raise ValueError("unsupported speed")
        with self.lock:
            self.speed = speed

    # ------------------------------------------------------------ simulation --
    def advance(self, sim_seconds: float) -> None:
        """Advance simulated time (called by the pacing thread; also used directly by tests)."""
        with self.lock:
            target = self.sim.now + sim_seconds
            while self._next_snap <= target:
                self.sim.run(self._next_snap)
                self._publish(self._snapshot())
                self._next_snap += SNAP_EVERY
            self.sim.run(target)

    def _snapshot(self) -> dict:
        s, srv, now = self.sim, self.server, self.sim.now
        dt = max(now - self._last["t"], 1e-6)
        syn_rate = (srv.counters["syn"] - self._last["syn"]) / dt
        req_rate = (srv.counters["req"] - self._last["req"]) / dt
        served_rate = (srv.stats["served"] - self._last["served"]) / dt
        self._last = {"t": now, "syn": srv.counters["syn"], "req": srv.counters["req"], "served": srv.stats["served"]}

        ok = n = 0
        lat = []
        for m in reversed(self.metrics):                         # newest first; entries are appended when a request finishes
            finish = m[0] + m[2]
            if finish < now - WINDOW:
                break
            n += 1
            if m[1]:
                ok += 1
                lat.append(m[2])
        blocked = sorted(((exp - now, ip) for ip, exp in srv.blocked.items() if exp > now), reverse=True)
        g = self.guard
        stats = srv.stats
        return {
            "t": round(now, 1), "mode": self.mode, "speed": self.speed,
            "avail": None if n == 0 else round(100.0 * ok / n, 1),
            "latency_ms": None if not lat else round(1000 * sum(lat) / len(lat)),
            "req_rate": round(req_rate), "syn_rate": round(syn_rate), "served_rate": round(served_rate),
            "half_open": [len(srv.half_open), srv.backlog],
            "conns": [len(srv.conns), srv.max_conns],
            "queue": [len(srv.queue), srv.queue_limit],
            "workers": [srv.busy, srv.workers],
            "protections": {"syn_cookies": srv.syn_cookies, "rate_limit": None if srv.ip_rate_limit is None else round(srv.ip_rate_limit, 1),
                            "header_deadline": srv.header_deadline, "conn_limit": srv.per_ip_conn_limit, "known_good": len(srv.rate_exempt)},
            "attacks": {k: round(now - v["since"], 1) for k, v in self.attacks.items()},
            "blocked": [{"ip": ip, "secs": round(rem)} for rem, ip in blocked[:12]], "blocked_total": len(blocked),
            "drops": {k: stats[k] for k in ("syn_dropped", "conn_refused", "overload_503", "rate_limited", "fw_drop", "connlimit_drop", "slow_killed")},
            "alerts": 0 if g is None else len(g.alerts),
            "feed": list(self.feed)[-40:],
        }

    def _publish(self, snap: dict) -> None:
        point = {k: snap[k] for k in ("t", "avail", "req_rate", "syn_rate", "latency_ms", "mode")}
        point["atk"] = len(snap["attacks"])
        self.history.append(point)
        with self.cond:
            self.latest = json.dumps(snap, separators=(",", ":"))
            self.version += 1
            self.cond.notify_all()

    def state(self) -> dict:
        """Full state for a freshly loaded page: chart history + the latest snapshot."""
        with self.lock:
            snap = self._snapshot()
            return {"history": list(self.history), "snapshot": snap, "feed": list(self.feed)}

    # ------------------------------------------------------------ pacing thread --
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="dosguard-live")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        last = time.monotonic()
        while not self._stop.is_set():
            time.sleep(0.05)
            now = time.monotonic()
            wall, last = now - last, now
            self.advance(min(wall * self.speed, 0.4))            # never try to catch up more than 0.4 s at once
