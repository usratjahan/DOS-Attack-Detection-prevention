"""Experiment runner: server + legitimate users + one attack + (optionally) DosGuard."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Optional

from .guard import DosGuard
from .server import Server
from .sim import Sim
from .traffic import HttpBot, LegitClient, Slowloris, SynFlood

ATTACKS = ["syn_flood", "http_flood", "slowloris", "http_distributed"]
MODES = ["off", "monitor", "protect"]
LEGIT_PREFIX = "10.0."


@dataclass
class Result:
    attack: Optional[str]
    mode: str
    seed: int
    duration: float
    attack_start: float
    metrics: List[tuple] = field(default_factory=list)         # (t_start, ok, latency) of every legit request
    events: list = field(default_factory=list)
    alerts: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    blocked_history: list = field(default_factory=list)
    first_alert_ts: Optional[float] = None
    first_mitigation_ts: Optional[float] = None
    access_log: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def avail(self, t0: float, t1: float, group: Optional[str] = None) -> Optional[float]:
        """Share of legitimate requests started in [t0, t1) that succeeded.
        group: None = all users, 'ordinary' = the 40 normal visitors, 'heavy' = the NAT'd office + power user."""
        pick = {None: lambda ip: True, "ordinary": lambda ip: ip.startswith("10.0.0."),
                "heavy": lambda ip: ip.startswith(("10.0.1.", "10.0.2."))}[group]
        # requests started in the last 2 s had no time to finish before the run ended -> excluded (no bias)
        cutoff = self.duration - 2.0
        w = [m for m in self.metrics if t0 <= m[0] < min(t1, cutoff) and pick(m[3])]
        return None if not w else sum(1 for m in w if m[1]) / len(w)

    def series(self, step: float = 1.0) -> List[Optional[float]]:
        # the final 2 s are not measurable (requests had no time to finish), so the series stops there
        return [self.avail(i * step, (i + 1) * step) for i in range(int((self.duration - 2.0) / step))]

    @property
    def avail_pre(self):
        return self.avail(0, self.attack_start)

    @property
    def avail_attack(self):
        return self.avail(self.attack_start, self.duration)

    @property
    def avail_steady(self):
        return self.avail(self.attack_start + 10, self.duration)

    @property
    def mean_latency_ms(self) -> Optional[float]:
        lat = [m[2] for m in self.metrics if m[1] and m[0] >= self.attack_start + 10]
        return 1000 * sum(lat) / len(lat) if lat else None

    @property
    def detect_delay(self) -> Optional[float]:
        return None if self.first_alert_ts is None else max(0.0, self.first_alert_ts - self.attack_start)

    @property
    def mitigation_delay(self) -> Optional[float]:
        return None if self.first_mitigation_ts is None else max(0.0, self.first_mitigation_ts - self.attack_start)

    @property
    def legit_ips_blocked(self) -> List[str]:
        return sorted({ip for _, ip in self.blocked_history if ip.startswith(LEGIT_PREFIX)})


def run_scenario(attack: Optional[str] = "http_flood", mode: str = "protect", seed: int = 1, duration: float = 60.0,
                 attack_start: float = 15.0, flash_crowd: bool = False) -> Result:
    assert mode in MODES and (attack is None or attack in ATTACKS)
    rnd = random.Random(seed)
    sim = Sim()
    server = Server(sim)
    res = Result(attack, mode, seed, duration, attack_start)

    guard = DosGuard(server, mode, log=sim.log) if mode != "off" else None
    sim.log("guard" if guard else "info", f"server up; DosGuard mode = {mode}")

    # ---- legitimate users: 40 ordinary visitors + a NAT'd office (shared IP) + a power user ----
    clients = [LegitClient(sim, server, f"10.0.0.{i + 1}", 0.5, res.metrics, rnd) for i in range(40)]
    nat = LegitClient(sim, server, "10.0.1.1", 15.0, res.metrics, rnd)
    power = LegitClient(sim, server, "10.0.2.1", 8.0, res.metrics, rnd)
    for c in clients + [nat, power]:
        c.start(rnd.random())
    if flash_crowd:                                    # benign surge: ordinary visitors x10 for 10 s
        sim.at(25.0, lambda: [setattr(c, "mult", 10.0) for c in clients])
        sim.at(25.0, sim.log, "benign", "flash crowd: ordinary visitors x10 for 10 s")
        sim.at(35.0, lambda: [setattr(c, "mult", 1.0) for c in clients])

    # ---- attack --------------------------------------------------------------------------------
    a0, end = attack_start, duration
    if attack == "syn_flood":
        SynFlood(sim, server, rate=600, rng=rnd, start=a0, stop=end)
    elif attack == "http_flood":
        for i in range(15):
            HttpBot(sim, server, f"198.51.100.{i + 1}", 100.0, rnd, a0, end)
        sim.at(a0, sim.log, "attack", "HTTP flood starts: 15 bots x 100 req/s = 1500 req/s (server capacity 400)")
    elif attack == "http_distributed":
        for i in range(200):
            HttpBot(sim, server, f"203.{i // 250}.{i % 250}.{rnd.randrange(1, 255)}", 6.0, rnd, a0, end)
        sim.at(a0, sim.log, "attack", "Distributed HTTP flood: 200 bots x 6 req/s = 1200 req/s (each bot looks polite)")
    elif attack == "slowloris":
        Slowloris(sim, server, [f"192.0.2.{i + 1}" for i in range(5)], 60, rnd, a0, end)
        sim.at(a0, sim.log, "attack", "Slowloris starts: 5 IPs x 60 half-finished requests (server has 250 slots)")

    sim.run(duration)

    res.events, res.access_log, res.stats = sim.events, server.access_log, dict(server.stats)
    if guard:
        res.alerts, res.actions = guard.alerts, guard.actions
        res.blocked_history = guard.blocked_history
        res.first_alert_ts, res.first_mitigation_ts = guard.first_alert_ts, guard.first_mitigation_ts
    return res
