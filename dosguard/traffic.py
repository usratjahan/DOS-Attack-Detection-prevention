"""Traffic generators: legitimate users and the three DoS attackers (simulation only)."""
from __future__ import annotations

import itertools
import random
from typing import List, Optional

from .server import Server
from .sim import Sim

_cids = itertools.count(1)
TIMEOUT = 2.0              # a user gives up (counts as a failed request) after 2 s


class LegitClient:
    """Opens a fresh TCP connection per request (like a browser page load) at a Poisson rate."""

    def __init__(self, sim: Sim, server: Server, ip: str, rate: float, metrics: List[tuple], rng: random.Random):
        self.sim, self.server, self.ip, self.rate, self.metrics, self.rng = sim, server, ip, rate, metrics, rng
        self.mult = 1.0
        self.stop = 1e9

    def start(self, delay: float = 0.0) -> None:
        self.sim.at(delay + self.rng.expovariate(self.rate), self._go)

    def _go(self) -> None:
        if self.sim.now < self.stop:
            self._request()
            self.sim.at(self.rng.expovariate(self.rate * self.mult), self._go)

    def _request(self) -> None:
        sim, server, ip = self.sim, self.server, self.ip
        cid, t0, st = next(_cids), sim.now, {"done": False, "synack": False}

        def finish(ok: bool, *_):
            if st["done"]:
                return
            st["done"] = True
            self.metrics.append((t0, ok, sim.now - t0, ip))
            if not ok:
                server.close(cid)

        def on_est(ok: bool):
            if ok:
                server.request(cid, ip, finish, True)
            else:
                finish(False)

        def on_synack(cookie):
            if st["synack"] or st["done"]:
                return
            st["synack"] = True
            sim.at(0.01, server.ack, ip, cid, cookie, on_est)

        def send_syn():
            server.syn(ip, cid, on_synack)

        send_syn()
        sim.at(1.0, lambda: send_syn() if not st["synack"] and not st["done"] else None)   # TCP SYN retransmit
        sim.at(TIMEOUT, finish, False)


class SynFlood:
    """Spoofed-source SYN flood: SYNs from random fake IPs that never complete the handshake."""

    def __init__(self, sim: Sim, server: Server, rate: float, rng: random.Random, start: float, stop: float):
        self.sim, self.server, self.rate, self.rng, self.stop = sim, server, rate, rng, stop
        self.sent = 0
        sim.at(start, self._burst)
        sim.at(start, sim.log, "attack", f"SYN flood starts: {rate:.0f} spoofed SYN/s")

    def _burst(self) -> None:
        if self.sim.now >= self.stop:
            return
        for _ in range(max(1, int(self.rate * 0.01))):
            ip = "%d.%d.%d.%d" % (self.rng.randrange(11, 223), self.rng.randrange(256), self.rng.randrange(256), self.rng.randrange(1, 255))
            self.server.syn(ip, next(_cids), lambda c: None)
            self.sent += 1
        self.sim.at(0.01, self._burst)


class HttpBot:
    """One bot: completes a real handshake, then hammers requests on a keep-alive connection."""

    def __init__(self, sim: Sim, server: Server, ip: str, rps: float, rng: random.Random, start: float, stop: float):
        self.sim, self.server, self.ip, self.rps, self.rng, self.stop = sim, server, ip, rps, rng, stop
        self.cid: Optional[int] = None
        self.connecting = False
        sim.at(start + rng.random(), self._connect)

    def _connect(self) -> None:
        if self.sim.now >= self.stop or self.connecting:
            return
        cid = next(_cids)
        self.connecting = True

        def on_est(ok):
            if not (self.connecting and cid == self._attempt):
                return                                    # stale callback
            self.connecting = False
            if ok:
                self.cid = cid
                self._fire()
            else:
                self.sim.at(1.0, self._connect)

        def timeout():
            if self.connecting and cid == self._attempt:   # SYN/ACK was dropped: retry
                self.connecting = False
                self._connect()

        self._attempt = cid
        self.server.syn(self.ip, cid, lambda ck: self.sim.at(0.01, self.server.ack, self.ip, cid, ck, on_est))
        self.sim.at(1.5, timeout)

    def _fire(self) -> None:
        if self.sim.now >= self.stop:
            return
        if self.cid not in self.server.conns:             # killed / blocked -> try to reconnect
            self.cid = None
            self.sim.at(1.0, self._connect)
            return
        self.server.request(self.cid, self.ip, lambda *a: None, close=False)
        self.sim.at(self.rng.uniform(0.7, 1.3) / self.rps, self._fire)


class Slowloris:
    """Opens many connections and drip-feeds one header byte every ~10 s so they never time out."""

    def __init__(self, sim: Sim, server: Server, ips: List[str], conns_per_ip: int, rng: random.Random, start: float, stop: float):
        self.sim, self.server, self.rng, self.stop = sim, server, rng, stop
        for ip in ips:
            for _ in range(conns_per_ip):
                sim.at(start + rng.uniform(0, 2.0), self._slot, ip, None)

    def _slot(self, ip: str, cid: Optional[int]) -> None:
        if self.sim.now >= self.stop:
            return
        if cid is not None and self.server.trickle(cid):
            self.sim.at(self.rng.uniform(8, 12), self._slot, ip, cid)
            return
        new, st = next(_cids), {"resolved": False}

        def on_est(ok):
            if st["resolved"]:
                return
            st["resolved"] = True
            self.sim.at(self.rng.uniform(8, 12) if ok else 1.0, self._slot, ip, new if ok else None)

        def timeout():
            if not st["resolved"]:                        # SYN dropped: try again
                st["resolved"] = True
                self._slot(ip, None)

        self.server.syn(ip, new, lambda ck: self.sim.at(0.01, self.server.ack, ip, new, ck, on_est))
        self.sim.at(3.0, timeout)
