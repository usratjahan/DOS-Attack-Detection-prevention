"""Tiny discrete-event simulator: a virtual clock and an event queue."""
from __future__ import annotations

import heapq
import itertools
from typing import List


class Sim:
    def __init__(self):
        self.now = 0.0
        self._q: list = []
        self._n = itertools.count()
        self.events: List[tuple] = []          # (t, kind, message) timeline for the report

    def at(self, delay: float, fn, *args) -> None:
        heapq.heappush(self._q, (self.now + max(delay, 0.0), next(self._n), fn, args))

    def run(self, until: float) -> None:
        while self._q and self._q[0][0] <= until:
            t, _, fn, args = heapq.heappop(self._q)
            self.now = t
            fn(*args)
        self.now = until

    def log(self, kind: str, msg: str) -> None:
        self.events.append((round(self.now, 3), kind, msg))
