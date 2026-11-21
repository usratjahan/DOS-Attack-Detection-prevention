"""Proof of concept: each attack against an unprotected server, detection-only, and a protected server."""
from __future__ import annotations

import os
import sys

from .firewall import REAL_WORLD_MAP
from .logs import write_access_log
from .scenario import Result, run_scenario

USE_COLOR = sys.stdout.isatty()
COL = {"red": "31", "green": "32", "yellow": "33", "cyan": "36", "bold": "1", "dim": "2"}


def c(text: str, color: str) -> str:
    return f"\033[{COL[color]}m{text}\033[0m" if USE_COLOR else text


KIND_COL = {"attack": "red", "guard": "green", "benign": "cyan", "info": "dim"}

ATTACK_INFO = {
    "syn_flood": ("1. SYN FLOOD", "Attacker sends 600 SYN/s from random fake IPs and never finishes the handshake. The server's half-open "
                  "queue (64 slots) fills, so real users' connections are refused."),
    "http_flood": ("2. HTTP FLOOD", "15 bots, 100 requests/s each, finish real handshakes and hammer the site (1500 req/s vs a capacity of 400). "
                   "The request queue overflows and real users get errors/timeouts."),
    "slowloris": ("3. SLOWLORIS", "5 IPs open 300 connections and drip one header byte every ~10 s. Almost no traffic, but all 250 "
                  "connection slots are held forever."),
    "http_distributed": ("4. DISTRIBUTED HTTP FLOOD", "200 bots at only 6 req/s each (every bot looks polite, so per-IP limits can't see it) "
                         "add up to 1200 req/s."),
}
LEVELS = " .:-=+*#%@"


def bar(res: Result) -> str:
    return "".join("?" if a is None else LEVELS[min(9, int(round(a * 9)))] for a in res.series(1.0))


def pc(x) -> str:
    return "  - " if x is None else f"{100 * x:4.0f}%"


def condensed(events: list, per_key: int = 2, limit: int = 14):
    """Keep the story, hide repetition: only the first few alerts of each rule / IP blocks are shown."""
    seen: dict = {}
    rows, hidden = [], 0
    for t, k, m in events:
        if k not in ("attack", "guard", "benign"):
            continue
        key = ("ALERT", m.split()[2]) if m.startswith("ALERT") else ("BLOCK",) if m.startswith("ACTION BLOCK") else None
        if key:
            seen[key] = seen.get(key, 0) + 1
            if seen[key] > per_key:
                hidden += 1
                continue
        rows.append((t, k, m))
    hidden += max(0, len(rows) - limit)
    return rows[:limit], hidden


def timeline(res: Result) -> list:
    rows, hidden = condensed(res.events)
    out = [f"  t={t:6.1f}s  {c(k.upper().ljust(6), KIND_COL.get(k, 'dim'))} {m}" for t, k, m in rows]
    if hidden:
        out.append(f"  ... {hidden} similar alert/block lines hidden (one per attacking IP; bans expire and repeat offenders are re-banned)")
    return out


def run_demo(outdir: str = "output", seed: int = 7, verbose: bool = True) -> dict:
    os.makedirs(outdir, exist_ok=True)
    results: dict = {}
    for attack, (title, blurb) in ATTACK_INFO.items():
        runs = {m: run_scenario(attack, m, seed=seed, attack_start=15.0) for m in ("off", "monitor", "protect")}
        results[attack] = runs
        if not verbose:
            continue
        print("\n" + c("=" * 100, "bold"))
        print(c(title, "bold"))
        print(c(blurb, "dim"))
        print(c("=" * 100, "bold"))
        print("Availability of LEGITIMATE users, 1 character per second ('@' = 100% served ... ' ' = 0%); attack starts at t=15 s:")
        for m, r in runs.items():
            print(f"  {m:<8}|{bar(r)}|")
        print("          " + "".join(str(i // 10) if i % 10 == 0 else " " for i in range(60)) + "   (x10 s)")
        print(f"\nTimeline (guard in PROTECT mode):")
        print("\n".join(timeline(runs["protect"])))
        print(f"\n  {'mode':<9}{'before':>8}{'attack':>9}{'steady*':>9}{'latency':>10}{'1st alert':>11}{'mitigated':>11}{'legit IPs blocked':>19}")
        for m, r in runs.items():
            lat = "-" if r.mean_latency_ms is None else f"{r.mean_latency_ms:.0f} ms"
            al = "-" if r.detect_delay is None else f"+{r.detect_delay:.0f} s"
            mi = "-" if r.mitigation_delay is None else f"+{r.mitigation_delay:.0f} s"
            print(f"  {m:<9}{pc(r.avail_pre):>8}{pc(r.avail_attack):>9}{pc(r.avail_steady):>9}{lat:>10}{al:>11}{mi:>11}{len(r.legit_ips_blocked):>19}")
        off, pr = runs["off"], runs["protect"]
        verdict = "DEFEATED" if (pr.avail_steady or 0) >= 0.9 else "PARTLY MITIGATED"
        print(c(f"\n  RESULT: server unprotected -> {pc(off.avail_steady).strip()} of real users served; "
                f"with DosGuard -> {pc(pr.avail_steady).strip()}  [{verdict}]", "green" if verdict == "DEFEATED" else "yellow"))
        print("  (*steady = from 10 s after the attack starts, i.e. after the guard has had time to react)")
    # evidence: a web-server access log of the unprotected HTTP flood (for `analyze-log`)
    n = write_access_log(os.path.join(outdir, "access_http_flood.log"), results["http_flood"]["off"].access_log)
    if verbose:
        print("\n" + c("Real-world equivalents of the guard's actions (what an admin would run on Linux):", "bold"))
        for a, cmd in REAL_WORLD_MAP:
            print(f"  {a:<28} {cmd}")
        print(f"\nWrote {outdir}/access_http_flood.log ({n} requests, nginx/Apache format). Try:")
        print(f"  python -m dosguard analyze-log {outdir}/access_http_flood.log")
    return results
