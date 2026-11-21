"""Real-world mode: analyse a real web-server access log (nginx/Apache 'combined' format)
for HTTP-flood sources and print the firewall commands DosGuard would apply (dry-run)."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List

from .firewall import ShellFirewall

LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3})')


def write_access_log(path: str, access_log: List[tuple], base: datetime = None) -> int:
    """Write the simulator's request log in combined log format (so analyze-log can be tried on it)."""
    base = base or datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone(timedelta(hours=6)))
    with open(path, "w") as f:
        for t, ip, status in sorted(access_log):
            ts = (base + timedelta(seconds=t)).strftime("%d/%b/%Y:%H:%M:%S %z")
            f.write(f'{ip} - - [{ts}] "GET /index.html HTTP/1.1" {status} 512 "-" "sim-client"\n')
    return len(access_log)


def analyze_log(path: str, rps_limit: int = 50, min_seconds: int = 2, echo: Callable = print) -> Dict:
    """Flag IPs that sustain >= rps_limit requests/second for >= min_seconds consecutive seconds."""
    per: Dict[str, Counter] = defaultdict(Counter)
    cache: Dict[str, int] = {}
    lines = bad = 0
    with open(path, errors="replace") as f:
        for line in f:
            m = LOG_RE.match(line)
            if not m:
                bad += 1
                continue
            ip, ts, _req, _status = m.groups()
            sec = cache.get(ts)
            if sec is None:
                try:
                    sec = cache[ts] = int(datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp())
                except ValueError:
                    bad += 1
                    continue
            per[ip][sec] += 1
            lines += 1
    flagged: Dict[str, dict] = {}
    for ip, secs in per.items():
        run = best = 0
        prev = None
        peak = max(secs.values())
        for s in sorted(secs):
            if secs[s] >= rps_limit:
                run = run + 1 if prev is not None and s == prev + 1 else 1
                best = max(best, run)
            else:
                run = 0
            prev = s
        if best >= min_seconds:
            flagged[ip] = {"peak_rps": peak, "seconds_over_limit": sum(1 for v in secs.values() if v >= rps_limit), "requests": sum(secs.values())}
    echo(f"parsed {lines} requests from {len(per)} IPs ({bad} unparsable lines); threshold {rps_limit} req/s for {min_seconds}+ s")
    top = sorted(((sum(c.values()), ip) for ip, c in per.items()), reverse=True)[:5]
    echo("top talkers: " + ", ".join(f"{ip} ({n})" for n, ip in top))
    if not flagged:
        echo("no HTTP-flood sources found")
    fw = ShellFirewall(dry_run=True, echo=lambda s: echo("   -> " + s))
    for ip, info in sorted(flagged.items(), key=lambda kv: -kv[1]["peak_rps"]):
        echo(f"FLOOD SOURCE {ip}: peak {info['peak_rps']} req/s, {info['seconds_over_limit']} s over limit, {info['requests']} requests")
        fw.block_ip(ip)
    return {"lines": lines, "ips": len(per), "flagged": flagged, "unparsable": bad}
