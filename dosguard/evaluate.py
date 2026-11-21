"""Randomised evaluation across attacks x modes x seeds, plus false-positive tests."""
from __future__ import annotations

import csv
import json
import statistics
from typing import Dict, List, Optional

from .scenario import ATTACKS, MODES, run_scenario


def _mean(xs: List[Optional[float]]) -> Optional[float]:
    xs = [x for x in xs if x is not None]
    return round(statistics.mean(xs), 3) if xs else None


def _pct(x: Optional[float]) -> Optional[float]:
    return None if x is None else round(100 * x, 1)


def evaluate(seeds: int = 10, benign_seeds: int = 30, progress=None) -> Dict:
    out: Dict = {"seeds": seeds, "benign_seeds": benign_seeds, "matrix": [], "benign": {}}
    for a in ATTACKS:
        for m in MODES:
            runs = [run_scenario(a, m, seed=s, attack_start=10.0 + (s % 6)) for s in range(1, seeds + 1)]
            out["matrix"].append({
                "attack": a, "mode": m, "runs": len(runs),
                "avail_before_pct": _pct(_mean([r.avail_pre for r in runs])),
                "avail_during_pct": _pct(_mean([r.avail_attack for r in runs])),
                "avail_steady_pct": _pct(_mean([r.avail_steady for r in runs])),
                "avail_ordinary_steady_pct": _pct(_mean([r.avail(r.attack_start + 10, r.duration, "ordinary") for r in runs])),
                "avail_heavy_steady_pct": _pct(_mean([r.avail(r.attack_start + 10, r.duration, "heavy") for r in runs])),
                "mean_latency_ms": _mean([r.mean_latency_ms for r in runs]) and round(_mean([r.mean_latency_ms for r in runs])),
                "detected_pct": _pct(sum(1 for r in runs if r.first_alert_ts is not None) / len(runs)),
                "mean_alert_delay_s": _mean([r.detect_delay for r in runs]),
                "mean_mitigation_delay_s": _mean([r.mitigation_delay for r in runs]),
                "legit_ips_blocked": sum(len(r.legit_ips_blocked) for r in runs),
            })
            if progress:
                progress(f"{a}/{m}")

    clean = [run_scenario(None, "protect", seed=s) for s in range(1, benign_seeds + 1)]
    flash = [run_scenario(None, "protect", seed=s, flash_crowd=True) for s in range(1, benign_seeds + 1)]
    def false_alarms(rs):
        return sum(1 for r in rs if r.alerts or r.blocked_history or r.first_mitigation_ts is not None)
    out["benign"] = {
        "runs_per_case": benign_seeds,
        "clean_runs_with_false_alarm": false_alarms(clean),
        "flash_crowd_runs_with_false_alarm": false_alarms(flash),
        "legit_ips_blocked_total": sum(len(r.legit_ips_blocked) for r in clean + flash),
        "clean_availability_pct": _pct(_mean([r.avail(0, r.duration) for r in clean])),
        "flash_crowd_availability_pct": _pct(_mean([r.avail(0, r.duration) for r in flash])),
        "legit_traffic": "40 ordinary visitors (0.5 req/s), a shared-IP office (15 req/s), a power user (8 req/s); flash crowd = visitors x10 for 10 s",
    }
    return out


def save(res: Dict, json_path: str, csv_path: str) -> None:
    with open(json_path, "w") as f:
        json.dump(res, f, indent=2)
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(res["matrix"][0].keys()))
        w.writeheader()
        w.writerows(res["matrix"])


def format_table(res: Dict) -> str:
    L = [f"{'attack':<18}{'mode':<9}{'before%':>8}{'during%':>9}{'steady%':>9}{'latency':>9}{'alert(s)':>9}{'mitig(s)':>9}{'legitIPs blocked':>18}",
         "-" * 98]
    for r in res["matrix"]:
        def v(x, suf=""):
            return "-" if x is None else f"{x}{suf}"
        L.append(f"{r['attack']:<18}{r['mode']:<9}{v(r['avail_before_pct']):>8}{v(r['avail_during_pct']):>9}{v(r['avail_steady_pct']):>9}"
                 f"{v(r['mean_latency_ms'], 'ms'):>9}{v(r['mean_alert_delay_s']):>9}{v(r['mean_mitigation_delay_s']):>9}{r['legit_ips_blocked']:>18}")
    b = res["benign"]
    L += ["", f"False alarms on legitimate traffic ({b['runs_per_case']} runs each):",
          f"  normal traffic : {b['clean_runs_with_false_alarm']} runs with any alert/action   (availability {b['clean_availability_pct']}%)",
          f"  flash crowd x10: {b['flash_crowd_runs_with_false_alarm']} runs with any alert/action   (availability {b['flash_crowd_availability_pct']}%)",
          f"  legitimate IPs ever blocked: {b['legit_ips_blocked_total']}"]
    return "\n".join(L)
