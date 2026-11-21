"""Self-contained HTML report (no external assets)."""
from __future__ import annotations

import html
from typing import Dict

from .demo import ATTACK_INFO, condensed
from .firewall import REAL_WORLD_MAP

CSS = """
:root{--bg:#f7f8fa;--fg:#1b2330;--mut:#5b6677;--card:#fff;--bd:#dde2ea;--ok:#157347;--bad:#c0392b;--warn:#b7791f;--acc:#2456d6}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--fg:#e6ebf2;--mut:#98a3b5;--card:#171e28;--bd:#2a3442;--ok:#4cc38a;--bad:#ff6b5e;--warn:#e0b34f;--acc:#7aa2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,Segoe UI,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}h1{font-size:28px;margin:.2em 0}h2{margin:2em 0 .5em;font-size:21px}h3{margin:.2em 0;font-size:16px}
p.lead{color:var(--mut);margin-top:0}.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px;margin:14px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px;display:block;overflow-x:auto}th,td{padding:6px 10px;border-bottom:1px solid var(--bd);text-align:left;white-space:nowrap}
th{color:var(--mut);font-weight:600}td.n{text-align:right;font-variant-numeric:tabular-nums}code,pre{font:12.5px ui-monospace,Menlo,Consolas,monospace}
pre{background:color-mix(in srgb,var(--fg) 6%,transparent);padding:10px;border-radius:8px;overflow-x:auto;margin:8px 0}
.k-attack{color:var(--bad)}.k-guard{color:var(--ok)}.k-benign{color:var(--acc)}svg text{fill:var(--fg);font:11px system-ui}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.stat{font-size:28px;font-weight:700}.stat small{display:block;font-size:12px;font-weight:400;color:var(--mut)}
.legend span{display:inline-block;margin-right:14px;font-size:13px}.legend i{display:inline-block;width:18px;height:3px;vertical-align:middle;margin-right:5px}
"""
COLORS = {"off": "var(--bad)", "monitor": "var(--warn)", "protect": "var(--ok)"}
NAMES = {"off": "no protection", "monitor": "detection only", "protect": "DosGuard protect"}


def chart(runs: Dict, attack_start: float, duration: float = 60.0) -> str:
    W, H, L, B = 640, 190, 38, 24
    x = lambda t: L + (W - L - 10) * t / duration
    y = lambda a: 10 + (H - B - 10) * (1 - a)
    out = [f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="Availability of legitimate users over time">']
    for g in (0, .5, 1):
        out.append(f'<line x1="{L}" x2="{W - 10}" y1="{y(g):.1f}" y2="{y(g):.1f}" stroke="var(--bd)"/><text x="2" y="{y(g) + 4:.1f}">{int(g * 100)}%</text>')
    for t in range(0, int(duration) + 1, 10):
        out.append(f'<text x="{x(t) - 6:.1f}" y="{H - 8}">{t}s</text>')
    out.append(f'<line x1="{x(attack_start):.1f}" x2="{x(attack_start):.1f}" y1="8" y2="{H - B}" stroke="var(--mut)" stroke-dasharray="4 3"/>'
               f'<text x="{x(attack_start) + 4:.1f}" y="20">attack starts</text>')
    for m, r in runs.items():
        pts = [(i + 0.5, a) for i, a in enumerate(r.series(1.0)) if a is not None]
        d = " ".join(f"{x(t):.1f},{y(a):.1f}" for t, a in pts)
        out.append(f'<polyline points="{d}" fill="none" stroke="{COLORS[m]}" stroke-width="2.2" stroke-linejoin="round"/>')
    out.append("</svg>")
    out.append('<div class="legend">' + "".join(f'<span><i style="background:{COLORS[m]}"></i>{NAMES[m]}</span>' for m in runs) + "</div>"
               '<p class=lead style="font-size:13px;margin:4px 0 8px">Red and orange overlap exactly: detecting an attack without preventing it does nothing for real users.</p>')
    return "".join(out)


def build_report(demos: Dict, ev: Dict, path: str) -> str:
    e = html.escape
    P = [f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>DosGuard Report</title><style>{CSS}</style><main>",
         "<h1>DosGuard - DoS Attack Detection &amp; Prevention</h1>"
         "<p class=lead>Simulates three real denial-of-service attacks against a default-configured web server, shows legitimate users being locked out, "
         "then detects and stops each attack automatically.</p>"]
    m = {(r["attack"], r["mode"]): r for r in ev["matrix"]}
    attacks = [a for a in ATTACK_INFO]
    avg = lambda mode, key: round(sum(m[(a, mode)][key] for a in attacks) / len(attacks), 1)
    b = ev["benign"]
    P.append('<div class=grid>'
             f'<div class="card stat">{avg("off", "avail_steady_pct")}%<small>real users served during attack - no protection</small></div>'
             f'<div class="card stat">{avg("protect", "avail_steady_pct")}%<small>real users served during attack - DosGuard</small></div>'
             f'<div class="card stat">{avg("protect", "detected_pct")}%<small>attacks detected (4 attack types)</small></div>'
             f'<div class="card stat">{b["legit_ips_blocked_total"]}<small>legitimate IPs ever blocked ({2 * b["runs_per_case"]} clean/flash-crowd runs)</small></div></div>')

    P.append("<h2>1. The three attacks</h2><div class=card><table><tr><th>Attack</th><th>Resource exhausted</th><th>Why a default server fails</th></tr>"
             "<tr><td>SYN flood</td><td>half-open connection queue</td><td style='white-space:normal'>Spoofed SYNs never complete; each one holds a queue slot for 8 s.</td></tr>"
             "<tr><td>HTTP flood</td><td>CPU / request workers</td><td style='white-space:normal'>More requests than the server can process; queue overflows, real requests time out.</td></tr>"
             "<tr><td>Slowloris</td><td>connection slots</td><td style='white-space:normal'>Slow, never-finished requests hold every slot with almost no bandwidth.</td></tr></table></div>")

    P.append("<h2>2. How DosGuard detects and prevents</h2><div class=card><table><tr><th>Detection rule</th><th>Signal</th><th>Automatic prevention</th></tr>"
             "<tr><td><code>SYN_FLOOD</code></td><td style='white-space:normal'>&gt;=100 SYN/s, &lt;30% complete the handshake, backlog filling</td><td style='white-space:normal'>SYN cookies (stateless handshake), block non-spoofed sources</td></tr>"
             "<tr><td><code>HTTP_FLOOD</code></td><td style='white-space:normal'>one IP &gt;=50 req/s for 2 s</td><td style='white-space:normal'>temporary ban, doubling for repeat offenders</td></tr>"
             "<tr><td><code>GLOBAL_OVERLOAD</code></td><td style='white-space:normal'>total load &gt;=90% of capacity</td><td style='white-space:normal'>max-min fair-share rate limit; IPs with a clean history are exempt</td></tr>"
             "<tr><td><code>SLOWLORIS</code></td><td style='white-space:normal'>&gt;=10 connections from one IP still without request headers after 3 s</td><td style='white-space:normal'>block IP + kill connections; hardening: 5 s header deadline, 20 connections/IP</td></tr></table>"
             "<p>Every ban expires automatically so mistakes heal themselves. Legitimate traffic includes a shared-IP office (15 req/s) and a power user (8 req/s), which a naive limiter would block.</p></div>")

    P.append("<h2>3. Proof of concept</h2>")
    for attack, runs in demos.items():
        title, blurb = ATTACK_INFO[attack]
        off, pr = runs["off"], runs["protect"]
        P.append(f"<div class=card><h3>{e(title)}</h3><p class=lead>{e(blurb)}</p>{chart(runs, off.attack_start)}")
        P.append("<table><tr><th>Mode</th><th>Before</th><th>During attack</th><th>Steady (+10 s)</th><th>Latency</th><th>First alert</th><th>Mitigated</th><th>Legit IPs blocked</th></tr>")
        for mode, r in runs.items():
            f = lambda x: "-" if x is None else f"{100 * x:.0f}%"
            lat = "-" if r.mean_latency_ms is None else f"{r.mean_latency_ms:.0f} ms"
            P.append(f"<tr><td>{NAMES[mode]}</td><td class=n>{f(r.avail_pre)}</td><td class=n>{f(r.avail_attack)}</td><td class=n>{f(r.avail_steady)}</td>"
                     f"<td class=n>{lat}</td><td class=n>{'-' if r.detect_delay is None else '+%.0f s' % r.detect_delay}</td>"
                     f"<td class=n>{'-' if r.mitigation_delay is None else '+%.0f s' % r.mitigation_delay}</td><td class=n>{len(r.legit_ips_blocked)}</td></tr>")
        P.append("</table><pre>")
        rows, hidden = condensed(pr.events)
        for t, kind, msg in rows:
            P.append(f'<span class="k-{kind}">t={t:6.1f}s  {kind.upper():<6} {e(msg)}</span>\n')
        if hidden:
            P.append(f"... {hidden} similar alert/block lines hidden (one per attacking IP)\n")
        P.append("</pre></div>")

    P.append("<h2>4. Evaluation</h2><div class=card>"
             f"<p>Every attack x every mode x {ev['seeds']} random seeds (random attack start, bot timing, user arrivals). Availability = share of real users' requests served within 2 s.</p>"
             "<table><tr><th>Attack</th><th>Mode</th><th>Before %</th><th>During %</th><th>Steady %</th><th>Ordinary %</th><th>Heavy users %</th><th>Latency</th><th>Alert (s)</th><th>Mitigated (s)</th><th>Legit IPs blocked</th></tr>")
    v = lambda x, s="": "-" if x is None else f"{x}{s}"
    for r in ev["matrix"]:
        P.append(f"<tr><td>{r['attack']}</td><td>{r['mode']}</td><td class=n>{v(r['avail_before_pct'])}</td><td class=n>{v(r['avail_during_pct'])}</td>"
                 f"<td class=n>{v(r['avail_steady_pct'])}</td><td class=n>{v(r['avail_ordinary_steady_pct'])}</td><td class=n>{v(r['avail_heavy_steady_pct'])}</td>"
                 f"<td class=n>{v(r['mean_latency_ms'], ' ms')}</td><td class=n>{v(r['mean_alert_delay_s'])}</td><td class=n>{v(r['mean_mitigation_delay_s'])}</td><td class=n>{r['legit_ips_blocked']}</td></tr>")
    P.append(f"</table><h3 style='margin-top:16px'>False alarms on legitimate traffic</h3><p>{e(b['legit_traffic'])}.<br>"
             f"Normal traffic: <b>{b['clean_runs_with_false_alarm']}/{b['runs_per_case']}</b> runs with any alert or action. "
             f"Flash crowd: <b>{b['flash_crowd_runs_with_false_alarm']}/{b['runs_per_case']}</b>. Legitimate IPs blocked in total: <b>{b['legit_ips_blocked_total']}</b>.</p></div>")

    P.append("<h2>5. Real-world mapping</h2><div class=card><p>The simulator applies each mitigation in memory. On a real Linux server they correspond to:</p><table><tr><th>DosGuard action</th><th>Real command / setting</th></tr>")
    for a, cmd in REAL_WORLD_MAP:
        P.append(f"<tr><td>{e(a)}</td><td><code>{e(cmd)}</code></td></tr>")
    P.append("</table><p><code>python -m dosguard analyze-log access.log</code> runs the same per-IP flood rule on a real nginx/Apache log and prints the iptables commands (dry-run).</p></div>")

    P.append("<h2>6. Limitations (honest)</h2><div class=card><ul>"
             "<li>It is a simulation with simplified servers and attackers; the numbers describe the model, not a production system.</li>"
             "<li>Thresholds (50 req/s per IP, 100 SYN/s, ...) are fixed and tuned for this model; a real deployment must tune them to its own baseline.</li>"
             "<li>A very large shared-IP network (NAT) above the per-IP limit would be treated as a flood.</li>"
             "<li>Sleeper bots that behave for a while build a good reputation and then escape the fair-share limit. A rate-only defence also cannot tell a busy office from polite bots; real systems add CAPTCHA / JavaScript challenges.</li>"
             "<li>Volumetric floods that saturate the network link before reaching the server need upstream scrubbing / a CDN; software on the server cannot help.</li></ul></div>")
    P.append("</main></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(P))
    return path
