import argparse
import os
import sys

from . import demo as demo_mod
from .evaluate import evaluate, format_table, save
from .logs import analyze_log
from .report import build_report


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):                 # never crash on a Windows console encoding
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(prog="dosguard", description="DoS attack detection and prevention (SYN flood, HTTP flood, Slowloris)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="proof of concept: 4 attacks x (no protection / detection only / protected)")
    d.add_argument("--out", default="output")
    d.add_argument("--seed", type=int, default=7)
    d.add_argument("--no-color", action="store_true")
    e = sub.add_parser("evaluate", help="randomised evaluation table")
    e.add_argument("--seeds", type=int, default=10)
    e.add_argument("--benign-seeds", type=int, default=30)
    e.add_argument("--out", default="output")
    r = sub.add_parser("report", help="demo + evaluation -> output/report.html")
    r.add_argument("--out", default="output")
    r.add_argument("--seeds", type=int, default=10)
    w = sub.add_parser("serve", help="real-time web dashboard (frontend + backend) at http://127.0.0.1:8000")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("--host", default="127.0.0.1", help="keep 127.0.0.1 unless you really want other machines to connect")
    w.add_argument("--no-browser", action="store_true")
    a = sub.add_parser("analyze-log", help="find HTTP-flood sources in a real nginx/Apache access log")
    a.add_argument("logfile")
    a.add_argument("--rps", type=int, default=50, help="requests/second per IP considered abusive (default 50)")
    a.add_argument("--seconds", type=int, default=2, help="how many consecutive seconds (default 2)")
    args = p.parse_args(argv)

    if args.cmd == "demo":
        demo_mod.USE_COLOR = sys.stdout.isatty() and not args.no_color
        demo_mod.run_demo(args.out, args.seed)
    elif args.cmd == "evaluate":
        os.makedirs(args.out, exist_ok=True)
        res = evaluate(args.seeds, args.benign_seeds)
        save(res, os.path.join(args.out, "evaluation.json"), os.path.join(args.out, "evaluation.csv"))
        print(format_table(res))
    elif args.cmd == "report":
        demo_mod.USE_COLOR = False
        demos = demo_mod.run_demo(args.out, verbose=False)
        res = evaluate(args.seeds, 30)
        save(res, os.path.join(args.out, "evaluation.json"), os.path.join(args.out, "evaluation.csv"))
        path = build_report(demos, res, os.path.join(args.out, "report.html"))
        print(format_table(res))
        print(f"\nreport: {path}")
    elif args.cmd == "serve":
        from .webserver import serve
        serve(args.host, args.port, not args.no_browser)
    elif args.cmd == "analyze-log":
        analyze_log(args.logfile, args.rps, args.seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
