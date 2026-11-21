"""Backend for the live dashboard: stdlib HTTP server (no dependencies).

  GET  /                 dashboard (web/index.html)
  GET  /static/<file>    style.css, app.js (whitelisted)
  GET  /api/state        chart history + latest snapshot + event feed (page load)
  GET  /events           Server-Sent Events stream: one JSON snapshot every 0.5 simulated seconds
  POST /api/attack       {"type": "syn_flood|http_flood|slowloris|http_distributed", "action": "start|stop"}
  POST /api/mode         {"mode": "off|monitor|protect"}
  POST /api/speed        {"speed": 1|2|4}
  POST /api/reset        {}

Binds to 127.0.0.1 by default. The "attacks" only ever act on the in-memory simulation.
"""
from __future__ import annotations

import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .live import LiveSim

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
STATIC = {"index.html": "text/html; charset=utf-8", "style.css": "text/css; charset=utf-8", "app.js": "application/javascript; charset=utf-8"}
MAX_BODY = 2048


class Handler(BaseHTTPRequestHandler):
    live: LiveSim = None                                   # set by make_server()
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):                     # keep the terminal quiet
        pass

    # ---- helpers ----------------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _file(self, name: str) -> None:
        ctype = STATIC.get(name)
        if ctype is None:
            return self._json(404, {"error": "not found"})
        with open(os.path.join(WEB_DIR, name), "rb") as f:
            self._send(200, f.read(), ctype)

    # ---- GET ------------------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._file("index.html")
        if path.startswith("/static/"):
            return self._file(path[len("/static/"):])
        if path == "/api/state":
            return self._json(200, self.live.state())
        if path == "/events":
            return self._events()
        self._json(404, {"error": "not found"})

    def _events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        live, seen = self.live, -1
        try:
            while True:
                with live.cond:
                    if live.version == seen:
                        live.cond.wait(timeout=15.0)
                    version, payload = live.version, live.latest
                if version == seen or not payload:
                    self.wfile.write(b": keep-alive\n\n")             # heartbeat so dead clients are noticed
                else:
                    seen = version
                    self.wfile.write(b"data: " + payload.encode() + b"\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return

    # ---- POST -----------------------------------------------------------------------
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > MAX_BODY:
                return self._json(413, {"error": "body too large"})
            data = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("body must be a JSON object")
            path, live = self.path.split("?", 1)[0], self.live
            if path == "/api/attack":
                action = data.get("action")
                if action == "start":
                    live.start_attack(str(data.get("type")))
                elif action == "stop":
                    live.stop_attack(str(data.get("type")))
                else:
                    raise ValueError("action must be start or stop")
            elif path == "/api/mode":
                live.set_mode(str(data.get("mode")))
            elif path == "/api/speed":
                live.set_speed(float(data.get("speed")))
            elif path == "/api/reset":
                live.reset()
            else:
                return self._json(404, {"error": "not found"})
            self._json(200, {"ok": True})
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            self._json(400, {"error": str(e)})


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(host: str = "127.0.0.1", port: int = 8000, live: Optional[LiveSim] = None) -> ThreadingHTTPServer:
    live = live or LiveSim()
    handler = type("BoundHandler", (Handler,), {"live": live})
    srv = QuietServer((host, port), handler)
    srv.live = live
    return srv


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    srv = make_server(host, port)
    srv.live.start()
    url = f"http://{host}:{srv.server_address[1]}/"
    print(f"DosGuard Live running at {url}   (Ctrl+C to stop)")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        srv.live.stop()
        srv.server_close()
