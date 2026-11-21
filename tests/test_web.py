import json, threading, unittest, urllib.request, urllib.error
from dosguard.live import LiveSim
from dosguard.webserver import make_server


class LiveTests(unittest.TestCase):
    def test_baseline_healthy(self):
        l = LiveSim(1); l.advance(10)
        s = l._snapshot()
        self.assertGreater(s["avail"], 90)

    def test_attack_hurts_and_protection_heals(self):
        l = LiveSim(1); l.advance(6)
        l.start_attack("http_flood"); l.advance(15)
        self.assertLess(l._snapshot()["avail"], 60)
        l.set_mode("protect"); l.advance(30)
        s = l._snapshot()
        self.assertGreater(s["avail"], 85)
        self.assertGreater(s["blocked_total"], 0)

    def test_mode_switch_clears_protections(self):
        l = LiveSim(1); l.set_mode("protect"); l.advance(3)
        l.start_attack("syn_flood"); l.advance(6)
        self.assertTrue(l._snapshot()["protections"]["syn_cookies"])
        l.set_mode("off")
        p = l._snapshot()["protections"]
        self.assertFalse(p["syn_cookies"]); self.assertEqual(l._snapshot()["blocked_total"], 0)

    def test_stop_attack_and_validation(self):
        l = LiveSim(1); self.assertTrue(l.start_attack("slowloris")); self.assertFalse(l.start_attack("slowloris"))
        self.assertTrue(l.stop_attack("slowloris")); self.assertFalse(l.stop_attack("slowloris"))
        for bad in (lambda: l.start_attack("x"), lambda: l.set_mode("x"), lambda: l.set_speed(3)):
            with self.assertRaises(ValueError): bad()

    def test_history_has_atk(self):
        l = LiveSim(1); l.start_attack("syn_flood"); l.advance(3)
        self.assertEqual(l.history[-1]["atk"], 1)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live = LiveSim(1)
        cls.srv = make_server("127.0.0.1", 0, cls.live)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def req(self, path, data=None):
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=None if data is None else json.dumps(data).encode(),
                                   headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r, timeout=5) as x: return x.status, x.read()
        except urllib.error.HTTPError as e: return e.code, e.read()

    def test_static_and_state(self):
        for p in ("/", "/static/app.js", "/static/style.css"):
            self.assertEqual(self.req(p)[0], 200)
        c, b = self.req("/api/state"); self.assertEqual(c, 200); self.assertIn("snapshot", json.loads(b))

    def test_validation_and_traversal(self):
        self.assertEqual(self.req("/api/attack", {"type": "nope", "action": "start"})[0], 400)
        self.assertEqual(self.req("/api/mode", {"mode": "zzz"})[0], 400)
        self.assertEqual(self.req("/api/speed", {"speed": 9})[0], 400)
        self.assertEqual(self.req("/static/../__main__.py")[0], 404)
        self.assertEqual(self.req("/static/%2e%2e/live.py")[0], 404)
        self.assertEqual(self.req("/nothing")[0], 404)

    def test_controls_work(self):
        self.assertEqual(self.req("/api/mode", {"mode": "protect"})[0], 200)
        self.assertEqual(self.live.mode, "protect")
        self.assertEqual(self.req("/api/attack", {"type": "syn_flood", "action": "start"})[0], 200)
        self.assertIn("syn_flood", self.live.attacks)
        self.assertEqual(self.req("/api/reset", {})[0], 200)
        self.assertEqual(self.live.mode, "off")

    def test_sse_first_event(self):
        self.live.advance(1)
        r = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/events", timeout=5)
        line = b""
        while not line.startswith(b"data:"): line = r.readline()
        self.assertIn("avail", json.loads(line[5:])); r.close()


if __name__ == "__main__":
    unittest.main()
