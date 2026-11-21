import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dosguard import DosGuard, Server, ShellFirewall, fair_share
from dosguard.logs import analyze_log, write_access_log
from dosguard.scenario import ATTACKS, run_scenario
from dosguard.server import Conn
from dosguard.sim import Sim


def quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)


class FairShareTests(unittest.TestCase):
    def test_everyone_fits(self):
        self.assertEqual(fair_share({"a": 1, "b": 2}, 100), float("inf"))

    def test_heavy_sources_capped_light_untouched(self):
        level = fair_share({"a": 1, "b": 1, "x": 500, "y": 500}, 102)
        self.assertAlmostEqual(level, 50.0)

    def test_equal_split(self):
        self.assertAlmostEqual(fair_share({"a": 10, "b": 10, "c": 10}, 15), 5.0)


class ServerTests(unittest.TestCase):
    def test_syn_cookies_are_stateless(self):
        sim = Sim()
        s = Server(sim)
        s.syn_cookies = True
        for i in range(1000):
            s.syn("9.9.9.%d" % (i % 250), i, lambda c: None)
        sim.run(1.0)
        self.assertEqual(len(s.half_open), 0)

    def test_forged_cookie_rejected_valid_cookie_accepted(self):
        sim = Sim()
        s, got = Server(sim), []
        s.syn_cookies = True
        cookie = []
        s.syn("1.2.3.4", 77, cookie.append)
        sim.run(0.1)
        s.ack("1.2.3.4", 78, 12345, got.append)        # forged
        s.ack("1.2.3.4", 77, cookie[0], got.append)    # genuine
        self.assertEqual(got, [False, True])

    def test_backlog_fills_without_cookies(self):
        s = Server(Sim())
        for i in range(500):
            s.syn("9.9.%d.%d" % (i // 250, i % 250), i, lambda c: None)
        self.assertEqual(len(s.half_open), s.backlog)
        self.assertGreater(s.stats["syn_dropped"], 0)

    def test_ban_expires_automatically(self):
        sim = Sim()
        s = Server(sim)
        s.block("5.5.5.5", 10)
        self.assertTrue(s.is_blocked("5.5.5.5"))
        sim.run(11.0)
        self.assertFalse(s.is_blocked("5.5.5.5"))

    def test_token_bucket_limits_rate(self):
        sim = Sim()
        s = Server(sim)
        s.ip_rate_limit = 5.0
        allowed = sum(s._take_token("1.1.1.1") for _ in range(100))   # 100 requests in the same instant
        self.assertLessEqual(allowed, 6)

    def test_header_deadline_kills_slow_connections(self):
        sim = Sim()
        s = Server(sim)
        s.header_deadline = 5.0
        s.conns[1] = Conn(1, "1.1.1.1", 0.0)           # a client that opened a connection at t=0 ...
        s.ip_conns["1.1.1.1"] += 1
        sim.at(3.0, s.trickle, 1)                      # ... and drip-feeds a byte at t=3, never finishing its headers
        sim.run(8.0)
        self.assertNotIn(1, s.conns)
        self.assertEqual(s.stats["slow_killed"], 1)


class EndToEndTests(unittest.TestCase):
    def test_no_attack_everything_served(self):
        r = run_scenario(None, "off", seed=1)
        self.assertGreaterEqual(r.avail(0, 60), 0.99)

    def test_every_attack_hurts_an_unprotected_server(self):
        for a in ATTACKS:
            r = run_scenario(a, "off", seed=2)
            self.assertLess(r.avail_steady, 0.45, a)
            self.assertGreaterEqual(r.avail_pre, 0.99, a)

    def test_protection_restores_service_for_every_attack(self):
        for a in ATTACKS:
            for seed in (1, 2, 3):
                r = run_scenario(a, "protect", seed=seed)
                self.assertGreaterEqual(r.avail_steady, 0.85, (a, seed))
                self.assertEqual(r.legit_ips_blocked, [], (a, seed))
                self.assertIsNotNone(r.mitigation_delay, (a, seed))

    def test_every_attack_is_detected_in_monitor_mode_but_not_stopped(self):
        for a in ATTACKS:
            r = run_scenario(a, "monitor", seed=4)
            self.assertIsNotNone(r.first_alert_ts, a)
            self.assertIsNone(r.first_mitigation_ts, a)
            self.assertLess(r.avail_steady, 0.45, a)

    def test_correct_rule_fires_for_each_attack(self):
        want = {"syn_flood": "SYN_FLOOD", "http_flood": "HTTP_FLOOD", "slowloris": "SLOWLORIS", "http_distributed": "GLOBAL_OVERLOAD"}
        for a, rule in want.items():
            r = run_scenario(a, "protect", seed=5)
            self.assertIn(rule, {x.rule for x in r.alerts}, a)

    def test_spoofed_syn_flood_cannot_be_ip_blocked_but_cookies_work(self):
        r = run_scenario("syn_flood", "protect", seed=6)
        self.assertEqual(r.blocked_history, [])                 # every source IP was fake and different
        self.assertTrue(any("SYN cookies ON" in d for _, d in r.actions))

    def test_no_false_alarms_on_clean_or_flash_crowd_traffic(self):
        for seed in range(1, 16):
            for flash in (False, True):
                r = run_scenario(None, "protect", seed=seed, flash_crowd=flash)
                self.assertEqual(r.alerts, [], (seed, flash))
                self.assertEqual(r.blocked_history, [], (seed, flash))
                self.assertGreaterEqual(r.avail(0, 60), 0.99, (seed, flash))

    def test_repeat_offenders_get_longer_bans(self):
        r = run_scenario("slowloris", "protect", seed=1, duration=120.0)
        ip = "192.0.2.1"
        bans = [d for _, d in r.actions if d.startswith(f"BLOCK {ip} ")]
        self.assertGreaterEqual(len(bans), 2)
        self.assertIn("for 30s", bans[0])
        self.assertIn("for 60s", bans[1])


class LogAnalyzerTests(unittest.TestCase):
    def test_flags_flood_sources_only(self):
        r = run_scenario("http_flood", "off", seed=7)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "access.log")
            write_access_log(p, r.access_log)
            res = quiet(analyze_log, p)
        flagged = set(res["flagged"])
        self.assertEqual(len(flagged), 15)
        self.assertTrue(all(ip.startswith("198.51.100.") for ip in flagged))   # no legit visitor / NAT office / power user

    def test_survives_garbage_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.log")
            with open(p, "w") as f:
                f.write("garbage\n\x00\x01\n" + '1.2.3.4 - - [15/Nov/2026:12:00:00 +0600] "GET / HTTP/1.1" 200 5\n')
            res = quiet(analyze_log, p)
        self.assertEqual(res["lines"], 1)
        self.assertEqual(res["unparsable"], 2)
        self.assertEqual(res["flagged"], {})


class FirewallTests(unittest.TestCase):
    def test_dry_run_builds_expected_commands(self):
        out = []
        fw = ShellFirewall(echo=out.append)
        self.assertEqual(fw.block_ip("198.51.100.7"), ["iptables", "-I", "INPUT", "-s", "198.51.100.7", "-j", "DROP"])
        self.assertEqual(fw.syn_cookies(), ["sysctl", "-w", "net.ipv4.tcp_syncookies=1"])
        self.assertTrue(all(o.startswith("[dry-run]") for o in out))

    def test_rejects_injection(self):
        fw = ShellFirewall(echo=lambda s: None)
        for bad in ("1.2.3.4; rm -rf /", "$(reboot)", "1.2.3"):
            with self.assertRaises(ValueError):
                fw.block_ip(bad)
        with self.assertRaises(ValueError):
            fw.rate_limit("10; id")
        with self.assertRaises(ValueError):
            fw.conn_limit(0)

    def test_executes_without_shell(self):
        calls = []
        fw = ShellFirewall(dry_run=False, runner=lambda cmd, **kw: calls.append((cmd, kw)), echo=lambda s: None)
        fw.block_ip("203.0.113.9")
        cmd, kw = calls[0]
        self.assertIsInstance(cmd, list)
        self.assertNotIn("shell", kw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
