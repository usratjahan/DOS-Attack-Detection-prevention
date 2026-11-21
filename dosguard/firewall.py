"""How DosGuard's decisions map to *real* Linux commands (dry-run by default).

The simulator applies the same mitigations in memory; this class shows what an administrator /
agent would run on an actual server. Arguments are validated and executed without a shell.
"""
from __future__ import annotations

import ipaddress
import subprocess
from typing import Callable, List


class ShellFirewall:
    def __init__(self, dry_run: bool = True, runner: Callable = subprocess.run, echo: Callable = print):
        self.dry_run, self.runner, self.echo = dry_run, runner, echo
        self.history: List[List[str]] = []

    def _run(self, cmd: List[str]) -> List[str]:
        self.history.append(cmd)
        self.echo(("[dry-run] " if self.dry_run else "[exec] ") + " ".join(cmd))
        if not self.dry_run:
            self.runner(cmd, check=False, capture_output=True)
        return cmd

    @staticmethod
    def _int(v, lo: int, hi: int) -> str:
        v = int(v)
        if not lo <= v <= hi:
            raise ValueError(f"value {v} outside {lo}..{hi}")
        return str(v)

    def block_ip(self, ip: str) -> List[str]:
        ip = str(ipaddress.ip_address(ip))
        return self._run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])

    def syn_cookies(self, on: bool = True) -> List[str]:
        return self._run(["sysctl", "-w", f"net.ipv4.tcp_syncookies={1 if on else 0}"])

    def conn_limit(self, n: int, port: int = 80) -> List[str]:
        return self._run(["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "--dport", self._int(port, 1, 65535),
                          "-m", "connlimit", "--connlimit-above", self._int(n, 1, 100000), "-j", "REJECT"])

    def rate_limit(self, rps: int, port: int = 80) -> List[str]:
        return self._run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", self._int(port, 1, 65535),
                          "-m", "hashlimit", "--hashlimit-above", f"{self._int(rps, 1, 1000000)}/sec",
                          "--hashlimit-mode", "srcip", "--hashlimit-name", "dosguard", "-j", "DROP"])

    @staticmethod
    def header_timeout_config(seconds: int = 5) -> str:
        """Web-server setting (not a shell command): nginx / Apache equivalents of the header deadline."""
        s = int(seconds)
        return f"nginx:  client_header_timeout {s}s;\napache: RequestReadTimeout header=20-{s},MinRate=500"


REAL_WORLD_MAP = [
    ("SYN cookies ON", "sysctl -w net.ipv4.tcp_syncookies=1"),
    ("BLOCK <ip> for N s", "iptables -I INPUT -s <ip> -j DROP   (+ timed removal, or `ipset ... timeout N`)"),
    ("max connections per IP", "iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j REJECT"),
    ("per-IP request rate limit", "iptables -m hashlimit --hashlimit-above 50/sec --hashlimit-mode srcip -j DROP  (or nginx limit_req)"),
    ("header deadline", "nginx client_header_timeout 5s;  Apache mod_reqtimeout"),
]
