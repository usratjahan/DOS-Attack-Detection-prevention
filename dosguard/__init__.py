"""DosGuard - detection and prevention of SYN flood, HTTP flood and Slowloris denial-of-service attacks."""
from .firewall import ShellFirewall
from .guard import DosGuard, fair_share
from .server import Server

__version__ = "1.0.0"
__all__ = ["DosGuard", "Server", "ShellFirewall", "fair_share"]
