"""HTB VPN checks: is the box routed through an OpenVPN tunnel, and if not, why.

Reachability is judged by the kernel route to the target (``ip route get``), not by pinging it:
many HTB boxes drop ICMP, and this way the check sends nothing to the target. The tunnel IP is
also your LHOST for reverse shells.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path

from cyberdeck.core.runner import have_binary, run_local
from cyberdeck.core.scope import DEFAULT_SCOPE_CIDRS, Scope

_ADDR_RE = re.compile(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/\d+")
_DEV_RE = re.compile(r"\bdev (\S+)")
_TUNNEL_PREFIXES = ("tun", "tap")
OPENVPN_LOG = Path("/tmp/cyberdeck-openvpn.log")  # noqa: S108 - root-owned openvpn log
HTB_SCOPE = Scope.from_cidrs(DEFAULT_SCOPE_CIDRS)


@dataclass(frozen=True)
class Tunnel:
    name: str
    ip: str


@dataclass(frozen=True)
class VpnStatus:
    target_ip: str
    checked: bool  # False when the `ip` command isn't available (e.g. not Linux)
    tunnels: list[Tunnel] = field(default_factory=list)
    route_dev: str | None = None
    openvpn_running: bool = False
    configs: list[Path] = field(default_factory=list)
    services: list[str] = field(default_factory=list)  # e.g. openvpn-client@htb.service

    @property
    def applicable(self) -> bool:
        """Only HTB lab IPs need the HTB VPN (local test targets don't)."""
        return HTB_SCOPE.contains(self.target_ip)

    @property
    def up(self) -> bool:
        return bool(self.tunnels)

    @property
    def routed_via_tunnel(self) -> bool:
        return self.route_dev is not None and self.route_dev.startswith(_TUNNEL_PREFIXES)

    @property
    def lhost(self) -> str | None:
        if self.route_dev:
            for tunnel in self.tunnels:
                if tunnel.name == self.route_dev:
                    return tunnel.ip
        return self.tunnels[0].ip if self.tunnels else None


def parse_ip_addr(output: str) -> list[Tunnel]:
    """Parse ``ip -4 -o addr show`` and keep tun/tap interfaces."""
    tunnels: list[Tunnel] = []
    for line in output.splitlines():
        match = _ADDR_RE.match(line.strip())
        if match and match.group(1).startswith(_TUNNEL_PREFIXES):
            tunnels.append(Tunnel(match.group(1), match.group(2)))
    return tunnels


def parse_route_dev(output: str) -> str | None:
    """Parse ``ip route get <ip>`` -> outgoing device."""
    match = _DEV_RE.search(output)
    return match.group(1) if match else None


def find_configs(root: Path, explicit: Path | None) -> list[Path]:
    if explicit is not None:
        path = explicit.expanduser()
        return [path] if path.is_file() else []
    root = root.expanduser()
    if not root.is_dir():
        return []
    # Regular boxes use the "machines" VPN; prefer it over competitive/starting-point/etc.
    return sorted(root.glob("*.ovpn"), key=lambda p: (not p.name.startswith("machines"), p.name))


def parse_vpn_services(output: str) -> list[str]:
    """Parse ``systemctl list-units --plain --no-legend 'openvpn*'`` -> unit names."""
    units: list[str] = []
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service") and "@" in parts[0]:
            units.append(parts[0])
    return units


def vpn_status(target_ip: str, root: Path, explicit: Path | None = None) -> VpnStatus:
    configs = find_configs(root, explicit)
    if not have_binary("ip"):
        return VpnStatus(target_ip, checked=False, configs=configs)
    _, addrs = run_local(["ip", "-4", "-o", "addr", "show"])
    route_dev = None
    try:
        ip_address(target_ip)
    except ValueError:
        pass
    else:
        code, route = run_local(["ip", "route", "get", target_ip])
        route_dev = parse_route_dev(route) if code == 0 else None
    running = have_binary("pgrep") and run_local(["pgrep", "-x", "openvpn"])[0] == 0
    units: list[str] = []
    if have_binary("systemctl"):
        _, listing = run_local(
            ["systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend"]
            + ["openvpn*"]
        )
        units = parse_vpn_services(listing)
    return VpnStatus(
        target_ip,
        checked=True,
        tunnels=parse_ip_addr(addrs),
        route_dev=route_dev,
        openvpn_running=running,
        configs=configs,
        services=units,
    )


def start_command(config: Path, log: Path = OPENVPN_LOG) -> list[str]:
    """The command shown to the user and run (after ``sudo -v``) to start the VPN."""
    return ["sudo", "-n", "openvpn", "--config", str(config), "--daemon", "cyberdeck-vpn"] + [
        "--log",
        str(log),
    ]


def start_service_command(unit: str) -> list[str]:
    return ["sudo", "-n", "systemctl", "start", unit]


def start_service(unit: str) -> tuple[bool, str]:
    code, out = run_local(start_service_command(unit), timeout=30)
    if code != 0:
        return False, out.strip() or f"systemctl start {unit} failed; try: journalctl -u {unit}"
    return True, ""


def start_vpn(config: Path, log: Path = OPENVPN_LOG) -> tuple[bool, str]:
    if not have_binary("openvpn"):
        return False, "openvpn is not installed (sudo apt install openvpn)"
    code, out = run_local(start_command(config, log), timeout=30)
    if code != 0:
        return False, out.strip() or f"openvpn exited with {code}; see {log}"
    return True, ""


def wait_for_tunnel(
    target_ip: str, root: Path, explicit: Path | None, seconds: int = 20
) -> VpnStatus:
    status = vpn_status(target_ip, root, explicit)
    deadline = time.monotonic() + seconds
    while not status.routed_via_tunnel and time.monotonic() < deadline:
        time.sleep(1)
        status = vpn_status(target_ip, root, explicit)
    return status
