"""Setup check (``cyberdeck doctor``, the TUI welcome screen; docs/LEARNING-PLAN.md W1).

Checks the things that trip beginners up before they ever reach a box: the HTB VPN, the core
tools, wordlists (SecLists, an unzipped rockyou.txt), sudo, the hosts file, the clock and the
workspace folder. Every check says what it is for and, when something is wrong, the exact
command that fixes it. Nothing here changes the system: fixes are shown, never run (creating
the workspace folder is offered by the callers, with consent).
"""

from __future__ import annotations

import grp
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from cyberdeck.core.config import Settings
from cyberdeck.core.runner import have_binary, is_root, run_local
from cyberdeck.plugins import wordlists as wl
from cyberdeck.util.vpn import vpn_status

ROCKYOU_GZ = wl.KALI_LISTS / "rockyou.txt.gz"

# The tools a first box needs: (binary, apt package, what it's for). Alternatives: any one will do.
CORE_TOOLS: list[tuple[tuple[str, ...], str, str]] = [
    (("nmap",), "nmap", "port scanning, always the first step"),
    (("whatweb",), "whatweb", "fingerprinting websites"),
    (("feroxbuster", "gobuster", "dirsearch", "ffuf"), "feroxbuster", "finding hidden web pages"),
    (("ffuf",), "ffuf", "finding virtual hosts (vhost fuzzing)"),
    (("searchsploit",), "exploitdb", "looking up known exploits offline"),
    (("smbclient",), "smbclient", "looking at Windows file shares"),
    (("openvpn",), "openvpn", "connecting to the HTB VPN"),
]


class Level(StrEnum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    level: Level
    detail: str
    purpose: str  # one line: why this matters
    fix: str | None = None  # a command to run, or an instruction


def _vpn(settings: Settings) -> list[Check]:
    purpose = "HTB machines are only reachable through the HTB VPN ([[vpn]])."
    status = vpn_status("", settings.vpn_search_dir, settings.vpn_config)
    configs, units = status.configs, status.services
    checks: list[Check] = []
    if configs or units:
        where = ", ".join([*(str(c) for c in configs), *units])
        checks.append(Check("vpn-config", "VPN config", Level.OK, where, purpose))
    else:
        checks.append(
            Check(
                "vpn-config",
                "VPN config",
                Level.FAIL,
                f"no .ovpn file in {settings.vpn_search_dir} and no openvpn-client@ service",
                purpose,
                "Download it from app.hackthebox.com (Connect to HTB > Machines > OpenVPN) and "
                f"save it in {settings.vpn_search_dir} (or set CYBERDECK_VPN_DIR in .env)",
            )
        )
    if not status.checked:
        return checks
    if status.tunnels:
        names = ", ".join(f"{t.name} {t.ip}" for t in status.tunnels)
        checks.append(Check("vpn-up", "VPN connected", Level.OK, f"{names} (your LHOST)", purpose))
    else:
        fix = (
            f"sudo systemctl start {units[0]}"
            if units
            else (f"sudo openvpn {configs[0]}" if configs else "connect the VPN first")
        )
        checks.append(
            Check(
                "vpn-up",
                "VPN connected",
                Level.WARN,
                "no tunnel is up (fine until you start a box; Cyberdeck offers to start it)",
                purpose,
                fix,
            )
        )
    return checks


def _tools() -> list[Check]:
    checks: list[Check] = []
    for binaries, apt, purpose in CORE_TOOLS:
        found = next((b for b in binaries if have_binary(b)), None)
        name = " / ".join(binaries)
        if found:
            detail = "installed" if len(binaries) == 1 else f"using {found}"
            checks.append(Check(f"tool-{binaries[0]}", name, Level.OK, detail, purpose))
        else:
            checks.append(
                Check(
                    f"tool-{binaries[0]}",
                    name,
                    Level.FAIL if binaries[0] == "nmap" else Level.WARN,
                    "not installed",
                    purpose,
                    f"sudo apt install {apt}",
                )
            )
    return checks


def _wordlists(overrides: dict[str, str]) -> list[Check]:
    checks: list[Check] = []
    seclists = wl.SECLISTS.is_dir() or all(
        w.exists for w in wl.all_wordlists(overrides) if w.name != "passwords"
    )
    checks.append(
        Check(
            "seclists",
            "SecLists wordlists",
            Level.OK if seclists else Level.WARN,
            str(wl.SECLISTS) if seclists else "not installed",
            "Lists of likely page names, subdomains and usernames ([[wordlist]]).",
            None if seclists else wl.INSTALL_HINT,
        )
    )
    rockyou = wl.resolve("passwords", overrides)
    if rockyou is not None and rockyou.exists:
        checks.append(
            Check("rockyou", "rockyou.txt", Level.OK, str(rockyou.path), "Password cracking.")
        )
    else:
        zipped = ROCKYOU_GZ.is_file()
        checks.append(
            Check(
                "rockyou",
                "rockyou.txt",
                Level.WARN,
                "still zipped (Kali ships rockyou.txt.gz)" if zipped else "not found",
                "The standard password list for [[hash-cracking]] ([[rockyou]]).",
                f"sudo gunzip -k {ROCKYOU_GZ}" if zipped else "sudo apt install wordlists",
            )
        )
    return checks


def _in_sudo_group() -> bool:
    try:
        groups = {grp.getgrgid(g).gr_name for g in os.getgroups()}
    except (KeyError, OSError):
        return False
    return bool(groups & {"sudo", "wheel", "admin"})


def _sudo(settings: Settings) -> list[Check]:
    purpose = "Needed for SYN/UDP scans and adding box names to /etc/hosts ([[sudo]])."
    if is_root():
        ok = Check("sudo", "sudo", Level.OK, "running as root", purpose)
    elif have_binary("sudo") and _in_sudo_group():
        ok = Check("sudo", "sudo", Level.OK, "you can use sudo (you type the password)", purpose)
    else:
        ok = Check(
            "sudo",
            "sudo",
            Level.WARN,
            "sudo not available for this user",
            purpose,
            "add yourself to the sudo group: su -c 'usermod -aG sudo $USER', then log in again",
        )
    hosts = settings.hosts_file
    writable = os.access(hosts, os.W_OK)
    detail = f"{hosts} " + ("is writable" if writable else "needs sudo to edit (normal)")
    level = Level.OK if writable or ok.level is Level.OK else Level.WARN
    return [
        ok,
        Check(
            "hosts-file",
            "Hosts file",
            level,
            detail,
            "HTB sites answer on names like box.htb, which go in [[etc-hosts|/etc/hosts]].",
        ),
    ]


def _clock() -> list[Check]:
    purpose = "Windows / Active Directory boxes ([[kerberos]]) refuse logins if your clock is off."
    if not have_binary("timedatectl"):
        return []
    code, out = run_local(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if code != 0:
        return []
    synced = out.strip() == "yes"
    return [
        Check(
            "clock",
            "Clock in sync",
            Level.OK if synced else Level.WARN,
            "synchronised" if synced else "not synchronised",
            purpose,
            None if synced else "sudo timedatectl set-ntp true",
        )
    ]


def _workspace(settings: Settings) -> list[Check]:
    root = settings.root
    purpose = "Each box gets its own folder here (scans, loot, notes)."
    if root.is_dir():
        level = Level.OK if os.access(root, os.W_OK) else Level.FAIL
        detail = str(root) if level is Level.OK else f"{root} is not writable"
        return [Check("workspace", "Workspace folder", level, detail, purpose)]
    return [
        Check(
            "workspace",
            "Workspace folder",
            Level.WARN,
            f"{root} doesn't exist yet",
            purpose,
            f"mkdir -p {root}",
        )
    ]


def _disk(settings: Settings) -> list[Check]:
    base = settings.root if settings.root.is_dir() else Path.home()
    try:
        free_gb = shutil.disk_usage(base).free / 1e9
    except OSError:
        return []
    level = Level.OK if free_gb >= 2 else Level.WARN
    return [
        Check(
            "disk",
            "Free disk space",
            level,
            f"{free_gb:.1f} GB free",
            "Scans, wordlists and tool output need some room.",
            None if level is Level.OK else "free some space (sudo apt clean is a start)",
        )
    ]


def run_checks(settings: Settings, overrides: dict[str, str] | None = None) -> list[Check]:
    """All checks, in the order a beginner should fix them."""
    groups: list[Callable[[], list[Check]]] = [
        lambda: _workspace(settings),
        lambda: _vpn(settings),
        _tools,
        lambda: _wordlists(overrides or {}),
        lambda: _sudo(settings),
        _clock,
        lambda: _disk(settings),
    ]
    checks: list[Check] = []
    for group in groups:
        checks.extend(group())
    return checks


def summary(checks: list[Check]) -> str:
    fails = sum(c.level is Level.FAIL for c in checks)
    warns = sum(c.level is Level.WARN for c in checks)
    if not fails and not warns:
        return "Everything looks ready. Start a box!"
    parts = []
    if fails:
        parts.append(f"{fails} problem(s) to fix first")
    if warns:
        parts.append(f"{warns} thing(s) worth fixing")
    return ", ".join(parts) + "."
