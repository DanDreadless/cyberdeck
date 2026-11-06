"""Tool registry: the built-in nmap stages (ADR 0004) plus YAML manifests (docs/PLUGINS.md).

``get_tool``/``all_tools`` are what every front end uses; manifests are loaded lazily from the
built-in ``plugins/tools/`` and the user's ``~/.config/cyberdeck/plugins/tools/``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from cyberdeck.core.options import DetectSpec, OptionError, OptionSpec, Teach, ToolSpec

_NMAP_LEARN = "https://nmap.org/book/man-briefoptions.html"
_NMAP_DETECT = DetectSpec(
    binary="nmap",
    version_cmd=["nmap", "--version"],
    version_regex=r"Nmap version (\S+)",
    help_cmd=["nmap", "--help"],
    apt="nmap",
)


def _common(*, verbose: bool, timing: str | None = "4") -> list[OptionSpec]:
    return [
        OptionSpec(
            id="no_ping",
            flag="-Pn",
            type="bool",
            default=True,
            label="Skip ping (-Pn)",
            help="Treat the host as up. Many HTB boxes (especially Windows) drop ping.",
        ),
        OptionSpec(
            id="reason",
            flag="--reason",
            type="bool",
            default=True,
            label="Show reasons (--reason)",
            help="Show why each port got its state (syn-ack, reset, no-response...).",
        ),
        OptionSpec(
            id="timing",
            flag="-T",
            joined=True,
            type="choice",
            choices=["0", "1", "2", "3", "4", "5"],
            default=timing,
            label="Timing (-T)",
            help="3 = normal, 4 = faster (fine for HTB), 5 = insane (can miss ports).",
        ),
        OptionSpec(
            id="verbose",
            flag="-v",
            type="bool",
            default=verbose,
            label="Verbose (-v)",
            help="Print open ports as they are discovered.",
        ),
        OptionSpec(
            id="max_retries",
            flag="--max-retries",
            type="int",
            label="Max retries",
            help="Probe retransmissions per port. Raise it on a lossy VPN.",
            advanced=True,
        ),
        OptionSpec(
            id="stats",
            flag="--stats-every",
            default="10s",
            label="Progress interval",
            help="How often nmap reports progress (drives Cyberdeck's progress bar).",
            advanced=True,
        ),
    ]


_SCAN_TYPE = OptionSpec(
    id="scan_type",
    type="choice",
    choices=["auto", "syn", "connect"],
    default="auto",
    render_map={"auto": [], "syn": ["-sS"], "connect": ["-sT"]},
    label="Scan type",
    help="auto: SYN scan (-sS) when root, otherwise nmap falls back to a TCP connect scan (-sT).",
    requires_root=True,
    root_values=["syn"],
)

_TAIL = ["{opt.no_ping}", "{opt.reason}", "{opt.timing}", "{opt.verbose}"]
_TAIL += ["{opt.max_retries}", "{opt.stats}", "{extra}", "-oA", "{out}", "{target.ip}"]

NMAP_ALLPORTS = ToolSpec(
    id="nmap-allports",
    name="nmap stage 1: all TCP ports",
    description="Fast sweep of every TCP port so nothing on a high port is missed.",
    teach=Teach(
        does="Knocks on all 65,535 TCP [[port|ports]] quickly to see which ones answer. It "
        "doesn't ask what runs there yet; stage 2 does that on just the open ones.",
        look_for="The list of open ports. Anything unusual (8080, 9091, 5000...) is often the "
        "custom app the box is built around.",
    ),
    binary="nmap",
    category="recon",
    detect=_NMAP_DETECT,
    options=[
        _SCAN_TYPE,
        OptionSpec(
            id="ports",
            flag="-p",
            joined=True,
            default="-",
            label="Ports (-p)",
            help="'-' = all 65535 TCP ports. Or a list/range like 22,80,8000-8100.",
        ),
        OptionSpec(
            id="top_ports",
            flag="--top-ports",
            type="int",
            label="Top ports",
            help="Scan the N most common ports instead (clear Ports first).",
        ),
        OptionSpec(
            id="min_rate",
            flag="--min-rate",
            type="int",
            default=5000,
            label="Min rate (--min-rate)",
            help="Packets/second floor. Lower it (e.g. 1000) if the VPN is flaky and drops ports.",
        ),
        OptionSpec(
            id="open_only",
            flag="--open",
            type="bool",
            default=False,
            label="Open only (--open)",
            help="Only show open ports in nmap's own output.",
            advanced=True,
        ),
        *_common(verbose=True),
    ],
    presets={
        "quick": {"ports": None, "top_ports": 1000},
        "reliable": {"min_rate": 1000, "timing": "3", "max_retries": 3},
    },
    command=["nmap", "{opt.scan_type}", "{opt.ports}", "{opt.top_ports}", "{opt.min_rate}"]
    + ["{opt.open_only}", *_TAIL],
    out="nmap/{target.slug}-allports",
    ingest="nmap",
    timeout=3600,
    learn=_NMAP_LEARN,
)

NMAP_SERVICES = ToolSpec(
    id="nmap-services",
    name="nmap stage 2: scripts + versions",
    description="Default scripts and version detection on the open ports from stage 1.",
    teach=Teach(
        does="Asks each open port what program it is and which version ([[version-detection]]), "
        "and runs nmap's safe default scripts against it.",
        look_for="Product names and versions (search them for known [[cve|exploits]]), a "
        "[[redirect]] to a name like box.htb ([[hostname]]), page titles, and anything marked "
        "anonymous or allowed.",
    ),
    binary="nmap",
    category="recon",
    detect=_NMAP_DETECT,
    options=[
        _SCAN_TYPE,
        OptionSpec(
            id="ports",
            flag="-p",
            joined=True,
            label="Ports (-p)",
            help="Filled in from the open ports already found. Empty = nmap's top 1000.",
        ),
        OptionSpec(
            id="scripts",
            flag="-sC",
            type="bool",
            default=True,
            label="Default scripts (-sC)",
            help="Page titles, TLS certs, anonymous FTP, SMB info... the best source of hints.",
        ),
        OptionSpec(
            id="versions",
            flag="-sV",
            type="bool",
            default=True,
            label="Versions (-sV)",
            help="Identify software and versions, so you can look for known exploits.",
        ),
        OptionSpec(
            id="os_detect",
            flag="-O",
            type="bool",
            default=False,
            label="OS detection (-O)",
            help="Guess the operating system. Needs root.",
            requires_root=True,
        ),
        OptionSpec(
            id="script",
            flag="--script",
            label="Extra scripts (--script)",
            help="More NSE scripts, e.g. vuln or http-enum. Slower.",
            advanced=True,
        ),
        OptionSpec(
            id="version_all",
            flag="--version-all",
            type="bool",
            default=False,
            label="Try every version probe",
            help="Slower, but identifies stubborn services.",
            advanced=True,
        ),
        *_common(verbose=False),
    ],
    presets={
        "thorough": {"version_all": True, "os_detect": True},
        "light": {"scripts": False},
    },
    command=["nmap", "{opt.scan_type}", "{opt.ports}", "{opt.scripts}", "{opt.versions}"]
    + ["{opt.os_detect}", "{opt.script}", "{opt.version_all}", *_TAIL],
    out="nmap/{target.slug}",
    ingest="nmap",
    timeout=3600,
    dynamic_defaults={"ports": "open_tcp_ports"},
    learn=_NMAP_LEARN,
)

NMAP_UDP = ToolSpec(
    id="nmap-udp",
    name="nmap UDP: top ports",
    description="UDP scan of the most common ports (SNMP, TFTP, DNS...). Slow and needs root.",
    teach=Teach(
        does="Checks the most common [[tcp-udp|UDP]] ports, which a TCP scan never sees.",
        look_for="161 ([[snmp|SNMP]]), 69 (TFTP) and 53 ([[dns|DNS]]) marked open. "
        "'open|filtered' means nmap couldn't tell; that's normal for UDP.",
    ),
    binary="nmap",
    category="recon",
    detect=_NMAP_DETECT,
    requires_root=True,
    options=[
        OptionSpec(
            id="top_ports",
            flag="--top-ports",
            type="int",
            default=20,
            label="Top ports",
            help="How many of the most common UDP ports to try.",
        ),
        OptionSpec(
            id="versions",
            flag="-sV",
            type="bool",
            default=False,
            label="Versions (-sV)",
            help="Version detection on UDP is slow; turn on when you know which ports matter.",
        ),
        *_common(verbose=True),
    ],
    presets={"wider": {"top_ports": 100}},
    command=["nmap", "-sU", "{opt.top_ports}", "{opt.versions}", *_TAIL],
    out="nmap/{target.slug}-udp",
    ingest="nmap",
    timeout=3600,
    learn=_NMAP_LEARN,
)

BUILTIN_TOOLS: dict[str, ToolSpec] = {t.id: t for t in (NMAP_ALLPORTS, NMAP_SERVICES, NMAP_UDP)}
SCAN_STAGES: tuple[str, ...] = ("nmap-allports", "nmap-services")


@dataclass
class Registry:
    tools: dict[str, ToolSpec]
    errors: list[tuple[Path, str]] = field(default_factory=list)
    overridden: list[str] = field(default_factory=list)

    def groups(self) -> dict[str, list[ToolSpec]]:
        found: dict[str, list[ToolSpec]] = {}
        for tool in self.tools.values():
            if tool.group:
                found.setdefault(tool.group, []).append(tool)
        for members in found.values():
            members.sort(key=lambda t: (t.rank, t.id))
        return found


_CACHE: dict[tuple[Path, Path], Registry] = {}


def registry(*, reload: bool = False) -> Registry:
    """Built-in tools + manifests. Cached per (built-in dir, user dir)."""
    from cyberdeck.plugins.manifest import builtin_tools_dir, load_manifests, user_tools_dir

    key = (builtin_tools_dir(), user_tools_dir())
    if reload or key not in _CACHE:
        loaded = load_manifests(*key)
        tools = dict(BUILTIN_TOOLS)
        errors = list(loaded.errors)
        for tool_id, spec in loaded.tools.items():
            if tool_id in BUILTIN_TOOLS:
                errors.append((Path(spec.source or "?"), f"{tool_id!r} is a reserved built-in id"))
                continue
            tools[tool_id] = spec
        _CACHE[key] = Registry(tools, errors, loaded.overridden)
    return _CACHE[key]


def get_tool(tool_id: str) -> ToolSpec:
    tools = registry().tools
    try:
        return tools[tool_id]
    except KeyError:
        known = ", ".join(sorted(tools))
        raise OptionError(f"unknown tool {tool_id!r} (available: {known})") from None


def all_tools() -> list[ToolSpec]:
    return list(registry().tools.values())


# --- nmap live output -----------------------------------------------------------------------

_PROGRESS_RE = re.compile(
    r"^(?P<phase>[A-Za-z][\w /-]*?) Timing: About (?P<pct>[\d.]+)% done"
    r"(?:; ETC: \S+ \((?P<left>[\d:]+) remaining\))?"
)
_OPEN_RE = re.compile(r"^Discovered open port (\d+)/(\w+)")


@dataclass(frozen=True)
class Progress:
    phase: str
    percent: float
    remaining: str | None


def parse_progress(line: str) -> Progress | None:
    match = _PROGRESS_RE.match(line.strip())
    if not match:
        return None
    return Progress(match.group("phase"), float(match.group("pct")), match.group("left"))


def parse_discovered(line: str) -> tuple[int, str] | None:
    match = _OPEN_RE.match(line.strip())
    return (int(match.group(1)), match.group(2)) if match else None
