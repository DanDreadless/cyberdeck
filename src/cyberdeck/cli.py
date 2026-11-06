"""Typer CLI. All real work lives in cyberdeck.core.services; this module only talks to the user."""

import asyncio
import shlex
import sys
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from cyberdeck import __version__
from cyberdeck.core import glossary, services
from cyberdeck.core.classify import service_kind
from cyberdeck.core.config import Settings, load_settings
from cyberdeck.core.models import (
    Approval,
    Finding,
    FindingType,
    Hostname,
    JobStatus,
    Software,
    Suggestion,
    SuggestionStatus,
    Url,
)
from cyberdeck.core.options import OptionError, RunPlan
from cyberdeck.core.runner import have_binary, is_root, sudo_cached, sudo_validate
from cyberdeck.core.scope import ScopeError
from cyberdeck.core.summarize import JobSummary
from cyberdeck.core.tools import SCAN_STAGES, all_tools, get_tool, parse_discovered, parse_progress
from cyberdeck.core.userconfig import load_user_config
from cyberdeck.core.workspace import Workspace, WorkspaceError
from cyberdeck.ui.banner import BANNER
from cyberdeck.ui.run_dialog import run_dialog
from cyberdeck.util import vpn
from cyberdeck.util.hosts import HostsChange

app = typer.Typer(
    help="Cyberdeck: HTB recon handler. Create a box, run nmap, get suggested next steps.",
    no_args_is_help=False,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

TargetOpt = Annotated[
    str | None,
    typer.Option(
        "--target",
        "-t",
        help="Box name or workspace path. Default: the workspace containing the current dir.",
    ),
]
RootOpt = Annotated[
    Path | None,
    typer.Option(
        "--root", help="Workspace folder. Default: CYBERDECK_WORKSPACE_ROOT or ~/Documents/htb."
    ),
]
PresetOpt = Annotated[
    str | None, typer.Option("--preset", "-p", help="Option preset to start from.")
]
OptOpt = Annotated[
    list[str] | None,
    typer.Option("--opt", "-o", help="Set an option: --opt min_rate=1000 (repeatable)."),
]
SudoOpt = Annotated[
    bool, typer.Option("--sudo", help="Run with sudo (SYN/UDP/OS scans). Asks for your password.")
]
YesOpt = Annotated[
    bool, typer.Option("--yes", "-y", help="Don't open the Run dialog; run with the options given.")
]
ExtraArg = Annotated[
    list[str] | None,
    typer.Argument(
        help="Extra tool arguments, after --  e.g. -- --script vuln", show_default=False
    ),
]

STAGES: dict[str, tuple[str, ...]] = {
    "all": SCAN_STAGES,
    "1": ("nmap-allports",),
    "allports": ("nmap-allports",),
    "2": ("nmap-services",),
    "services": ("nmap-services",),
    "udp": ("nmap-udp",),
}


def _fail(message: str) -> NoReturn:
    err_console.print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(1)


def _open(target: str | None) -> Workspace:
    try:
        ws = services.open_target(load_settings(), target)
    except WorkspaceError as exc:
        _fail(str(exc))
    if ws.resolved_via == "current":
        console.print(
            f"[dim]Box: {escape(ws.meta.name)} ({ws.meta.ip}), the current box. "
            "Use -t <box> for another.[/]"
        )
    return ws


def _parse_opts(pairs: list[str] | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        if not sep or not key.strip():
            _fail(f"--opt expects name=value, got {pair!r}")
        parsed[key.strip()] = value
    return parsed


def _confirm(question: str, *, default: bool, interactive: bool) -> bool:
    return typer.confirm(question, default=default) if interactive else default


def _print_hosts_hint(created: list[Finding]) -> None:
    names = [f.as_(Hostname).fqdn for f in created if f.type is FindingType.HOSTNAME]
    if names:
        console.print(
            f"\n[bold]New hostnames: {escape(', '.join(names))}.[/] HTB sites often only answer "
            "on their name: [bold]cyberdeck hosts add[/] adds them to /etc/hosts (shows the change "
            "first)."
        )


# --- VPN preflight --------------------------------------------------------------------------


def _pick_config(configs: list[Path], interactive: bool) -> Path | None:
    if not configs:
        return None
    if len(configs) == 1 or not interactive:
        return configs[0]
    for index, path in enumerate(configs, start=1):
        console.print(f"  {index}) {escape(str(path))}")
    choice = typer.prompt("Which VPN config", default="1")
    try:
        picked = configs[int(choice) - 1]
    except (ValueError, IndexError):
        _fail(f"no config number {choice}")
    services.remember_vpn_config(picked)
    return picked


def _vpn_preflight(settings: Settings, ip: str, *, interactive: bool) -> bool:
    """Check the box is routed through the HTB VPN; offer to start it. True = go ahead."""
    status = services.vpn_check(settings, ip)
    if not status.applicable:
        return True
    if not status.checked:
        console.print("[yellow]![/] Can't check the VPN here (no `ip` command); continuing.")
        return True
    if status.routed_via_tunnel:
        console.print(
            f"[green]✓[/] VPN: {ip} is routed via {status.route_dev} "
            f"(your tunnel IP / LHOST: {status.lhost})"
        )
        return True
    if status.up:
        tunnels = ", ".join(f"{t.name} {t.ip}" for t in status.tunnels)
        console.print(
            f"[yellow]![/] A VPN tunnel is up ({tunnels}) but {ip} isn't routed through it. "
            "You may be on the wrong HTB VPN (Machines vs Starting Point, or another region)."
        )
        return _confirm("Scan anyway?", default=False, interactive=interactive)

    reason = (
        " (openvpn is running but has no tunnel yet; check its log)"
        if status.openvpn_running
        else ""
    )
    console.print(f"[red]✗[/] {ip} isn't reachable: the HTB VPN tunnel is not up{reason}.")
    if status.services:
        unit = status.services[0]
        shown = shlex.join(vpn.start_service_command(unit)).replace("sudo -n ", "sudo ", 1)
        console.print("Your VPN is a systemd service. Start it with:")
        console.print(f"  {shown}", markup=False, highlight=False)
        if not interactive:
            console.print("Not starting the VPN automatically (--yes); start it and re-run.")
            return False
        if not typer.confirm("Start it now? (asks for your sudo password)", default=True):
            return _confirm("Scan anyway?", default=False, interactive=True)
        if not sudo_validate():
            _fail("sudo failed; VPN not started")
        started, message = vpn.start_service(unit)
        config: Path | None = None
    else:
        config = _pick_config(status.configs, interactive)
        if config is None:
            console.print(
                f"No .ovpn file in {escape(str(settings.vpn_search_dir))}. Download yours from HTB "
                "(Connect to HTB > Machines > OpenVPN) into that folder, or set "
                "CYBERDECK_VPN_CONFIG."
            )
            return _confirm("Scan anyway?", default=False, interactive=interactive)
        shown = shlex.join(vpn.start_command(config)).replace("sudo -n ", "sudo ", 1)
        console.print("Start it with:")
        console.print(f"  {shown}", markup=False, highlight=False)
        if not interactive:
            console.print("Not starting the VPN automatically (--yes); start it and re-run.")
            return False
        if not typer.confirm("Start the VPN now? (asks for your sudo password)", default=True):
            return _confirm("Scan anyway?", default=False, interactive=True)
        if not sudo_validate():
            _fail("sudo failed; VPN not started")
        started, message = vpn.start_vpn(config)
    if not started:
        console.print(f"[red]✗[/] {escape(message)}")
        return _confirm("Scan anyway?", default=False, interactive=True)
    console.print("Waiting for the tunnel...")
    status = vpn.wait_for_tunnel(ip, settings.vpn_search_dir, config or settings.vpn_config)
    if status.routed_via_tunnel:
        console.print(f"[green]✓[/] VPN up: {status.route_dev} {status.lhost}")
        return True
    log = vpn.OPENVPN_LOG if config else "journalctl -u " + (status.services or ["openvpn"])[0]
    console.print(f"[red]✗[/] Still no route to {ip} via a tunnel. Check: {log}")
    return _confirm("Scan anyway?", default=False, interactive=True)


# --- running tools --------------------------------------------------------------------------


def _run_with_progress(
    ws: Workspace,
    settings: Settings,
    plan: RunPlan,
    origin: str = "cli",
    suggestion_id: int | None = None,
    approval_id: int | None = None,
) -> tuple[services.RunOutcome, list[str]]:
    stderr_tail: deque[str] = deque(maxlen=8)
    name = plan.tool.name
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(name, total=100 if plan.tool.ingest == "nmap" else None)

        is_nmap = plan.tool.ingest == "nmap"

        def on_line(stream: str, line: str) -> None:
            if stream == "err":
                stderr_tail.append(line)
                return
            if not is_nmap:
                if line.strip():
                    progress.console.print(f"  {line}", style="dim", markup=False, highlight=False)
                return
            prog = parse_progress(line)
            if prog:
                left = f", {prog.remaining} left" if prog.remaining else ""
                progress.update(
                    task, completed=prog.percent, description=f"{name}: {prog.phase}{left}"
                )
                return
            found = parse_discovered(line)
            if found:
                progress.console.print(f"  [green]open[/] {found[0]}/{found[1]}")

        try:
            if approval_id is not None:
                job = services.run_approved_job(ws, settings, approval_id, on_line=on_line)
            else:
                job = services.execute_plan(
                    ws,
                    settings,
                    plan,
                    on_line=on_line,
                    origin=origin,
                    suggestion_id=suggestion_id,
                )
            outcome = asyncio.run(job)
        except ScopeError as exc:
            _fail(str(exc))
        except KeyboardInterrupt:
            err_console.print("[yellow]Cancelled.[/] The job was stopped and recorded.")
            raise typer.Exit(130) from None
    return outcome, list(stderr_tail)


def _print_job_summary(summary: JobSummary) -> None:
    """The plain-English "so what?" of a job (learning L2; off with learning.summaries)."""
    console.print(f"[bold cyan]▶ {escape(summary.headline)}[/]")
    for line in summary.lines:
        console.print(f"  {escape(glossary.plain(line))}")
    for hl in summary.highlights:
        console.print(
            f"  [bold yellow]★ {escape(hl.title)}[/]: {escape(glossary.plain(hl.meaning))}"
        )


def _report(ws: Workspace, outcome: services.RunOutcome, stderr_tail: list[str]) -> None:
    job = outcome.result.job
    try:
        tool_name = get_tool(job.tool).name
    except OptionError:
        tool_name = job.tool
    took = f"{job.duration:.0f}s" if job.duration is not None else "?"
    raw = outcome.result.out_path.relative_to(ws.path)
    if outcome.result.ok:
        console.print(f"[green]✓[/] {tool_name} finished in {took} (job #{job.id}, output: {raw})")
    else:
        detail = f" (exit {job.exit_code})" if job.exit_code is not None else ""
        console.print(
            f"[red]✗[/] {tool_name}: {job.status.value}{detail}. {escape(job.note or '')}"
        )
        for line in stderr_tail:
            console.print(f"    {line}", style="dim", markup=False, highlight=False)
    for note in outcome.notes:
        console.print(f"[yellow]![/] {escape(note)}")
    if outcome.parse_report is not None:
        _print_parse_report(ws, outcome.parse_report)
    if outcome.summary is not None and services.summaries_enabled():
        _print_job_summary(outcome.summary)
    if outcome.possible_credentials:
        console.print(
            "  [yellow]![/] Something in the output looks like a password: "
            "[bold]cyberdeck suggest[/] asks whether to save it to Loot."
        )
    report = outcome.import_report
    if report is None:
        return
    console.print(f"  {len(report.created)} new findings, {len(report.updated)} updated.")
    if job.tool == "nmap-allports":
        ports = services.open_tcp_ports(ws)
        if ports:
            console.print(f"  Open TCP ports: [bold]{ports}[/]")
        else:
            console.print(
                "[yellow]![/] No open ports found. Is the box spawned? On a flaky VPN "
                "--min-rate can drop ports: try [bold]cyberdeck scan -s 1 -p reliable[/]."
            )
    _print_hosts_hint(report.created)


def _finding_line(finding: Finding) -> str:
    payload = finding.payload()
    if isinstance(payload, Url):
        status = f" ({payload.status})" if payload.status else ""
        extra = f" -> {payload.redirect}" if payload.redirect else ""
        title = f"  {payload.title}" if payload.title else ""
        return f"url       {payload.url}{status}{extra}{title}"
    if isinstance(payload, Software):
        return f"software  {payload.name} {payload.version or ''}".rstrip()
    if isinstance(payload, Hostname):
        return f"hostname  {payload.fqdn}"
    return f"{finding.type.value:<9} {finding.key}"


def _print_parse_report(ws: Workspace, report: services.ParseReport, limit: int = 25) -> None:
    if report.error:
        console.print(f"[yellow]![/] {escape(report.error)}")
        return
    console.print(f"  {len(report.created)} new findings, {len(report.updated)} updated.")
    for finding in report.created[:limit]:
        console.print(f"    {_finding_line(finding)}", markup=False, highlight=False)
    if len(report.created) > limit:
        console.print(f"    ... and {len(report.created) - limit} more (cyberdeck show)")
    _print_hosts_hint(report.created)


def _run_tools(
    ws: Workspace,
    settings: Settings,
    tool_ids: tuple[str, ...],
    *,
    preset: str | None,
    overrides: dict[str, str],
    extra: list[str],
    sudo: bool,
    yes: bool,
) -> int:
    """Run tools in order through the Run dialog (or straight through with --yes)."""
    try:
        tools = [services.resolve_tool(t) for t in tool_ids]
    except OptionError as exc:
        _fail(str(exc))
    for tool in tools:
        if not have_binary(tool.binary):
            hint = tool.detect_spec.apt or tool.binary
            _fail(f"{tool.binary} is not installed (sudo apt install {hint})")
    known_opts = {o.id for t in tools for o in t.options}
    unknown = sorted(set(overrides) - known_opts)
    if unknown:
        _fail(f"unknown option(s) for {', '.join(tool_ids)}: {', '.join(unknown)}")
    if preset and not any(preset in t.presets for t in tools):
        names = sorted({p for t in tools for p in t.presets})
        _fail(f"no preset {preset!r} (available: {', '.join(names)})")
    if not _vpn_preflight(settings, ws.meta.ip, interactive=not yes):
        raise typer.Exit(1)

    root = is_root()
    ran = 0
    for tool in tools:
        mine = {k: v for k, v in overrides.items() if any(o.id == k for o in tool.options)}
        try:
            plan = services.plan_tool(
                ws,
                tool.id,
                preset=preset if preset in tool.presets else None,
                overrides=mine,
                extra=extra,
                sudo=sudo,
                settings=settings,
            )
        except OptionError as exc:
            _fail(str(exc))
        if _confirm_and_run(ws, settings, plan, yes=yes, root=root) is not None:
            ran += 1
    return ran


def _confirm_and_run(
    ws: Workspace,
    settings: Settings,
    plan: RunPlan,
    *,
    yes: bool,
    root: bool,
    origin: str = "cli",
    suggestion_id: int | None = None,
    strict: bool = True,
) -> services.RunOutcome | None:
    """Show the plan in the Run dialog (or print the exact command with --yes), then run it.
    Returns None if the user skipped it, or (``strict=False``) if it can't run as planned."""
    if yes:
        for warning in plan.warnings:
            console.print(f"[yellow]![/] {escape(warning)}")
        if plan.tool.safety != "safe":
            console.print(f"[yellow]![/] {plan.tool.name} is tagged {plan.tool.safety}.")
        problems = plan.problems(root)
        if problems and strict:
            _fail("; ".join(problems))
        if problems:
            console.print(f"[red]✗[/] {plan.tool.name}: {escape('; '.join(problems))}")
            return None
        console.print(Text("$ " + plan.command_line(), style="bold cyan"))
    else:
        chosen = run_dialog(
            plan,
            console,
            is_root=root,
            save_user=lambda p: str(services.save_plan_defaults(ws, p, "user")),
            save_box=lambda p: str(services.save_plan_defaults(ws, p, "box")),
            show_help=lambda p: services.help_text(p.tool.id),
        )
        if chosen is None:
            console.print(f"Skipped {plan.tool.name}.")
            return None
        plan = chosen
    if plan.sudo and not root and not sudo_cached():
        console.print("sudo needs your password (typed into sudo itself, never into Cyberdeck):")
        if not sudo_validate():
            _fail("sudo failed")
    outcome, tail = _run_with_progress(ws, settings, plan, origin, suggestion_id)
    _report(ws, outcome, tail)
    if outcome.suggestions:
        console.print(f"  [bold]{len(outcome.suggestions)} new suggestion(s):[/]")
        for sug in outcome.suggestions[:5]:
            console.print(f"    {_suggestion_line(sug)}")
    return outcome


# --- commands -------------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", help="Show version and exit.")] = False,
    web: Annotated[
        bool,
        typer.Option("--web", help="Serve the TUI in your browser (needs the web extra)."),
    ] = False,
    port: Annotated[int, typer.Option("--port", help="Port for --web (127.0.0.1 only).")] = 8000,
) -> None:
    """No command: open the TUI (box picker), or print the banner when not in a terminal."""
    if version:
        console.print(f"cyberdeck {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is not None:
        return
    if web:
        _serve_web(port)
        return
    if sys.stdin.isatty() and sys.stdout.isatty():
        from cyberdeck.ui.tui.app import run_tui

        run_tui()
        return
    console.print(BANNER, style="bold green", highlight=False)
    console.print(
        "Run [bold]cyberdeck[/] in a terminal for the TUI, or use the commands: [bold]new[/], "
        "[bold]resume[/], [bold]scan[/], [bold]suggest[/], [bold]auto[/]... see "
        "[bold]cyberdeck --help[/]."
    )


def _serve_web(port: int) -> None:
    try:
        from textual_serve.server import Server
    except ImportError:
        _fail('the web UI needs textual-serve: uv tool install -e ".[web]"')
    console.print(f"Serving the Cyberdeck TUI on http://127.0.0.1:{port} (ctrl+c to stop)")
    Server(f"{shlex.quote(sys.executable)} -m cyberdeck tui", host="127.0.0.1", port=port).serve()


@app.command()
def tui(target: TargetOpt = None) -> None:
    """Open the TUI (on a box with -t, else the box picker). Same as plain `cyberdeck`."""
    from cyberdeck.ui.tui.app import run_tui

    run_tui(box=target)


@app.command()
def new(
    name: Annotated[str | None, typer.Argument(help="Box name, e.g. the HTB machine name.")] = None,
    ip: Annotated[str | None, typer.Option("--ip", help="Target IP (asked if omitted).")] = None,
    root: RootOpt = None,
    scan: Annotated[
        bool | None,
        typer.Option("--scan/--no-scan", help="Run the two-stage nmap scan straight away."),
    ] = None,
    yes: YesOpt = False,
) -> None:
    """Create a box workspace (<root>/<box>/ with nmap/, raw/, loot/, notes) and scan it."""
    settings = load_settings()
    wizard = name is None or ip is None
    if name is None:
        name = typer.prompt("Box name (the HTB machine name)")
    if ip is None:
        ip = typer.prompt("Target IP")
    if root is None and wizard and not yes:
        answer = Path(typer.prompt("Workspace folder", default=str(settings.root))).expanduser()
        if answer != settings.root:
            root = answer
            if typer.confirm(f"Use {answer} for new boxes from now on?", default=True):
                saved = services.remember_workspace_root(answer)
                console.print(f"[dim]Saved in {saved}[/]")
    try:
        ws = services.create_target(settings, name, ip, root)
    except (ScopeError, WorkspaceError) as exc:
        _fail(str(exc))
    services.use_target(ws)
    console.print(f"[green]✓[/] Created [bold]{escape(str(ws.path))}[/] (now the current box)")
    console.print("  nmap/  raw/  loot/  notes.md  target.db  target.yaml", style="dim")

    if scan is None:
        scan = yes or typer.confirm("Run the initial nmap scan now?", default=True)
    if not scan:
        slug, target_ip = ws.meta.slug, ws.meta.ip
        console.print(
            "\n[bold]Next:[/] [bold]cyberdeck scan[/] from the box folder, or run nmap yourself "
            "and [bold]cyberdeck import[/]:"
        )
        steps = [
            f"cd {ws.path}",
            f"nmap -p- --min-rate 5000 -Pn -T4 --reason -oA nmap/{slug}-allports {target_ip}",
            f"ports=$(grep -oP '\\d+(?=/open)' nmap/{slug}-allports.gnmap | paste -sd,)",
            f'nmap -sC -sV -Pn --reason -p"$ports" -oA nmap/{slug} {target_ip}',
            "cyberdeck import",
        ]
        for step in steps:
            console.print(f"  {step}", markup=False, highlight=False)
        return
    ran = _run_tools(
        ws, settings, SCAN_STAGES, preset=None, overrides={}, extra=[], sudo=False, yes=yes
    )
    if ran:
        console.print()
        _print_summary(ws)
        _print_next(ws)


@app.command()
def scan(
    stage: Annotated[
        str, typer.Option("--stage", "-s", help="all (default), 1/allports, 2/services, udp.")
    ] = "all",
    preset: PresetOpt = None,
    opt: OptOpt = None,
    sudo: SudoOpt = False,
    yes: YesOpt = False,
    target: TargetOpt = None,
    extra: ExtraArg = None,
) -> None:
    """Run the nmap stages (all ports, then scripts+versions on the open ones), or UDP."""
    if stage not in STAGES:
        _fail(f"unknown stage {stage!r} (choose: {', '.join(STAGES)})")
    ws = _open(target)
    settings = load_settings()
    ran = _run_tools(
        ws,
        settings,
        STAGES[stage],
        preset=preset,
        overrides=_parse_opts(opt),
        extra=list(extra or []),
        sudo=sudo,
        yes=yes,
    )
    if ran:
        console.print()
        _print_summary(ws)
        _print_next(ws)


@app.command()
def run(
    tool: Annotated[str, typer.Argument(help="Tool id or group (see `cyberdeck run list`).")],
    preset: PresetOpt = None,
    opt: OptOpt = None,
    sudo: SudoOpt = False,
    yes: YesOpt = False,
    target: TargetOpt = None,
    extra: ExtraArg = None,
) -> None:
    """Run a tool, or a group's preferred tool (e.g. dir-bruteforce), via the Run dialog.

    `cyberdeck run list` shows the tools. Inputs such as the URL are options too: --opt url=...
    """
    if tool == "list":
        table = Table()
        for column in ("Tool", "Group", "Safety", "What it does", "Presets"):
            table.add_column(column)
        for spec in all_tools():
            table.add_row(
                spec.id,
                spec.group or "-",
                spec.safety,
                spec.description,
                ", ".join(spec.presets) or "-",
            )
        console.print(table)
        console.print("[dim]Installed or not: cyberdeck tools[/]")
        return
    try:
        services.resolve_tool(tool)
    except OptionError as exc:
        _fail(str(exc))
    ws = _open(target)
    _run_tools(
        ws,
        load_settings(),
        (tool,),
        preset=preset,
        overrides=_parse_opts(opt),
        extra=list(extra or []),
        sudo=sudo,
        yes=yes,
    )


@app.command("import")
def import_(
    path: Annotated[
        Path | None,
        typer.Argument(help="nmap file or directory. Default: the workspace's nmap/ folder."),
    ] = None,
    target: TargetOpt = None,
    force: Annotated[
        bool, typer.Option("--force", help="Re-import files that were already imported.")
    ] = False,
) -> None:
    """Import nmap results you ran yourself (.xml preferred, .gnmap fallback)."""
    ws = _open(target)
    try:
        report = services.import_nmap(ws, path, force=force)
    except FileNotFoundError as exc:
        _fail(str(exc))
    for file in report.imported:
        console.print(f"[green]✓[/] {escape(str(file))}")
    for file, reason in report.skipped:
        console.print(f"[yellow]-[/] {escape(str(file))}: {escape(reason)}")
    for note in report.notes:
        console.print(f"[yellow]![/] {escape(note)}")
    if not report.imported and not report.skipped:
        console.print(f"No nmap .xml or .gnmap files found in {escape(str(path or ws.nmap_dir))}")
        return
    console.print(f"\n{len(report.created)} new findings, {len(report.updated)} updated.")
    if report.other_hosts:
        others = ", ".join(sorted(report.other_hosts))
        console.print(
            f"[yellow]![/] Ignored results for other hosts ({others}); this box is {ws.meta.ip}."
        )
    _print_hosts_hint(report.created)
    console.print("\nRun [bold]cyberdeck show[/] to see everything.")
    _print_next(ws)


def _print_summary(ws: Workspace) -> None:
    summary = services.target_summary(ws)
    meta = summary.meta
    header = (
        f"[bold]{escape(meta.name)}[/]  {meta.ip}  "
        f"OS: {escape(summary.best_os or 'unknown')}\n[dim]{escape(str(summary.path))}[/]"
    )
    console.print(Panel(header, expand=False))

    if summary.services:
        table = Table(title="Services", title_justify="left")
        for column in ("Port", "Kind", "Service", "Version", "Scripts"):
            table.add_column(column)
        for svc in summary.services:
            name = svc.name or "?"
            if svc.tunnel:
                name = f"{svc.tunnel}/{name}"
            table.add_row(
                f"{svc.port}/{svc.proto}",
                escape(service_kind(svc)),
                escape(name),
                escape(svc.banner),
                escape(", ".join(sorted(svc.scripts)) or "-"),
            )
        console.print(table)
    else:
        console.print(
            "No services yet. Run [bold]cyberdeck scan[/] (or [bold]cyberdeck import[/])."
        )

    if summary.hostnames:
        table = Table(title="Hostnames", title_justify="left")
        for column in ("Name", "Kind", "Found by"):
            table.add_column(column)
        for host in summary.hostnames:
            table.add_row(escape(host.fqdn), host.kind, escape(", ".join(host.origins)))
        console.print(table)
        line = services.hosts_file_line(meta.ip, summary.hostnames)
        if line:
            console.print(f"Hosts line: [bold]{escape(line)}[/]  (cyberdeck hosts add)")

    if summary.software:
        table = Table(title="Software", title_justify="left")
        for column in ("Name", "Version", "Where"):
            table.add_column(column)
        for sw in summary.software:
            table.add_row(escape(sw.name), escape(sw.version or "?"), escape(sw.where or "-"))
        console.print(table)

    others = {
        t: n
        for t, n in summary.counts.items()
        if t not in (FindingType.SERVICE, FindingType.HOSTNAME, FindingType.SOFTWARE)
    }
    if others:
        console.print("Other findings: " + ", ".join(f"{t.value}: {n}" for t, n in others.items()))


@app.command()
def show(target: TargetOpt = None) -> None:
    """Show what is known about a box: services, hostnames, software, OS."""
    _print_summary(_open(target))


def _progress_marks(progress: services.TargetProgress) -> str:
    short = ["ports", "versions", "udp", "hosts", "user", "root"]
    return " ".join(
        f"[green]{name}[/]" if step.done else f"[dim]{name}[/]"
        for name, step in zip(short, progress.steps, strict=True)
    )


@app.command("list")
def list_(root: RootOpt = None) -> None:
    """List boxes (most recently opened first) with their progress."""
    settings = load_settings()
    targets = services.list_targets(settings, root)
    current = load_user_config().current_target
    if targets:
        never = datetime.min.replace(tzinfo=UTC)
        targets.sort(key=lambda w: w.meta.last_opened or w.meta.created_at or never, reverse=True)
        table = Table()
        for column in ("", "Box", "IP", "Last opened", "Progress"):
            table.add_column(column)
        for ws in targets:
            opened = ws.meta.last_opened or ws.meta.created_at
            table.add_row(
                "*" if current and Path(current) == ws.path else "",
                escape(ws.meta.name),
                ws.meta.ip,
                opened.astimezone().strftime("%Y-%m-%d %H:%M"),
                _progress_marks(services.target_progress(ws)),
            )
        console.print(table)
        console.print("[dim]* = current box. Pick up where you left off: cyberdeck resume <box>[/]")
    else:
        console.print(
            f"No Cyberdeck boxes under {escape(str(root or settings.root))} yet. "
            "Create one with [bold]cyberdeck new[/]."
        )
    loose = services.list_unmanaged(settings, root)
    if loose:
        names = ", ".join(escape(p.name) for p in loose)
        console.print(
            f"\nFolders not set up yet: {names}\n[dim]Adopt one (keeps its files): "
            "cyberdeck new <name> --ip <ip>, then cyberdeck import to load old nmap scans.[/]"
        )


def _print_progress(ws: Workspace) -> services.TargetProgress:
    progress = services.target_progress(ws)
    summary = services.target_summary(ws)
    meta = ws.meta
    header = (
        f"[bold]{escape(meta.name)}[/]  {meta.ip}  OS: {escape(summary.best_os or 'unknown')}"
        f"\n[dim]{escape(str(ws.path))}[/]"
    )
    console.print(Panel(header, expand=False))
    for step in progress.steps:
        mark = "[green]✓[/]" if step.done else "[dim]·[/]"
        detail = f"  [dim]{escape(step.detail)}[/]" if step.detail else ""
        console.print(f"  {mark} {step.label}{detail}")
    last = progress.last_job
    if last is not None:
        when = last.ended_at or last.started_at or last.created_at
        console.print(
            f"Last activity: job #{last.id} {last.tool} ({last.status.value}) "
            f"at {when.astimezone():%Y-%m-%d %H:%M}"
        )
    for job_ in progress.interrupted:
        console.print(
            f"[yellow]![/] Job #{job_.id} {job_.tool} was interrupted (Cyberdeck closed while it "
            f"ran). Re-run it with [bold]cyberdeck run {job_.tool}[/]."
        )
    console.print(f"[bold]Next:[/] {escape(progress.next_hint)}")
    return progress


@app.command()
def status(target: TargetOpt = None) -> None:
    """Where a box is up to: what's done, what was interrupted, what to do next."""
    _print_progress(_open(target))


@app.command()
def resume(
    box: Annotated[
        str | None, typer.Argument(help="Box name or path. Default: the current box.")
    ] = None,
    yes: YesOpt = False,
) -> None:
    """Go back to a box, make it current, and carry on with the next step."""
    ws = _open(box)
    services.use_target(ws)
    progress = _print_progress(ws)
    tools = progress.next_tools
    if not tools:
        _print_next(ws)
        return
    names = " then ".join(get_tool(t).name for t in tools)
    if yes or typer.confirm(f"Run {names} now?", default=True):
        ran = _run_tools(
            ws, load_settings(), tools, preset=None, overrides={}, extra=[], sudo=False, yes=yes
        )
        if ran:
            console.print()
            _print_summary(ws)
            _print_next(ws)


@app.command()
def use(box: Annotated[str, typer.Argument(help="Box name or path.")]) -> None:
    """Set the current box, used when you're not inside a box folder and give no -t."""
    ws = _open(box)
    services.use_target(ws)
    console.print(f"[green]✓[/] Current box: [bold]{escape(ws.meta.name)}[/] ({ws.meta.ip})")


@app.command("set-ip")
def set_ip(
    ip: Annotated[str, typer.Argument(help="The box's new IP.")],
    target: TargetOpt = None,
) -> None:
    """Change a box's IP after HTB re-spawns it. Findings and history are kept."""
    ws = _open(target)
    try:
        old = services.set_ip(load_settings(), ws, ip)
    except ScopeError as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/] {escape(ws.meta.name)}: {old} -> {ws.meta.ip}")
    if old == ws.meta.ip:
        return
    settings = load_settings()
    lines, _ = services.hosts_status(ws, settings)
    if lines:
        console.print("This box has a line in your hosts file; move it to the new IP:")
        _hosts_add_flow(ws, settings, [], yes=False)
    console.print("[dim]Re-scan with cyberdeck scan to confirm nothing changed.[/]")


@app.command()
def flag(
    kind: Annotated[str, typer.Argument(help="user or root")],
    value: Annotated[str, typer.Argument(help="The flag (32 hex characters on HTB).")],
    target: TargetOpt = None,
) -> None:
    """Record a captured flag for a box."""
    if kind not in ("user", "root"):
        _fail("flag kind must be 'user' or 'root'")
    ws = _open(target)
    looks_right = services.record_flag(ws, "user" if kind == "user" else "root", value)
    console.print(f"[green]✓[/] {kind} flag saved for {escape(ws.meta.name)}.")
    if not looks_right:
        console.print(
            "[yellow]![/] That doesn't look like an HTB flag (32 hex chars); saved anyway."
        )
    elif sys.stdin.isatty():
        console.print("🚩 " + ("Halfway there!" if kind == "user" else "Box done. Nice work!"))
        _ask_lesson(ws, "user" if kind == "user" else "root")
    else:
        console.print("[dim]Note what you learned: cyberdeck lesson --kind " + kind + "[/]")


@app.command()
def jobs(target: TargetOpt = None) -> None:
    """List the jobs run against a box (exact commands are kept in raw/)."""
    ws = _open(target)
    rows = services.list_jobs(ws)
    if not rows:
        console.print("No jobs yet.")
        return
    table = Table()
    for column in ("#", "Tool", "Status", "Exit", "Took", "Started", "Command"):
        table.add_column(column)
    colours = {JobStatus.DONE: "green", JobStatus.FAILED: "red", JobStatus.TIMEOUT: "red"}
    for job in rows:
        colour = colours.get(job.status, "yellow")
        table.add_row(
            str(job.id),
            job.tool,
            Text(job.status.value, style=colour),
            "-" if job.exit_code is None else str(job.exit_code),
            "-" if job.duration is None else f"{job.duration:.0f}s",
            job.started_at.strftime("%H:%M:%S") if job.started_at else "-",
            Text(shlex.join(job.argv), overflow="fold"),
        )
    console.print(table)


@app.command()
def job(
    job_id: Annotated[int, typer.Argument(help="Job number from `cyberdeck jobs`.")],
    target: TargetOpt = None,
    err: Annotated[bool, typer.Option("--err", help="Show stderr instead of stdout.")] = False,
    tail: Annotated[int, typer.Option("--tail", help="Lines to show (0 = all).")] = 40,
) -> None:
    """Show one job: its exact command and the end of its output."""
    ws = _open(target)
    try:
        record, cmd_path, out_path, err_path = services.job_files(ws, job_id)
    except OptionError as exc:
        _fail(str(exc))
    console.print(
        f"[bold]#{record.id} {record.tool}[/]  {record.status.value}  origin={record.origin}"
    )
    if cmd_path.is_file():
        console.print(cmd_path.read_text(encoding="utf-8"), markup=False, highlight=False)
    if services.summaries_enabled():
        _print_job_summary(services.job_summary(ws, job_id))
    path = err_path if err else out_path
    if not path.is_file():
        console.print(f"(no {path.name})")
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    shown = lines if tail <= 0 else lines[-tail:]
    console.print(f"[dim]--- {path} ({len(lines)} lines) ---[/]")
    for line in shown:
        console.print(line, markup=False, highlight=False)


@app.command("vpn")
def vpn_cmd(target: TargetOpt = None) -> None:
    """Check the HTB VPN tunnel (and your LHOST); offer to start it if it's down."""
    settings = load_settings()
    ip = ""
    try:
        ip = services.open_target(settings, target).meta.ip
    except WorkspaceError:
        if target:
            _fail(f"no box {target!r}")
    status = services.vpn_check(settings, ip)
    if not status.checked:
        _fail("can't check: the `ip` command isn't available here")
    if status.tunnels:
        for tunnel in status.tunnels:
            console.print(f"[green]✓[/] Tunnel {tunnel.name}: {tunnel.ip}")
    else:
        console.print("[red]✗[/] No VPN tunnel is up.")
    if status.configs:
        console.print("VPN configs: " + ", ".join(escape(str(c)) for c in status.configs))
    if ip:
        _vpn_preflight(settings, ip, interactive=True)


# --- learning aids: doctor, glossary (docs/LEARNING-PLAN.md L1) ----------------------------

_LEVEL_MARK = {"ok": "[green]✓[/]", "warn": "[yellow]![/]", "fail": "[red]✗[/]"}


@app.command()
def doctor(
    fix_workspace: Annotated[
        bool, typer.Option("--create-folder", help="Create the workspace folder if it's missing.")
    ] = False,
) -> None:
    """Check your setup before the first box: VPN, tools, wordlists, sudo, clock, folder.

    Nothing is changed (except the workspace folder with --create-folder); every problem comes
    with the exact command that fixes it.
    """
    settings = load_settings()
    if fix_workspace and not settings.root.is_dir():
        console.print(f"[green]✓[/] Created {services.create_workspace_root(settings)}")
    checks = services.setup_checks(settings)
    for check in checks:
        console.print(
            f"{_LEVEL_MARK[check.level.value]} [bold]{escape(check.title)}[/]: "
            f"{escape(check.detail)}"
        )
        if check.level.value != "ok":
            console.print(f"    [dim]{escape(glossary.plain(check.purpose))}[/]")
            if check.fix:
                console.print(f"    fix: [bold]{escape(check.fix)}[/]")
    console.print()
    console.print(escape(services.setup_summary(checks)))
    if any(c.level.value == "fail" for c in checks):
        raise typer.Exit(1)


@app.command("glossary")
def glossary_cmd(
    term: Annotated[
        str | None, typer.Argument(help="A term, e.g. vhost or 'reverse shell'.")
    ] = None,
) -> None:
    """Plain-word definitions of the jargon Cyberdeck uses (vhost, LHOST, SUID...)."""
    gloss = services.load_glossary()
    for error in gloss.errors:
        err_console.print(f"[yellow]![/] {escape(error)}")
    if term:
        found = gloss.get(term)
        if found is None:
            matches = [
                t
                for t in gloss.terms.values()
                if term.lower() in t.term.lower()
                or any(term.lower() in a.lower() for a in t.aliases)
            ]
            if not matches:
                _fail(f"no glossary entry for {term!r} (cyberdeck glossary lists them all)")
            if len(matches) > 1:
                console.print("Did you mean: " + ", ".join(escape(t.term) for t in matches))
                return
            found = matches[0]
        console.print(f"[bold]{escape(found.term)}[/]")
        console.print(escape(glossary.plain(found.short)))
        if found.learn:
            console.print(f"[dim]Learn more: {escape(found.learn)}[/]")
        related = [gloss.terms[r].term for r in found.see if r in gloss.terms]
        if related:
            console.print(f"[dim]See also: {escape(', '.join(related))}[/]")
        return
    if not gloss.terms:
        console.print("The glossary is empty (built-in terms are off in Settings).")
        return
    table = Table(show_header=True)
    table.add_column("Term", style="bold")
    table.add_column("Meaning")
    for entry in sorted(gloss.terms.values(), key=lambda t: t.term.lower()):
        table.add_row(entry.term, glossary.plain(entry.short))
    console.print(table)


# --- learning L4: journal, lessons, write-up, playbook, path ---------------------------------


def _ask_lesson(ws: Workspace, kind: Literal["user", "root", "note"]) -> None:
    """The three flag questions in the terminal (every answer optional)."""
    console.print("[bold]Three quick questions while it's fresh[/] (Enter to skip any):")
    got_in = typer.prompt("  What got you in?", default="", show_default=False)
    sooner = typer.prompt(
        "  What would you check sooner next time?", default="", show_default=False
    )
    known = services.techniques()
    console.print("  Techniques: " + ", ".join(sorted(known)))
    raw = typer.prompt("  Which did you use? (comma-separated ids)", default="", show_default=False)
    picked = [t.strip() for t in raw.split(",") if t.strip()]
    unknown = [t for t in picked if t not in known]
    if unknown:
        console.print(f"  [yellow]![/] Ignoring unknown: {', '.join(unknown)}")
        picked = [t for t in picked if t in known]
    if got_in.strip() or sooner.strip() or picked:
        services.record_lesson(ws, kind, got_in, sooner, picked)
        console.print("[green]✓[/] Saved to the journal and your playbook (cyberdeck playbook).")


@app.command()
def lesson(
    target: TargetOpt = None,
    kind: Annotated[str, typer.Option("--kind", help="user, root or note.")] = "note",
) -> None:
    """Write down what you learned on the box (asked after `cyberdeck flag` too)."""
    if kind not in ("user", "root", "note"):
        _fail("--kind must be user, root or note")
    _ask_lesson(_open(target), "user" if kind == "user" else "root" if kind == "root" else "note")


@app.command("journal")
def journal_cmd(target: TargetOpt = None) -> None:
    """The box's story: scans and jobs (with highlights), flags, leads, help, lessons."""
    ws = _open(target)
    for entry in services.journal(ws):
        stamp = entry.at.astimezone().strftime("%m-%d %H:%M")
        style = {"flag": "bold green", "lesson": "bold cyan", "help": "yellow"}.get(entry.kind, "")
        text = escape(glossary.plain(entry.text))
        console.print(f"[dim]{stamp}[/]  " + (f"[{style}]{text}[/]" if style else text))
        for detail in entry.details:
            console.print(f"               [dim]{escape(glossary.plain(detail))}[/]")


@app.command()
def writeup(
    target: TargetOpt = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="File to write (default: writeup.md in the box folder)."
        ),
    ] = None,
    stdout: Annotated[bool, typer.Option("--stdout", help="Print it instead of saving.")] = False,
    reveal: Annotated[
        bool, typer.Option("--reveal", help="Keep passwords, hashes, flags and real paths in it.")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Replace an existing write-up file.")
    ] = False,
) -> None:
    """A Markdown write-up of the box. Loot and your paths are masked unless --reveal.

    Saves to the box's write-up file (writeup.md, or an existing WRITEUP.md in any case) and
    won't replace one that exists unless --force."""
    ws = _open(target)
    settings = load_settings()
    if stdout:
        console.print(services.writeup(ws, settings, reveal=reveal), markup=False, highlight=False)
        return
    try:
        path = services.export_writeup(ws, settings, path=output, reveal=reveal, overwrite=force)
    except services.WriteupExistsError as exc:
        console.print(
            f"[red]✗[/] {escape(str(exc))}. Use --force to replace it, -o to write elsewhere, "
            "or --stdout to print it."
        )
        raise typer.Exit(1) from exc
    console.print(f"[green]✓[/] Write-up saved to {escape(str(path))}")
    if not reveal:
        console.print(
            "  [dim]Passwords, hashes, flags and your home/workspace paths are masked.[/]"
        )


@app.command()
def playbook(
    query: Annotated[str, typer.Argument(help="Search text (technique, word, box name).")] = "",
) -> None:
    """Your lessons from every box, newest first."""
    entries = services.playbook(load_settings(), query)
    if not entries:
        console.print("No lessons yet. They're asked when you record a flag (cyberdeck flag).")
        return
    for entry in entries:
        lesson = entry.lesson
        console.print(
            f"[bold]{escape(entry.box)}[/] "
            f"[dim]({lesson.kind}, {lesson.at.astimezone():%Y-%m-%d})[/]"
        )
        if lesson.got_in:
            console.print(f"  Got in: {escape(lesson.got_in)}")
        if lesson.sooner:
            console.print(f"  Next time: {escape(lesson.sooner)}")
        if lesson.techniques:
            console.print(f"  [cyan]{escape(', '.join(lesson.techniques))}[/]")


@app.command("path")
def path_cmd() -> None:
    """A suggested order of boxes to learn on, and how far you got."""
    found = services.learning_paths(load_settings())
    if not found:
        console.print("No learning path (turned off in Settings, or none installed).")
        return
    titles = {t.id: t.title for t in services.techniques().values()}
    mark = {
        "root": "[green]✓ root[/]",
        "user": "[yellow]◐ user[/]",
        "started": "[cyan]· started[/]",
        "todo": "",
    }
    for learning_path, steps in found:
        done = sum(s.status == "root" for s in steps)
        console.print(f"[bold]{escape(learning_path.title)}[/]  {done}/{len(steps)} rooted")
        console.print(f"[dim]{escape(learning_path.description)}[/]")
        table = Table(show_header=True)
        for column in ("Box", "Stage", "OS", "You", "Practises"):
            table.add_column(column)
        for s in steps:
            table.add_row(
                s.step.box,
                s.step.stage,
                s.step.os or "",
                Text.from_markup(mark[s.status]),
                ", ".join(titles.get(k, k) for k in s.step.skills),
            )
        console.print(table)


@app.command()
def skills() -> None:
    """Techniques you've used (from your lessons), and the ones still to practise."""
    table = Table(show_header=True)
    for column in ("Technique", "id", "Boxes"):
        table.add_column(column)
    for skill in services.skills(load_settings()):
        boxes = ", ".join(skill.boxes)
        table.add_row(
            Text(skill.technique.title, style="bold" if boxes else "dim"),
            skill.technique.id,
            boxes or Text("·", style="dim"),
        )
    console.print(table)


# --- learning L3: checklist, stuck, leads ---------------------------------------------------

_CHECK_MARK = {"done": "[green]✓[/]", "auto": "[green]✓[/]", "na": "[dim]–[/]", "open": "·"}

checklist_app = typer.Typer(
    help="Methodology checklist for the box: what to check, per service and phase.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(checklist_app, name="checklist")


def _print_checklist(ws: Workspace, *, show_all: bool) -> None:
    entries = services.checklist(ws)
    content = services.load_methodology()
    for error in content.errors:
        err_console.print(f"[yellow]![/] {escape(error)}")
    if not entries:
        console.print(
            "No checklist items apply yet (scan first), or checklists are off in Settings."
        )
        return
    cover = services.coverage(entries)
    section = None
    for entry in entries:
        item = entry.item
        if not show_all and entry.state != "open":
            continue
        if item.section != section:
            section = item.section
            done, total = cover[section]
            title = services.SECTION_TITLES.get(section, section)
            console.print(f"\n[bold]{escape(title)}[/] [dim]{done}/{total} done[/]")
        auto = " [dim](auto)[/]" if entry.state == "auto" else ""
        console.print(f"  {_CHECK_MARK[entry.state]} {escape(item.title)}{auto}  [dim]{item.id}[/]")
        if entry.state == "open":
            console.print(f"      [dim]{escape(glossary.plain(item.why))}[/]")
            if item.how:
                console.print(f"      how: [cyan]{escape(item.how)}[/]")
    opened = sum(e.state == "open" for e in entries)
    console.print(
        f"\n{opened} open of {len(entries)}. Tick one: cyberdeck checklist done <id> "
        "(na <id> = doesn't apply)" + ("" if show_all else "; --all shows the done ones")
    )


@checklist_app.callback()
def checklist_main(
    ctx: typer.Context,
    target: TargetOpt = None,
    show_all: Annotated[bool, typer.Option("--all", "-a", help="Include done items.")] = False,
) -> None:
    """List the open checklist items (default), or tick one with a subcommand."""
    if ctx.invoked_subcommand is None:
        _print_checklist(_open(target), show_all=show_all)


ItemArg = Annotated[str, typer.Argument(help="Checklist item id, e.g. web.robots.")]


@checklist_app.command("done")
def checklist_done(item: ItemArg, target: TargetOpt = None) -> None:
    """Tick an item: you've checked it."""
    _mark(item, "done", target)


@checklist_app.command("na")
def checklist_na(item: ItemArg, target: TargetOpt = None) -> None:
    """Mark an item as not applicable to this box."""
    _mark(item, "na", target)


@checklist_app.command("reset")
def checklist_reset(item: ItemArg, target: TargetOpt = None) -> None:
    """Open an item again."""
    _mark(item, "open", target)


def _mark(item: str, status: Literal["done", "na", "open"], target: str | None) -> None:
    ws = _open(target)
    try:
        services.mark_checklist(ws, item, status)
    except OptionError as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/] {item}: {status}")


@app.command()
def stuck(
    target: TargetOpt = None,
    hint: Annotated[
        bool, typer.Option("--hint", help="Also show general hints for this situation (level 2).")
    ] = False,
) -> None:
    """Stuck? What you haven't tried yet; with --hint, what usually works in this situation."""
    ws = _open(target)
    report = services.stuck_report(ws, 2 if hint else 1)
    console.print("[bold]What haven't you tried?[/]")
    if report.untried:
        for entry in report.untried[:12]:
            item = entry.item
            area = services.SECTION_TITLES.get(item.section, item.section)
            console.print(f"  · [bold]{escape(item.title)}[/] [dim]({escape(area)}, {item.id})[/]")
            if item.how:
                console.print(f"      how: [cyan]{escape(item.how)}[/]")
        if len(report.untried) > 12:
            console.print(f"  [dim]...and {len(report.untried) - 12} more: cyberdeck checklist[/]")
    else:
        console.print("  Every checklist item that applies is done.")
    if report.suggestions:
        console.print("[bold]Open next steps:[/]")
        for sug in report.suggestions[:5]:
            console.print(f"  #{sug.id} {escape(sug.title)}")
    if report.set_aside:
        console.print("[bold]You set these aside (worth a second look?):[/]")
        for sug in report.set_aside[:5]:
            console.print(f"  #{sug.id} {escape(sug.title)} [dim]({sug.status.value})[/]")
    if report.parked:
        console.print("[bold]Parked leads:[/]")
        for lead in report.parked:
            console.print(f"  #{lead.id} {escape(lead.title)}")
    if report.seen_before:
        console.print("[bold]You've seen this before:[/]")
        for seen in report.seen_before:
            what = seen.lesson.got_in or ", ".join(seen.lesson.techniques)
            console.print(f"  On {escape(seen.box)}: {escape(what)}")
    if hint:
        console.print("[bold]Hints (general, no spoilers):[/]")
        if not report.hints:
            console.print("  None for this situation (or hints are off in Settings).")
        for pattern in report.hints[:4]:
            console.print(f"  [bold yellow]★ {escape(pattern.title)}[/]")
            console.print(f"    {escape(glossary.plain(pattern.hint))}")
    else:
        console.print("[dim]Still stuck? cyberdeck stuck --hint[/]")


lead_app = typer.Typer(
    help="What you're working on: the rabbit-hole timer warns when it stops giving results.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(lead_app, name="lead")


@lead_app.callback()
def lead_main(ctx: typer.Context, target: TargetOpt = None) -> None:
    """List leads (default), or start / park / finish one."""
    if ctx.invoked_subcommand is not None:
        return
    ws = _open(target)
    leads = services.list_leads(ws)
    if not leads:
        console.print("No leads yet: cyberdeck lead start '<what you are working on>'")
        return
    for lead in leads:
        line = f"#{lead.id} {escape(lead.title)}  [dim]{lead.status}[/]"
        if lead.status == "active":
            status = services.lead_status(ws, lead)
            line += (
                f"  {status.minutes_on:.0f} min on it, "
                f"{status.minutes_quiet:.0f} min since the last new finding"
            )
        console.print(line)


@lead_app.command("start")
def lead_start(
    title: Annotated[str, typer.Argument(help="What you're working on, e.g. 'the /upload page'.")],
    target: TargetOpt = None,
) -> None:
    """Start working on something (any active lead is parked)."""
    ws = _open(target)
    try:
        lead = services.start_lead(ws, title)
    except OptionError as exc:
        _fail(str(exc))
    minutes = load_user_config().learning.rabbit_hole_minutes
    console.print(
        f"[green]✓[/] Working on #{lead.id} {escape(lead.title)}."
        + (f" The TUI warns after {minutes} min without new findings." if minutes else "")
    )


LeadOpt = Annotated[int | None, typer.Argument(help="Lead number (default: the active one).")]


@lead_app.command("park")
def lead_park(lead_id: LeadOpt = None, target: TargetOpt = None) -> None:
    """Set a lead aside for later (it shows up in cyberdeck stuck)."""
    _end_lead("parked", lead_id, target)


@lead_app.command("done")
def lead_done(lead_id: LeadOpt = None, target: TargetOpt = None) -> None:
    """Close a lead: it led somewhere (or you've ruled it out)."""
    _end_lead("done", lead_id, target)


@lead_app.command("resume")
def lead_resume(lead_id: LeadOpt = None, target: TargetOpt = None) -> None:
    """Work on a parked lead again."""
    _end_lead("active", lead_id, target)


def _end_lead(
    status: Literal["parked", "done", "active"], lead_id: int | None, target: str | None
) -> None:
    ws = _open(target)
    try:
        lead = services.end_lead(ws, status, lead_id)
    except OptionError as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/] #{lead.id} {escape(lead.title)}: {lead.status}")


# --- tools ----------------------------------------------------------------------------------

tools_app = typer.Typer(
    help="Kali tools Cyberdeck can run: installed or not, enable/disable, preferred per group.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(tools_app, name="tools")


def _print_tools(refresh: bool) -> None:
    infos = services.tool_infos(refresh=refresh)
    table = Table()
    table.add_column("Tool", no_wrap=True)
    for column in ("Group / category", "Safety", "Installed", "Version", "Enabled"):
        table.add_column(column)
    for info in sorted(infos, key=lambda i: i.tool.id):  # A-Z; the category is a column
        tool, status = info.tool, info.status
        name = tool.id + (" *" if info.preferred else "")
        installed = (
            Text("yes", style="green")
            if status.installed
            else Text(f"no: {status.install_hint}", style="red")
        )
        table.add_row(
            name,
            tool.group or tool.category,
            tool.safety,
            installed,
            status.version or "-",
            "yes" if info.enabled else Text("no", style="yellow"),
        )
    console.print(table)
    console.print(
        "[dim]* = the tool used when you run its group (cyberdeck run dir-bruteforce). "
        "Change it with: cyberdeck tools prefer <tool>[/]"
    )
    for path, error in services.tool_load_errors():
        console.print(f"[red]✗[/] {escape(str(path))}: {escape(error)}")


@tools_app.callback()
def tools_main(ctx: typer.Context) -> None:
    """List tools (default), or use a subcommand."""
    if ctx.invoked_subcommand is None:
        _print_tools(refresh=False)


@tools_app.command("list")
def tools_list() -> None:
    """List tools with install status and version (cached)."""
    _print_tools(refresh=False)


@tools_app.command("detect")
def tools_detect() -> None:
    """Re-check which tools are installed and their versions, and refresh cached --help."""
    _print_tools(refresh=True)
    for tool in all_tools():
        services.help_text(tool.id, refresh=True)


@tools_app.command("enable")
def tools_enable(tool: Annotated[str, typer.Argument(help="Tool id.")]) -> None:
    """Enable a tool (it can be picked for its group and suggested again)."""
    try:
        path = services.set_tool_enabled(tool, True)
    except OptionError as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/] {tool} enabled ({path})")


@tools_app.command("disable")
def tools_disable(tool: Annotated[str, typer.Argument(help="Tool id.")]) -> None:
    """Disable a tool: never picked for its group or suggested. `cyberdeck run <id>` still works."""
    try:
        path = services.set_tool_enabled(tool, False)
    except OptionError as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/] {tool} disabled ({path})")


@tools_app.command("prefer")
def tools_prefer(tool: Annotated[str, typer.Argument(help="Tool id, e.g. gobuster-dir.")]) -> None:
    """Make a tool the one used for its alternatives group (e.g. dir-bruteforce)."""
    try:
        group, path = services.prefer_tool(tool)
    except OptionError as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/] {tool} is now used for {group} ({path})")


@tools_app.command("help")
def tools_help(
    tool: Annotated[str, typer.Argument(help="Tool id.")],
    refresh: Annotated[bool, typer.Option("--refresh", help="Capture it again.")] = False,
) -> None:
    """Show a tool's own --help output (captured once and cached)."""
    try:
        text = services.help_text(tool, refresh=refresh)
    except OptionError as exc:
        _fail(str(exc))
    if not text:
        _fail(f"no help available for {tool} (is it installed?)")
    console.print(text, markup=False, highlight=False)


@tools_app.command("check")
def tools_check(
    paths: Annotated[
        list[Path], typer.Argument(help="Manifest files or folders (e.g. plugins/tools/web).")
    ],
) -> None:
    """Validate tool manifests and show every problem, e.g. after copying _template.yaml."""
    results = services.check_manifests(paths)
    if not results:
        _fail("no .yaml manifests found there")
    bad = 0
    for result in results:
        if result.tool is None:
            bad += 1
            console.print(f"[red]✗[/] {escape(str(result.path))}: {escape(result.error or '')}")
            continue
        tool = result.tool
        console.print(
            f"[green]✓[/] {escape(str(result.path))}: {tool.id} "
            f"[dim]({tool.category}, {tool.safety})[/]"
        )
        for warning in result.warnings:
            console.print(f"    [yellow]![/] {escape(warning)}")
    console.print(f"{len(results) - bad} valid, {bad} with errors.")
    if bad:
        raise typer.Exit(1)


@tools_app.command("wordlists")
def tools_wordlists() -> None:
    """Show the named wordlists ({wordlists.<name>} in manifests) and whether they exist."""
    table = Table()
    for column in ("Name", "For", "Path", "Found"):
        table.add_column(column)
    missing = False
    for wl in services.wordlist_status():
        missing = missing or not wl.exists
        found = Text("yes", style="green") if wl.exists else Text("no", style="red")
        path = str(wl.path) + (" (yours)" if wl.overridden else "")
        table.add_row(wl.name, wl.purpose, path, found)
    console.print(table)
    if missing:
        console.print(
            "[yellow]![/] Missing lists: sudo apt install seclists, or set your own under "
            "wordlists: in ~/.config/cyberdeck/config.yaml"
        )


@app.command()
def reparse(
    job_id: Annotated[int, typer.Argument(help="Job number from `cyberdeck jobs`.")],
    target: TargetOpt = None,
) -> None:
    """Parse a past job's saved output again (picks up parser fixes; findings merge)."""
    ws = _open(target)
    try:
        report = services.reparse_job(ws, job_id)
    except OptionError as exc:
        _fail(str(exc))
    _print_parse_report(ws, report)


# --- suggestions (docs/RULES.md) ------------------------------------------------------------

_SAFETY_STYLE = {"safe": "green", "intrusive": "yellow", "bruteforce": "red", "exploit": "red"}


def _suggestion_line(sug: Suggestion) -> str:
    if sug.kind == "ask":
        tag = "[magenta]question[/]"
    else:
        style = _SAFETY_STYLE.get(sug.safety, "red")
        tag = f"[{style}]{escape(sug.tool or '?')}[/]"
        if sug.safety != "safe":
            tag += f" [{style}]({sug.safety})[/]"
    return f"[bold]#{sug.id}[/] {escape(sug.title)}  {tag}"


def _print_next(ws: Workspace, limit: int = 3) -> None:
    """The top open suggestions, with how to act on them."""
    top = services.list_suggestions(ws)
    if not top:
        return
    console.print("\n[bold]Suggested next steps[/] (all: cyberdeck suggest):")
    for sug in top[:limit]:
        console.print(f"  {_suggestion_line(sug)}")
    console.print(
        f"[dim]Do one: cyberdeck suggest run {top[0].id}   Chain the safe ones: cyberdeck auto[/]"
    )


suggest_app = typer.Typer(
    help="Suggested next steps for a box: list, run, answer, skip or snooze them.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(suggest_app, name="suggest")

ExplainOpt = Annotated[
    bool, typer.Option("--explain", "-e", help="Also show the learn-more links.")
]


def _print_suggestions(ws: Workspace, *, show_all: bool, explain: bool) -> None:
    result = services.refresh_suggestions(ws)
    items = services.list_suggestions(ws, include_closed=show_all, refresh=False)
    if not items:
        console.print("No open suggestions. Run more tools or add findings, then check again.")
    for sug in items:
        status = "" if sug.status is SuggestionStatus.OPEN else f" [dim]{sug.status.value}[/]"
        job = f" [dim](job #{sug.job_id})[/]" if sug.job_id else ""
        console.print(f"{_suggestion_line(sug)}{status}{job}")
        if sug.why:
            console.print(f"    [dim]{escape(glossary.plain(sug.why))}[/]")
        if explain and sug.learn:
            console.print(f"    [dim]Learn: {escape(sug.learn)}[/]")
    if items:
        console.print(
            "[dim]cyberdeck suggest run <#> (Run dialog / question), skip <#>, snooze <#> "
            "(until something new is found), cyberdeck auto (chain the safe ones)[/]"
        )
    for error in result.errors:
        console.print(f"[red]✗[/] {escape(error)}")


@suggest_app.callback()
def suggest_main(
    ctx: typer.Context,
    target: TargetOpt = None,
    show_all: Annotated[
        bool, typer.Option("--all", "-a", help="Include done, skipped and snoozed ones.")
    ] = False,
    explain: ExplainOpt = False,
) -> None:
    """List suggestions (default), or use a subcommand."""
    if ctx.invoked_subcommand is None:
        _print_suggestions(_open(target), show_all=show_all, explain=explain)


@suggest_app.command("list")
def suggest_list(
    target: TargetOpt = None,
    show_all: Annotated[
        bool, typer.Option("--all", "-a", help="Include done, skipped and snoozed ones.")
    ] = False,
    explain: ExplainOpt = False,
) -> None:
    """List the box's suggestions, highest priority first, with why."""
    _print_suggestions(_open(target), show_all=show_all, explain=explain)


SuggestionArg = Annotated[int, typer.Argument(help="Suggestion number from `cyberdeck suggest`.")]


@suggest_app.command("run")
def suggest_run(
    suggestion: SuggestionArg,
    target: TargetOpt = None,
    yes: YesOpt = False,
) -> None:
    """Act on a suggestion: open its tool in the Run dialog, or answer its question."""
    ws = _open(target)
    settings = load_settings()
    try:
        sug = services.get_suggestion(ws, suggestion)
    except OptionError as exc:
        _fail(str(exc))
    if sug.status is not SuggestionStatus.OPEN:
        console.print(f"[dim]#{sug.id} is {sug.status.value}; running it anyway.[/]")
    if sug.why:
        console.print(f"[dim]Why: {escape(glossary.plain(sug.why))}[/]")
    if sug.kind == "ask":
        _answer(ws, settings, sug, yes=yes)
        return
    try:
        _, plan = services.plan_suggestion(ws, suggestion, settings)
    except OptionError as exc:
        _fail(str(exc))
    if not have_binary(plan.tool.binary):
        _fail(f"{plan.tool.binary} is not installed (sudo apt install {plan.tool.detect_spec.apt})")
    if not _vpn_preflight(settings, ws.meta.ip, interactive=not yes):
        raise typer.Exit(1)
    _confirm_and_run(ws, settings, plan, yes=yes, root=is_root(), suggestion_id=suggestion)


def _answer(ws: Workspace, settings: Settings, sug: Suggestion, *, yes: bool) -> None:
    sid = sug.id or 0
    action = sug.ask.get("action", "none")
    prompt = str(sug.ask.get("prompt") or sug.title)
    if action == "hosts.add":
        if _hosts_add_flow(ws, settings, None, yes=yes):
            services.complete_suggestion(ws, sid)
        return
    if sug.ask.get("input"):
        if yes:
            _fail("this question needs an answer; run it without --yes")
        answer: str | bool = typer.prompt(prompt, default=sug.ask.get("default") or "")
    else:
        answer = yes or typer.confirm(prompt, default=True)
    try:
        result = services.answer_question(ws, sid, answer)
    except OptionError as exc:
        _fail(str(exc))
    if result.suggestion.status is SuggestionStatus.SKIPPED:
        console.print(f"Skipped #{sug.id}.")
        return
    console.print(f"[green]✓[/] {escape(result.message or 'answered')}")
    _print_hosts_hint(result.created)
    _print_next(ws)


def _set_status(suggestion: int, target: str | None, status: SuggestionStatus, note: str) -> None:
    ws = _open(target)
    try:
        sug = services.set_suggestion_status(ws, suggestion, status)
    except OptionError as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/] #{sug.id} {note}: {escape(sug.title)}")


@suggest_app.command("skip")
def suggest_skip(suggestion: SuggestionArg, target: TargetOpt = None) -> None:
    """Dismiss a suggestion for good (cyberdeck suggest reopen <#> brings it back)."""
    _set_status(suggestion, target, SuggestionStatus.SKIPPED, "skipped")


@suggest_app.command("snooze")
def suggest_snooze(suggestion: SuggestionArg, target: TargetOpt = None) -> None:
    """Hide a suggestion until something new is found on the box."""
    _set_status(suggestion, target, SuggestionStatus.SNOOZED, "snoozed until the next finding")


@suggest_app.command("reopen")
def suggest_reopen(suggestion: SuggestionArg, target: TargetOpt = None) -> None:
    """Bring back a skipped, snoozed or done suggestion."""
    _set_status(suggestion, target, SuggestionStatus.OPEN, "reopened")


# --- auto mode ------------------------------------------------------------------------------


@app.command()
def auto(
    target: TargetOpt = None,
    rounds: Annotated[
        int,
        typer.Option(
            "--rounds", "-r", min=1, help="Chain depth: results of one round feed the next."
        ),
    ] = 3,
    minutes: Annotated[
        int, typer.Option("--minutes", "-m", min=1, help="Don't start new jobs after this long.")
    ] = 60,
    dont_ask: Annotated[
        bool,
        typer.Option(
            "--dont-ask",
            help="Skip the Run dialog for safe tools (the exact command is still printed). "
            "Default: auto_confirm_safe in config.yaml (off).",
        ),
    ] = False,
) -> None:
    """Work through the safe suggestions (fingerprinting, dir and vhost discovery) in order.

    Only tools tagged safe that are installed and need no root are chained. Questions
    (/etc/hosts, hostnames) and intrusive, bruteforce or exploit tools always wait for you.
    """
    ws = _open(target)
    settings = load_settings()
    skip_dialog = dont_ask or load_user_config().auto_confirm_safe
    if not _vpn_preflight(settings, ws.meta.ip, interactive=True):
        raise typer.Exit(1)
    deadline = datetime.now(UTC).timestamp() + minutes * 60
    tried: set[int] = set()
    root = is_root()
    ran = 0
    out_of_time = False
    for round_no in range(1, rounds + 1):
        batch = [
            s
            for s in services.auto_runnable(ws, services.list_suggestions(ws))
            if s.id is not None and s.id not in tried
        ]
        if not batch or out_of_time:
            break
        console.rule(f"Auto round {round_no}/{rounds}: {len(batch)} safe step(s)")
        for sug in batch:
            if datetime.now(UTC).timestamp() > deadline:
                console.print(f"[yellow]![/] Time budget ({minutes} min) used up.")
                out_of_time = True
                break
            sid = sug.id or 0
            tried.add(sid)
            current = services.get_suggestion(ws, sid)
            if current.status is not SuggestionStatus.OPEN:
                continue  # an earlier run in this round covered it
            console.print(f"\n{_suggestion_line(current)}")
            try:
                _, plan = services.plan_suggestion(ws, sid, settings)
            except OptionError as exc:
                console.print(f"[yellow]![/] {escape(str(exc))}")
                continue
            outcome = _confirm_and_run(
                ws,
                settings,
                plan,
                yes=skip_dialog,
                root=root,
                origin="auto",
                suggestion_id=sid,
                strict=False,
            )
            if outcome is not None:
                ran += 1
            elif not skip_dialog:  # you said no in the dialog: don't offer it again
                services.set_suggestion_status(ws, sid, SuggestionStatus.SKIPPED)
    console.print(f"\n[bold]Auto mode ran {ran} job(s).[/]")
    remaining = services.list_suggestions(ws)
    runnable = {s.id for s in services.auto_runnable(ws, remaining)} - tried
    waiting = [s for s in remaining if s.id not in runnable]
    if runnable:
        console.print(f"{len(runnable)} more safe step(s): run cyberdeck auto again.")
    if waiting:
        console.print("[bold]Waiting for you[/] (questions, non-safe or root tools):")
        for sug in waiting[:8]:
            console.print(f"  {_suggestion_line(sug)}")
        console.print("[dim]cyberdeck suggest run <#>[/]")


# --- /etc/hosts -----------------------------------------------------------------------------

HostsYesOpt = Annotated[
    bool, typer.Option("--yes", "-y", help="Don't ask (the diff is still shown).")
]

hosts_app = typer.Typer(
    help="This box's /etc/hosts lines: show, add (diff + confirm + sudo), remove.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(hosts_app, name="hosts")


def _show_change(change: HostsChange) -> None:
    for line in change.diff().splitlines():
        style = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim"
        console.print(line, style=style, markup=False, highlight=False)
    for warning in change.warnings:
        console.print(f"[yellow]![/] {escape(warning)}")


def _apply_change(
    ws: Workspace | None, settings: Settings, change: HostsChange, *, yes: bool
) -> bool:
    _show_change(change)
    if not yes and not typer.confirm(f"Write this to {change.path}?", default=True):
        console.print("Not changed.")
        return False
    if services.hosts_needs_sudo(settings) and not is_root() and not sudo_cached():
        console.print("sudo needs your password (typed into sudo itself, never into Cyberdeck):")
        if not sudo_validate():
            _fail("sudo failed; hosts file not changed")
    try:
        backup = services.hosts_apply(change, ws, settings)
    except services.HostsError as exc:
        _fail(str(exc))
    saved = f" (old file saved as {backup.relative_to(ws.path)})" if backup and ws else ""
    console.print(f"[green]✓[/] {escape(str(change.path))} updated{escape(saved)}.")
    return True


def _hosts_add_flow(
    ws: Workspace, settings: Settings, names: list[str] | None, *, yes: bool
) -> bool:
    change = services.hosts_plan_add(ws, names, settings)
    if not change.changed:
        console.print(f"[green]✓[/] {escape(str(change.path))} already maps them to {ws.meta.ip}.")
        for warning in change.warnings:
            console.print(f"[yellow]![/] {escape(warning)}")
        return True
    if not _apply_change(ws, settings, change, yes=yes):
        return False
    _print_next(ws)
    return True


@hosts_app.callback()
def hosts_main(ctx: typer.Context, target: TargetOpt = None) -> None:
    """Show this box's hosts lines and names not mapped yet (default), or use a subcommand."""
    if ctx.invoked_subcommand is not None:
        return
    ws = _open(target)
    settings = load_settings()
    lines, missing = services.hosts_status(ws, settings)
    console.print(f"Hosts file: {escape(str(settings.hosts_file))}")
    for line in lines:
        console.print(f"  {line}", markup=False, highlight=False)
    if not lines:
        console.print("  [dim]no Cyberdeck line for this box[/]")
    if missing:
        console.print(
            f"Not mapped to {ws.meta.ip} yet: [bold]{escape(', '.join(missing))}[/] "
            "(cyberdeck hosts add)"
        )


@hosts_app.command("add")
def hosts_add(
    names: Annotated[
        list[str] | None,
        typer.Argument(help="Names to map to the box IP. Default: every hostname found."),
    ] = None,
    target: TargetOpt = None,
    yes: HostsYesOpt = False,
) -> None:
    """Map the box's hostnames to its IP: shows the diff, asks, then writes with sudo.

    Names you give are also recorded as the box's hostnames. Cyberdeck keeps one tagged line
    per box (# cyberdeck:<box>) and updates it in place, e.g. after set-ip. Lines you wrote
    yourself are never changed.
    """
    ws = _open(target)
    settings = load_settings()
    wanted = list(names) if names else None
    if wanted is None and not services.box_hostnames(ws):
        _fail("no hostnames known for this box yet; give them: cyberdeck hosts add box.htb")
    if wanted:
        try:
            services.record_hostnames(ws, wanted)  # names you give become findings too
        except OptionError as exc:
            _fail(str(exc))
    _hosts_add_flow(ws, settings, wanted, yes=yes)


@hosts_app.command("remove")
def hosts_remove(
    target: TargetOpt = None,
    every: Annotated[
        bool, typer.Option("--all", help="Remove every Cyberdeck line, for all boxes.")
    ] = False,
    yes: HostsYesOpt = False,
) -> None:
    """Remove this box's tagged lines (when you're done with it, or the IP went to another box)."""
    settings = load_settings()
    ws = None if every else _open(target)
    change = services.hosts_plan_remove(ws, settings)
    if not change.changed:
        console.print("Nothing to remove.")
        return
    _apply_change(ws, settings, change, yes=yes)


# --- MCP server and approvals (ADR 0007, docs/MCP.md) ---------------------------------------


def _ensure_mcp_token(settings: Settings) -> tuple[str, Path | None]:
    """The bearer token for --http: CYBERDECK_MCP_TOKEN, else a new one saved (mode 600) in
    ~/.config/cyberdeck/.env. Returns (token, file written or None)."""
    if settings.mcp_token is not None:
        return settings.mcp_token.get_secret_value(), None
    import secrets as _secrets

    from cyberdeck.core.config import config_dir

    token = _secrets.token_urlsafe(32)
    env_file = config_dir() / ".env"
    env_file.parent.mkdir(parents=True, exist_ok=True)
    existing = env_file.read_text(encoding="utf-8") if env_file.is_file() else ""
    sep = "" if not existing or existing.endswith("\n") else "\n"
    env_file.write_text(f"{existing}{sep}CYBERDECK_MCP_TOKEN={token}\n", encoding="utf-8")
    env_file.chmod(0o600)
    return token, env_file


@app.command()
def mcp(
    target: TargetOpt = None,
    http: Annotated[
        str | None,
        typer.Option(
            "--http", help="Serve streamable HTTP on HOST:PORT, e.g. 127.0.0.1:8765 (loopback)."
        ),
    ] = None,
    allow_remote: Annotated[
        bool, typer.Option("--allow-remote", help="Allow --http to bind a non-loopback address.")
    ] = False,
) -> None:
    """MCP server for Claude Code and other MCP clients (stdio unless --http).

    Same guardrails as the TUI: commands are previewed before they run, only safe tools run
    directly, and non-safe or root jobs and /etc/hosts edits wait for you in
    `cyberdeck approvals` or the TUI. -t pins the session to one box (recommended).
    """
    from ipaddress import ip_address

    from cyberdeck.mcp_server import server as mcp_server

    settings = load_settings()
    if target:
        try:
            services.open_target(settings, target)
        except WorkspaceError as exc:
            _fail(str(exc))
    if http is None:
        mcp_server.run_stdio(target)  # stdout belongs to the protocol: print nothing
        return
    bind = http or load_user_config().mcp.http_bind  # "--http ''" uses config.yaml's
    host, sep, port_text = bind.rpartition(":")
    if not sep or not port_text.isdigit():
        _fail(f"--http expects HOST:PORT, got {bind!r}")
    host = host.strip("[]") or "127.0.0.1"
    try:
        loopback = host == "localhost" or ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback and not allow_remote:
        _fail(
            f"refusing to serve MCP on {host}: use 127.0.0.1 and an SSH tunnel, or --allow-remote"
        )
    token, written = _ensure_mcp_token(settings)
    if written is not None:
        console.print(f"Generated a bearer token in {escape(str(written))} (CYBERDECK_MCP_TOKEN).")
    console.print(
        f"MCP on http://{host}:{port_text}/mcp "
        "(header: Authorization: Bearer <CYBERDECK_MCP_TOKEN>)"
    )
    mcp_server.run_http(host, int(port_text), token, target)


approvals_app = typer.Typer(
    help="Requests from MCP clients waiting for you: non-safe or root jobs, /etc/hosts edits.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(approvals_app, name="approvals")


def _print_approvals(rows: list[tuple[Workspace, Approval]], show_box: bool) -> None:
    if not rows:
        console.print("No requests waiting.")
        return
    table = Table()
    for column in (
        "#",
        *(["Box"] if show_box else []),
        "Kind",
        "Request",
        "Safety",
        "Why",
        "Asked",
    ):
        table.add_column(column)
    for ws, a in rows:
        detail = a.payload.get("command") or a.title
        table.add_row(
            str(a.id),
            *([escape(ws.meta.name)] if show_box else []),
            a.kind,
            Text(str(detail), overflow="fold"),
            Text(a.safety, style=_SAFETY_STYLE.get(a.safety, "yellow")),
            escape(a.reason or str(a.payload.get("why_approval") or "")),
            a.created_at.astimezone().strftime("%H:%M"),
        )
    console.print(table)
    console.print("[dim]cyberdeck approvals approve <#> / deny <#>  (-t <box> for another box)[/]")


@approvals_app.callback()
def approvals_main(
    ctx: typer.Context,
    target: TargetOpt = None,
    every: Annotated[
        bool, typer.Option("--all", help="Every box under the workspace root.")
    ] = False,
) -> None:
    """List waiting requests (default), or approve/deny one."""
    if ctx.invoked_subcommand is not None:
        return
    if every:
        _print_approvals(services.pending_approvals_everywhere(load_settings()), True)
        return
    ws = _open(target)
    _print_approvals([(ws, a) for a in services.list_approvals(ws)], False)


ApprovalArg = Annotated[int, typer.Argument(help="Request number from `cyberdeck approvals`.")]


@approvals_app.command("approve")
def approvals_approve(
    approval_id: ApprovalArg,
    target: TargetOpt = None,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Don't ask (the command/diff is still shown).")
    ] = False,
) -> None:
    """Carry out a request: runs exactly the requested command, or writes the hosts change."""
    ws = _open(target)
    settings = load_settings()
    try:
        approval = services.get_approval(ws, approval_id)
        if approval.kind == "hosts":
            change = services.approval_hosts_change(ws, approval_id, settings)
        else:
            plan = services.approval_plan(ws, approval_id)
    except OptionError as exc:
        _fail(str(exc))
    if approval.reason:
        console.print(f"[dim]Reason given: {escape(approval.reason)}[/]")
    if approval.kind == "hosts":
        if not change.changed:
            console.print("The hosts file already has these names; nothing to write.")
            services.deny_approval(ws, approval_id, "already in the hosts file")
            return
        _show_change(change)
        if not yes and not typer.confirm(f"Write this to {change.path}?", default=True):
            console.print("Left pending.")
            return
        if services.hosts_needs_sudo(settings) and not is_root() and not sudo_cached():
            console.print(
                "sudo needs your password (typed into sudo itself, never into Cyberdeck):"
            )
            if not sudo_validate():
                _fail("sudo failed; hosts file not changed")
        try:
            services.approve_hosts(ws, approval_id, change, settings)
        except services.HostsError as exc:
            _fail(str(exc))
        console.print(f"[green]✓[/] {escape(str(change.path))} updated.")
        _print_next(ws)
        return
    style = _SAFETY_STYLE.get(plan.tool.safety, "red")
    console.print(
        f"{escape(plan.tool.name)} [{style}]{plan.tool.safety}[/] "
        f"requested by {approval.requested_by}:"
    )
    console.print(Text("$ " + plan.command_line(), style="bold cyan"))
    for warning in plan.warnings:
        console.print(f"[yellow]![/] {escape(warning)}")
    if not yes and not typer.confirm("Run exactly this?", default=False):
        console.print(f"Left pending (deny it with: cyberdeck approvals deny {approval_id}).")
        return
    if not _vpn_preflight(settings, ws.meta.ip, interactive=not yes):
        raise typer.Exit(1)
    if plan.sudo and not is_root() and not sudo_cached():
        console.print("sudo needs your password (typed into sudo itself, never into Cyberdeck):")
        if not sudo_validate():
            _fail("sudo failed")
    outcome, tail = _run_with_progress(ws, settings, plan, approval_id=approval_id)
    _report(ws, outcome, tail)


@approvals_app.command("deny")
def approvals_deny(approval_id: ApprovalArg, target: TargetOpt = None) -> None:
    """Refuse a request (the MCP client sees it as denied)."""
    ws = _open(target)
    try:
        approval = services.deny_approval(ws, approval_id)
    except OptionError as exc:
        _fail(str(exc))
    console.print(f"[green]✓[/] Denied #{approval.id}: {escape(approval.title)}")
