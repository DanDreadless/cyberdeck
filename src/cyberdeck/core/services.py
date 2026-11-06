"""Service layer: the one API used by the CLI, TUI and MCP server (ADR 0007).

Front ends call these functions; they never touch the store or workspace internals directly.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from cyberdeck.core import credscan, doctor, methodology
from cyberdeck.core import glossary as glossary_mod
from cyberdeck.core import journal as journal_mod
from cyberdeck.core import summarize as summarize_mod
from cyberdeck.core.classify import kind_table
from cyberdeck.core.config import Settings, load_settings
from cyberdeck.core.events import FindingsChanged, SuggestionsChanged, bus
from cyberdeck.core.facts import BoxFacts, best_domain, best_hostname, matches_when, web_urls
from cyberdeck.core.models import (
    PAYLOAD_TYPES,
    Approval,
    ApprovalState,
    Credential,
    Finding,
    FindingType,
    Hostname,
    Job,
    JobStatus,
    Note,
    OsGuess,
    Service,
    Software,
    Suggestion,
    SuggestionStatus,
    utcnow,
)
from cyberdeck.core.options import (
    OptionError,
    RunPlan,
    Teach,
    ToolSpec,
    render_template,
    resolve_values,
)
from cyberdeck.core.runner import (
    JobRequest,
    JobResult,
    Launcher,
    LineCallback,
    Runner,
    StartCallback,
    fix_ownership,
    is_root,
    needs_privilege,
    pid_alive,
    raw_paths,
    write_file_privileged,
)
from cyberdeck.core.tools import get_tool, registry
from cyberdeck.core.userconfig import UserConfig, load_user_config, save_user_config
from cyberdeck.core.workspace import (
    TargetMeta,
    Workspace,
    WorkspaceNotFoundError,
    list_workspaces,
    unmanaged_folders,
)
from cyberdeck.ingest.nmap import ImportReport, import_path
from cyberdeck.plugins import wordlists
from cyberdeck.plugins.detect import ToolStatus, detect, detect_all, man_page, tool_help
from cyberdeck.plugins.parsers import ParseContext, ParserError, run_parser
from cyberdeck.plugins.parsers import load_all as load_parsers
from cyberdeck.plugins.wordlists import Wordlist
from cyberdeck.rules.engine import BoxState, RuleSet, evaluate, load_rules
from cyberdeck.store.db import Lead, Lesson
from cyberdeck.util import hosts as hostsfile
from cyberdeck.util.hosts import HostsChange, resolves_to
from cyberdeck.util.vpn import VpnStatus, vpn_status

# Tests swap in a fake nmap here; production runs argv unchanged.
RUNNER_LAUNCHER: Launcher | None = None


def create_target(settings: Settings, name: str, ip: str, root: Path | None = None) -> Workspace:
    return Workspace.create(root or settings.root, name, ip, settings.scope())


def open_target(settings: Settings, ref: str | None = None, cwd: Path | None = None) -> Workspace:
    """Open a box: by name/path, else the box folder you're in, else the current box
    (``cyberdeck use``). Marks jobs orphaned by a dead Cyberdeck process as interrupted and
    records when the box was last opened, so ``list``/``status`` can pick up where you left off.
    """
    try:
        ws = Workspace.resolve(ref, settings.root, cwd or Path.cwd())
    except WorkspaceNotFoundError:
        current = load_user_config().current_target
        if ref or not current:
            raise
        ws = Workspace.open(Path(current))
        ws.resolved_via = "current"
    with ws.store() as store:
        store.reap_interrupted(pid_alive)
    ws.meta.last_opened = utcnow()
    ws.save_meta()
    return ws


def use_target(ws: Workspace) -> None:
    """Make ``ws`` the current box for commands run outside any box folder."""
    cfg = load_user_config()
    cfg.current_target = str(ws.path)
    save_user_config(cfg)


def set_ip(settings: Settings, ws: Workspace, ip: str) -> str:
    """Change a box's IP (HTB gives re-spawned boxes new addresses). Findings are kept."""
    old = ws.meta.ip
    ws.meta.ip = settings.scope().check(ip)
    ws.save_meta()
    with ws.notes_file.open("a", encoding="utf-8") as notes:
        notes.write(f"\n- {utcnow():%Y-%m-%d %H:%M} IP changed {old} -> {ws.meta.ip}\n")
    return old


_FLAG_RE = re.compile(r"^[0-9a-f]{32}$")


def record_flag(ws: Workspace, kind: Literal["user", "root"], value: str) -> bool:
    """Save a captured flag. Returns False if it doesn't look like an HTB flag (still saved)."""
    value = value.strip()
    setattr(ws.meta.flags, kind, value)
    setattr(ws.meta.flags, f"{kind}_at", utcnow())
    ws.save_meta()
    return bool(_FLAG_RE.match(value))


def list_targets(settings: Settings, root: Path | None = None) -> list[Workspace]:
    return list_workspaces(root or settings.root)


def import_nmap(ws: Workspace, path: Path | None = None, *, force: bool = False) -> ImportReport:
    """Import nmap output, then re-evaluate the box's suggestions."""
    with ws.store() as store:
        report = import_path(store, path or ws.nmap_dir, ws.meta.ip, force=force)
    _findings_changed(ws, report.created, report.updated, "import")
    refresh_suggestions(ws)
    return report


def _findings_changed(
    ws: Workspace, created: list[Finding], updated: list[Finding], source: str
) -> None:
    if created or updated:
        bus.emit(FindingsChanged(ws.path, list(created), list(updated), source))


@dataclass(frozen=True)
class TargetSummary:
    meta: TargetMeta
    path: Path
    services: list[Service]
    hostnames: list[Hostname]
    software: list[Software]
    os_guesses: list[tuple[OsGuess, float]]
    counts: dict[FindingType, int]

    @property
    def best_os(self) -> str | None:
        return self.os_guesses[0][0].family if self.os_guesses else None


def target_summary(ws: Workspace) -> TargetSummary:
    with ws.store() as store:
        services = sorted(
            (f.as_(Service) for f in store.findings(FindingType.SERVICE)),
            key=lambda s: (s.proto, s.port),
        )
        hostnames = sorted(
            (f.as_(Hostname) for f in store.findings(FindingType.HOSTNAME)),
            key=lambda h: (h.kind != "host", h.fqdn),
        )
        software = sorted(
            (f.as_(Software) for f in store.findings(FindingType.SOFTWARE)),
            key=lambda s: s.name.lower(),
        )
        os_guesses = sorted(
            ((f.as_(OsGuess), f.confidence) for f in store.findings(FindingType.OS)),
            key=lambda pair: -pair[1],
        )
        counts = store.counts()
    return TargetSummary(ws.meta, ws.path, services, hostnames, software, os_guesses, counts)


def hosts_file_line(ip: str, hostnames: list[Hostname]) -> str | None:
    """A single ``/etc/hosts`` line for the given names (hosts first, then domains)."""
    names = [h.fqdn for h in hostnames if h.kind == "host"]
    names += [h.fqdn for h in hostnames if h.kind == "domain" and h.fqdn not in names]
    return f"{ip} {' '.join(names)}" if names else None


# --- planning and running tools (Run dialog backend, ADR 0005) -------------------------------


def open_tcp_ports(ws: Workspace) -> str | None:
    with ws.store() as store:
        ports = sorted(
            {
                svc.port
                for svc in (f.as_(Service) for f in store.findings(FindingType.SERVICE))
                if svc.proto == "tcp"
            }
        )
    return ",".join(str(p) for p in ports) or None


def _box_facts(ws: Workspace) -> BoxFacts:
    with ws.store() as store:
        return BoxFacts.from_findings(store.findings())


def _provide(
    provider: str, ws: Workspace, facts: BoxFacts, hosts_file: Path, warnings: list[str]
) -> str | None:
    ip = ws.meta.ip
    if provider == "target_ip":
        return ip
    if provider == "host":
        host = best_hostname(facts)
        return host if host is not None and resolves_to(hosts_file, host, ip) else ip
    if provider == "open_tcp_ports":
        ports = sorted({s.port for s in facts.services if s.proto == "tcp"})
        if not ports:
            warnings.append("No open TCP ports known yet; run stage 1 first or set Ports.")
        return ",".join(str(p) for p in ports) or None
    if provider == "hostname":
        return best_hostname(facts)
    if provider == "domain":
        domain = best_domain(facts)
        if domain is None:
            warnings.append("No domain known yet (e.g. box.htb): type the one you expect.")
        return domain
    if provider in ("web_url", "web_url_ip"):
        host = best_hostname(facts) if provider == "web_url" else None
        if host is not None and not resolves_to(hosts_file, host, ip):
            warnings.append(
                f"{host} is not in {hosts_file} yet, so the IP is used. Add "
                f"'{ip} {host}': the site may only answer on its name."
            )
            host = None
        urls = web_urls(facts, ip, host)
        if not urls:
            warnings.append("No web service known yet; type the URL.")
            return None
        if len(urls) > 1:
            warnings.append(f"Other web services: {', '.join(urls[1:])} (change URL to use one).")
        return urls[0]
    raise OptionError(f"unknown input source {provider!r}")


def _expand(value: Any, ctx: dict[str, str]) -> Any:
    if isinstance(value, str) and "{" in value:
        try:
            return render_template(value, ctx)
        except OptionError:
            return value
    return value


def plan_tool(
    ws: Workspace,
    tool_id: str,
    *,
    preset: str | None = None,
    overrides: dict[str, str] | None = None,
    extra: Sequence[str] = (),
    sudo: bool = False,
    settings: Settings | None = None,
) -> RunPlan:
    """Build a RunPlan with defaults resolved; raises OptionError on bad input.

    Inputs and finding-derived defaults come from the box's DB (``_provide``); ``when:``
    options are only pre-filled if their findings match; wordlist names are expanded.
    """
    settings = settings or load_settings()
    tool = get_tool(tool_id)
    cfg = load_user_config()
    facts = _box_facts(ws)
    warnings = _readiness_warnings(tool, facts)
    dynamic: dict[str, Any] = {}
    for option_id, provider in tool.dynamic_defaults.items():
        value = _provide(provider, ws, facts, settings.hosts_file, warnings)
        if value is not None:
            dynamic[option_id] = value
    for opt in tool.options:
        if opt.when and not matches_when(opt.when, facts):
            dynamic.setdefault(opt.id, None)
    ctx = {
        "target.ip": ws.meta.ip,
        "target.slug": ws.meta.slug,
        "target.name": ws.meta.name,
        "stamp": utcnow().strftime("%Y%m%d-%H%M%S"),
        **wordlists.context(cfg.wordlists),
    }
    for name, provider in (("hostname", "hostname"), ("domain", "domain")):
        value = _provide(provider, ws, facts, settings.hosts_file, [])
        if value:
            ctx[name] = value
    if any("{lhost}" in part for part in tool.command):
        lhost = vpn_check(settings, ws.meta.ip).lhost
        if lhost:
            ctx["lhost"] = lhost
        else:
            warnings.append("No VPN tunnel address found for {lhost}; is the VPN up?")
    out = tool.out or ("raw/{tool}-{stamp}" if tool.ingest is None else None)
    if out:
        ctx["out"] = render_template(out.replace("{tool}", tool.id), ctx)
    baseline = resolve_values(tool, dynamic=dynamic)
    values = resolve_values(
        tool,
        dynamic=dynamic,
        user_defaults=cfg.tool_defaults.get(tool.id),
        box_defaults=ws.meta.tool_defaults.get(tool.id),
        preset=preset,
    )
    values = {k: _expand(v, ctx) for k, v in values.items()}
    plan = RunPlan(
        tool,
        values,
        ctx,
        extra=list(extra),
        preset=preset,
        sudo=sudo,
        warnings=warnings,
        baseline={k: _expand(v, ctx) for k, v in baseline.items()},
    )
    for option_id, raw in (overrides or {}).items():
        plan.set_option(option_id, raw)
    return plan


def _readiness_warnings(tool: ToolSpec, facts: BoxFacts) -> list[str]:
    """Why a run would fail before it starts: the tool isn't installed, or the box has been
    scanned and none of the ports the tool talks to (manifest ``ports:``) is open. Warnings,
    not problems: the scan can be incomplete, and tests run fake tools."""
    warnings: list[str] = []
    if tool.ingest is None:
        status = detect(tool)
        if not status.installed:
            warnings.append(f"{tool.binary} is not installed: {status.install_hint}")
    if tool.ports and facts.services:
        open_ports = {s.port for s in facts.services if s.state.startswith("open")}
        if not open_ports & set(tool.ports):
            wanted = ", ".join(str(p) for p in tool.ports)
            warnings.append(
                f"{tool.name} talks to port {wanted}, which the scans didn't find open on this "
                "box: it will probably just time out."
            )
    return warnings


def save_plan_defaults(ws: Workspace, plan: RunPlan, where: Literal["user", "box"]) -> Path:
    """Remember the plan's changed options as the user's or this box's defaults."""
    values = plan.changed_values()
    if where == "user":
        cfg = load_user_config()
        cfg.tool_defaults[plan.tool.id] = values
        return save_user_config(cfg)
    ws.meta.tool_defaults[plan.tool.id] = values
    ws.save_meta()
    return ws.meta_file


@dataclass(frozen=True)
class ParseReport:
    created: list[Finding] = field(default_factory=list)
    updated: list[Finding] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class RunOutcome:
    result: JobResult
    import_report: ImportReport | None
    notes: list[str]
    parse_report: ParseReport | None = None
    suggestions: list[Suggestion] = field(default_factory=list)  # newly opened by this run
    summary: summarize_mod.JobSummary | None = None  # plain-English "so what?" (learning L2)
    possible_credentials: list[Finding] = field(default_factory=list)  # credscan notes


def _nmap_outputs(ws: Workspace, plan: RunPlan) -> list[Path]:
    if "out" not in plan.ctx:
        return []
    prefix = ws.path / plan.ctx["out"]
    return [prefix.with_name(prefix.name + ext) for ext in (".xml", ".gnmap", ".nmap")]


def _job_meta(plan: RunPlan) -> dict[str, Any]:
    return {
        "ctx": plan.full_context(),
        "values": plan.values,
        "outputs": plan.output_paths(),
        "preset": plan.preset,
        "extra": plan.extra,
        "edited": plan.raw_argv is not None,
    }


def _parse_job(ws: Workspace, job: Job) -> ParseReport:
    """Run the tool's parser over a job's saved output and merge the findings."""
    try:
        tool = get_tool(job.tool)
    except OptionError as exc:
        return ParseReport(error=str(exc))
    if not tool.parser:
        return ParseReport()
    _, out, err = raw_paths(ws, job.id, job.tool)
    meta = job.meta or {}
    pctx = ParseContext(
        tool_id=tool.id,
        job_id=job.id,
        target_ip=ws.meta.ip,
        workspace=ws.path,
        stdout=out,
        stderr=err,
        outputs=[ws.path / p for p in meta.get("outputs", [])],
        values=dict(meta.get("values") or {}),
        ctx=dict(meta.get("ctx") or {}),
        config=tool.parser_config,
    )
    try:
        findings = run_parser(tool.parser, pctx)
    except ParserError as exc:
        return ParseReport(error=str(exc))
    created: list[Finding] = []
    updated: list[Finding] = []
    with ws.store() as store:
        for finding in findings:
            result = store.upsert(finding)
            if result.created:
                created.append(result.finding)
            elif result.data_changed:
                updated.append(result.finding)
    _findings_changed(ws, created, updated, pctx.source)
    return ParseReport(created, updated)


_PARSEABLE = (JobStatus.DONE, JobStatus.FAILED, JobStatus.TIMEOUT, JobStatus.CANCELLED)


async def execute_plan(
    ws: Workspace,
    settings: Settings,
    plan: RunPlan,
    *,
    on_line: LineCallback | None = None,
    origin: str = "cli",
    suggestion_id: int | None = None,
    on_start: StartCallback | None = None,
) -> RunOutcome:
    """Run a plan through the Runner, then import (nmap) or parse (manifest tools) its output
    and re-evaluate suggestions. Callers must have shown ``plan.command_line()`` to the user and
    checked ``plan.problems()``. ``suggestion_id``: the suggestion this run carries out (marked
    done when the job succeeds)."""
    runner = Runner(ws, settings.scope(), launcher=RUNNER_LAUNCHER)
    for output in plan.output_paths():
        (ws.path / output).parent.mkdir(parents=True, exist_ok=True)
    request = JobRequest(
        tool=plan.tool.id,
        argv=plan.argv(),
        target_ip=ws.meta.ip,
        cwd=ws.path,
        timeout=plan.tool.timeout,
        origin=origin,
        meta=_job_meta(plan),
    )
    result = await runner.run(request, on_line, on_start)
    outputs = _nmap_outputs(ws, plan) + [ws.path / p for p in plan.output_paths()]
    if plan.sudo:
        fix_ownership(outputs)
    notes: list[str] = []
    report: ImportReport | None = None
    parsed: ParseReport | None = None
    if plan.tool.ingest == "nmap" and result.ok:
        source = next((p for p in outputs[:2] if p.is_file()), None)
        if source is None:
            notes.append("nmap finished but no .xml/.gnmap output was found (was -oA removed?)")
        else:
            with ws.store() as store:
                report = import_path(store, source, ws.meta.ip, force=True)
            _findings_changed(ws, report.created, report.updated, f"job:{result.job.id}:nmap")
    elif plan.tool.parser and result.job.status in _PARSEABLE:
        parsed = _parse_job(ws, result.job)
        if parsed.error:
            notes.append(f"parsing failed: {parsed.error} (raw output is kept)")
    if suggestion_id is not None and result.ok:
        complete_suggestion(ws, suggestion_id, job_id=result.job.id)
    spotted = scan_job_for_credentials(ws, result.job)
    opened = refresh_suggestions(ws, settings).opened
    created = (report.created if report else []) + (parsed.created if parsed else [])
    updated = (report.updated if report else []) + (parsed.updated if parsed else [])
    summary = summarize_mod.summarize(
        plan.tool.name,
        result.job.status,
        created + spotted,
        updated,
        new_suggestions=len(opened),
        output_tail=_output_tail(result.out_path, result.err_path),
        note=result.job.note,
    )
    return RunOutcome(result, report, notes, parsed, opened, summary, spotted)


def _output_tail(*paths: Path, limit: int = 8000) -> str:
    parts: list[str] = []
    for path in paths:
        if path.is_file():
            with path.open("rb") as handle:
                handle.seek(max(0, path.stat().st_size - limit))
                parts.append(handle.read().decode("utf-8", errors="replace"))
    return chr(10).join(parts)


def scan_job_for_credentials(ws: Workspace, job: Job) -> list[Finding]:
    """Password-shaped strings in a job's saved output become notes tagged
    ``possible-credential`` (core/credscan.py); the ``creds.possible-password`` rule then asks
    whether to save each to Loot. Ones already in Loot are skipped. Returns the new notes."""
    if job.id is None:
        return []
    out_path = raw_paths(ws, job.id, job.tool)[1]
    if not out_path.is_file():
        return []
    with out_path.open("rb") as handle:
        text = handle.read(credscan.MAX_SCAN_BYTES).decode("utf-8", errors="replace")
    candidates = credscan.find_candidates(text)
    if not candidates:
        return []
    created: list[Finding] = []
    with ws.store() as store:
        known = {str(f.data.get("secret")) for f in store.findings(FindingType.CREDENTIAL)}
        for cand in candidates:
            if cand.secret in known:
                continue
            note = Note(
                title=f"Possible password: {cand.label} of {job.tool}'s output (job #{job.id})",
                text=f"{cand.user}:{cand.secret}",
                note_id=f"cred-{cand.fingerprint}",
            )
            finding = Finding.of(
                note,
                source=f"job:{job.id}:{job.tool}",
                confidence=0.5,
                tags=[summarize_mod.POSSIBLE_CREDENTIAL],
            )
            result = store.upsert(finding)
            if result.created:
                created.append(result.finding)
    _findings_changed(ws, created, [], f"job:{job.id}:credscan")
    return created


def summaries_enabled() -> bool:
    """``learning.summaries``: plain-English job summaries, highlights and Run-dialog teaching."""
    return load_user_config().learning.summaries


def job_summary(ws: Workspace, job_id: int) -> summarize_mod.JobSummary:
    """The "so what?" summary of a past job, rebuilt from the findings it produced (findings a
    later job also saw stay attributed to the first one). nmap jobs summarise the box's scan
    results, since imports are recorded per scan file."""
    with ws.store() as store:
        job = store.get_job(job_id)
        findings = store.findings()
    if job is None:
        raise OptionError(f"no job #{job_id} for {ws.meta.name}")
    try:
        tool = get_tool(job.tool)
        name, ingest = tool.name, tool.ingest
    except OptionError:
        name, ingest = job.tool, None
    marker = f"job:{job_id}:"
    if ingest == "nmap":
        mine = [
            f
            for f in findings
            if f.type in (FindingType.SERVICE, FindingType.HOSTNAME, FindingType.OS)
            and any(s.startswith("nmap:") for s in f.sources)
        ]
        created, updated = mine, []
    else:
        created = [f for f in findings if f.sources and f.sources[0].startswith(marker)]
        updated = [
            f for f in findings if f not in created and any(s.startswith(marker) for s in f.sources)
        ]
    out_path, err_path = raw_paths(ws, job_id, job.tool)[1:]
    return summarize_mod.summarize(
        name,
        job.status,
        created,
        updated,
        output_tail=_output_tail(out_path, err_path),
        note=job.note,
    )


def reparse_job(ws: Workspace, job_id: int) -> ParseReport:
    """Parse a past job's saved output again, e.g. after a parser improved."""
    with ws.store() as store:
        job = store.get_job(job_id)
    if job is None:
        raise OptionError(f"no job #{job_id} for {ws.meta.name}")
    tool = get_tool(job.tool)
    if tool.ingest == "nmap":
        report = import_nmap_job(ws, job)
        _findings_changed(ws, report.created, report.updated, f"job:{job.id}:nmap")
        parsed = ParseReport(report.created, report.updated)
    elif not tool.parser:
        return ParseReport(error=f"{tool.name} has no parser")
    else:
        parsed = _parse_job(ws, job)
    refresh_suggestions(ws)
    return parsed


def import_nmap_job(ws: Workspace, job: Job) -> ImportReport:
    out = (job.meta.get("ctx") or {}).get("out") if job.meta else None
    if not out:
        argv = job.argv
        out = argv[argv.index("-oA") + 1] if "-oA" in argv[:-1] else None
    if not out:
        raise OptionError(f"job #{job.id} has no -oA output to import")
    prefix = ws.path / out
    source = next(
        (p for p in (prefix.with_name(prefix.name + e) for e in (".xml", ".gnmap")) if p.is_file()),
        None,
    )
    if source is None:
        raise OptionError(f"no nmap output found at {out}.xml/.gnmap")
    with ws.store() as store:
        return import_path(store, source, ws.meta.ip, force=True)


# --- tools: detection, groups, enable/disable -------------------------------------------------


@dataclass(frozen=True)
class ToolInfo:
    tool: ToolSpec
    status: ToolStatus
    enabled: bool
    preferred: bool  # the member a group resolves to


def tool_infos(*, refresh: bool = False) -> list[ToolInfo]:
    reg = registry(reload=refresh)
    statuses = detect_all(list(reg.tools.values()), refresh=refresh)
    cfg = load_user_config()
    chosen = {g: _pick(members, statuses, cfg) for g, members in reg.groups().items()}
    return [
        ToolInfo(
            tool,
            statuses[tool.id],
            tool.id not in cfg.disabled_tools,
            bool(tool.group) and chosen.get(tool.group or "") is tool,
        )
        for tool in reg.tools.values()
    ]


@dataclass(frozen=True)
class ManifestCheck:
    path: Path
    tool: ToolSpec | None
    error: str | None = None
    warnings: tuple[str, ...] = ()


def check_manifests(paths: Sequence[Path]) -> list[ManifestCheck]:
    """Validate manifest files (or every manifest under a folder) without loading them into
    the registry: the ``cyberdeck tools check`` backend."""
    import yaml

    from cyberdeck.plugins.manifest import ManifestError, manifest_files, manifest_to_spec

    files: list[Path] = []
    for path in paths:
        files += manifest_files(path) if path.is_dir() else [path]
    known = registry().tools
    results: list[ManifestCheck] = []
    for path in files:
        folder = path.parent.name if path.parent.name not in ("tools", "") else None
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            spec = manifest_to_spec(raw, path, folder_category=folder)
        except (OSError, yaml.YAMLError, ManifestError) as exc:
            results.append(ManifestCheck(path, None, str(exc)))
            continue
        warnings: list[str] = []
        other = known.get(spec.id)
        if other is not None and other.source and Path(other.source).resolve() != path.resolve():
            warnings.append(f"id {spec.id!r} is also used by {other.source}")
        if spec.safety == "safe" and spec.requires_root:
            warnings.append("needs root but is tagged safe: consider intrusive")
        results.append(ManifestCheck(path, spec, None, tuple(warnings)))
    return results


def tool_load_errors() -> list[tuple[Path, str]]:
    """Broken manifests, parsers and service-kind entries (shown by ``cyberdeck tools``)."""
    return registry().errors + [(p, e) for p, e in load_parsers()] + kind_table().errors


def _pick(
    members: list[ToolSpec], statuses: dict[str, ToolStatus], cfg: UserConfig
) -> ToolSpec | None:
    usable = [t for t in members if t.id not in cfg.disabled_tools and statuses[t.id].installed]
    group = members[0].group if members else None
    preferred = cfg.group_prefs.get(group or "")
    for tool in usable:
        if tool.id == preferred:
            return tool
    return usable[0] if usable else None


def group_members(group: str) -> list[ToolSpec]:
    return registry().groups().get(group, [])


def resolve_tool(ref: str) -> ToolSpec:
    """A tool id, or an alternatives group (``dir-bruteforce``) resolved to the preferred
    installed, enabled member."""
    reg = registry()
    if ref in reg.tools:
        return reg.tools[ref]
    members = reg.groups().get(ref)
    if not members:
        known = ", ".join(sorted([*reg.tools, *reg.groups()]))
        raise OptionError(f"unknown tool or group {ref!r} (available: {known})")
    statuses = {t.id: detect(t) for t in members}
    chosen = _pick(members, statuses, load_user_config())
    if chosen is None:
        hints = ", ".join(statuses[t.id].install_hint for t in members)
        raise OptionError(f"no tool of group {ref!r} is installed and enabled ({hints})")
    return chosen


def set_tool_enabled(tool_id: str, enabled: bool) -> Path:
    get_tool(tool_id)
    cfg = load_user_config()
    disabled = [t for t in cfg.disabled_tools if t != tool_id]
    if not enabled:
        disabled.append(tool_id)
    cfg.disabled_tools = disabled
    return save_user_config(cfg)


def prefer_tool(tool_id: str) -> tuple[str, Path]:
    """Make ``tool_id`` the preferred member of its group. Returns (group, config path)."""
    tool = get_tool(tool_id)
    if not tool.group:
        raise OptionError(f"{tool.id} is not part of an alternatives group")
    cfg = load_user_config()
    cfg.group_prefs[tool.group] = tool.id
    return tool.group, save_user_config(cfg)


def help_text(tool_id: str, *, refresh: bool = False) -> str | None:
    return tool_help(get_tool(tool_id), refresh=refresh)


def man_text(tool_id: str, *, refresh: bool = False) -> str | None:
    return man_page(get_tool(tool_id), refresh=refresh)


def wordlist_status() -> list[Wordlist]:
    return wordlists.all_wordlists(load_user_config().wordlists)


def list_jobs(ws: Workspace) -> list[Job]:
    with ws.store() as store:
        return store.jobs()


def plan_rerun(ws: Workspace, job_id: int, settings: Settings | None = None) -> RunPlan:
    """The Run-dialog plan for running a past job again: same tool, option values, preset,
    extra args and sudo, with a fresh output folder. If the command that ran isn't what those
    values give (edited by hand, or an older job without saved extra args), the exact command
    comes back as an edited command (old output folder swapped for the new one)."""
    with ws.store() as store:
        job = store.get_job(job_id)
    if job is None:
        raise OptionError(f"no job #{job_id} for {ws.meta.name}")
    plan = plan_tool(ws, job.tool, settings=settings)
    meta = job.meta or {}
    old_out = str((meta.get("ctx") or {}).get("out") or "")
    new_out = plan.ctx.get("out", "")

    def fresh(value: Any) -> Any:
        if isinstance(value, str) and old_out and new_out and old_out in value:
            return value.replace(old_out, new_out)
        return value

    saved = meta.get("values") or {}
    for opt in plan.tool.options:
        if opt.id in saved:
            plan.values[opt.id] = fresh(saved[opt.id])
    if meta.get("preset") in plan.tool.presets:
        plan.preset = meta["preset"]
    plan.extra = [str(a) for a in meta.get("extra") or []]
    argv = [str(fresh(a)) for a in job.argv]
    if argv[:2] == ["sudo", "-n"]:
        plan.sudo, argv = True, argv[2:]
    try:
        same = plan.base_argv() == argv
    except OptionError:
        same = False
    if not same and argv:
        plan.raw_argv = argv
    return plan


def job_files(ws: Workspace, job_id: int) -> tuple[Job, Path, Path, Path]:
    with ws.store() as store:
        job = store.get_job(job_id)
    if job is None:
        raise OptionError(f"no job #{job_id} for {ws.meta.name}")
    cmd, out, err = raw_paths(ws, job.id, job.tool)
    return job, cmd, out, err


# --- VPN ------------------------------------------------------------------------------------


def vpn_check(settings: Settings, target_ip: str) -> VpnStatus:
    """VPN/tunnel state for reaching ``target_ip`` (settings.vpn_config also comes from
    config.yaml once remembered)."""
    return vpn_status(target_ip, settings.vpn_search_dir, settings.vpn_config)


def remember_vpn_config(path: Path) -> None:
    cfg = load_user_config()
    cfg.vpn_config = str(path)
    save_user_config(cfg)


def remember_workspace_root(path: Path) -> Path:
    cfg = load_user_config()
    cfg.workspace_root = str(path)
    return save_user_config(cfg)


def list_unmanaged(settings: Settings, root: Path | None = None) -> list[Path]:
    return unmanaged_folders(root or settings.root)


# --- progress / resume ----------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    label: str
    done: bool
    detail: str = ""


@dataclass(frozen=True)
class TargetProgress:
    ws: Workspace
    steps: list[Step]
    last_job: Job | None
    interrupted: list[Job]
    next_hint: str
    next_tools: tuple[str, ...]  # what `cyberdeck resume` offers to run next


def target_progress(ws: Workspace) -> TargetProgress:
    """What's been done on a box and what to do next. Derived from the box's own DB, so it
    survives restarts and works for boxes whose scans were imported by hand."""
    with ws.store() as store:
        jobs = store.jobs()
        services_ = [f.as_(Service) for f in store.findings(FindingType.SERVICE)]
        hostnames = store.findings(FindingType.HOSTNAME)

    def done(tool: str) -> Job | None:
        finished = [j for j in jobs if j.tool == tool and j.status is JobStatus.DONE]
        return finished[-1] if finished else None

    stage1, stage2, udp = done("nmap-allports"), done("nmap-services"), done("nmap-udp")
    have_versions = any(s.product or s.scripts for s in services_)
    ports = ",".join(str(s.port) for s in sorted(services_, key=lambda s: s.port))
    flags = ws.meta.flags
    steps = [
        Step("Stage 1: all TCP ports", bool(stage1) or bool(services_), ports),
        Step("Stage 2: scripts + versions", bool(stage2) or have_versions),
        Step("UDP top ports (optional, needs root)", bool(udp)),
        Step("Hostnames found", bool(hostnames), str(len(hostnames)) if hostnames else ""),
        Step("User flag", bool(flags.user)),
        Step("Root flag", bool(flags.root)),
    ]
    interrupted = [j for j in jobs if j.status is JobStatus.INTERRUPTED]
    tools: tuple[str, ...] = ()
    if not steps[0].done:
        hint = "Scan all TCP ports, then scripts + versions."
        tools = ("nmap-allports", "nmap-services")
    elif not steps[1].done:
        hint, tools = "Run stage 2 (scripts + versions) on the open ports.", ("nmap-services",)
    elif not flags.user:
        top = list_suggestions(ws)
        if top:
            hint = f"{top[0].title} (see all: cyberdeck suggest)"
        else:
            hint = (
                "Enumerate the services (cyberdeck show); no suggestions left (cyberdeck suggest)."
            )
    elif not flags.root:
        hint = "You have user: work on privilege escalation for root."
    else:
        hint = "Box complete. Nice work."
    return TargetProgress(ws, steps, jobs[-1] if jobs else None, interrupted, hint, tools)


# -- learning aids (docs/LEARNING-PLAN.md, phase L1) -----------------------------------------


@dataclass(frozen=True)
class JourneyStage:
    label: str
    state: Literal["done", "current", "todo"]
    hint: str  # what this stage is about, in plain words ([[term]] links allowed)


JOURNEY = (
    ("Scan", "Find the open [[port|ports]] and what runs on them."),
    (
        "Enumerate",
        "List everything each [[service]] tells you; the way in is usually something you found "
        "([[enumeration]]).",
    ),
    (
        "Foothold",
        "Turn a finding into access: a login that works, a shell, a file you can read "
        "([[foothold]]). Mark a password that worked in Loot (m).",
    ),
    ("User flag", "Find user.txt in a user's home directory and record it (f) ([[flag]])."),
    (
        "Root flag",
        "Escalate to root ([[privilege-escalation]]): start with [[sudo|sudo -l]], then SUID "
        "files and config files with passwords.",
    ),
)


def journey(ws: Workspace) -> list[JourneyStage]:
    """The beginner journey bar: Scan > Enumerate > Foothold > User flag > Root flag. Derived from
    the box (scans, a credential marked as working, flags), like :func:`target_progress`."""
    progress = target_progress(ws)
    with ws.store() as store:
        creds = [f.as_(Credential) for f in store.findings(FindingType.CREDENTIAL)]
    flags = ws.meta.flags
    foothold = bool(flags.user) or any(c.verified_on for c in creds)
    done = [
        progress.steps[0].done and progress.steps[1].done,
        foothold,
        foothold,
        bool(flags.user),
        bool(flags.root),
    ]
    stages: list[JourneyStage] = []
    current_seen = False
    for (label, hint), is_done in zip(JOURNEY, done, strict=True):
        if is_done:
            state: Literal["done", "current", "todo"] = "done"
        elif not current_seen:
            state, current_seen = "current", True
        else:
            state = "todo"
        stages.append(JourneyStage(label, state, hint))
    return stages


def setup_checks(settings: Settings | None = None) -> list[doctor.Check]:
    """``cyberdeck doctor``: VPN, tools, wordlists, sudo, clock, workspace (nothing is changed)."""
    return doctor.run_checks(settings or load_settings(), load_user_config().wordlists)


def setup_summary(checks: list[doctor.Check]) -> str:
    return doctor.summary(checks)


def create_workspace_root(settings: Settings | None = None) -> Path:
    root = (settings or load_settings()).root
    root.mkdir(parents=True, exist_ok=True)
    return root


def teaching(tool: ToolSpec) -> Teach | None:
    """The tool's beginner explanation for the Run dialog, unless explanations are turned off
    (``learning.summaries``)."""
    if tool.teach is None or not load_user_config().learning.summaries:
        return None
    if not tool.teach.does and not tool.teach.look_for:
        return None
    return tool.teach


# -- methodology: checklists, Stuck?, leads (learning L3) -----------------------------------

ChecklistState = Literal["done", "auto", "na", "open"]
SECTION_TITLES = {
    "general": "Recon",
    "web": "Website",
    "smb": "SMB shares",
    "services": "Other services",
    "windows": "Windows domain",
    "creds": "Passwords and hashes",
    "linux-shell": "On the box (Linux)",
    "windows-shell": "On the box (Windows)",
}


@dataclass(frozen=True)
class ChecklistEntry:
    item: methodology.ChecklistItem
    state: ChecklistState  # auto = ticked by its done_when; done/na = you set it


def load_methodology() -> methodology.Content:
    """Built-in checklists and hints (unless turned off in Settings) plus your own."""
    return methodology.load_content()


def learn_state(ws: Workspace, settings: Settings | None = None) -> methodology.LearnState:
    flags = ws.meta.flags
    return methodology.LearnState(box_state(ws, settings), bool(flags.user), bool(flags.root))


def _section_key(item: methodology.ChecklistItem) -> tuple[int, int, int, str]:
    order = methodology.SECTIONS
    section = order.index(item.section) if item.section in order else len(order)
    return (section, methodology.PHASE_ORDER[item.phase], -item.priority, item.id)


def checklist(
    ws: Workspace,
    settings: Settings | None = None,
    *,
    content: methodology.Content | None = None,
    state: methodology.LearnState | None = None,
) -> list[ChecklistEntry]:
    """The checklist items that apply to this box, by section, phase and priority, each with
    whether it's done (by you or by itself), not applicable, or still open."""
    content = content or load_methodology()
    state = state or learn_state(ws, settings)
    with ws.store() as store:
        marks = store.checklist_marks()
    entries: list[ChecklistEntry] = []
    for item in sorted(content.checklist.values(), key=_section_key):
        if not state.holds(item.applies):
            continue
        mark = marks.get(item.id)
        if mark in ("done", "na"):
            entries.append(ChecklistEntry(item, "done" if mark == "done" else "na"))
        elif item.done_when is not None and state.holds(item.done_when):
            entries.append(ChecklistEntry(item, "auto"))
        else:
            entries.append(ChecklistEntry(item, "open"))
    return entries


def mark_checklist(ws: Workspace, item_id: str, status: Literal["done", "na", "open"]) -> None:
    """Tick an item (done), say it doesn't apply (na), or open it again."""
    if item_id not in load_methodology().checklist:
        raise OptionError(f"no checklist item {item_id!r} (cyberdeck checklist lists them)")
    with ws.store() as store:
        store.set_checklist_mark(item_id, None if status == "open" else status)


def coverage(entries: list[ChecklistEntry]) -> dict[str, tuple[int, int]]:
    """Section -> (done or not applicable, total)."""
    result: dict[str, tuple[int, int]] = {}
    for entry in entries:
        done, total = result.get(entry.item.section, (0, 0))
        result[entry.item.section] = (done + (entry.state != "open"), total + 1)
    return result


@dataclass(frozen=True)
class LeadStatus:
    lead: Lead
    minutes_on: float  # since you started (or restarted) it
    minutes_quiet: float  # since the last new finding (or the start, if none since)


@dataclass
class StuckReport:
    """ "What haven't you tried?" (level 1) and general hints (level 2), docs/LEARNING-PLAN W5."""

    level: int
    untried: list[ChecklistEntry] = field(default_factory=list)
    suggestions: list[Suggestion] = field(default_factory=list)  # still open
    set_aside: list[Suggestion] = field(default_factory=list)  # skipped or snoozed
    parked: list[Lead] = field(default_factory=list)
    hints: list[methodology.Pattern] = field(default_factory=list)  # level 2
    seen_before: list[PlaybookEntry] = field(default_factory=list)  # your lessons elsewhere


def stuck_report(
    ws: Workspace, level: int = 1, settings: Settings | None = None, *, log: bool = True
) -> StuckReport:
    """Level 1: open checklist items, open and set-aside suggestions, parked leads. Level 2 adds
    general hints matched on the box's state (never box-specific spoilers). Each request is
    logged in the box (help_log) for the journal."""
    content = load_methodology()
    state = learn_state(ws, settings)
    entries = checklist(ws, settings, content=content, state=state)
    suggestions = list_suggestions(ws, include_closed=True)
    report = StuckReport(
        level=level,
        untried=[e for e in entries if e.state == "open"],
        suggestions=[s for s in suggestions if s.status is SuggestionStatus.OPEN],
        set_aside=[
            s
            for s in suggestions
            if s.status in (SuggestionStatus.SKIPPED, SuggestionStatus.SNOOZED)
        ],
        parked=[lead for lead in list_leads(ws) if lead.status == "parked"],
        seen_before=seen_before(ws, settings, content=content, state=state),
    )
    if level >= 2:
        report.hints = sorted(
            (p for p in content.patterns.values() if state.holds(p.when)),
            key=lambda p: -p.priority,
        )
    if log:
        with ws.store() as store:
            store.log_help(f"stuck-{level}", f"{len(report.untried)} untried checks")
    return report


def list_leads(ws: Workspace) -> list[Lead]:
    with ws.store() as store:
        return store.leads()


def active_lead(ws: Workspace) -> Lead | None:
    return next((lead for lead in list_leads(ws) if lead.status == "active"), None)


def start_lead(ws: Workspace, title: str) -> Lead:
    """Say what you're working on; the rabbit-hole timer watches it. Parks any other lead."""
    title = " ".join(title.split())
    if not title:
        raise OptionError("say what you're working on, e.g. 'the /upload page'")
    with ws.store() as store:
        return store.add_lead(title)


def end_lead(
    ws: Workspace, status: Literal["parked", "done", "active"], lead_id: int | None = None
) -> Lead:
    """Park a lead (come back later), mark it done (it led somewhere), or resume a parked one."""
    leads = list_leads(ws)
    if lead_id is None:
        lead = next((x for x in leads if x.status == "active"), None)
        if lead is None:
            raise OptionError("no lead is active (cyberdeck lead start '<what you work on>')")
    else:
        lead = next((x for x in leads if x.id == lead_id), None)
        if lead is None:
            raise OptionError(f"no lead #{lead_id}")
    with ws.store() as store:
        store.set_lead(lead.id, status=status)
        return next(x for x in store.leads() if x.id == lead.id)


def last_finding_at(ws: Workspace) -> datetime | None:
    with ws.store() as store:
        findings = store.findings()
    return max((f.created_at for f in findings), default=None)


def lead_status(ws: Workspace, lead: Lead, now: datetime | None = None) -> LeadStatus:
    now = now or utcnow()
    newest = last_finding_at(ws)
    since = max(lead.started_at, newest) if newest else lead.started_at
    return LeadStatus(
        lead,
        (now - lead.started_at).total_seconds() / 60,
        (now - since).total_seconds() / 60,
    )


def rabbit_hole_check(ws: Workspace, now: datetime | None = None) -> LeadStatus | None:
    """The active lead, if it's had no new findings for ``learning.rabbit_hole_minutes`` and
    hasn't been warned about yet (it's then marked warned and logged)."""
    limit = load_user_config().learning.rabbit_hole_minutes
    lead = active_lead(ws)
    if not limit or lead is None or lead.warned:
        return None
    status = lead_status(ws, lead, now)
    if status.minutes_quiet < limit:
        return None
    with ws.store() as store:
        store.set_lead(lead.id, warned=True)
        store.log_help("rabbit-hole", lead.title)
    return status


def log_help(ws: Workspace, kind: str, detail: str = "") -> None:
    with ws.store() as store:
        store.log_help(kind, detail)


# -- journal, lessons, write-up, playbook, path (learning L4) --------------------------------


@dataclass(frozen=True)
class PlaybookEntry:
    box: str
    lesson: Lesson


def box_record(ws: Workspace) -> journal_mod.BoxRecord:
    """Everything the journal and write-up need, read once from the box."""
    with ws.store() as store:
        jobs = store.jobs()
        findings = store.findings()
        leads = store.leads()
        helped = store.help_log()
        lessons = store.lessons()
    commands: dict[int, str] = {}
    names: dict[str, str] = {}
    for job in jobs:
        cmd_path = raw_paths(ws, job.id, job.tool)[0]
        if cmd_path.is_file():
            commands[job.id] = cmd_path.read_text(encoding="utf-8", errors="replace")
        try:
            names[job.tool] = get_tool(job.tool).name
        except OptionError:
            names[job.tool] = job.tool
    flags = ws.meta.flags
    return journal_mod.BoxRecord(
        name=ws.meta.name,
        ip=ws.meta.ip,
        created_at=ws.meta.created_at,
        jobs=jobs,
        findings=findings,
        leads=leads,
        help=helped,
        lessons=lessons,
        flag_user_at=flags.user_at,
        flag_root_at=flags.root_at,
        flag_values=[v for v in (flags.user, flags.root) if v],
        commands=commands,
        notes=read_notes(ws),
        tool_names=names,
    )


def journal(ws: Workspace) -> list[journal_mod.Entry]:
    """The box's story, oldest first: scans and jobs (with highlights), flags, leads, help asked
    for, lessons."""
    return journal_mod.journal(box_record(ws))


def techniques() -> dict[str, methodology.Technique]:
    return load_methodology().techniques


def record_lesson(
    ws: Workspace,
    kind: Literal["user", "root", "note"],
    got_in: str,
    sooner: str,
    techniques_used: list[str],
) -> Lesson:
    """Save the answers to the flag questions (any can be empty)."""
    known = techniques()
    unknown = [t for t in techniques_used if t not in known]
    if unknown:
        raise OptionError(f"unknown technique(s) {unknown}: see cyberdeck skills for the list")
    with ws.store() as store:
        return store.add_lesson(kind, got_in.strip(), sooner.strip(), list(techniques_used))


def list_lessons(ws: Workspace) -> list[Lesson]:
    with ws.store() as store:
        return store.lessons()


def writeup(ws: Workspace, settings: Settings | None = None, *, reveal: bool = False) -> str:
    """The box's Markdown write-up. Loot and personal paths are masked unless ``reveal``."""
    settings = settings or load_settings()
    paths = journal_mod.personal_paths(ws.path, settings.root)
    return journal_mod.writeup(box_record(ws), reveal=reveal, paths=paths)


WRITEUP_NAME = "writeup.md"


class WriteupExistsError(FileExistsError):
    """The write-up file already exists and overwriting it wasn't asked for."""


def writeup_file(ws: Workspace) -> Path:
    """The box's write-up file: an existing ``writeup.md`` in any letter case (so a
    ``WRITEUP.md`` you or Claude wrote counts), else ``writeup.md`` in the box folder."""
    default = ws.path / WRITEUP_NAME
    if default.is_file():
        return default
    try:
        for candidate in sorted(ws.path.iterdir()):
            if candidate.is_file() and candidate.name.lower() == WRITEUP_NAME:
                return candidate
    except OSError:
        pass
    return default


def read_writeup(ws: Workspace) -> str:
    """The write-up file's text as written (no masking), or "" if there isn't one."""
    try:
        return writeup_file(ws).read_text(encoding="utf-8")
    except OSError:
        return ""


def save_writeup(ws: Workspace, text: str) -> Path:
    target = writeup_file(ws)
    target.write_text(text, encoding="utf-8")
    return target


def export_writeup(
    ws: Workspace,
    settings: Settings | None = None,
    *,
    path: Path | None = None,
    reveal: bool = False,
    overwrite: bool = False,
) -> Path:
    """Write a generated write-up to ``path`` (default: the box's write-up file, see
    ``writeup_file``). An existing file is only replaced with ``overwrite``, because it may
    hold a write-up edited by hand."""
    target = path or writeup_file(ws)
    if target.exists() and not overwrite:
        raise WriteupExistsError(f"{target.name} already exists")
    target.write_text(writeup(ws, settings, reveal=reveal), encoding="utf-8")
    return target


def playbook(settings: Settings | None = None, query: str = "") -> list[PlaybookEntry]:
    """Your lessons from every box in the workspace, newest first. Derived from the boxes
    themselves (no global store); ``query`` matches the text, techniques or box name."""
    settings = settings or load_settings()
    q = query.strip().lower()
    found: list[PlaybookEntry] = []
    for ws in list_targets(settings):
        for lesson in list_lessons(ws):
            haystack = " ".join(
                [ws.meta.name, lesson.got_in, lesson.sooner, *lesson.techniques]
            ).lower()
            if not q or q in haystack:
                found.append(PlaybookEntry(ws.meta.name, lesson))
    return sorted(found, key=lambda e: e.lesson.at, reverse=True)


def seen_before(
    ws: Workspace,
    settings: Settings | None = None,
    *,
    content: methodology.Content | None = None,
    state: methodology.LearnState | None = None,
    limit: int = 3,
) -> list[PlaybookEntry]:
    """Lessons from your other boxes whose techniques fit this box's situation ("You've seen
    this before: on Soccer you...")."""
    content = content or load_methodology()
    state = state or learn_state(ws, settings)
    relevant = {t.id for t in content.techniques.values() if t.when and state.holds(t.when)}
    picks = [
        entry
        for entry in playbook(settings)
        if entry.box != ws.meta.name and relevant & set(entry.lesson.techniques)
    ]
    return picks[:limit]


@dataclass(frozen=True)
class PathStepStatus:
    step: methodology.PathStep
    status: Literal["root", "user", "started", "todo"]


def learning_paths(
    settings: Settings | None = None,
) -> list[tuple[methodology.LearningPath, list[PathStepStatus]]]:
    """Each learning path with how far you got on each box (matched by box name)."""
    settings = settings or load_settings()
    boxes = {ws.meta.name.lower(): ws for ws in list_targets(settings)}
    result = []
    for learning_path in load_methodology().paths.values():
        steps: list[PathStepStatus] = []
        for step in learning_path.steps:
            ws = boxes.get(step.box.lower())
            if ws is None:
                status: Literal["root", "user", "started", "todo"] = "todo"
            elif ws.meta.flags.root:
                status = "root"
            elif ws.meta.flags.user:
                status = "user"
            else:
                status = "started"
            steps.append(PathStepStatus(step, status))
        result.append((learning_path, steps))
    return result


@dataclass(frozen=True)
class Skill:
    technique: methodology.Technique
    boxes: list[str]  # boxes where a lesson used it


def skills(settings: Settings | None = None) -> list[Skill]:
    """Every technique with the boxes your lessons tagged it on, most practised first."""
    entries = playbook(settings)
    result = []
    for tech in techniques().values():
        boxes = sorted({e.box for e in entries if tech.id in e.lesson.techniques})
        result.append(Skill(tech, boxes))
    return sorted(result, key=lambda s: (-len(s.boxes), s.technique.title))


def load_glossary() -> glossary_mod.Glossary:
    """Built-in terms (unless turned off in Settings) plus the user's glossary.yaml."""
    return glossary_mod.load_glossary()


# --- rules and suggestions (docs/RULES.md) --------------------------------------------------

_SEVERITY = {"safe": 0, "intrusive": 1, "bruteforce": 2, "exploit": 3}


def rule_set() -> RuleSet:
    """Built-in + user rules, with rules that name unknown tools, options or presets moved to
    ``errors`` (reported by ``cyberdeck suggest --errors``, never fatal)."""
    rules = load_rules()
    reg = registry()
    groups = reg.groups()
    for rule_id, rule in list(rules.rules.items()):
        if rule.suggest is None:
            continue
        ref = rule.suggest.ref
        members = (
            [reg.tools[ref]] if ref in reg.tools and not rule.suggest.group else groups.get(ref, [])
        )
        problem = None
        if not members:
            problem = f"unknown {'group' if rule.suggest.group else 'tool'} {ref!r}"
        else:
            for key in rule.suggest.with_:
                if any(key not in {o.id for o in t.options} for t in members):
                    problem = f"{ref} has no option or input {key!r}"
            preset = rule.suggest.preset
            if preset and not any(preset in t.presets for t in members):
                problem = f"{ref} has no preset {preset!r}"
        if problem:
            rules.errors.append((Path(rule.source or "?"), f"rule {rule_id}: {problem}"))
            del rules.rules[rule_id]
    return rules


def _safety(ref: str) -> str:
    """A tool's safety tag; for a group, the most severe member's (conservative)."""
    reg = registry()
    members = [reg.tools[ref]] if ref in reg.tools else reg.groups().get(ref, [])
    tags = [t.safety for t in members] or ["intrusive"]
    return max(tags, key=lambda tag: _SEVERITY.get(tag, 3))


def box_state(ws: Workspace, settings: Settings | None = None) -> BoxState:
    settings = settings or load_settings()
    with ws.store() as store:
        findings = store.findings()
        jobs = store.jobs()
    groups = {g: [t.id for t in members] for g, members in registry().groups().items()}
    return BoxState(
        ip=ws.meta.ip,
        name=ws.meta.name,
        slug=ws.meta.slug,
        findings=findings,
        jobs=jobs,
        hosts=hostsfile.read_hosts(settings.hosts_file),
        groups=groups,
    )


def _enabled(ref: str, cfg: UserConfig) -> bool:
    reg = registry()
    if ref in reg.tools:
        return ref not in cfg.disabled_tools
    return any(t.id not in cfg.disabled_tools for t in reg.groups().get(ref, []))


@dataclass(frozen=True)
class RefreshResult:
    opened: list[Suggestion]
    errors: list[str]


def refresh_suggestions(ws: Workspace, settings: Settings | None = None) -> RefreshResult:
    """Re-run the rules over the box and update its stored suggestions.

    New matches open; ones a finished job already covers are done; ones whose rule no longer
    matches go stale (hidden); snoozed ones re-open once a newer finding exists. Skipped and
    done suggestions stay as they are. Disabled tools are never suggested.
    """
    settings = settings or load_settings()
    rules = rule_set()
    evaluation = evaluate(rules.rules.values(), box_state(ws, settings))
    cfg = load_user_config()
    opened: list[Suggestion] = []
    with ws.store() as store:
        existing = {s.key: s for s in store.suggestions()}
        newest = store.max_finding_id()
        live: set[str] = set()
        for cand in evaluation.candidates:
            rule = cand.rule
            ref = rule.suggest.ref if rule.suggest else None
            if ref is not None and not _enabled(ref, cfg):
                continue
            live.add(cand.key)
            old = existing.get(cand.key)
            status = SuggestionStatus.DONE if cand.done_job else SuggestionStatus.OPEN
            job_id, mark = cand.done_job, None
            if old is not None:
                status, job_id, mark = old.status, old.job_id, old.snooze_mark
                reopen = old.status is SuggestionStatus.STALE or (
                    old.status is SuggestionStatus.SNOOZED and newest > (mark or 0)
                )
                if cand.done_job and status is not SuggestionStatus.DONE:
                    status, job_id = SuggestionStatus.DONE, cand.done_job
                elif reopen:
                    status = SuggestionStatus.OPEN
            sug = Suggestion(
                key=cand.key,
                rule_id=rule.id,
                kind=rule.kind,
                title=cand.title,
                why=rule.why.strip(),
                learn=rule.learn,
                phase=rule.phase,
                priority=rule.priority,
                safety=_safety(ref) if ref else "safe",
                tool=ref,
                values=cand.values,
                preset=rule.suggest.preset if rule.suggest else None,
                ask=cand.ask,
                finding=cand.finding,
                status=status,
                job_id=job_id,
                snooze_mark=mark,
            )
            if old is not None and _same(old, sug):
                continue
            saved = store.save_suggestion(sug)
            if status is SuggestionStatus.OPEN and (
                old is None or old.status is not SuggestionStatus.OPEN
            ):
                opened.append(saved)
        for key, old in existing.items():
            if key not in live and old.status in (SuggestionStatus.OPEN, SuggestionStatus.SNOOZED):
                store.save_suggestion(old.model_copy(update={"status": SuggestionStatus.STALE}))
    if opened:
        bus.emit(SuggestionsChanged(ws.path, opened))
    errors = [f"{path.name}: {msg}" for path, msg in rules.errors + kind_table().errors]
    errors += [f"rule {rule_id}: {msg}" for rule_id, msg in evaluation.errors]
    return RefreshResult(opened, errors)


def _same(a: Suggestion, b: Suggestion) -> bool:
    skip = {"id", "created_at", "updated_at"}
    return a.model_dump(exclude=skip) == b.model_dump(exclude=skip)


def list_suggestions(
    ws: Workspace, *, include_closed: bool = False, refresh: bool = True
) -> list[Suggestion]:
    """Open suggestions, highest priority first (``include_closed``: all but stale ones)."""
    if refresh:
        refresh_suggestions(ws)
    with ws.store() as store:
        items = store.suggestions()
    if include_closed:
        return [s for s in items if s.status is not SuggestionStatus.STALE]
    return [s for s in items if s.status is SuggestionStatus.OPEN]


def get_suggestion(ws: Workspace, suggestion_id: int) -> Suggestion:
    with ws.store() as store:
        sug = store.get_suggestion(suggestion_id)
    if sug is None:
        raise OptionError(f"no suggestion #{suggestion_id} for {ws.meta.name}")
    return sug


def set_suggestion_status(
    ws: Workspace, suggestion_id: int, status: SuggestionStatus, *, job_id: int | None = None
) -> Suggestion:
    """Skip, snooze (until a new finding arrives), reopen or complete a suggestion."""
    sug = get_suggestion(ws, suggestion_id)
    update: dict[str, Any] = {"status": status}
    with ws.store() as store:
        if status is SuggestionStatus.SNOOZED:
            update["snooze_mark"] = store.max_finding_id()
        if job_id is not None:
            update["job_id"] = job_id
        return store.save_suggestion(sug.model_copy(update=update))


def complete_suggestion(ws: Workspace, suggestion_id: int, job_id: int | None = None) -> None:
    set_suggestion_status(ws, suggestion_id, SuggestionStatus.DONE, job_id=job_id)


def plan_suggestion(
    ws: Workspace, suggestion_id: int, settings: Settings | None = None
) -> tuple[Suggestion, RunPlan]:
    """The Run-dialog plan for a tool suggestion: its group resolved to your preferred
    installed tool, its ``with:`` values and preset applied on top of the usual defaults."""
    sug = get_suggestion(ws, suggestion_id)
    if sug.kind != "tool" or not sug.tool:
        raise OptionError(f"suggestion #{suggestion_id} is a question, not a tool run")
    tool = resolve_tool(sug.tool)
    known = {o.id for o in tool.options}
    plan = plan_tool(
        ws,
        tool.id,
        preset=sug.preset if sug.preset in tool.presets else None,
        overrides={k: v for k, v in sug.values.items() if k in known},
        settings=settings,
    )
    return sug, plan


@dataclass(frozen=True)
class AnswerResult:
    suggestion: Suggestion
    created: list[Finding] = field(default_factory=list)
    message: str = ""


def answer_question(ws: Workspace, suggestion_id: int, answer: str | bool) -> AnswerResult:
    """Answer a question suggestion. ``False``/empty = no (skipped). ``finding.add`` questions
    turn the answer into a finding (e.g. the box's hostname). ``hosts.add`` questions are
    answered with :func:`hosts_plan_add` + :func:`hosts_apply` (they need the diff shown and
    sudo), then :func:`complete_suggestion`."""
    sug = get_suggestion(ws, suggestion_id)
    if sug.kind != "ask":
        raise OptionError(f"suggestion #{suggestion_id} is a tool run, not a question")
    if answer is False or answer == "":
        return AnswerResult(set_suggestion_status(ws, suggestion_id, SuggestionStatus.SKIPPED))
    action = sug.ask.get("action", "none")
    if action == "hosts.add":
        raise OptionError("hosts.add questions are answered via hosts_plan_add/hosts_apply")
    created: list[Finding] = []
    message = ""
    if action == "finding.add":
        spec = dict(sug.ask.get("finding") or {})
        text = str(answer).strip()
        user, sep, secret = text.partition(":")
        answer_ctx = {
            "answer": text,
            "answer.user": (user.strip() if sep else "") or "unknown",
            "answer.secret": secret if sep else text,
        }
        try:
            ftype = FindingType(spec.pop("type"))
            fields = {
                k: render_template(v, answer_ctx) if isinstance(v, str) else v
                for k, v in spec.items()
            }
            payload = PAYLOAD_TYPES[ftype].model_validate(fields)
        except (ValueError, OptionError) as exc:
            raise OptionError(f"can't use that answer: {exc}") from None
        finding = Finding.of(payload, source=f"answer:{sug.rule_id}", confidence=0.6)
        with ws.store() as store:
            result = store.upsert(finding)
        if result.created:
            created.append(result.finding)
        _findings_changed(ws, created, [] if result.created else [result.finding], "answer")
        message = f"recorded {ftype.value} {finding.key}"
    done = set_suggestion_status(ws, suggestion_id, SuggestionStatus.DONE)
    refresh_suggestions(ws)
    return AnswerResult(done, created, message)


def auto_runnable(ws: Workspace, suggestions: list[Suggestion]) -> list[Suggestion]:
    """The suggestions auto mode may chain: tool runs tagged ``safe`` whose tool is installed,
    enabled and doesn't need root. Everything else waits for the user."""
    picked: list[Suggestion] = []
    for sug in suggestions:
        if sug.kind != "tool" or sug.safety != "safe" or not sug.tool:
            continue
        try:
            tool = resolve_tool(sug.tool)
        except OptionError:
            continue
        if tool.safety != "safe" or tool.requires_root or not detect(tool).installed:
            continue
        picked.append(sug)
    return picked


# --- /etc/hosts (CLAUDE.md rule 7) -----------------------------------------------------------


class HostsError(Exception):
    pass


def box_hostnames(ws: Workspace) -> list[str]:
    """The box's names for its hosts line: hosts (short first), then domains."""
    with ws.store() as store:
        names = [f.as_(Hostname) for f in store.findings(FindingType.HOSTNAME)]
    hosts = sorted((h.fqdn for h in names if h.kind == "host"), key=lambda n: (n.count("."), n))
    domains = [h.fqdn for h in names if h.kind == "domain" and h.fqdn not in hosts]
    return hosts + domains


def record_hostnames(ws: Workspace, names: list[str], source: str = "user") -> list[Finding]:
    """Record names you typed (``cyberdeck hosts add box.htb``) as Hostname findings."""
    created: list[Finding] = []
    with ws.store() as store:
        for name in names:
            try:
                payload = Hostname(fqdn=name, ip=ws.meta.ip, origins=[source])
            except ValueError as exc:
                raise OptionError(f"{name!r} is not a usable hostname") from exc
            result = store.upsert(Finding.of(payload, source=source))
            if result.created:
                created.append(result.finding)
    _findings_changed(ws, created, [], source)
    return created


def hosts_status(ws: Workspace, settings: Settings | None = None) -> tuple[list[str], list[str]]:
    """(this box's Cyberdeck lines, box names the hosts file doesn't map to the box IP)."""
    settings = settings or load_settings()
    text = hostsfile.read_text(settings.hosts_file)
    mapped = hostsfile.parse_hosts(text)
    missing = [n for n in box_hostnames(ws) if ws.meta.ip not in mapped.get(n, [])]
    return hostsfile.tagged_lines(text, ws.meta.slug), missing


def hosts_plan_add(
    ws: Workspace, names: list[str] | None = None, settings: Settings | None = None
) -> HostsChange:
    """The change that maps ``names`` (default: all the box's names) to the box IP on its
    tagged line. Nothing is written; show ``change.diff()`` and call :func:`hosts_apply`."""
    settings = settings or load_settings()
    wanted = names if names is not None else box_hostnames(ws)
    return hostsfile.plan_add(settings.hosts_file, ws.meta.ip, wanted, ws.meta.slug)


def hosts_plan_remove(ws: Workspace | None, settings: Settings | None = None) -> HostsChange:
    """The change that removes this box's lines (``None``: every Cyberdeck line)."""
    settings = settings or load_settings()
    return hostsfile.plan_remove(settings.hosts_file, ws.meta.slug if ws else None)


def hosts_needs_sudo(settings: Settings | None = None) -> bool:
    return needs_privilege((settings or load_settings()).hosts_file)


def hosts_apply(
    change: HostsChange, ws: Workspace | None = None, settings: Settings | None = None
) -> Path | None:
    """Write a planned change the user has confirmed. Refuses if the file changed since the
    plan; backs the old file up into the box's ``raw/`` first. Returns the backup path. The
    caller must have run ``sudo_validate()`` when :func:`hosts_needs_sudo` is true."""
    if not change.changed:
        return None
    if hostsfile.read_text(change.path) != change.before:
        raise HostsError(f"{change.path} changed since the diff was shown; try again")
    backup: Path | None = None
    if ws is not None:
        ws.raw_dir.mkdir(exist_ok=True)
        backup = ws.raw_dir / f"hosts-{utcnow():%Y%m%d-%H%M%S}.bak"
        backup.write_text(change.before, encoding="utf-8")
    ok, message = write_file_privileged(change.path, change.after)
    if not ok:
        raise HostsError(f"could not write {change.path}: {message}")
    if ws is not None:
        refresh_suggestions(ws, settings)
    return backup


# --- findings, loot, notes (TUI / MCP read side) --------------------------------------------


def list_findings(ws: Workspace, type_: FindingType | None = None) -> list[Finding]:
    with ws.store() as store:
        return store.findings(type_)


def _update_finding(ws: Workspace, type_: FindingType, key: str, data: dict[str, Any]) -> Finding:
    """Merge user-supplied fields into an existing finding (history keeps the old data)."""
    with ws.store() as store:
        old = store.get(type_, key)
        if old is None:
            raise OptionError(f"no {type_.value} finding {key!r}")
        update = Finding(
            type=type_, key=key, data={**old.data, **data}, confidence=1.0, sources=["user"]
        )
        result = store.upsert(update)
    _findings_changed(ws, [], [result.finding], "user")
    refresh_suggestions(ws)
    return result.finding


def edit_finding(
    ws: Workspace, type_: FindingType, key: str, changes: dict[str, Any], *, source: str = "user"
) -> Finding:
    """Correct a finding by hand: ``changes`` overwrite its fields (None clears one), fields not
    named are kept. Validated like any finding; the old data stays in its history."""
    with ws.store() as store:
        old = store.get(type_, key)
        if old is None:
            raise OptionError(f"no {type_.value} finding {key!r}")
        try:
            payload = PAYLOAD_TYPES[type_].model_validate({**old.data, **changes})
        except ValueError as exc:
            raise OptionError(f"invalid {type_.value} finding: {exc}") from None
        new = Finding.of(payload, source=source, confidence=1.0, tags=old.tags)
        try:
            stored = store.replace(type_, key, new)
        except ValueError as exc:
            raise OptionError(str(exc)) from None
    _findings_changed(ws, [], [stored], source)
    refresh_suggestions(ws)
    return stored


def delete_finding(ws: Workspace, type_: FindingType, key: str) -> Finding:
    """Remove a finding (a wrong entry, a junk hint). Suggestions that came from it go stale.
    A tool that finds it again (or a re-parse) adds it back."""
    with ws.store() as store:
        old = store.delete(type_, key)
    if old is None:
        raise OptionError(f"no {type_.value} finding {key!r}")
    refresh_suggestions(ws)
    return old


def mark_credential_verified(ws: Workspace, key: str, where: str) -> Finding:
    """Record that a credential works on ``where`` (e.g. ``ssh``, ``smb``, ``web login``)."""
    with ws.store() as store:
        old = store.get(FindingType.CREDENTIAL, key)
    if old is None:
        raise OptionError(f"no credential {key!r}")
    verified = list(old.data.get("verified_on") or [])
    if where not in verified:
        verified.append(where)
    return _update_finding(ws, FindingType.CREDENTIAL, key, {"verified_on": verified})


def set_hash_cracked(ws: Workspace, key: str, plaintext: str) -> Finding:
    """Record the cracked value of a hash."""
    if not plaintext:
        raise OptionError("the cracked value is empty")
    return _update_finding(ws, FindingType.HASH, key, {"cracked": plaintext})


def read_notes(ws: Workspace) -> str:
    try:
        return ws.notes_file.read_text(encoding="utf-8")
    except OSError:
        return ""


def save_notes(ws: Workspace, text: str) -> Path:
    ws.notes_file.write_text(text, encoding="utf-8")
    return ws.notes_file


def box_change_marker(ws: Workspace) -> tuple[float, ...]:
    """Changes whenever the box DB or target.yaml is written, by this or another process
    (a CLI in another terminal, later the MCP server); the TUI polls it to refresh."""
    paths = (ws.db_file, ws.db_file.with_name(ws.db_file.name + "-wal"), ws.meta_file)
    marks: list[float] = []
    for path in paths:
        try:
            marks.append(path.stat().st_mtime)
        except OSError:
            marks.append(0.0)
    return tuple(marks)


# --- MCP: approvals, previews, masking (ADR 0007, docs/MCP.md) ------------------------------

SECRET_FIELDS: dict[FindingType, tuple[str, ...]] = {
    FindingType.CREDENTIAL: ("secret",),
    FindingType.HASH: ("value", "cracked"),
    FindingType.FLAG: ("value",),
}


def mask_finding(finding: Finding, *, reveal: bool = False) -> dict[str, Any]:
    """A finding as plain data, with loot (passwords, hashes, flags) masked unless ``reveal``."""
    data = dict(finding.data)
    if not reveal and summarize_mod.POSSIBLE_CREDENTIAL in finding.tags:
        data["text"] = f"<hidden: {len(str(data.get('text') or ''))} chars>"
    if not reveal:
        for name in SECRET_FIELDS.get(finding.type, ()):
            value = data.get(name)
            if value:
                data[name] = f"<hidden: {len(str(value))} chars>"
    return {
        "type": finding.type.value,
        "key": finding.key if reveal or finding.type not in SECRET_FIELDS else _masked_key(finding),
        "data": data,
        "confidence": finding.confidence,
        "sources": finding.sources,
        "tags": finding.tags,
    }


def _masked_key(finding: Finding) -> str:
    if finding.type is FindingType.HASH:
        return f"hash#{finding.id}"
    return finding.key  # credential keys hold only a digest of the secret; flags: user/root


def needs_approval(plan: RunPlan, mode: str | None = None) -> str | None:
    """Why an MCP-requested job must wait for a human (None: it may run now)."""
    mode = mode or load_user_config().mcp.approval
    if plan.tool.safety != "safe":
        return f"{plan.tool.name} is tagged {plan.tool.safety}"
    if plan.sudo or (plan.tool.requires_root and not is_root()):
        return "it needs root (sudo), and only a human can type the sudo password"
    if mode == "all":
        return "mcp.approval is 'all' in config.yaml"
    return None


def request_job_approval(
    ws: Workspace,
    plan: RunPlan,
    *,
    reason: str = "",
    requested_by: str = "mcp",
    suggestion_id: int | None = None,
) -> Approval:
    """Queue a job with its exact argv for a human to approve (TUI Approvals or
    ``cyberdeck approvals``). The argv can't change after this."""
    approval = Approval(
        kind="job",
        title=f"Run {plan.tool.name}",
        safety=plan.tool.safety,
        requested_by=requested_by,
        reason=reason,
        payload={
            "tool": plan.tool.id,
            "argv": plan.argv(),
            "command": plan.command_line(),
            "values": plan.values,
            "ctx": plan.ctx,
            "extra": plan.extra,
            "preset": plan.preset,
            "sudo": plan.sudo,
            "warnings": plan.warnings,
            "suggestion_id": suggestion_id,
            "why_approval": needs_approval(plan) or "requested",
        },
    )
    with ws.store() as store:
        return store.save_approval(approval)


def request_hosts_approval(
    ws: Workspace,
    names: list[str] | None = None,
    *,
    reason: str = "",
    requested_by: str = "mcp",
    settings: Settings | None = None,
    suggestion_id: int | None = None,
) -> Approval:
    """Queue an /etc/hosts edit (always needs a human: it is shown as a diff and needs sudo)."""
    change = hosts_plan_add(ws, names, settings)
    if not change.changed:
        raise OptionError(f"{change.path} already maps those names to {ws.meta.ip}")
    wanted = names if names is not None else box_hostnames(ws)
    approval = Approval(
        kind="hosts",
        title=f"Add {', '.join(wanted)} to {change.path}",
        safety="hosts",
        requested_by=requested_by,
        reason=reason,
        payload={
            "names": wanted,
            "path": str(change.path),
            "diff": change.diff(),
            "suggestion_id": suggestion_id,
        },
    )
    with ws.store() as store:
        return store.save_approval(approval)


def list_approvals(ws: Workspace, *, pending_only: bool = True) -> list[Approval]:
    with ws.store() as store:
        return store.approvals(ApprovalState.PENDING if pending_only else None)


def pending_approvals_everywhere(settings: Settings) -> list[tuple[Workspace, Approval]]:
    """Pending requests across all boxes under the workspace root."""
    found: list[tuple[Workspace, Approval]] = []
    for ws in list_targets(settings):
        found += [(ws, a) for a in list_approvals(ws)]
    return found


def get_approval(ws: Workspace, approval_id: int) -> Approval:
    with ws.store() as store:
        approval = store.get_approval(approval_id)
    if approval is None:
        raise OptionError(f"no approval request #{approval_id} for {ws.meta.name}")
    return approval


def _decide(
    ws: Workspace,
    approval: Approval,
    state: ApprovalState,
    *,
    job_id: int | None = None,
    note: str | None = None,
) -> Approval:
    update: dict[str, Any] = {"state": state, "decided_at": utcnow()}
    if job_id is not None:
        update["job_id"] = job_id
    if note is not None:
        update["note"] = note
    with ws.store() as store:
        return store.save_approval(approval.model_copy(update=update))


def _pending(ws: Workspace, approval_id: int, kind: str) -> Approval:
    approval = get_approval(ws, approval_id)
    if approval.state is not ApprovalState.PENDING:
        raise OptionError(f"request #{approval_id} is already {approval.state.value}")
    if approval.kind != kind:
        raise OptionError(f"request #{approval_id} is a {approval.kind} request")
    return approval


def deny_approval(ws: Workspace, approval_id: int, note: str | None = None) -> Approval:
    approval = get_approval(ws, approval_id)
    if approval.state is not ApprovalState.PENDING:
        raise OptionError(f"request #{approval_id} is already {approval.state.value}")
    return _decide(ws, approval, ApprovalState.DENIED, note=note or "denied")


def approval_plan(ws: Workspace, approval_id: int) -> RunPlan:
    """The exact plan a job request was made with (``raw_argv`` = the requested argv)."""
    approval = _pending(ws, approval_id, "job")
    data = approval.payload
    tool = get_tool(str(data["tool"]))
    return RunPlan(
        tool,
        dict(data.get("values") or {}),
        dict(data.get("ctx") or {}),
        extra=list(data.get("extra") or []),
        preset=data.get("preset"),
        sudo=bool(data.get("sudo")),
        raw_argv=list(data["argv"]),
        warnings=list(data.get("warnings") or []),
    )


async def run_approved_job(
    ws: Workspace,
    settings: Settings,
    approval_id: int,
    *,
    on_line: LineCallback | None = None,
) -> RunOutcome:
    """Carry out an approved job request: exactly the requested argv, ``origin=mcp``. The
    caller has shown the command to the human and got sudo if ``plan.sudo``."""
    approval = _pending(ws, approval_id, "job")
    plan = approval_plan(ws, approval_id)
    suggestion_id = approval.payload.get("suggestion_id")
    try:
        outcome = await execute_plan(
            ws,
            settings,
            plan,
            on_line=on_line,
            origin=approval.requested_by,
            suggestion_id=int(suggestion_id) if suggestion_id else None,
        )
    except Exception as exc:
        _decide(ws, approval, ApprovalState.FAILED, note=str(exc))
        raise
    _decide(ws, approval, ApprovalState.APPROVED, job_id=outcome.result.job.id)
    return outcome


def approval_hosts_change(
    ws: Workspace, approval_id: int, settings: Settings | None = None
) -> HostsChange:
    """The hosts change for a request, planned against the file as it is *now* (show this
    diff to the human, then :func:`approve_hosts`)."""
    approval = _pending(ws, approval_id, "hosts")
    return hosts_plan_add(ws, list(approval.payload.get("names") or []), settings)


def approve_hosts(
    ws: Workspace, approval_id: int, change: HostsChange, settings: Settings | None = None
) -> Path | None:
    """Write an approved hosts change (the caller showed ``change.diff()`` and got sudo)."""
    approval = _pending(ws, approval_id, "hosts")
    try:
        backup = hosts_apply(change, ws, settings)
    except HostsError as exc:
        _decide(ws, approval, ApprovalState.FAILED, note=str(exc))
        raise
    _decide(ws, approval, ApprovalState.APPROVED)
    suggestion_id = approval.payload.get("suggestion_id")
    if suggestion_id:
        complete_suggestion(ws, int(suggestion_id))
    return backup


def add_finding(
    ws: Workspace, type_: FindingType, data: dict[str, Any], *, source: str, confidence: float
) -> Finding:
    """Record a finding from outside a tool (MCP client, user). Validated like any other."""
    try:
        payload = PAYLOAD_TYPES[type_].model_validate(data)
    except ValueError as exc:
        raise OptionError(f"invalid {type_.value} finding: {exc}") from None
    with ws.store() as store:
        result = store.upsert(Finding.of(payload, source=source, confidence=confidence))
    created = [result.finding] if result.created else []
    _findings_changed(ws, created, [] if result.created else [result.finding], source)
    refresh_suggestions(ws)
    return result.finding


def append_note(ws: Workspace, text: str, *, author: str) -> Path:
    """Append a dated entry to the box's notes.md (what the TUI Notes screen edits)."""
    stamp = utcnow().astimezone().strftime("%Y-%m-%d %H:%M")
    with ws.notes_file.open("a", encoding="utf-8") as notes:
        notes.write(f"\n### {stamp} ({author})\n{text.strip()}\n")
    return ws.notes_file


def job_findings(ws: Workspace, job_id: int) -> list[Finding]:
    marker = f"job:{job_id}:"
    return [f for f in list_findings(ws) if any(s.startswith(marker) for s in f.sources)]
