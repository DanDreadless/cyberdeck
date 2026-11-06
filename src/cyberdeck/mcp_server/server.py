"""``cyberdeck mcp``: an MCP server over ``core/services.py`` (ADR 0007, docs/MCP.md).

Same guardrails as the TUI and CLI:
- Every job is ``preview_command`` (argv fixed, shown to the client) then ``run_tool(preview_id)``.
- Only ``safe`` tools that need no root run straight away (unless ``mcp.approval: all``);
  everything else, and every /etc/hosts edit, goes to the approvals queue for a human.
- The scope guard applies to every job; loot is masked unless revealed on purpose.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from cyberdeck import __version__
from cyberdeck.core import glossary, services
from cyberdeck.core.config import Settings, load_settings
from cyberdeck.core.models import FindingType, Job, SuggestionStatus
from cyberdeck.core.options import OptionError, RunPlan
from cyberdeck.core.runner import is_root
from cyberdeck.core.scope import ScopeError
from cyberdeck.core.tools import SCAN_STAGES
from cyberdeck.core.userconfig import load_user_config
from cyberdeck.core.workspace import Workspace, WorkspaceError

PREVIEW_TTL = 30 * 60  # seconds a preview stays runnable
START_TIMEOUT = 20.0  # seconds to wait for a launched job to get its id

INSTRUCTIONS = """\
Cyberdeck is a CTF companion tool for Hack The Box machines. It tracks the user's progress on
a box, keeps everything known about it (services, hostnames, URLs, software, loot, flags),
suggests next steps with the reason for each, and wraps the Kali tools. It is not an autopilot:
the user works the box (browser, shells, exploits, privesc) and decides what to run. Suggestions
are options to discuss, not a queue to work through on your own.

How to work with it:
1. target_progress / target_summary / list_suggestions to see where the box is up to.
2. To run anything: preview_command (or preview_suggestion / start_scan) returns the exact
   command and a preview_id. Show the command to the user, then run_tool(preview_id).
3. Safe tools run at once and return a job_id: poll job_status / job_output.
   Intrusive, bruteforce or exploit tools, anything needing root, and /etc/hosts edits are
   queued for the human to approve in Cyberdeck (TUI Approvals or `cyberdeck approvals`).
   There is no way around that; tell the user what is waiting.
4. Only the box's scope (HTB ranges + the user's) can be targeted.
5. Record what the user finds outside Cyberdeck (creds from a config file, a user from a
   shell, a flag) with add_finding / add_note / record_flag so the suggestions use it.
Passwords, hashes and flags are masked unless the user enabled mcp.reveal_secrets.
"""


@dataclass
class Preview:
    box: Path
    plan: RunPlan
    created: float
    suggestion_id: int | None = None


@dataclass
class State:
    settings: Settings
    pinned: Workspace | None = None
    previews: dict[str, Preview] = field(default_factory=dict)
    tasks: set[asyncio.Task[Any]] = field(default_factory=set)

    def ws(self, target: str | None) -> Workspace:
        if self.pinned is not None:
            if (
                target
                and target not in (self.pinned.meta.name, self.pinned.meta.slug)
                and Path(target).expanduser() != self.pinned.path
            ):
                raise ToolError(
                    f"this server is pinned to {self.pinned.meta.name}; it can't use {target!r}"
                )
            return services.open_target(self.settings, str(self.pinned.path))
        try:
            return services.open_target(self.settings, target)
        except WorkspaceError as exc:
            raise ToolError(f"{exc} (list_targets shows the boxes)") from None

    def remember(self, ws: Workspace, plan: RunPlan, suggestion_id: int | None = None) -> str:
        now = time.monotonic()
        for key in [k for k, p in self.previews.items() if now - p.created > PREVIEW_TTL]:
            del self.previews[key]
        preview_id = secrets.token_hex(6)
        self.previews[preview_id] = Preview(ws.path, plan, now, suggestion_id)
        return preview_id


def _err(exc: Exception) -> ToolError:
    return ToolError(str(exc))


def _preview_result(
    state: State, ws: Workspace, plan: RunPlan, sid: int | None = None
) -> dict[str, Any]:
    problems = plan.problems(is_root())
    result: dict[str, Any] = {
        "box": ws.meta.name,
        "tool": plan.tool.id,
        "name": plan.tool.name,
        "safety": plan.tool.safety,
        "warnings": plan.warnings,
        "problems": problems,
        "options": {k: v for k, v in plan.values.items() if v is not None},
        "presets": list(plan.tool.presets),
    }
    if problems:
        result["preview_id"] = None
        result["next"] = "Fix the problems (set inputs/options) and preview again."
        return result
    result["command"] = plan.command_line()
    result["argv"] = plan.argv()
    result["preview_id"] = state.remember(ws, plan, sid)
    reason = services.needs_approval(plan)
    result["needs_approval"] = reason
    result["next"] = (
        f"run_tool(preview_id) will queue it for the human to approve ({reason})."
        if reason
        else "Show the command to the user, then run_tool(preview_id)."
    )
    return result


def _job_dict(job: Job) -> dict[str, Any]:
    return {
        "job_id": job.id,
        "tool": job.tool,
        "status": job.status.value,
        "exit_code": job.exit_code,
        "origin": job.origin,
        "started": job.started_at.isoformat() if job.started_at else None,
        "ended": job.ended_at.isoformat() if job.ended_at else None,
        "duration_s": round(job.duration, 1) if job.duration is not None else None,
        "note": job.note,
        "command": " ".join(job.argv),
    }


def build_server(settings: Settings | None = None, target: str | None = None) -> MCPServer:
    """The MCP server. ``target`` pins the session to one box (recommended)."""
    settings = settings or load_settings()
    pinned = services.open_target(settings, target) if target else None
    state = State(settings, pinned)
    mcp = MCPServer("cyberdeck", instructions=INSTRUCTIONS, version=__version__)

    # -- boxes ---------------------------------------------------------------------------
    @mcp.tool()
    def list_targets() -> list[dict[str, Any]]:
        """Boxes Cyberdeck knows (most recently opened first) with their progress."""
        boxes = [state.pinned] if state.pinned else services.list_targets(settings)
        out = []
        for ws in boxes:
            progress = services.target_progress(ws)
            out.append(
                {
                    "name": ws.meta.name,
                    "ip": ws.meta.ip,
                    "path": str(ws.path),
                    "done": [s.label for s in progress.steps if s.done],
                    "next": progress.next_hint,
                }
            )
        return out

    @mcp.tool()
    def create_target(name: str, ip: str) -> dict[str, Any]:
        """Create a box workspace (scope-checked: HTB ranges + the user's). Doesn't scan."""
        if state.pinned is not None:
            raise ToolError("this server is pinned to one box; start it without --target")
        try:
            ws = services.create_target(settings, name, ip)
        except (ScopeError, WorkspaceError) as exc:
            raise _err(exc) from None
        return {"name": ws.meta.name, "ip": ws.meta.ip, "path": str(ws.path)}

    @mcp.tool()
    def target_summary(target: str | None = None) -> dict[str, Any]:
        """Services (with their kind: web, winrm, smb...), hostnames, software and OS of a box.
        ``target``: box name; default the pinned/current box."""
        from cyberdeck.core.classify import service_kind

        ws = state.ws(target)
        s = services.target_summary(ws)
        return {
            "name": s.meta.name,
            "ip": s.meta.ip,
            "os": s.best_os,
            "services": [
                {
                    "port": svc.port,
                    "proto": svc.proto,
                    "kind": service_kind(svc),
                    "nmap_name": svc.name,
                    "version": svc.banner,
                    "scripts": sorted(svc.scripts),
                }
                for svc in s.services
            ],
            "hostnames": [{"fqdn": h.fqdn, "kind": h.kind} for h in s.hostnames],
            "software": [
                {"name": sw.name, "version": sw.version, "where": sw.where} for sw in s.software
            ],
            "counts": {t.value: n for t, n in s.counts.items()},
            "flags": {"user": bool(s.meta.flags.user), "root": bool(s.meta.flags.root)},
        }

    @mcp.tool()
    def target_progress(target: str | None = None) -> dict[str, Any]:
        """What's done on a box, what was interrupted, and the next step."""
        ws = state.ws(target)
        p = services.target_progress(ws)
        return {
            "steps": [{"step": s.label, "done": s.done, "detail": s.detail} for s in p.steps],
            "interrupted_jobs": [j.id for j in p.interrupted],
            "next": p.next_hint,
            "pending_approvals": len(services.list_approvals(ws)),
        }

    @mcp.tool()
    def get_checklist(target: str | None = None, include_done: bool = False) -> dict[str, Any]:
        """The box's methodology checklist (manual checks and tool runs, per service and phase):
        state is open, done (ticked by the user), auto (ticked by a finished job) or na."""
        ws = state.ws(target)
        entries = services.checklist(ws, settings)
        return {
            "coverage": {
                k: {"done": d, "total": t} for k, (d, t) in services.coverage(entries).items()
            },
            "items": [
                {
                    "id": e.item.id,
                    "section": e.item.section,
                    "phase": e.item.phase,
                    "title": e.item.title,
                    "why": glossary.plain(e.item.why),
                    "how": e.item.how,
                    "tool": e.item.tool,
                    "state": e.state,
                }
                for e in entries
                if include_done or e.state == "open"
            ],
        }

    @mcp.tool()
    def get_journal(target: str | None = None) -> list[dict[str, Any]]:
        """The box's story, oldest first: scans and jobs with their highlights, flags (when, not
        the value), leads, help asked for, and the user's lessons."""
        ws = state.ws(target)
        return [
            {
                "at": e.at.isoformat(),
                "kind": e.kind,
                "text": glossary.plain(e.text),
                "details": [glossary.plain(d) for d in e.details],
            }
            for e in services.journal(ws)
        ]

    @mcp.tool()
    def get_playbook(query: str = "") -> list[dict[str, Any]]:
        """The user's lessons from every box (what got them in, what to check sooner,
        techniques), newest first; ``query`` filters them. Useful to remind them of their own
        past experience instead of giving answers."""
        return [
            {
                "box": e.box,
                "kind": e.lesson.kind,
                "at": e.lesson.at.isoformat(),
                "got_in": e.lesson.got_in,
                "sooner": e.lesson.sooner,
                "techniques": e.lesson.techniques,
            }
            for e in services.playbook(settings, query)
        ]

    @mcp.tool()
    def stuck_report(level: int = 1, target: str | None = None) -> dict[str, Any]:
        """What hasn't been tried yet (level 1), plus general hints for the box's situation
        (level 2; never box-specific spoilers). Logged in the box like the TUI's Stuck?."""
        ws = state.ws(target)
        report = services.stuck_report(ws, 2 if level >= 2 else 1, settings)
        return {
            "untried_checks": [
                {"id": e.item.id, "title": e.item.title, "how": e.item.how} for e in report.untried
            ],
            "open_suggestions": [{"id": s.id, "title": s.title} for s in report.suggestions],
            "set_aside": [
                {"id": s.id, "title": s.title, "status": s.status.value} for s in report.set_aside
            ],
            "parked_leads": [lead.title for lead in report.parked],
            "hints": [{"title": p.title, "hint": glossary.plain(p.hint)} for p in report.hints],
        }

    @mcp.tool()
    def vpn_status(target: str | None = None) -> dict[str, Any]:
        """Whether the box is routed through the HTB VPN tunnel, and the tunnel IP (LHOST)."""
        ws = state.ws(target)
        v = services.vpn_check(settings, ws.meta.ip)
        return {
            "routed_via_tunnel": v.routed_via_tunnel,
            "route_dev": v.route_dev,
            "lhost": v.lhost,
            "tunnels": [{"name": t.name, "ip": t.ip} for t in v.tunnels],
        }

    @mcp.tool()
    def set_ip(ip: str, target: str | None = None) -> dict[str, str]:
        """Change a box's IP after HTB re-spawns it (scope-checked; findings are kept)."""
        ws = state.ws(target)
        try:
            old = services.set_ip(settings, ws, ip)
        except ScopeError as exc:
            raise _err(exc) from None
        return {
            "old": old,
            "new": ws.meta.ip,
            "note": "Its /etc/hosts line, if any, needs the human (cyberdeck set-ip or hosts add).",
        }

    @mcp.tool()
    def record_flag(kind: str, value: str, target: str | None = None) -> dict[str, Any]:
        """Record a captured flag (kind: user or root)."""
        if kind not in ("user", "root"):
            raise ToolError("kind must be 'user' or 'root'")
        ws = state.ws(target)
        ok = services.record_flag(ws, "user" if kind == "user" else "root", value)
        return {"saved": True, "looks_like_htb_flag": ok}

    # -- findings and notes --------------------------------------------------------------
    @mcp.tool()
    def list_findings(
        type: str | None = None,
        query: str | None = None,
        reveal: bool = False,
        limit: int = 200,
        target: str | None = None,
    ) -> dict[str, Any]:
        """Findings for a box. ``type``: service, hostname, url, software, user, credential,
        hash, vuln, share, os, note, flag. ``query``: text filter. Passwords, hashes and flags
        are masked unless ``reveal`` is true AND the user set mcp.reveal_secrets."""
        ws = state.ws(target)
        try:
            ftype = FindingType(type) if type else None
        except ValueError:
            raise ToolError(f"unknown type {type!r}") from None
        allowed = reveal and load_user_config().mcp.reveal_secrets
        items = [
            services.mask_finding(f, reveal=allowed) for f in services.list_findings(ws, ftype)
        ]
        if query:
            needle = query.lower()
            items = [i for i in items if needle in json.dumps(i).lower()]
        result: dict[str, Any] = {"count": len(items), "findings": items[: max(1, limit)]}
        if reveal and not allowed:
            result["note"] = "Secrets stay masked: the user hasn't enabled mcp.reveal_secrets."
        return result

    @mcp.tool()
    def add_finding(type: str, data: dict[str, Any], target: str | None = None) -> dict[str, Any]:
        """Record something you worked out (e.g. type=hostname, data={"fqdn": "dev.box.htb"}).
        Stored with source "mcp"; validated like tool findings."""
        ws = state.ws(target)
        try:
            finding = services.add_finding(
                ws, FindingType(type), data, source="mcp", confidence=0.7
            )
        except (ValueError, OptionError) as exc:
            raise _err(exc) from None
        return services.mask_finding(finding)

    @mcp.tool()
    def add_note(text: str, target: str | None = None) -> dict[str, str]:
        """Append a dated entry to the box's notes.md (markdown)."""
        ws = state.ws(target)
        path = services.append_note(ws, text, author="mcp")
        return {"notes": str(path)}

    # -- suggestions -----------------------------------------------------------------------
    @mcp.tool()
    def list_suggestions(
        include_closed: bool = False, target: str | None = None
    ) -> list[dict[str, Any]]:
        """Next steps for the box, highest priority first, each with why. kind=tool: use
        preview_suggestion(id). kind=ask: a question, answer_question(id, answer)."""
        ws = state.ws(target)
        return [
            {
                "id": s.id,
                "kind": s.kind,
                "title": s.title,
                "why": glossary.plain(s.why),
                "learn": s.learn,
                "tool": s.tool,
                "inputs": s.values,
                "safety": s.safety,
                "status": s.status.value,
                "question": s.ask.get("prompt") if s.kind == "ask" else None,
                "default_answer": s.ask.get("default") if s.kind == "ask" else None,
            }
            for s in services.list_suggestions(ws, include_closed=include_closed)
        ]

    def _set_status(
        suggestion_id: int, status: SuggestionStatus, target: str | None
    ) -> dict[str, Any]:
        ws = state.ws(target)
        try:
            sug = services.set_suggestion_status(ws, suggestion_id, status)
        except OptionError as exc:
            raise _err(exc) from None
        return {"id": sug.id, "status": sug.status.value, "title": sug.title}

    @mcp.tool()
    def skip_suggestion(suggestion_id: int, target: str | None = None) -> dict[str, Any]:
        """Dismiss a suggestion (the human can reopen it)."""
        return _set_status(suggestion_id, SuggestionStatus.SKIPPED, target)

    @mcp.tool()
    def snooze_suggestion(suggestion_id: int, target: str | None = None) -> dict[str, Any]:
        """Hide a suggestion until something new is found on the box."""
        return _set_status(suggestion_id, SuggestionStatus.SNOOZED, target)

    @mcp.tool()
    def preview_suggestion(suggestion_id: int, target: str | None = None) -> dict[str, Any]:
        """The exact command for a tool suggestion (its group resolved to the user's preferred
        installed tool). Then run_tool(preview_id)."""
        ws = state.ws(target)
        try:
            _, plan = services.plan_suggestion(ws, suggestion_id, settings)
        except OptionError as exc:
            raise _err(exc) from None
        return _preview_result(state, ws, plan, suggestion_id)

    @mcp.tool()
    def answer_question(
        suggestion_id: int, answer: str, reason: str = "", target: str | None = None
    ) -> dict[str, Any]:
        """Answer a question suggestion: "yes"/"no", or the text it asks for (e.g. a hostname).
        A question about /etc/hosts becomes a request the human approves (it needs sudo)."""
        ws = state.ws(target)
        try:
            sug = services.get_suggestion(ws, suggestion_id)
            if sug.kind != "ask":
                raise OptionError(
                    f"suggestion #{suggestion_id} is a tool run: use preview_suggestion"
                )
            if sug.ask.get("action") == "hosts.add":
                if answer.strip().lower() in ("no", "n", "false", ""):
                    services.answer_question(ws, suggestion_id, False)
                    return {"status": "skipped"}
                approval = services.request_hosts_approval(
                    ws, None, reason=reason, settings=settings, suggestion_id=suggestion_id
                )
                return {
                    "status": "awaiting_approval",
                    "approval_id": approval.id,
                    "diff": approval.payload["diff"],
                    "message": "The human must approve this hosts edit in Cyberdeck.",
                }
            value: str | bool = answer
            if not sug.ask.get("input"):
                value = answer.strip().lower() in ("yes", "y", "true", "ok")
            result = services.answer_question(ws, suggestion_id, value)
        except OptionError as exc:
            raise _err(exc) from None
        return {"status": result.suggestion.status.value, "message": result.message}

    # -- tools and jobs --------------------------------------------------------------------
    @mcp.tool()
    def list_tools() -> list[dict[str, Any]]:
        """Tools Cyberdeck can run: installed or not, safety tag, group, inputs, options and
        presets (use these names in preview_command)."""
        out = []
        for info in services.tool_infos():
            tool = info.tool
            out.append(
                {
                    "id": tool.id,
                    "name": tool.name,
                    "description": tool.description,
                    "group": tool.group,
                    "safety": tool.safety,
                    "installed": info.status.installed,
                    "enabled": info.enabled,
                    "preferred_in_group": info.preferred,
                    "inputs": [o.id for o in tool.options if o.input],
                    "options": {o.id: o.help or o.title for o in tool.options if not o.input},
                    "presets": list(tool.presets),
                    "notes": tool.notes or None,
                }
            )
        return out

    @mcp.tool()
    def preview_command(
        tool: str,
        inputs: dict[str, str] | None = None,
        options: dict[str, str] | None = None,
        preset: str | None = None,
        extra: list[str] | None = None,
        sudo: bool = False,
        target: str | None = None,
    ) -> dict[str, Any]:
        """Build the exact command for a tool (or a group like dir-bruteforce) with inputs
        (url, domain...) filled from the box's findings unless given. Returns the argv, safety,
        warnings and a preview_id for run_tool. Nothing runs."""
        ws = state.ws(target)
        try:
            spec = services.resolve_tool(tool)
            known = {o.id for o in spec.options}
            overrides = {**(inputs or {}), **(options or {})}
            unknown = sorted(set(overrides) - known)
            if unknown:
                raise OptionError(
                    f"{spec.id} has no input/option {', '.join(unknown)} (list_tools)"
                )
            if preset and preset not in spec.presets:
                raise OptionError(f"{spec.id} has no preset {preset!r}")
            plan = services.plan_tool(
                ws,
                spec.id,
                preset=preset,
                overrides=overrides,
                extra=extra or [],
                sudo=sudo,
                settings=settings,
            )
        except (OptionError, ValueError) as exc:
            raise _err(exc) from None
        return _preview_result(state, ws, plan)

    @mcp.tool()
    def start_scan(
        stage: str = "1", options: dict[str, str] | None = None, target: str | None = None
    ) -> dict[str, Any]:
        """Preview an nmap stage: "1" all TCP ports, "2" scripts + versions on the open ports
        (after stage 1), "udp" top UDP ports (needs root, so it's queued for approval)."""
        tool = {"1": SCAN_STAGES[0], "2": SCAN_STAGES[1], "udp": "nmap-udp"}.get(stage)
        if tool is None:
            raise ToolError("stage must be '1', '2' or 'udp'")
        root_only = services.resolve_tool(tool).requires_root and not is_root()
        return preview_command(tool, options=options, sudo=root_only, target=target)

    @mcp.tool()
    async def run_tool(preview_id: str, reason: str = "", wait: bool = False) -> dict[str, Any]:
        """Run a previewed command exactly as previewed. Safe tools start now and return a
        job_id (``wait``: return when it finishes). Others are queued for the human to approve;
        ``reason`` is shown to them."""
        preview = state.previews.pop(preview_id, None)
        if preview is None:
            raise ToolError("unknown or expired preview_id: preview the command again")
        ws = services.open_target(settings, str(preview.box))
        plan = preview.plan
        why = services.needs_approval(plan)
        if why:
            approval = services.request_job_approval(
                ws, plan, reason=reason, suggestion_id=preview.suggestion_id
            )
            return {
                "status": "awaiting_approval",
                "approval_id": approval.id,
                "command": plan.command_line(),
                "why": why,
                "message": "Queued: the human must approve it in Cyberdeck (TUI Approvals or "
                f"`cyberdeck approvals approve {approval.id}`).",
            }
        vpn = services.vpn_check(settings, ws.meta.ip)
        if vpn.applicable and vpn.checked and not vpn.routed_via_tunnel:
            raise ToolError(
                f"{ws.meta.ip} isn't routed through a VPN tunnel; ask the user to start the HTB VPN"
            )
        loop = asyncio.get_running_loop()
        started: asyncio.Future[int] = loop.create_future()

        def on_start(job: Job) -> None:
            if not started.done():
                started.set_result(job.id)

        task = asyncio.create_task(
            services.execute_plan(
                ws,
                settings,
                plan,
                origin="mcp",
                suggestion_id=preview.suggestion_id,
                on_start=on_start,
            )
        )
        state.tasks.add(task)
        task.add_done_callback(state.tasks.discard)

        def failed_early(t: asyncio.Task[Any]) -> None:
            if not started.done():
                exc = t.exception() if not t.cancelled() else None
                started.set_exception(exc or RuntimeError("the job didn't start"))

        task.add_done_callback(failed_early)
        try:
            job_id = await asyncio.wait_for(asyncio.shield(started), START_TIMEOUT)
        except ScopeError as exc:
            raise _err(exc) from None
        if wait:
            outcome = await task
            return {**_job_dict(outcome.result.job), **_outcome_extra(outcome)}
        return {
            "status": "running",
            "job_id": job_id,
            "command": plan.command_line(),
            "next": "Poll job_status(job_id); job_output(job_id) shows the output so far.",
        }

    def _outcome_extra(outcome: services.RunOutcome) -> dict[str, Any]:
        created = (outcome.parse_report.created if outcome.parse_report else []) + (
            outcome.import_report.created if outcome.import_report else []
        )
        return {
            "new_findings": [services.mask_finding(f) for f in created[:50]],
            "new_suggestions": [s.title for s in outcome.suggestions],
            "notes": outcome.notes,
            "summary": (
                [glossary.plain(outcome.summary.headline)]
                + [glossary.plain(line) for line in outcome.summary.lines]
                + [f"* {h.title}: {glossary.plain(h.meaning)}" for h in outcome.summary.highlights]
                if outcome.summary is not None
                else []
            ),
        }

    @mcp.tool()
    def job_status(job_id: int, target: str | None = None) -> dict[str, Any]:
        """A job's state; once finished, the findings it produced."""
        ws = state.ws(target)
        try:
            job, *_ = services.job_files(ws, job_id)
        except OptionError as exc:
            raise _err(exc) from None
        result = _job_dict(job)
        if job.ended_at is not None:
            result["findings"] = [
                services.mask_finding(f) for f in services.job_findings(ws, job_id)[:50]
            ]
        return result

    @mcp.tool()
    def job_output(
        job_id: int, tail: int = 60, stream: str = "out", target: str | None = None
    ) -> dict[str, Any]:
        """The last ``tail`` lines of a job's stdout (stream="err": stderr), from raw/."""
        ws = state.ws(target)
        try:
            job, _, out, err = services.job_files(ws, job_id)
        except OptionError as exc:
            raise _err(exc) from None
        path = err if stream == "err" else out
        lines = (
            path.read_text(encoding="utf-8", errors="replace").splitlines()
            if path.is_file()
            else []
        )
        return {
            "job_id": job.id,
            "status": job.status.value,
            "lines": len(lines),
            "output": "\n".join(lines[-max(1, tail) :]),
        }

    @mcp.tool()
    def list_jobs(target: str | None = None) -> list[dict[str, Any]]:
        """Every job run against the box (newest first)."""
        ws = state.ws(target)
        return [_job_dict(j) for j in reversed(services.list_jobs(ws))]

    # -- approvals -------------------------------------------------------------------------
    @mcp.tool()
    def request_hosts_entry(
        names: list[str] | None = None, reason: str = "", target: str | None = None
    ) -> dict[str, Any]:
        """Ask the human to add names (default: every hostname found) to /etc/hosts for the box.
        Always queued: it's shown to them as a diff and needs sudo."""
        ws = state.ws(target)
        try:
            approval = services.request_hosts_approval(ws, names, reason=reason, settings=settings)
        except OptionError as exc:
            raise _err(exc) from None
        return {
            "status": "awaiting_approval",
            "approval_id": approval.id,
            "diff": approval.payload["diff"],
        }

    @mcp.tool()
    def list_approvals(
        include_decided: bool = False, target: str | None = None
    ) -> list[dict[str, Any]]:
        """Requests waiting for the human (and, with include_decided, what they decided)."""
        ws = state.ws(target)
        return [
            {
                "id": a.id,
                "kind": a.kind,
                "title": a.title,
                "safety": a.safety,
                "state": a.state.value,
                "job_id": a.job_id,
                "note": a.note,
                "command": a.payload.get("command"),
            }
            for a in services.list_approvals(ws, pending_only=not include_decided)
        ]

    # -- resources and prompts ---------------------------------------------------------------
    @mcp.resource("cyberdeck://target/{name}/summary", mime_type="application/json")
    def summary_resource(name: str) -> str:
        """A box's summary (same as target_summary)."""
        return json.dumps(target_summary(name), indent=2)

    @mcp.resource("cyberdeck://target/{name}/notes", mime_type="text/markdown")
    def notes_resource(name: str) -> str:
        """A box's notes.md."""
        return services.read_notes(state.ws(name))

    @mcp.resource("cyberdeck://target/{name}/findings/{type}", mime_type="application/json")
    def findings_resource(name: str, type: str) -> str:
        """A box's findings of one type (secrets masked)."""
        return json.dumps(list_findings(type=type, target=name), indent=2)

    @mcp.prompt(name="next-steps")
    def next_steps(target: str = "") -> str:
        """Summarise the box and recommend what to do next."""
        box = target or "the current box"
        return (
            f"Use Cyberdeck's tools on {box}: target_progress, target_summary and "
            "list_suggestions. Summarise what is known in a few lines, then recommend the next "
            "2-3 steps with the reason for each (use the suggestions' `why`). Preview commands "
            "with preview_suggestion or preview_command and show them to me before any "
            "run_tool. Don't run anything I haven't seen."
        )

    @mcp.prompt(name="stuck")
    def stuck(target: str = "") -> str:
        """What hasn't been tried yet, service by service."""
        box = target or "the current box"
        return (
            f"I'm stuck on {box}. I'm learning, so be a tutor: give me the smallest useful nudge, "
            "not the answer. Use Cyberdeck's stuck_report (level 1 first) and get_checklist, plus "
            "target_summary and list_findings, to point at one or two things I haven't tried or "
            "set aside too early, and ask me a question that leads there. Only use stuck_report "
            "level 2 hints if I ask for more. Never look up a write-up for this box. Preview any "
            "command before running it."
        )

    return mcp


# --- transports -------------------------------------------------------------------------------


def run_stdio(target: str | None = None) -> None:
    build_server(target=target).run("stdio")


class BearerAuth:
    """ASGI wrapper: every HTTP request needs ``Authorization: Bearer <token>``."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            given = headers.get(b"authorization", b"")
            if not secrets.compare_digest(given, self.expected):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"text/plain"),
                            (b"www-authenticate", b"Bearer"),
                        ],
                    }
                )
                await send(
                    {"type": "http.response.body", "body": b"missing or wrong bearer token\n"}
                )
                return
        await self.app(scope, receive, send)


def http_app(token: str, target: str | None = None, host: str = "127.0.0.1") -> Any:
    server = build_server(target=target)
    return BearerAuth(server.streamable_http_app(host=host), token)


def run_http(host: str, port: int, token: str, target: str | None = None) -> None:
    import uvicorn

    uvicorn.run(http_app(token, target, host), host=host, port=port, log_level="warning")
