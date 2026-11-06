"""Journal, write-up and redaction (docs/LEARNING-PLAN.md W6, phase L4).

Everything here is derived from what a box already records (jobs, findings, flags, leads, the
help log, lessons, notes.md), so there is nothing extra to keep in sync. The write-up masks
loot (passwords, hashes, flags) and personal paths (your home folder, the workspace) unless you
ask for them, because people publish write-ups.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from cyberdeck.core import glossary
from cyberdeck.core.models import (
    Credential,
    Finding,
    FindingType,
    Hash,
    Job,
    JobStatus,
    Service,
)
from cyberdeck.core.summarize import POSSIBLE_CREDENTIAL, _interesting, summarize
from cyberdeck.store.db import HelpEntry, Lead, Lesson

HIDDEN = "‹hidden›"
HELP_TEXT = {
    "stuck-1": "Asked Stuck? (what haven't I tried)",
    "stuck-2": "Asked Stuck? for a hint",
    "idle-nudge": "Got the idle nudge",
    "rabbit-hole": "Rabbit-hole warning",
}


@dataclass(frozen=True)
class Entry:
    at: datetime
    kind: str  # box, job, flag, lead, help, lesson, finding
    text: str  # [[term]] links allowed
    details: tuple[str, ...] = ()


@dataclass
class BoxRecord:
    """Everything the journal and the write-up read, gathered once by the service layer."""

    name: str
    ip: str
    created_at: datetime
    jobs: list[Job]
    findings: list[Finding]
    leads: list[Lead]
    help: list[HelpEntry]
    lessons: list[Lesson]
    flag_user_at: datetime | None = None
    flag_root_at: datetime | None = None
    flag_values: list[str] = field(default_factory=list)
    commands: dict[int, str] = field(default_factory=dict)  # job id -> command line
    notes: str = ""
    tool_names: dict[str, str] = field(default_factory=dict)  # tool id -> display name


def _job_findings(record: BoxRecord) -> dict[int, list[Finding]]:
    """Findings each job created (attributed to the first job that reported them)."""
    by_job: dict[int, list[Finding]] = {}
    for f in record.findings:
        first = f.sources[0] if f.sources else ""
        match = re.match(r"job:(\d+):", first)
        if match:
            by_job.setdefault(int(match.group(1)), []).append(f)
    return by_job


def journal(record: BoxRecord) -> list[Entry]:
    """The box's story, oldest first."""
    entries = [Entry(record.created_at, "box", f"Started {record.name} ({record.ip}).")]
    by_job = _job_findings(record)
    ports_done = False
    for job in record.jobs:
        name = record.tool_names.get(job.tool, job.tool)
        at = job.started_at or job.created_at
        if job.tool.startswith("nmap-"):  # imports aren't attributed to jobs: describe the scan
            services = [f for f in record.findings if f.type is FindingType.SERVICE]
            if not ports_done and services and job.status is JobStatus.DONE:
                ports_done = True
                ports = ", ".join(
                    f"{f.data.get('port')}/{f.data.get('name') or '?'}"
                    for f in sorted(services, key=lambda f: int(f.data.get("port") or 0))
                )
                entries.append(Entry(at, "job", f"#{job.id} {name}: open ports {ports}."))
            else:
                entries.append(Entry(at, "job", f"#{job.id} {name}: {job.status.value}."))
            continue
        summary = summarize(name, job.status, by_job.get(job.id, []))
        details = tuple(f"★ {h.title}" for h in summary.highlights)
        entries.append(Entry(at, "job", f"#{job.id} {summary.headline}", details))
    for f in record.findings:
        if any(s.startswith(("user", "answer:")) for s in f.sources[:1]):
            label = {
                FindingType.CREDENTIAL: "a credential",
                FindingType.HASH: "a hash",
                FindingType.USER: f"user {f.data.get('name')}",
                FindingType.HOSTNAME: f"hostname {f.data.get('fqdn')}",
            }.get(f.type, f.type.value)
            entries.append(Entry(f.created_at, "finding", f"You added {label}."))
    for lead in record.leads:
        entries.append(Entry(lead.started_at, "lead", f"Started working on: {lead.title}"))
        if lead.ended_at and lead.status in ("parked", "done"):
            verb = "Parked" if lead.status == "parked" else "Finished"
            entries.append(Entry(lead.ended_at, "lead", f"{verb}: {lead.title}"))
    for item in record.help:
        text = HELP_TEXT.get(item.kind, item.kind)
        if item.kind == "rabbit-hole":
            text += f" on {item.detail}"
        entries.append(Entry(item.at, "help", text + "."))
    if record.flag_user_at:
        entries.append(Entry(record.flag_user_at, "flag", "🚩 User flag captured."))
    if record.flag_root_at:
        entries.append(Entry(record.flag_root_at, "flag", "🚩 Root flag captured. Box done!"))
    for lesson in record.lessons:
        details = tuple(
            text
            for text in (
                f"What got me in: {lesson.got_in}" if lesson.got_in else "",
                f"Check sooner next time: {lesson.sooner}" if lesson.sooner else "",
                f"Techniques: {', '.join(lesson.techniques)}" if lesson.techniques else "",
            )
            if text
        )
        entries.append(Entry(lesson.at, "lesson", f"Lesson ({lesson.kind})", details))
    return sorted(entries, key=lambda e: e.at)


def secrets_of(record: BoxRecord) -> list[str]:
    """Values the write-up masks: passwords, hashes, cracked values, flags, spotted passwords."""
    found: list[str] = list(record.flag_values)
    for f in record.findings:
        if f.type is FindingType.CREDENTIAL:
            found.append(f.as_(Credential).secret)
        elif f.type is FindingType.HASH:
            h = f.as_(Hash)
            found += [h.value] + ([h.cracked] if h.cracked else [])
        elif f.type is FindingType.NOTE and POSSIBLE_CREDENTIAL in f.tags:
            found.append(str(f.data.get("text", "")).partition(":")[2])
    return sorted({s for s in found if s and len(s) >= 3}, key=len, reverse=True)


def redact(text: str, secrets: Iterable[str], paths: dict[str, str]) -> str:
    """Mask secrets, and replace personal paths (home, workspace) with neutral ones."""
    for secret in secrets:
        text = text.replace(secret, HIDDEN)
    for real, shown in sorted(paths.items(), key=lambda kv: len(kv[0]), reverse=True):
        if real:
            text = text.replace(real, shown)
    return text


def _when(at: datetime | None) -> str:
    return at.astimezone().strftime("%Y-%m-%d %H:%M") if at else "?"


def writeup(
    record: BoxRecord,
    *,
    reveal: bool = False,
    paths: dict[str, str] | None = None,
    include_notes: bool = True,
) -> str:
    """A Markdown write-up: summary from your lessons, recon, what you found, the timeline, the
    commands you ran, the help you used, and your notes. Loot and personal paths are masked
    unless ``reveal``."""
    lines: list[str] = [f"# {record.name}: write-up", ""]
    start = _when(record.created_at)
    end_at = record.flag_root_at or record.flag_user_at
    lines.append(
        f"_Box IP {record.ip}. Started {start}"
        + (f", finished {_when(end_at)}._" if end_at else "._")
    )
    lines.append("")
    lines += ["## Summary", ""]
    if record.lessons:
        for lesson in record.lessons:
            lines.append(f"**{lesson.kind.capitalize()}**")
            if lesson.got_in:
                lines.append(f"- What got me in: {lesson.got_in}")
            if lesson.sooner:
                lines.append(f"- What I'd check sooner: {lesson.sooner}")
            if lesson.techniques:
                lines.append(f"- Techniques: {', '.join(lesson.techniques)}")
            lines.append("")
    else:
        lines += ["_No lessons recorded yet (they're asked when you record a flag)._", ""]

    services = sorted(
        (f.as_(Service) for f in record.findings if f.type is FindingType.SERVICE),
        key=lambda s: (s.proto, s.port),
    )
    lines += ["## Recon", ""]
    if services:
        lines += ["| Port | Service | Version |", "|--|--|--|"]
        for svc in services:
            lines.append(f"| {svc.port}/{svc.proto} | {svc.name or '?'} | {svc.banner or ''} |")
        lines.append("")
    hosts = [f.data.get("fqdn") for f in record.findings if f.type is FindingType.HOSTNAME]
    if hosts:
        lines += [f"Hostnames: {', '.join(str(h) for h in hosts)}", ""]

    lines += ["## What I found", ""]
    found_any = False
    for title, ftype in (
        ("Software", FindingType.SOFTWARE),
        ("Users", FindingType.USER),
        ("Shares", FindingType.SHARE),
        ("Possible vulnerabilities", FindingType.VULN),
    ):
        items = [f for f in record.findings if f.type is ftype]
        if not items:
            continue
        found_any = True
        lines.append(f"**{title}**")
        for f in items[:30]:
            d = f.data
            label = {
                FindingType.SOFTWARE: f"{d.get('name')} {d.get('version') or ''}".strip(),
                FindingType.USER: str(d.get("name")),
                FindingType.SHARE: f"{d.get('name')} ({d.get('perms') or '?'})",
                FindingType.VULN: f"{d.get('id')} {d.get('title') or ''}".strip(),
            }[ftype]
            lines.append(f"- {label}")
        lines.append("")
    urls = [f for f in record.findings if f.type is FindingType.URL]
    picks = [f for f in urls if _interesting(str(f.data.get("url", "")))]
    if urls:
        found_any = True
        lines.append(f"**Web paths** ({len(urls)} found; the interesting ones)")
        for f in (picks or urls)[:25]:
            lines.append(f"- {f.data.get('url')} ({f.data.get('status') or '?'})")
        lines.append("")
    loot = [f for f in record.findings if f.type in (FindingType.CREDENTIAL, FindingType.HASH)]
    if loot:
        found_any = True
        lines.append("**Loot**")
        for f in loot:
            if f.type is FindingType.CREDENTIAL:
                cred = f.as_(Credential)
                works = f" (works on: {', '.join(cred.verified_on)})" if cred.verified_on else ""
                lines.append(f"- credential: {cred.user} / {cred.secret}{works}")
            else:
                h = f.as_(Hash)
                cracked = f" -> {h.cracked}" if h.cracked else ""
                lines.append(f"- hash ({h.user or '?'}): {h.value}{cracked}")
        lines.append("")
    if not found_any:
        lines += ["_Nothing recorded beyond the scan._", ""]

    lines += ["## Timeline", ""]
    for entry in journal(record):
        lines.append(f"- {_when(entry.at)} {glossary.plain(entry.text)}")
        lines.extend(f"  - {glossary.plain(d)}" for d in entry.details)
    lines.append("")

    if record.commands:
        lines += ["## Commands", ""]
        for job_id, command in sorted(record.commands.items()):
            lines += [f"Job #{job_id}:", "```", command.strip(), "```"]
        lines.append("")

    if record.help:
        counts: dict[str, int] = {}
        for item in record.help:
            counts[item.kind] = counts.get(item.kind, 0) + 1
        lines += ["## Help used", ""]
        lines += [f"- {HELP_TEXT.get(k, k)}: {n}" for k, n in sorted(counts.items())]
        lines.append("")

    if include_notes and record.notes.strip():
        lines += ["## Notes", "", record.notes.strip(), ""]
    text = "\n".join(lines).rstrip() + "\n"
    if reveal:
        return redact(text, [], paths or {})
    return redact(text, secrets_of(record), paths or {})


def personal_paths(box_dir: Path, workspace: Path) -> dict[str, str]:
    """Real paths -> what the write-up shows instead."""
    return {
        str(box_dir): ".",
        str(workspace): "<workspace>",
        str(Path.home()): "~",
    }
