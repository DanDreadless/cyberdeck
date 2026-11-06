"""Hosts-file access (CLAUDE.md rule 7).

Reading: :func:`read_hosts` / :func:`resolves_to` (used to pick hostname vs IP URLs).

Writing is two steps so the user always sees the change first: :func:`plan_add` /
:func:`plan_remove` build a :class:`HostsChange` (old text, new text, unified diff, warnings)
without touching anything; the service layer shows the diff, asks, backs the old file up into
the box folder and writes it (``core/runner.py:write_file_privileged``, ``sudo tee`` when the
file isn't writable). Cyberdeck only ever edits lines it added, tagged ``# cyberdeck:<box>``; other
lines are never changed, only reported when they conflict.

The path comes from ``Settings.hosts_file`` (``CYBERDECK_HOSTS_FILE``), so tests and dev runs
never read or touch the real ``/etc/hosts``.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path

TAG = "# cyberdeck:"


def parse_hosts(text: str) -> dict[str, list[str]]:
    """Map each (lower-cased) name to the IPs it is listed with, in file order."""
    names: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        ip, *aliases = line.split()
        for alias in aliases:
            ips = names.setdefault(alias.lower(), [])
            if ip not in ips:
                ips.append(ip)
    return names


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_hosts(path: Path) -> dict[str, list[str]]:
    return parse_hosts(read_text(path))


def resolves_to(path: Path, name: str, ip: str) -> bool:
    """True if the hosts file maps ``name`` to ``ip``."""
    return ip in read_hosts(path).get(name.lower(), [])


@dataclass(frozen=True)
class _Line:
    raw: str
    ip: str | None = None
    names: tuple[str, ...] = ()
    tag: str | None = None  # box slug for Cyberdeck's lines


def _tag_of(raw: str) -> str | None:
    at = raw.find(TAG)
    if at < 0:
        return None
    rest = raw[at + len(TAG) :].split()
    return rest[0] if rest else None


def _split(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for raw in text.splitlines():
        parts = raw.split("#", 1)[0].split()
        if parts:
            lines.append(_Line(raw, parts[0], tuple(p.lower() for p in parts[1:]), _tag_of(raw)))
        else:
            lines.append(_Line(raw))
    return lines


def tagged_lines(text: str, tag: str | None = None) -> list[str]:
    """Cyberdeck's lines (for one box, or all of them)."""
    return [line.raw for line in _split(text) if line.tag and (tag is None or line.tag == tag)]


def _format(ip: str, names: list[str], tag: str) -> str:
    return f"{ip}\t{' '.join(names)}\t{TAG}{tag}"


@dataclass(frozen=True)
class HostsChange:
    path: Path
    before: str
    after: str
    added: list[str] = field(default_factory=list)  # names newly mapped
    removed: list[str] = field(default_factory=list)  # names no longer mapped by Cyberdeck
    warnings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.before != self.after

    def diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                self.before.splitlines(keepends=True),
                self.after.splitlines(keepends=True),
                fromfile=f"{self.path} (now)",
                tofile=f"{self.path} (after)",
            )
        )


def _join(lines: list[str]) -> str:
    return "\n".join(lines) + "\n" if lines else ""


def plan_add(path: Path, ip: str, names: list[str], tag: str) -> HostsChange:
    """Map ``names`` to ``ip`` on this box's tagged line (created, or updated in place, e.g.
    after ``set-ip``). The same names are dropped from other boxes' Cyberdeck lines (HTB reuses
    IPs, not names, but a re-created box would otherwise shadow itself). Lines Cyberdeck didn't
    write are left alone; if one maps a name elsewhere it is reported, because the first
    matching line wins."""
    before = read_text(path)
    wanted = [n.lower() for n in dict.fromkeys(names) if n]
    lines = _split(before)
    mine = [line for line in lines if line.tag == tag]
    current = [n for line in mine for n in line.names]
    merged = list(dict.fromkeys(current + wanted))
    warnings: list[str] = []
    removed: list[str] = []
    out: list[str] = []
    placed = False
    for number, line in enumerate(lines, start=1):
        if line.tag == tag:
            if not placed:
                out.append(_format(ip, merged, tag))
                placed = True
            continue
        if line.tag and line.ip:
            keep = [n for n in line.names if n not in wanted]
            if keep != list(line.names):
                removed += [n for n in line.names if n in wanted]
                if keep:
                    out.append(_format(line.ip, keep, line.tag))
                continue
        elif line.ip:
            for name in line.names:
                if name in wanted and line.ip != ip:
                    warnings.append(
                        f"line {number} maps {name} to {line.ip} (not added by Cyberdeck). The "
                        f"first matching line wins, so remove or edit it: {line.raw.strip()}"
                    )
        out.append(line.raw)
    if not placed and merged:
        out.append(_format(ip, merged, tag))
    after = _join(out)
    already = set(current) if all(line.ip == ip for line in mine) else set()
    added = [n for n in merged if n not in already]
    return HostsChange(path, before, after, added, sorted(set(removed)), warnings)


def plan_remove(path: Path, tag: str | None) -> HostsChange:
    """Drop this box's tagged lines (``tag=None``: every Cyberdeck line)."""
    before = read_text(path)
    out: list[str] = []
    removed: list[str] = []
    for line in _split(before):
        if line.tag and (tag is None or line.tag == tag):
            removed += list(line.names)
            continue
        out.append(line.raw)
    return HostsChange(path, before, _join(out), [], removed)
