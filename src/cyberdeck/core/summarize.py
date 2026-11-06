"""Plain-English "so what?" summaries of a job's results (docs/LEARNING-PLAN.md W3, phase L2).

Deterministic templates per finding type, no LLM: what the job found, which of it matters
(highlights: a credential, a hash, a new hostname, a product with a version, usernames, a
writable share, a hint...), and why. Failed jobs get a likely cause from the output
(:func:`explain_failure`). Text may hold ``[[term]]`` glossary links; front ends render them
(TUI) or flatten them (``glossary.plain`` for the CLI and MCP).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cyberdeck.core.models import Finding, FindingType, JobStatus

POSSIBLE_CREDENTIAL = "possible-credential"  # tag on notes made by core/credscan.py

# Paths a beginner should open first (matched against any path segment, case-insensitive).
INTERESTING = (
    "admin", "login", "dashboard", "upload", "backup", "bak", ".git", ".env", "config", "api",
    "dev", "debug", "test", "old", "console", "phpmyadmin", "server-status", "wp-admin",
    "portal", "manager", "private", "secret", "db", "sql", "panel", "internal", "staging",
)  # fmt: skip


@dataclass(frozen=True)
class Highlight:
    """A finding worth stopping for, with what it means for you."""

    kind: str  # credential, hash, hostname, vhost, version, users, share, hint, vuln, password?
    title: str
    meaning: str  # [[term]] links allowed
    key: str  # "<type>:<finding key>", as the dashboard's tables key their rows


@dataclass
class JobSummary:
    headline: str
    lines: list[str] = field(default_factory=list)  # [[term]] links allowed
    highlights: list[Highlight] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join([self.headline, *self.lines])


def _key(f: Finding) -> str:
    return f"{f.type.value}:{f.key}"


def _join(items: list[str], limit: int = 6) -> str:
    shown = items[:limit]
    more = len(items) - len(shown)
    return ", ".join(shown) + (f" and {more} more" if more > 0 else "")


def _path(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _interesting(url: str) -> bool:
    segments = [s.lower() for s in _path(url).split("/") if s]
    return any(word in seg for seg in segments for word in INTERESTING)


def _url_line(found: list[Finding]) -> tuple[str, list[str]]:
    """One line about new URLs, plus the interesting ones' labels."""
    by_status: dict[str, list[Finding]] = {}
    for f in found:
        status = f.data.get("status")
        group = "?" if status is None else f"{str(status)[0]}xx"
        by_status.setdefault(group, []).append(f)
    picks: list[str] = []
    for f in found:
        url, status = f.data.get("url", ""), f.data.get("status")
        if not _interesting(url) and status not in (401,):
            continue
        label = _path(url)
        if status in (301, 302, 303, 307, 308) and f.data.get("redirect"):
            label += f" ({status} → {_path(str(f.data['redirect']))})"
        elif status == 403:
            label += " (403: exists but forbidden)"
        elif status == 401:
            label += " (401: wants a login)"
        elif status:
            label += f" ({status})"
        picks.append(label)
    counts = ", ".join(f"{len(v)} × {k}" for k, v in sorted(by_status.items()))
    line = f"{len(found)} new path(s) ({counts})."
    if picks:
        line += f" Worth a look first: {_join(picks, 5)}."
    else:
        line += (
            " None has an obviously interesting name; open the 200s in a browser anyway "
            "([[http-status|status codes]])."
        )
    return line, picks


def summarize(
    tool_name: str,
    status: JobStatus,
    created: list[Finding],
    updated: list[Finding] | None = None,
    *,
    new_suggestions: int = 0,
    output_tail: str = "",
    note: str | None = None,
) -> JobSummary:
    """What a job found and why it matters. ``created`` are new findings, ``updated`` ones it
    merged into (shown only as a count). ``output_tail``: the end of stdout + stderr, used to
    explain failures."""
    updated = updated or []
    by_type: dict[FindingType, list[Finding]] = {}
    for f in created:
        by_type.setdefault(f.type, []).append(f)
    lines: list[str] = []
    highlights: list[Highlight] = []

    if status is not JobStatus.DONE:
        why = explain_failure(output_tail, status)
        headline = f"{tool_name} {status.value}" + (f" ({note})" if note else "") + "."
        if why:
            lines.append(why)
        elif status is JobStatus.CANCELLED:
            lines.append("You stopped it. Whatever it printed so far was kept and parsed.")
        else:
            lines.append("Check its output (j on the jobs list) for the error.")
        if not created:
            return JobSummary(headline, lines)
        lines.append("It still found something before it stopped:")
    elif created:
        headline = f"{tool_name} found {len(created)} new thing(s)."
    else:
        headline = f"{tool_name} found nothing new."

    services = by_type.get(FindingType.SERVICE, [])
    if services:
        ports = sorted(services, key=lambda f: int(f.data.get("port") or 0))
        labels = [f"{f.data.get('port')} ({f.data.get('name') or '?'})" for f in ports]
        lines.append(
            f"Open [[port|ports]]: {_join(labels, 10)}. Each one is a program you can talk to."
        )
        versions = [
            f"{f.data.get('product')} {f.data.get('version') or ''}".strip()
            for f in ports
            if f.data.get("product")
        ]
        if versions:
            lines.append(
                f"Running: {_join(versions)}. Exact versions are what you search for known "
                "[[cve|exploits]]."
            )

    for f in by_type.get(FindingType.SOFTWARE, []):
        name, version = f.data.get("name", "?"), f.data.get("version")
        where = f" on {f.data['where']}" if f.data.get("where") else ""
        if version:
            highlights.append(
                Highlight(
                    "version",
                    f"{name} {version}{where}",
                    "A product with an exact version: look it up for public [[cve|exploits]] "
                    "and its [[default-credentials|default login]].",
                    _key(f),
                )
            )
    software = by_type.get(FindingType.SOFTWARE, [])
    if software:
        names = [f"{f.data.get('name')} {f.data.get('version') or ''}".strip() for f in software]
        lines.append(f"Software identified ([[fingerprint|fingerprinting]]): {_join(names)}.")

    hostnames = by_type.get(FindingType.HOSTNAME, [])
    for f in hostnames:
        fqdn = f.data.get("fqdn", "?")
        vhost = "vhost" in f.tags
        highlights.append(
            Highlight(
                "vhost" if vhost else "hostname",
                f"New {'virtual host' if vhost else 'hostname'}: {fqdn}",
                (
                    "A separate site on the same IP ([[vhost]]), often less protected than the "
                    "main one. Add it to [[etc-hosts|/etc/hosts]] (h), then look at it."
                    if vhost
                    else "Add it to [[etc-hosts|/etc/hosts]] (h) so the site loads by name; "
                    "HTB sites often only answer on their [[hostname]]."
                ),
                _key(f),
            )
        )
    if hostnames:
        lines.append(f"New name(s): {_join([f.data.get('fqdn', '?') for f in hostnames])}.")

    urls = by_type.get(FindingType.URL, [])
    if urls:
        line, _ = _url_line(urls)
        lines.append(line)

    users = by_type.get(FindingType.USER, [])
    if users:
        names = [f.data.get("name", "?") for f in users]
        lines.append(
            f"Usernames: {_join(names, 8)}. Half a login: keep them for when you find a password "
            "([[password-reuse]])."
        )
        highlights.append(
            Highlight(
                "users",
                f"{len(users)} username(s): {_join(names, 4)}",
                "Real usernames turn a guess into half a login. Try any password you find with "
                "each of them.",
                _key(users[0]),
            )
        )

    for f in by_type.get(FindingType.CREDENTIAL, []):
        user = f.data.get("user") or "?"
        highlights.append(
            Highlight(
                "credential",
                f"New credential for {user}",
                "Passwords on HTB are often reused ([[password-reuse]]). Try it on every login "
                "you know about (SSH, the web app, SMB), and mark where it works in Loot (m).",
                _key(f),
            )
        )
    creds = by_type.get(FindingType.CREDENTIAL, [])
    if creds:
        lines.append(f"{len(creds)} new [[credential|credential(s)]] saved to Loot (l).")

    hashes = by_type.get(FindingType.HASH, [])
    if hashes:
        lines.append(
            f"{len(hashes)} password [[hash|hash(es)]]. Identify the type, then crack them "
            "with rockyou ([[hash-cracking]])."
        )
        highlights.append(
            Highlight(
                "hash",
                f"{len(hashes)} password hash(es)",
                "A hash is a scrambled password: crack it offline with a [[wordlist]] "
                "([[hash-cracking]]). Weak passwords fall in minutes.",
                _key(hashes[0]),
            )
        )

    shares = by_type.get(FindingType.SHARE, [])
    if shares:
        labels = [f"{f.data.get('name')} ({f.data.get('perms') or '?'})" for f in shares]
        lines.append(
            f"[[smb|Shares]]: {_join(labels)}. Readable ones often hold files with passwords."
        )
        for f in shares:
            if "WRITE" in str(f.data.get("perms") or "").upper():
                highlights.append(
                    Highlight(
                        "share",
                        f"Writable share: {f.data.get('name')}",
                        "You can put files there. If a website or a user opens files from that "
                        "share, it can be a way in.",
                        _key(f),
                    )
                )

    vulns = by_type.get(FindingType.VULN, [])
    if vulns:
        ids = [str(f.data.get("id")) for f in vulns]
        lines.append(
            f"Possible issues: {_join(ids)}. Check each really applies to this exact version "
            "before trying anything."
        )
        highlights.extend(
            Highlight(
                "vuln",
                f"Possible vulnerability: {f.data.get('id')}",
                "Scanners guess. Confirm the version matches, then read about it ([[cve]]).",
                _key(f),
            )
            for f in vulns[:3]
        )

    for f in by_type.get(FindingType.NOTE, []):
        if POSSIBLE_CREDENTIAL in f.tags:
            highlights.append(
                Highlight(
                    "password?",
                    "Something that looks like a password",
                    f"{f.data.get('title') or 'In the output'}. It's waiting in Next steps: "
                    "save it to Loot if it's real ([[credential]]).",
                    _key(f),
                )
            )
        elif "hint" in f.tags:
            text = " ".join(str(f.data.get("text") or "").split())[:120]
            highlights.append(
                Highlight(
                    "hint",
                    "A hint on the page",
                    f"“{text}”. On a CTF, hints like this are usually the intended path.",
                    _key(f),
                )
            )
    notes = [
        f
        for f in by_type.get(FindingType.NOTE, [])
        if POSSIBLE_CREDENTIAL not in f.tags and "hint" not in f.tags
    ]
    if notes:
        lines.append(f"{len(notes)} note(s) added (Other tab).")

    for f in by_type.get(FindingType.OS, []):
        lines.append(f"Operating system: {f.data.get('family')}.")

    trouble = explain_failure(output_tail) if status is JobStatus.DONE and not created else None
    if trouble:  # exited 0 but the output says why nothing came back (whatweb does this)
        lines.append(f"Its output points to a problem: {trouble}")
    elif not created and status is JobStatus.DONE:
        lines.append(
            "That's information too: rule it out and move on. If you expected results, check "
            "the output (j), try the [[hostname]] instead of the IP, or a bigger [[wordlist]]."
        )
    if updated:
        lines.append(f"It also confirmed {len(updated)} thing(s) already known.")
    if new_suggestions:
        lines.append(f"{new_suggestions} new next step(s) came out of this.")
    return JobSummary(headline, lines, highlights)


# -- failures ---------------------------------------------------------------------------------

_FAILURES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"Name or service not known|Could not resolve host|no such host|"
            r"getaddrinfo|Temporary failure in name resolution|NXDOMAIN|no address for",
            re.IGNORECASE,
        ),
        "The tool couldn't look up the hostname. Add it to [[etc-hosts|/etc/hosts]] (h) first.",
    ),
    (
        re.compile(r"wildcard|matches the provided options for non existing urls", re.IGNORECASE),
        "The site answers every path the same way (a wildcard), usually because you used the IP "
        "and it [[redirect|redirects]] everything. Use the hostname, or filter by response size.",
    ),
    (
        re.compile(
            r"requires root|Operation not permitted|You requested a scan type which requires",
            re.IGNORECASE,
        ),
        "It needs root: turn on 'Run with sudo' (u in the terminal dialog) and run it again.",
    ),
    (
        re.compile(r"Connection refused", re.IGNORECASE),
        "The port refused the connection: the service isn't listening there. Check the port "
        "number, and that the box hasn't been reset.",
    ),
    (
        re.compile(
            r"No route to host|Network is unreachable|Connection timed out|timed out|"
            r"Host seems down",
            re.IGNORECASE,
        ),
        "Can't reach the box. Is the HTB [[vpn|VPN]] up (cyberdeck vpn), is the box still running, "
        "and is the IP the same (boxes get a new one when respawned: cyberdeck set-ip)?",
    ),
    (
        re.compile(r"certificate verify failed|SSL|TLS", re.IGNORECASE),
        "A TLS (https) problem. Try http://, or the tool's option to ignore certificates.",
    ),
    (
        re.compile(r"command not found|No such file or directory", re.IGNORECASE),
        "A program or file it needs is missing: check `cyberdeck tools` and the wordlist path.",
    ),
    (
        re.compile(r"Authentication failed|LOGON_FAILURE|Access denied|NT_STATUS_ACCESS_DENIED"),
        "The login was refused: that user/password (or anonymous access) doesn't work here. "
        "That's a useful result: note it and try the next one.",
    ),
]


def explain_failure(text: str, status: JobStatus | None = None) -> str | None:
    """A likely cause and fix for a failed job, from its output. None if nothing matches."""
    for pattern, message in _FAILURES:
        if pattern.search(text or ""):
            return message
    if status is JobStatus.TIMEOUT:
        return (
            "It hit its time limit. Try a quicker preset or a smaller [[wordlist]], or raise the "
            "timeout."
        )
    return None
