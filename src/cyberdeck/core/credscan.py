"""Spot password-shaped strings in tool output (docs/LEARNING-PLAN.md W3, phase L2).

Beginners often have a working password in front of them and don't recognise it (a config
file a tool printed, a connection string, ``DB_PASSWORD=...``). This is a passive text scan of
output Cyberdeck already saved: it sends nothing anywhere and runs no tool. Each candidate
becomes a note tagged ``possible-credential``; the ``creds.possible-password`` rule then asks
you whether to save it to Loot. Deliberately conservative: placeholders, variable references
and HTML form fields are ignored.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

MAX_SCAN_BYTES = 2_000_000
MAX_CANDIDATES = 10

_KEYWORDS = (
    r"db_?pass(?:word)?|database_?password|mysql_?pass(?:word)?|passw(?:or)?d|pwd|pass|"
    r"secret(?:_?key)?|api_?key|auth_?token|access_?token"
)
# key = value / key: value / "key": "value" / KEY='value' / 'key' => 'value'. The password word
# must start the key or follow a separator (db_password, app.secret), and end it.
_ASSIGN = re.compile(
    r"""(?ix)
    (?<![\w])(?P<key>(?:[\w.-]*[_.-])?(?:"""
    + _KEYWORDS
    + r"""))\b
    ['"]?\s*(?:=>|[:=])\s*
    (?P<q>['"]?)(?P<value>[^'"\s,;)<>]{3,128})(?P=q)
    """
)
# PHP: define('DB_PASSWORD', 'value');
_DEFINE = re.compile(
    r"""(?ix)define\(\s*['"](?P<key>\w*(?:"""
    + _KEYWORDS
    + r"""))['"]\s*,\s*
    ['"](?P<value>[^'"]{3,128})['"]"""
)
_URI = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://(?P<user>[^:/\s@]{1,64}):(?P<value>[^@/\s]{3,128})@")
_USER = re.compile(
    r"""(?ix)
    (?:db_?user(?:name)?|user(?:name)?|login|uid)['"]?\s*(?:=>|[:=]|,)\s*
    (?P<q>['"]?)(?P<user>[\w.@\\-]{1,64})(?P=q)
    """
)
_PLACEHOLDERS = frozenset(
    {
        "password", "passwd", "pass", "pwd", "secret", "null", "none", "nil", "true", "false",
        "undefined", "string", "required", "changeme_please", "example", "xxx", "xxxx",
        "your_password", "yourpassword", "<password>", "hidden", "redacted", "text",
    }
)  # fmt: skip


@dataclass(frozen=True)
class Candidate:
    user: str  # "" when no username was seen near it
    secret: str
    label: str  # e.g. "DB_PASSWORD on line 12"
    line: int

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.user}\0{self.secret}".encode()).hexdigest()[:16]


def _plausible(value: str) -> bool:
    low = value.lower()
    if low in _PLACEHOLDERS or set(value) <= {"*", "x", "X", "•", "."}:
        return False
    if value[0] in "$%{[(<&@" or value.endswith(("(", "[")):
        return False  # $var, %s, {{x}}, function calls, HTML
    if re.fullmatch(r"[a-z_]+(\.[a-z_]+)+", value):  # this.password, form.pass
        return False
    if re.fullmatch(r"[A-Z_]{3,}", value):  # ENV_NAME references
        return False
    return not low.startswith(("http", "/", "./"))


def _nearby_user(lines: list[str], index: int) -> str:
    for offset in (0, -1, 1, -2, 2, -3, 3):
        i = index + offset
        if 0 <= i < len(lines):
            match = _USER.search(lines[i])
            if match and match.group("user").lower() not in _PLACEHOLDERS:
                return match.group("user")
    return ""


def find_candidates(text: str) -> list[Candidate]:
    """Password-shaped values in ``text``, most obvious first, at most ``MAX_CANDIDATES``."""
    lines = text[:MAX_SCAN_BYTES].splitlines()
    found: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    for index, line in enumerate(lines):
        if len(line) > 2000 or 'type="password"' in line.lower():
            continue
        for match in _URI.finditer(line):
            user, value = match.group("user"), match.group("value")
            if _plausible(value) and (user, value) not in seen:
                seen.add((user, value))
                found.append(
                    Candidate(user, value, f"a connection string on line {index + 1}", index + 1)
                )
        for match in [*_DEFINE.finditer(line), *_ASSIGN.finditer(line)]:
            value = match.group("value")
            if not _plausible(value):
                continue
            user = _nearby_user(lines, index)
            if (user, value) in seen:
                continue
            seen.add((user, value))
            key = match.group("key").strip("'\"")
            found.append(Candidate(user, value, f"{key} on line {index + 1}", index + 1))
        if len(found) >= MAX_CANDIDATES:
            break
    return found[:MAX_CANDIDATES]
