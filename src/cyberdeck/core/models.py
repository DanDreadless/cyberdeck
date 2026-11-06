"""Finding models: the typed facts Cyberdeck records about a target.

Every fact is stored as a generic :class:`Finding` envelope (type, natural key, JSON data,
confidence, provenance). ``data`` is validated by a typed payload model (:class:`Service`,
:class:`Hostname`, ...) registered in :data:`PAYLOAD_TYPES`. Findings with the same
``(type, key)`` are merged by the store using :func:`merge_data`.
"""

from __future__ import annotations

import builtins
import hashlib
import re
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address
from typing import Any, ClassVar, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FindingType(StrEnum):
    SERVICE = "service"
    SOFTWARE = "software"
    HOSTNAME = "hostname"
    OS = "os"
    URL = "url"
    USER = "user"
    CREDENTIAL = "credential"
    HASH = "hash"
    SHARE = "share"
    VULN = "vuln"
    NOTE = "note"
    FLAG = "flag"


def utcnow() -> datetime:
    return datetime.now(UTC)


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalise_fqdn(raw: str) -> str | None:
    """Lower-case and validate a DNS name. Returns None for IPs, single labels and junk."""
    name = raw.strip().strip(".").lower()
    if not name or "." not in name or len(name) > 253:
        return None
    try:
        ip_address(name)
    except ValueError:
        pass
    else:
        return None
    if name.endswith((".in-addr.arpa", ".ip6.arpa")):
        return None
    if not all(_LABEL_RE.match(label) for label in name.split(".")):
        return None
    return name


class Payload(BaseModel):
    """Base for typed finding data."""

    model_config = ConfigDict(extra="forbid")
    TYPE: ClassVar[FindingType]
    # Fields where the first value seen stays put when the same finding turns up again
    # (no conflict recorded). Software keeps its first ``where``; ``seen_at`` lists them all.
    KEEP_FIRST: ClassVar[frozenset[str]] = frozenset()

    def natural_key(self) -> str:
        raise NotImplementedError


_WEB_NAMES = frozenset({"http", "https", "http-proxy", "http-alt", "https-alt", "http-mgmt"})
_TLS_NAMES = frozenset({"https", "https-alt"})
_DEFAULT_PORTS = {"http": 80, "https": 443}


class Service(Payload):
    TYPE: ClassVar[FindingType] = FindingType.SERVICE
    proto: str = "tcp"
    port: int = Field(ge=0, le=65535)
    state: str = "open"
    reason: str | None = None
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    ostype: str | None = None
    tunnel: str | None = None
    cpe: list[str] = Field(default_factory=list)
    scripts: dict[str, str] = Field(default_factory=dict)

    def natural_key(self) -> str:
        return f"{self.proto}/{self.port}"

    @property
    def is_web(self) -> bool:
        name = (self.name or "").lower()
        return name in _WEB_NAMES or name.startswith("http")

    @property
    def is_tls(self) -> bool:
        return self.tunnel == "ssl" or (self.name or "").lower() in _TLS_NAMES

    @property
    def banner(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        text = " ".join(parts)
        if self.extrainfo:
            text = f"{text} ({self.extrainfo})" if text else self.extrainfo
        return text

    def url(self, host: str) -> str | None:
        """Base URL for a web service, e.g. ``http://box.htb/`` or ``https://1.2.3.4:8443/``."""
        if not self.is_web:
            return None
        scheme = "https" if self.is_tls else "http"
        port = "" if _DEFAULT_PORTS[scheme] == self.port else f":{self.port}"
        return f"{scheme}://{host}{port}/"


class Software(Payload):
    TYPE: ClassVar[FindingType] = FindingType.SOFTWARE
    name: str
    version: str | None = None
    cpe: str | None = None
    where: str | None = None  # first place it was seen: "tcp/80", a URL, or a path
    seen_at: list[str] = Field(default_factory=list)  # every place it was seen, ``where`` first
    KEEP_FIRST: ClassVar[frozenset[str]] = frozenset({"where"})

    @model_validator(mode="after")
    def _where_is_seen(self) -> Software:
        if self.where and self.where not in self.seen_at:
            self.seen_at.insert(0, self.where)
        return self

    def natural_key(self) -> str:
        """One finding per product and version, wherever it shows up (PHP on http and https is
        one entry with two ``seen_at`` places). See also ``Store.upsert``: a hit without a
        version joins the versioned entry of the same name."""
        return software_key(self.name, self.version)


def software_key(name: str, version: str | None) -> str:
    return f"{name.strip().lower()}@{(version or '').strip() or '?'}"


HostKind = Literal["host", "domain"]


class Hostname(Payload):
    TYPE: ClassVar[FindingType] = FindingType.HOSTNAME
    fqdn: str
    ip: str | None = None
    kind: HostKind = "host"
    origins: list[str] = Field(default_factory=list)

    @field_validator("fqdn")
    @classmethod
    def _valid_fqdn(cls, value: str) -> str:
        name = normalise_fqdn(value)
        if name is None:
            raise ValueError(f"not a usable hostname: {value!r}")
        return name

    def natural_key(self) -> str:
        return self.fqdn


class OsGuess(Payload):
    TYPE: ClassVar[FindingType] = FindingType.OS
    family: str
    name: str | None = None
    accuracy: int | None = None

    def natural_key(self) -> str:
        return self.family.lower()


class Url(Payload):
    TYPE: ClassVar[FindingType] = FindingType.URL
    url: str
    status: int | None = None
    length: int | None = None
    title: str | None = None
    redirect: str | None = None

    def natural_key(self) -> str:
        return self.url


class User(Payload):
    TYPE: ClassVar[FindingType] = FindingType.USER
    name: str
    realm: str | None = None
    valid: bool | None = None

    def natural_key(self) -> str:
        return f"{self.realm or ''}\\{self.name}".lower()


class Credential(Payload):
    TYPE: ClassVar[FindingType] = FindingType.CREDENTIAL
    user: str
    secret: str
    kind: Literal["password", "key", "token", "other"] = "password"
    realm: str | None = None
    verified_on: list[str] = Field(default_factory=list)

    def natural_key(self) -> str:
        digest = hashlib.sha256(self.secret.encode()).hexdigest()[:16]
        return f"{self.realm or ''}\\{self.user}:{digest}".lower()


class Hash(Payload):
    TYPE: ClassVar[FindingType] = FindingType.HASH
    value: str
    user: str | None = None
    hash_types: list[str] = Field(default_factory=list)
    hashcat_mode: int | None = None
    cracked: str | None = None

    def natural_key(self) -> str:
        return self.value


class Share(Payload):
    TYPE: ClassVar[FindingType] = FindingType.SHARE
    host: str
    name: str
    perms: str | None = None
    anonymous: bool | None = None

    def natural_key(self) -> str:
        return f"//{self.host}/{self.name}".lower()


class Vuln(Payload):
    TYPE: ClassVar[FindingType] = FindingType.VULN
    id: str
    title: str | None = None
    where: str | None = None
    severity: str | None = None

    def natural_key(self) -> str:
        return f"{self.id}@{self.where or ''}"


class Note(Payload):
    TYPE: ClassVar[FindingType] = FindingType.NOTE
    text: str
    title: str | None = None
    note_id: str = Field(default_factory=lambda: uuid.uuid4().hex)

    def natural_key(self) -> str:
        return self.note_id


class Flag(Payload):
    TYPE: ClassVar[FindingType] = FindingType.FLAG
    kind: Literal["user", "root"]
    value: str

    def natural_key(self) -> str:
        return self.kind


PAYLOAD_TYPES: dict[FindingType, type[Payload]] = {
    cls.TYPE: cls
    for cls in (
        Service,
        Software,
        Hostname,
        OsGuess,
        Url,
        User,
        Credential,
        Hash,
        Share,
        Vuln,
        Note,
        Flag,
    )
}

P = TypeVar("P", bound=Payload)


class Finding(BaseModel):
    """Envelope stored in the per-target DB."""

    id: int | None = None
    type: FindingType
    key: str
    data: dict[str, Any]
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @classmethod
    def of(
        cls,
        payload: Payload,
        *,
        source: str,
        confidence: float = 1.0,
        tags: Iterable[str] = (),
    ) -> Finding:
        return cls(
            type=payload.TYPE,
            key=payload.natural_key(),
            data=payload.model_dump(mode="json"),
            confidence=max(0.0, min(1.0, confidence)),
            sources=[source],
            tags=list(tags),
        )

    def payload(self) -> Payload:
        return PAYLOAD_TYPES[self.type].model_validate(self.data)

    # `builtins.type` because the `type` field shadows the builtin inside this class body.
    def as_(self, cls: builtins.type[P]) -> P:
        if cls.TYPE is not self.type:
            raise TypeError(f"finding is {self.type}, not {cls.TYPE}")
        return cls.model_validate(self.data)


def _is_empty(value: object) -> bool:
    return value is None or value == "" or value == [] or value == {}


def merge_data(
    old: dict[str, Any],
    new: dict[str, Any],
    *,
    old_confidence: float,
    new_confidence: float,
    keep_first: frozenset[str] = frozenset(),
) -> tuple[dict[str, Any], list[str]]:
    """Merge ``new`` into ``old``. Returns (merged, conflicting field names).

    Empty values never overwrite; lists are unioned; dicts merged key by key. A genuine
    conflict keeps whichever side has higher confidence (ties go to the new value) and is
    reported so the store can record it in history instead of overwriting silently.
    """
    merged = dict(old)
    conflicts: list[str] = []
    prefer_new = new_confidence >= old_confidence
    for key, new_value in new.items():
        old_value = old.get(key)
        if _is_empty(new_value) or new_value == old_value:
            continue
        if key in keep_first and not _is_empty(old_value):
            continue
        if _is_empty(old_value):
            merged[key] = new_value
        elif isinstance(old_value, list) and isinstance(new_value, list):
            merged[key] = old_value + [v for v in new_value if v not in old_value]
        elif isinstance(old_value, dict) and isinstance(new_value, dict):
            sub = dict(old_value)
            for sub_key, sub_value in new_value.items():
                if sub_key not in sub or _is_empty(sub[sub_key]):
                    sub[sub_key] = sub_value
                elif sub[sub_key] != sub_value:
                    conflicts.append(f"{key}.{sub_key}")
                    if prefer_new:
                        sub[sub_key] = sub_value
            merged[key] = sub
        else:
            conflicts.append(key)
            if prefer_new:
                merged[key] = new_value
    return merged, conflicts


# --- jobs -----------------------------------------------------------------------------------


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"  # Cyberdeck exited while the job was running


class Job(BaseModel):
    """One execution of a tool against the target (see core/runner.py)."""

    id: int
    tool: str
    argv: list[str]
    cwd: str
    origin: str = "cli"  # cli | tui | mcp | auto
    status: JobStatus = JobStatus.QUEUED
    exit_code: int | None = None
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    note: str | None = None
    pid: int | None = None
    meta: dict[str, Any] = Field(default_factory=dict)  # plan ctx/values/outputs, for re-parse

    @property
    def duration(self) -> float | None:
        if self.started_at is None or self.ended_at is None:
            return None
        return (self.ended_at - self.started_at).total_seconds()


# --- suggestions ----------------------------------------------------------------------------


class SuggestionStatus(StrEnum):
    OPEN = "open"
    DONE = "done"  # ran (job_id) or answered
    SKIPPED = "skipped"  # the user said no; stays hidden
    SNOOZED = "snoozed"  # hidden until a new finding arrives
    STALE = "stale"  # its rule no longer matches (e.g. the hostname is now in /etc/hosts)


SuggestionKind = Literal["tool", "ask"]


class Suggestion(BaseModel):
    """A next step proposed by a rule (rules/*.yaml, docs/RULES.md), kept in the box DB so its
    status (done, skipped, snoozed) survives restarts."""

    id: int | None = None
    key: str  # dedupe key: rule id + rendered inputs
    rule_id: str
    kind: SuggestionKind
    title: str
    why: str = ""
    learn: str | None = None
    phase: str = "enumeration"
    priority: int = 50
    safety: str = "safe"  # of the tool; questions are "safe" (they only ask)
    tool: str | None = None  # tool id or alternatives group
    values: dict[str, str] = Field(default_factory=dict)  # option/input overrides ("with:")
    preset: str | None = None
    ask: dict[str, Any] = Field(default_factory=dict)  # rendered question (prompt, action...)
    finding: str | None = None  # "type:key" of the finding that triggered it
    status: SuggestionStatus = SuggestionStatus.OPEN
    job_id: int | None = None
    snooze_mark: int | None = None  # highest finding id when snoozed
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# --- approvals (MCP requests that wait for a human, ADR 0007) --------------------------------


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"  # carried out (job_id set for jobs)
    DENIED = "denied"
    FAILED = "failed"  # approved but couldn't be carried out (note says why)


ApprovalKind = Literal["job", "hosts"]


class Approval(BaseModel):
    """A request from an MCP client that a human must approve in the TUI or CLI: a non-safe or
    sudo job (its exact argv is fixed here) or an /etc/hosts edit."""

    id: int | None = None
    kind: ApprovalKind
    title: str
    safety: str = "safe"
    payload: dict[str, Any] = Field(default_factory=dict)  # job: argv/plan; hosts: names/diff
    requested_by: str = "mcp"
    reason: str = ""  # why the client wants it (shown to the human)
    state: ApprovalState = ApprovalState.PENDING
    job_id: int | None = None
    note: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    decided_at: datetime | None = None
