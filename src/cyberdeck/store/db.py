"""Per-target SQLite store (ADR 0003): findings with provenance, merge history, imports."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from cyberdeck.core.models import (
    Approval,
    ApprovalState,
    Finding,
    FindingType,
    Job,
    JobStatus,
    Suggestion,
    SuggestionStatus,
    merge_data,
    utcnow,
)

# Append-only. Never edit a released migration; add a new one.
MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE findings (
        id          INTEGER PRIMARY KEY,
        type        TEXT NOT NULL,
        key         TEXT NOT NULL,
        data        TEXT NOT NULL,
        confidence  REAL NOT NULL,
        sources     TEXT NOT NULL,
        tags        TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        UNIQUE (type, key)
    );
    CREATE TABLE finding_history (
        id          INTEGER PRIMARY KEY,
        finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        source      TEXT NOT NULL,
        old_data    TEXT NOT NULL,
        new_data    TEXT NOT NULL,
        conflicts   TEXT NOT NULL,
        at          TEXT NOT NULL
    );
    CREATE TABLE imports (
        id      INTEGER PRIMARY KEY,
        path    TEXT NOT NULL,
        sha256  TEXT NOT NULL UNIQUE,
        kind    TEXT NOT NULL,
        at      TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE jobs (
        id          INTEGER PRIMARY KEY,
        tool        TEXT NOT NULL,
        argv        TEXT NOT NULL,
        cwd         TEXT NOT NULL,
        origin      TEXT NOT NULL,
        status      TEXT NOT NULL,
        exit_code   INTEGER,
        created_at  TEXT NOT NULL,
        started_at  TEXT,
        ended_at    TEXT,
        note        TEXT
    );
    """,
    """
    ALTER TABLE jobs ADD COLUMN pid INTEGER;
    """,
    # Plan details (template context, option values, output files) so a job can be re-parsed.
    """
    ALTER TABLE jobs ADD COLUMN meta TEXT;
    """,
    # Suggestions from the rule engine; status survives restarts (docs/RULES.md).
    """
    CREATE TABLE suggestions (
        id          INTEGER PRIMARY KEY,
        key         TEXT NOT NULL UNIQUE,
        rule_id     TEXT NOT NULL,
        kind        TEXT NOT NULL,
        priority    INTEGER NOT NULL,
        status      TEXT NOT NULL,
        data        TEXT NOT NULL,
        job_id      INTEGER,
        snooze_mark INTEGER,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
    );
    """,
    # Requests from MCP clients that wait for a human (ADR 0007).
    """
    CREATE TABLE approvals (
        id          INTEGER PRIMARY KEY,
        kind        TEXT NOT NULL,
        state       TEXT NOT NULL,
        data        TEXT NOT NULL,
        job_id      INTEGER,
        created_at  TEXT NOT NULL,
        decided_at  TEXT
    );
    """,
    # Learning track L3 (docs/LEARNING-PLAN.md): checklist ticks, leads you're working on (the
    # rabbit-hole timer) and a log of the help you asked for (Stuck? levels, for the journal).
    """
    CREATE TABLE checklist (
        item_id     TEXT PRIMARY KEY,
        status      TEXT NOT NULL,
        updated_at  TEXT NOT NULL
    );
    CREATE TABLE leads (
        id          INTEGER PRIMARY KEY,
        title       TEXT NOT NULL,
        status      TEXT NOT NULL,
        started_at  TEXT NOT NULL,
        ended_at    TEXT,
        warned      INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE help_log (
        id          INTEGER PRIMARY KEY,
        at          TEXT NOT NULL,
        kind        TEXT NOT NULL,
        detail      TEXT NOT NULL
    );
    """,
    # Learning track L4: what you learned on the box (asked when you record a flag).
    """
    CREATE TABLE lessons (
        id          INTEGER PRIMARY KEY,
        kind        TEXT NOT NULL,
        got_in      TEXT NOT NULL,
        sooner      TEXT NOT NULL,
        techniques  TEXT NOT NULL,
        at          TEXT NOT NULL
    );
    """,
)


@dataclass(frozen=True)
class Lesson:
    """Answers to the flag questions: what got you in, what to check sooner, which techniques."""

    id: int
    kind: str  # user | root | note
    got_in: str
    sooner: str
    techniques: list[str]
    at: datetime


@dataclass(frozen=True)
class Lead:
    """Something you said you're working on (a URL, a service, an idea)."""

    id: int
    title: str
    status: str  # active | parked | done
    started_at: datetime
    ended_at: datetime | None
    warned: bool  # the rabbit-hole warning was shown


@dataclass(frozen=True)
class HelpEntry:
    id: int
    at: datetime
    kind: str  # stuck-1, stuck-2, idle-nudge, rabbit-hole...
    detail: str


class StoreError(Exception):
    pass


@dataclass(frozen=True)
class UpsertResult:
    finding: Finding
    created: bool
    data_changed: bool
    conflicts: tuple[str, ...] = ()


def _union(old: list[str], new: list[str]) -> list[str]:
    return old + [item for item in new if item not in old]


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    # -- lifecycle -------------------------------------------------------------------------
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def schema_version(self) -> int:
        return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    def _migrate(self) -> None:
        current = self.schema_version
        if current > len(MIGRATIONS):
            raise StoreError(
                f"{self.path} has schema v{current}, newer than this Cyberdeck "
                f"(v{len(MIGRATIONS)}). Upgrade Cyberdeck."
            )
        for version, sql in enumerate(MIGRATIONS[current:], start=current + 1):
            self._conn.executescript(f"BEGIN;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;")

    # -- findings --------------------------------------------------------------------------
    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding.model_validate(
            {
                "id": row["id"],
                "type": row["type"],
                "key": row["key"],
                "data": json.loads(row["data"]),
                "confidence": row["confidence"],
                "sources": json.loads(row["sources"]),
                "tags": json.loads(row["tags"]),
                "created_at": datetime.fromisoformat(row["created_at"]),
                "updated_at": datetime.fromisoformat(row["updated_at"]),
            }
        )

    def upsert(self, finding: Finding) -> UpsertResult:
        """Insert a finding, or merge it into the existing one with the same (type, key)."""
        now = utcnow()
        with self._conn:
            row = self._conn.execute(
                "SELECT * FROM findings WHERE type = ? AND key = ?",
                (finding.type.value, finding.key),
            ).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO findings (type, key, data, confidence, sources, tags, "
                    "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        finding.type.value,
                        finding.key,
                        json.dumps(finding.data, sort_keys=True),
                        finding.confidence,
                        json.dumps(finding.sources),
                        json.dumps(finding.tags),
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )
                stored = finding.model_copy(
                    update={"id": cur.lastrowid, "created_at": now, "updated_at": now}
                )
                return UpsertResult(stored, created=True, data_changed=True)

            old = self._row_to_finding(row)
            merged, conflicts = merge_data(
                old.data,
                finding.data,
                old_confidence=old.confidence,
                new_confidence=finding.confidence,
            )
            sources = _union(old.sources, finding.sources)
            tags = _union(old.tags, finding.tags)
            confidence = max(old.confidence, finding.confidence)
            data_changed = merged != old.data
            if not data_changed and (sources, tags, confidence) == (
                old.sources,
                old.tags,
                old.confidence,
            ):
                return UpsertResult(old, created=False, data_changed=False)

            self._conn.execute(
                "UPDATE findings SET data = ?, confidence = ?, sources = ?, tags = ?, "
                "updated_at = ? WHERE id = ?",
                (
                    json.dumps(merged, sort_keys=True),
                    confidence,
                    json.dumps(sources),
                    json.dumps(tags),
                    now.isoformat(),
                    old.id,
                ),
            )
            if data_changed:
                self._conn.execute(
                    "INSERT INTO finding_history (finding_id, source, old_data, new_data, "
                    "conflicts, at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        old.id,
                        ",".join(finding.sources) or "unknown",
                        json.dumps(old.data, sort_keys=True),
                        json.dumps(finding.data, sort_keys=True),
                        json.dumps(conflicts),
                        now.isoformat(),
                    ),
                )
            stored = old.model_copy(
                update={
                    "data": merged,
                    "confidence": confidence,
                    "sources": sources,
                    "tags": tags,
                    "updated_at": now,
                }
            )
            return UpsertResult(
                stored, created=False, data_changed=data_changed, conflicts=tuple(conflicts)
            )

    def delete(self, type_: FindingType, key: str) -> Finding | None:
        """Remove a finding (its history goes with it). Returns what was removed."""
        old = self.get(type_, key)
        if old is None:
            return None
        with self._conn:
            self._conn.execute("DELETE FROM findings WHERE id = ?", (old.id,))
        return old

    def replace(self, type_: FindingType, key: str, finding: Finding) -> Finding:
        """Overwrite a finding's data (a correction, not a merge): the key may change, the old
        data is kept in its history. Refuses if the new key belongs to another finding."""
        old = self.get(type_, key)
        if old is None:
            raise KeyError(key)
        if finding.key != key and self.get(type_, finding.key) is not None:
            raise ValueError("an entry with these values already exists")
        now = utcnow()
        sources = _union(old.sources, finding.sources)
        with self._conn:
            self._conn.execute(
                "UPDATE findings SET key = ?, data = ?, confidence = ?, sources = ?, "
                "updated_at = ? WHERE id = ?",
                (
                    finding.key,
                    json.dumps(finding.data, sort_keys=True),
                    finding.confidence,
                    json.dumps(sources),
                    now.isoformat(),
                    old.id,
                ),
            )
            self._conn.execute(
                "INSERT INTO finding_history (finding_id, source, old_data, new_data, "
                "conflicts, at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    old.id,
                    ",".join(finding.sources) or "user",
                    json.dumps(old.data, sort_keys=True),
                    json.dumps(finding.data, sort_keys=True),
                    json.dumps([]),
                    now.isoformat(),
                ),
            )
        stored = self.get(type_, finding.key)
        if stored is None:  # pragma: no cover - the row was just written in this transaction
            raise KeyError(finding.key)
        return stored

    def get(self, type_: FindingType, key: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT * FROM findings WHERE type = ? AND key = ?", (type_.value, key)
        ).fetchone()
        return None if row is None else self._row_to_finding(row)

    def findings(self, type_: FindingType | None = None) -> list[Finding]:
        if type_ is None:
            rows = self._conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE type = ? ORDER BY id", (type_.value,)
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def counts(self) -> dict[FindingType, int]:
        rows = self._conn.execute("SELECT type, COUNT(*) FROM findings GROUP BY type").fetchall()
        return {FindingType(r[0]): int(r[1]) for r in rows}

    def history(self, finding_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM finding_history WHERE finding_id = ? ORDER BY id", (finding_id,)
        ).fetchall()
        return [
            {
                "source": r["source"],
                "old": json.loads(r["old_data"]),
                "new": json.loads(r["new_data"]),
                "conflicts": json.loads(r["conflicts"]),
                "at": r["at"],
            }
            for r in rows
        ]

    # -- imports ---------------------------------------------------------------------------
    def has_import(self, sha256: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM imports WHERE sha256 = ?", (sha256,)).fetchone()
        return row is not None

    def record_import(self, path: Path, sha256: str, kind: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO imports (path, sha256, kind, at) VALUES (?, ?, ?, ?)",
                (str(path), sha256, kind, utcnow().isoformat()),
            )

    # -- jobs ------------------------------------------------------------------------------
    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> Job:
        def ts(value: str | None) -> datetime | None:
            return datetime.fromisoformat(value) if value else None

        return Job(
            id=row["id"],
            tool=row["tool"],
            argv=json.loads(row["argv"]),
            cwd=row["cwd"],
            origin=row["origin"],
            status=JobStatus(row["status"]),
            exit_code=row["exit_code"],
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=ts(row["started_at"]),
            ended_at=ts(row["ended_at"]),
            note=row["note"],
            pid=row["pid"],
            meta=json.loads(row["meta"]) if row["meta"] else {},
        )

    def create_job(
        self,
        tool: str,
        argv: list[str],
        cwd: str,
        origin: str,
        meta: dict[str, Any] | None = None,
        pid: int | None = None,
    ) -> Job:
        """``pid``: the Cyberdeck process that owns the job, recorded at once so another
        process opening the box never mistakes a starting job for an interrupted one."""
        now = utcnow()
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO jobs (tool, argv, cwd, origin, status, created_at, meta, pid) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tool,
                    json.dumps(argv),
                    cwd,
                    origin,
                    JobStatus.QUEUED.value,
                    now.isoformat(),
                    json.dumps(meta or {}, sort_keys=True, default=str),
                    pid,
                ),
            )
        job = self.get_job(int(cur.lastrowid or 0))
        if job is None:  # pragma: no cover - just inserted
            raise StoreError("job insert failed")
        return job

    def save_job(self, job: Job) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE jobs SET status = ?, exit_code = ?, started_at = ?, ended_at = ?, "
                "note = ?, pid = ? WHERE id = ?",
                (
                    job.status.value,
                    job.exit_code,
                    job.started_at.isoformat() if job.started_at else None,
                    job.ended_at.isoformat() if job.ended_at else None,
                    job.note,
                    job.pid,
                    job.id,
                ),
            )

    def get_job(self, job_id: int) -> Job | None:
        row = self._conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return None if row is None else self._row_to_job(row)

    def jobs(self) -> list[Job]:
        rows = self._conn.execute("SELECT * FROM jobs ORDER BY id").fetchall()
        return [self._row_to_job(r) for r in rows]

    def reap_interrupted(self, alive: Callable[[int], bool]) -> list[Job]:
        """Mark jobs left "running"/"queued" by a Cyberdeck process that has gone away."""
        reaped: list[Job] = []
        for job in self.jobs():
            if job.status not in (JobStatus.RUNNING, JobStatus.QUEUED):
                continue
            if job.pid is not None and alive(job.pid):
                continue
            done = job.model_copy(
                update={
                    "status": JobStatus.INTERRUPTED,
                    "ended_at": job.ended_at or utcnow(),
                    "note": "Cyberdeck exited before the job finished",
                }
            )
            self.save_job(done)
            reaped.append(done)
        return reaped

    # -- suggestions -----------------------------------------------------------------------
    _SUGGESTION_COLUMNS = frozenset(
        {"id", "key", "rule_id", "kind", "priority", "status", "job_id", "snooze_mark"}
        | {"created_at", "updated_at"}
    )

    @classmethod
    def _row_to_suggestion(cls, row: sqlite3.Row) -> Suggestion:
        data = json.loads(row["data"])
        return Suggestion.model_validate(
            {
                **data,
                "id": row["id"],
                "key": row["key"],
                "rule_id": row["rule_id"],
                "kind": row["kind"],
                "priority": row["priority"],
                "status": row["status"],
                "job_id": row["job_id"],
                "snooze_mark": row["snooze_mark"],
                "created_at": datetime.fromisoformat(row["created_at"]),
                "updated_at": datetime.fromisoformat(row["updated_at"]),
            }
        )

    def save_suggestion(self, sug: Suggestion) -> Suggestion:
        """Insert (by key) or update a suggestion; returns it with its id."""
        now = utcnow()
        data = json.dumps(
            sug.model_dump(mode="json", exclude=set(self._SUGGESTION_COLUMNS)), sort_keys=True
        )
        with self._conn:
            row = self._conn.execute(
                "SELECT id, created_at FROM suggestions WHERE key = ?", (sug.key,)
            ).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO suggestions (key, rule_id, kind, priority, status, data, job_id, "
                    "snooze_mark, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sug.key,
                        sug.rule_id,
                        sug.kind,
                        sug.priority,
                        sug.status.value,
                        data,
                        sug.job_id,
                        sug.snooze_mark,
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )
                return sug.model_copy(
                    update={"id": cur.lastrowid, "created_at": now, "updated_at": now}
                )
            self._conn.execute(
                "UPDATE suggestions SET rule_id = ?, kind = ?, priority = ?, status = ?, data = ?, "
                "job_id = ?, snooze_mark = ?, updated_at = ? WHERE id = ?",
                (
                    sug.rule_id,
                    sug.kind,
                    sug.priority,
                    sug.status.value,
                    data,
                    sug.job_id,
                    sug.snooze_mark,
                    now.isoformat(),
                    row["id"],
                ),
            )
            return sug.model_copy(update={"id": row["id"], "updated_at": now})

    def suggestions(self, status: SuggestionStatus | None = None) -> list[Suggestion]:
        """Suggestions, highest priority first."""
        query = "SELECT * FROM suggestions"
        params: tuple[str, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status.value,)
        rows = self._conn.execute(query + " ORDER BY priority DESC, id", params).fetchall()
        return [self._row_to_suggestion(r) for r in rows]

    def get_suggestion(self, suggestion_id: int) -> Suggestion | None:
        row = self._conn.execute(
            "SELECT * FROM suggestions WHERE id = ?", (suggestion_id,)
        ).fetchone()
        return None if row is None else self._row_to_suggestion(row)

    def max_finding_id(self) -> int:
        row = self._conn.execute("SELECT MAX(id) FROM findings").fetchone()
        return int(row[0] or 0)

    # -- approvals -------------------------------------------------------------------------
    @staticmethod
    def _row_to_approval(row: sqlite3.Row) -> Approval:
        data = json.loads(row["data"])
        return Approval.model_validate(
            {
                **data,
                "id": row["id"],
                "kind": row["kind"],
                "state": row["state"],
                "job_id": row["job_id"],
                "created_at": datetime.fromisoformat(row["created_at"]),
                "decided_at": datetime.fromisoformat(row["decided_at"])
                if row["decided_at"]
                else None,
            }
        )

    def save_approval(self, approval: Approval) -> Approval:
        """Insert (no id) or update an approval request."""
        data = json.dumps(
            approval.model_dump(
                mode="json", exclude={"id", "kind", "state", "job_id", "created_at", "decided_at"}
            ),
            sort_keys=True,
        )
        decided = approval.decided_at.isoformat() if approval.decided_at else None
        with self._conn:
            if approval.id is None:
                cur = self._conn.execute(
                    "INSERT INTO approvals (kind, state, data, job_id, created_at, decided_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        approval.kind,
                        approval.state.value,
                        data,
                        approval.job_id,
                        approval.created_at.isoformat(),
                        decided,
                    ),
                )
                return approval.model_copy(update={"id": cur.lastrowid})
            self._conn.execute(
                "UPDATE approvals SET state = ?, data = ?, job_id = ?, decided_at = ? WHERE id = ?",
                (approval.state.value, data, approval.job_id, decided, approval.id),
            )
            return approval

    def approvals(self, state: ApprovalState | None = None) -> list[Approval]:
        if state is None:
            rows = self._conn.execute("SELECT * FROM approvals ORDER BY id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM approvals WHERE state = ? ORDER BY id", (state.value,)
            ).fetchall()
        return [self._row_to_approval(r) for r in rows]

    def get_approval(self, approval_id: int) -> Approval | None:
        row = self._conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return None if row is None else self._row_to_approval(row)

    # -- learning: checklist ticks, leads, help log (schema v7) ----------------------------
    def checklist_marks(self) -> dict[str, str]:
        """Item id -> status you set (done | na). Items you never touched aren't listed."""
        rows = self._conn.execute("SELECT item_id, status FROM checklist").fetchall()
        return {str(r["item_id"]): str(r["status"]) for r in rows}

    def set_checklist_mark(self, item_id: str, status: str | None) -> None:
        """Mark a checklist item ``done`` or ``na`` (not applicable); ``None`` clears it."""
        with self._conn:
            if status is None:
                self._conn.execute("DELETE FROM checklist WHERE item_id = ?", (item_id,))
            else:
                self._conn.execute(
                    "INSERT INTO checklist (item_id, status, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(item_id) DO UPDATE SET status = excluded.status, "
                    "updated_at = excluded.updated_at",
                    (item_id, status, utcnow().isoformat()),
                )

    @staticmethod
    def _row_to_lead(row: sqlite3.Row) -> Lead:
        ended = row["ended_at"]
        return Lead(
            id=int(row["id"]),
            title=str(row["title"]),
            status=str(row["status"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            ended_at=datetime.fromisoformat(ended) if ended else None,
            warned=bool(row["warned"]),
        )

    def leads(self) -> list[Lead]:
        rows = self._conn.execute("SELECT * FROM leads ORDER BY id").fetchall()
        return [self._row_to_lead(r) for r in rows]

    def add_lead(self, title: str) -> Lead:
        """Start a lead; any other active one is parked (you work on one thing at a time)."""
        now = utcnow().isoformat()
        with self._conn:
            self._conn.execute(
                "UPDATE leads SET status = 'parked', ended_at = ? WHERE status = 'active'", (now,)
            )
            cur = self._conn.execute(
                "INSERT INTO leads (title, status, started_at) VALUES (?, 'active', ?)",
                (title, now),
            )
        row = self._conn.execute("SELECT * FROM leads WHERE id = ?", (cur.lastrowid,)).fetchone()
        return self._row_to_lead(row)

    def set_lead(
        self, lead_id: int, *, status: str | None = None, warned: bool | None = None
    ) -> None:
        with self._conn:
            if status is not None:
                ended = None if status == "active" else utcnow().isoformat()
                if status == "active":
                    self._conn.execute(
                        "UPDATE leads SET status = 'parked', ended_at = ? "
                        "WHERE status = 'active' AND id != ?",
                        (utcnow().isoformat(), lead_id),
                    )
                    self._conn.execute(
                        "UPDATE leads SET status = 'active', ended_at = NULL, started_at = ?, "
                        "warned = 0 WHERE id = ?",
                        (utcnow().isoformat(), lead_id),
                    )
                else:
                    self._conn.execute(
                        "UPDATE leads SET status = ?, ended_at = ? WHERE id = ?",
                        (status, ended, lead_id),
                    )
            if warned is not None:
                self._conn.execute(
                    "UPDATE leads SET warned = ? WHERE id = ?", (int(warned), lead_id)
                )

    def log_help(self, kind: str, detail: str = "") -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO help_log (at, kind, detail) VALUES (?, ?, ?)",
                (utcnow().isoformat(), kind, detail),
            )

    def help_log(self) -> list[HelpEntry]:
        rows = self._conn.execute("SELECT * FROM help_log ORDER BY id").fetchall()
        return [
            HelpEntry(
                int(r["id"]), datetime.fromisoformat(r["at"]), str(r["kind"]), str(r["detail"])
            )
            for r in rows
        ]

    # -- lessons (schema v8) -----------------------------------------------------------------
    def add_lesson(self, kind: str, got_in: str, sooner: str, techniques: list[str]) -> Lesson:
        now = utcnow()
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO lessons (kind, got_in, sooner, techniques, at) VALUES (?, ?, ?, ?, ?)",
                (kind, got_in, sooner, json.dumps(techniques), now.isoformat()),
            )
        return Lesson(int(cur.lastrowid or 0), kind, got_in, sooner, list(techniques), now)

    def lessons(self) -> list[Lesson]:
        rows = self._conn.execute("SELECT * FROM lessons ORDER BY id").fetchall()
        return [
            Lesson(
                int(r["id"]),
                str(r["kind"]),
                str(r["got_in"]),
                str(r["sooner"]),
                list(json.loads(r["techniques"])),
                datetime.fromisoformat(r["at"]),
            )
            for r in rows
        ]
