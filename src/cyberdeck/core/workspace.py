"""Target workspaces: one directory per box (docs/ARCHITECTURE.md "Workspace layout")."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from cyberdeck import __version__
from cyberdeck.core.models import utcnow
from cyberdeck.core.scope import Scope
from cyberdeck.store.db import Store

META_FILE = "target.yaml"
DB_FILE = "target.db"
NOTES_FILE = "notes.md"
SUBDIRS = ("nmap", "raw", "loot")

_SLUG_INVALID = re.compile(r"[^a-z0-9._-]+")


class WorkspaceError(Exception):
    pass


class WorkspaceExistsError(WorkspaceError):
    pass


class WorkspaceNotFoundError(WorkspaceError):
    pass


def slugify(name: str) -> str:
    slug = _SLUG_INVALID.sub("-", name.strip().lower()).strip("-.")
    if not slug:
        raise WorkspaceError(f"{name!r} is not a usable box name")
    return slug


class Flags(BaseModel):
    user: str | None = None
    root: str | None = None
    user_at: datetime | None = None  # when you recorded it (journal / write-up)
    root_at: datetime | None = None


class TargetMeta(BaseModel):
    name: str
    slug: str
    ip: str
    created_at: datetime = Field(default_factory=utcnow)
    last_opened: datetime | None = None
    os: str | None = None
    flags: Flags = Field(default_factory=Flags)
    tool_defaults: dict[str, dict[str, Any]] = Field(default_factory=dict)
    created_with: str = __version__


class Workspace:
    def __init__(self, path: Path, meta: TargetMeta) -> None:
        self.path = path
        self.meta = meta
        self.resolved_via = "path"  # path | name | cwd | current (set by resolve/services)

    def __repr__(self) -> str:
        return f"Workspace({self.meta.slug!r}, {str(self.path)!r})"

    @property
    def meta_file(self) -> Path:
        return self.path / META_FILE

    @property
    def db_file(self) -> Path:
        return self.path / DB_FILE

    @property
    def notes_file(self) -> Path:
        return self.path / NOTES_FILE

    @property
    def nmap_dir(self) -> Path:
        return self.path / "nmap"

    @property
    def raw_dir(self) -> Path:
        return self.path / "raw"

    @property
    def loot_dir(self) -> Path:
        return self.path / "loot"

    @classmethod
    def create(cls, root: Path, name: str, ip: str, scope: Scope) -> Workspace:
        """Create ``<root>/<slug>/``. An existing folder without a ``target.yaml`` (e.g. one
        holding a manual nmap scan) is adopted rather than refused."""
        checked_ip = scope.check(ip)
        slug = slugify(name)
        path = root.expanduser() / slug
        if (path / META_FILE).exists():
            raise WorkspaceExistsError(f"a workspace for {slug!r} already exists at {path}")
        path.mkdir(parents=True, exist_ok=True)
        for sub in SUBDIRS:
            (path / sub).mkdir(exist_ok=True)
        ws = cls(path, TargetMeta(name=name.strip(), slug=slug, ip=checked_ip))
        if not ws.notes_file.exists():
            ws.notes_file.write_text(
                f"# {ws.meta.name}\n\nIP: {checked_ip}\n\n## Notes\n", encoding="utf-8"
            )
        Store(ws.db_file).close()
        ws.save_meta()
        return ws

    @classmethod
    def open(cls, path: Path) -> Workspace:
        path = path.expanduser()
        meta_file = path / META_FILE
        if not meta_file.is_file():
            raise WorkspaceNotFoundError(f"no Cyberdeck workspace at {path}")
        try:
            raw = yaml.safe_load(meta_file.read_text(encoding="utf-8"))
            meta = TargetMeta.model_validate(raw)
        except (yaml.YAMLError, ValidationError) as exc:
            raise WorkspaceError(f"{meta_file} is corrupt: {exc}") from exc
        return cls(path, meta)

    @classmethod
    def resolve(cls, ref: str | None, root: Path, cwd: Path) -> Workspace:
        """Find a workspace by path, by box name under ``root``, or from ``cwd`` upwards."""
        if ref:
            as_path = Path(ref).expanduser()
            if (as_path / META_FILE).is_file():
                return cls.open(as_path)
            ws = cls.open(root.expanduser() / slugify(ref))
            ws.resolved_via = "name"
            return ws
        for directory in (cwd, *cwd.parents):
            if (directory / META_FILE).is_file():
                ws = cls.open(directory)
                ws.resolved_via = "cwd"
                return ws
        raise WorkspaceNotFoundError(
            "no target given and the current directory is not inside a Cyberdeck workspace; "
            "use --target <box> or cd into the box folder"
        )

    def save_meta(self) -> None:
        self.meta_file.write_text(
            yaml.safe_dump(self.meta.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
        )

    def store(self) -> Store:
        return Store(self.db_file)


def list_workspaces(root: Path) -> list[Workspace]:
    root = root.expanduser()
    if not root.is_dir():
        return []
    found: list[Workspace] = []
    for child in sorted(root.iterdir()):
        if (child / META_FILE).is_file():
            try:
                found.append(Workspace.open(child))
            except WorkspaceError:
                continue
    return found


def unmanaged_folders(root: Path) -> list[Path]:
    """Box folders under ``root`` that Cyberdeck hasn't set up yet (no target.yaml)."""
    root = root.expanduser()
    if not root.is_dir():
        return []
    return sorted(
        child
        for child in root.iterdir()
        if child.is_dir() and not child.name.startswith(".") and not (child / META_FILE).exists()
    )
