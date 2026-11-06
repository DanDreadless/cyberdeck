from __future__ import annotations

from pathlib import Path

import pytest

from cyberdeck.core.config import Settings
from cyberdeck.core.scope import ScopeError
from cyberdeck.core.workspace import (
    Workspace,
    WorkspaceError,
    WorkspaceExistsError,
    WorkspaceNotFoundError,
    list_workspaces,
    slugify,
)

from .conftest import make_ws


def test_slugify() -> None:
    assert slugify("  Lantern Box! ") == "lantern-box"
    with pytest.raises(WorkspaceError):
        slugify("!!!")


def test_create_layout(settings: Settings) -> None:
    ws = make_ws(settings, "Lantern", "10.129.231.15")
    assert ws.path == settings.root / "lantern"
    for name in ("nmap", "raw", "loot", "notes.md", "target.db", "target.yaml"):
        assert (ws.path / name).exists(), name
    assert "10.129.231.15" in ws.notes_file.read_text()
    reopened = Workspace.open(ws.path)
    assert reopened.meta.name == "Lantern" and reopened.meta.ip == "10.129.231.15"


def test_create_refuses_duplicates_and_out_of_scope(settings: Settings) -> None:
    make_ws(settings, "lantern", "10.129.231.15")
    with pytest.raises(WorkspaceExistsError):
        make_ws(settings, "Lantern", "10.129.231.15")
    with pytest.raises(ScopeError):
        make_ws(settings, "google", "8.8.8.8")


def test_create_adopts_existing_folder(settings: Settings) -> None:
    existing = settings.root / "drift" / "nmap"
    existing.mkdir(parents=True)
    (existing / "drift.xml").write_text("<nmaprun/>")
    ws = make_ws(settings, "drift", "10.129.50.5")
    assert (ws.nmap_dir / "drift.xml").exists()
    assert ws.notes_file.exists()


def test_resolve(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", "10.129.231.15")
    assert Workspace.resolve("Lantern", settings.root, Path("/")).path == ws.path
    assert Workspace.resolve(str(ws.path), settings.root, Path("/")).path == ws.path
    assert Workspace.resolve(None, settings.root, ws.nmap_dir).path == ws.path
    with pytest.raises(WorkspaceNotFoundError):
        Workspace.resolve(None, settings.root, settings.root)
    with pytest.raises(WorkspaceNotFoundError):
        Workspace.resolve("nothere", settings.root, Path("/"))


def test_corrupt_meta(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", "10.129.231.15")
    ws.meta_file.write_text("name: [unclosed")
    with pytest.raises(WorkspaceError, match="corrupt"):
        Workspace.open(ws.path)
    assert list_workspaces(settings.root) == []
