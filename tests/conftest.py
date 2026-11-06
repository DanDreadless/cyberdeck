from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from cyberdeck.core.config import Settings
from cyberdeck.core.workspace import Workspace

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep tests away from the developer's real .env, config dir and workspace root."""
    for name in list(os.environ):
        if name.startswith("CYBERDECK_") or name in ("WPSCAN_API_TOKEN", "HTB_API_TOKEN"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("CYBERDECK_WORKSPACE_ROOT", str(tmp_path / "htb"))
    hosts = tmp_path / "hosts"  # never the real /etc/hosts
    hosts.write_text("127.0.0.1\tlocalhost\n", encoding="utf-8")
    monkeypatch.setenv("CYBERDECK_HOSTS_FILE", str(hosts))
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    yield


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(workspace_root=tmp_path / "htb")


def make_ws(settings: Settings, name: str, ip: str) -> Workspace:
    return Workspace.create(settings.root, name, ip, settings.scope())
