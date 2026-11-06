from __future__ import annotations

from pathlib import Path

import pytest

from cyberdeck.core.config import config_dir, load_settings
from cyberdeck.core.scope import Scope, ScopeError


def test_defaults() -> None:
    s = load_settings()
    assert s.scope_cidrs == ["10.10.0.0/16", "10.129.0.0/16"]
    assert s.mcp_token is None


def test_env_file_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local = Path.cwd() / ".env"
    local.write_text("CYBERDECK_MCP_TOKEN=from-local\nCYBERDECK_SCOPE_EXTRA=192.168.152.0/24\n")
    user = config_dir() / ".env"
    user.parent.mkdir(parents=True)
    user.write_text("CYBERDECK_MCP_TOKEN=from-user\nWPSCAN_API_TOKEN=\n")

    s = load_settings()
    assert s.mcp_token is not None and s.mcp_token.get_secret_value() == "from-user"
    assert s.scope_extra == ["192.168.152.0/24"]
    assert s.wpscan_api_token is None  # empty values are ignored

    monkeypatch.setenv("CYBERDECK_MCP_TOKEN", "from-env")
    s = load_settings()
    assert s.mcp_token is not None and s.mcp_token.get_secret_value() == "from-env"


def test_secrets_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WPSCAN_API_TOKEN", "supersecret")
    s = load_settings()
    assert "supersecret" not in repr(s)
    assert s.wpscan_api_token is not None
    assert s.wpscan_api_token.get_secret_value() == "supersecret"


def test_scope_list_formats(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERDECK_SCOPE_EXTRA", '["192.168.1.0/24", "127.0.0.1/32"]')
    assert load_settings().scope().contains("127.0.0.1")


def test_scope_check() -> None:
    scope = Scope.from_cidrs(["10.129.0.0/16"])
    assert scope.check(" 10.129.1.2 ") == "10.129.1.2"
    with pytest.raises(ScopeError, match="outside the allowed scope"):
        scope.check("8.8.8.8")
    with pytest.raises(ScopeError, match="not a valid IP"):
        scope.check("box.htb")
    assert not scope.contains("::1")
    with pytest.raises(ScopeError, match="invalid scope CIDR"):
        Scope.from_cidrs(["nope"])
