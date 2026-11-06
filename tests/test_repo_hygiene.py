"""No personal data in files that get committed (CLAUDE.md "No personal data in the repo").

Catches the developer's own login name, home-directory paths and Windows user paths in the
source tree, so nothing personal reaches GitHub. Personal paths belong in .env (gitignored).
"""

from __future__ import annotations

import getpass
import re
from pathlib import Path

import pytest

from cyberdeck.core.config import Settings

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ["src", "tests", "docs", "plugins", "rules", "learn", "scripts"]
FILES = ["README.md", "CLAUDE.md", "pyproject.toml", ".env.example", ".gitignore", "LICENSE"]
# Public repo links (github.com/<account>/cyberdeck) and the LICENSE copyright line name the
# project's public account on purpose; they aren't personal data leaking from a dev machine.
PUBLIC_IDENTITY = ("github.com/", "Copyright (c)")
SKIP_PARTS = {"__pycache__", ".venv", ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
GENERIC_USERS = {"root", "user", "kali", "runner", "ubuntu", "vscode", "dev", "test"}
# /home/<name> and C:\Users\<name>, except placeholders like /home/<user> and /home/user.
HOME_PATH = re.compile(r"/home/(?!<|user\b|kali\b|\$)([A-Za-z0-9_.-]+)")
WIN_PATH = re.compile(r"[A-Za-z]:\\\\?Users\\\\?(?!<|Public\b)([A-Za-z0-9_.-]+)", re.IGNORECASE)


def _files() -> list[Path]:
    found = [ROOT / name for name in FILES if (ROOT / name).is_file()]
    for folder in SCANNED:
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and not SKIP_PARTS & set(path.parts) and path.suffix != ".pyc":
                found.append(path)
    return found


def _offences(pattern: re.Pattern[str]) -> list[str]:
    hits = []
    for path in _files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in pattern.finditer(text):
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            line = text[start : end if end != -1 else len(text)]
            if any(marker in line for marker in PUBLIC_IDENTITY):
                continue
            hits.append(f"{path.relative_to(ROOT)}: {match.group(0)}")
    return hits


def test_no_home_or_windows_user_paths() -> None:
    hits = _offences(HOME_PATH) + _offences(WIN_PATH)
    hits = [h for h in hits if h.rsplit("/", 1)[-1].split("\\")[-1].lower() not in GENERIC_USERS]
    assert hits == [], "personal paths in the repo (put them in .env, write ~):\n" + "\n".join(hits)


def test_no_developer_login_name() -> None:
    name = getpass.getuser()
    if name.lower() in GENERIC_USERS or len(name) < 4:
        pytest.skip(f"login name {name!r} is too generic to search for")
    hits = _offences(re.compile(re.escape(name), re.IGNORECASE))
    assert hits == [], f"your login name {name!r} appears in:\n" + "\n".join(hits)


def test_paths_from_your_env_are_not_in_the_repo() -> None:
    """The folders your own .env sets (workspace, VPN) appear nowhere in committed files."""
    env = ROOT / ".env"
    if not env.is_file():
        pytest.skip("no .env in the project")
    names = {f"CYBERDECK_{f.upper()}" for f in ("workspace_root", "vpn_dir", "vpn_config")}
    for line in env.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        value = value.split("#")[0].strip().strip("'\"")
        if not sep or key.strip() not in names or not value or value.startswith("~"):
            continue
        assert _offences(re.compile(re.escape(value))) == [], f"{key} value is in the repo"
    assert Settings.model_fields["vpn_dir"].default is None  # no personal default in code
