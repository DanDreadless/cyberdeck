"""Tool detection: is the binary installed, which version, and its ``--help`` text.

Results are cached in ``~/.cache/cyberdeck/tools.json`` keyed by the binary's path and mtime, so
an upgrade or reinstall is picked up automatically. ``refresh=True`` re-probes everything.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cyberdeck.core.config import cache_dir
from cyberdeck.core.options import ToolSpec
from cyberdeck.core.runner import run_local, which

CACHE_FILE = "tools.json"
HELP_DIR = "help"


@dataclass(frozen=True)
class ToolStatus:
    tool_id: str
    binary: str
    path: str | None
    version: str | None
    apt: str | None

    @property
    def installed(self) -> bool:
        return self.path is not None

    @property
    def install_hint(self) -> str:
        return f"sudo apt install {self.apt or self.binary}"


def _cache_path() -> Path:
    return cache_dir() / CACHE_FILE


def _load_cache() -> dict[str, Any]:
    try:
        data = json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_cache(data: dict[str, Any]) -> None:
    path = _cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    except OSError:
        pass  # a cache is optional


def probe_version(tool: ToolSpec) -> str | None:
    spec = tool.detect_spec
    if not spec.version_cmd:
        return None
    _, output = run_local(spec.version_cmd, timeout=15, merge_stderr=True)
    if spec.version_regex:
        match = re.search(spec.version_regex, output)
        return match.group(1) if match and match.groups() else None
    first = output.strip().splitlines()[:1]
    return first[0][:60] if first else None


def detect(
    tool: ToolSpec, *, refresh: bool = False, cache: dict[str, Any] | None = None
) -> ToolStatus:
    """Detect one tool. Pass ``cache`` to batch several detections (see :func:`detect_all`)."""
    spec = tool.detect_spec
    own_cache = cache is None
    data = _load_cache() if cache is None else cache
    path = which(spec.binary)
    version: str | None = None
    if path is not None:
        try:
            mtime = Path(path).stat().st_mtime
        except OSError:
            mtime = 0.0
        entry = data.get(tool.id)
        fresh = (
            not refresh
            and isinstance(entry, dict)
            and entry.get("path") == path
            and entry.get("mtime") == mtime
        )
        if fresh and isinstance(entry, dict):
            version = entry.get("version")
        else:
            version = probe_version(tool)
            data[tool.id] = {"path": path, "mtime": mtime, "version": version}
            if own_cache:
                _save_cache(data)
    return ToolStatus(tool.id, spec.binary, path, version, spec.apt)


def detect_all(tools: list[ToolSpec], *, refresh: bool = False) -> dict[str, ToolStatus]:
    data = _load_cache()
    found = {t.id: detect(t, refresh=refresh, cache=data) for t in tools}
    _save_cache(data)
    return found


def status_dict(status: ToolStatus) -> dict[str, Any]:
    return {**asdict(status), "installed": status.installed, "install_hint": status.install_hint}


def man_page(tool: ToolSpec, *, refresh: bool = False) -> str | None:
    """The tool's man page as plain text (``man -P cat <binary>``), cached; None if it has
    none (many Kali tools, e.g. the impacket scripts, only have --help)."""
    binary = tool.detect_spec.binary
    path = cache_dir() / HELP_DIR / f"{tool.id}.man.txt"
    if path.is_file() and not refresh:
        return path.read_text(encoding="utf-8", errors="replace")
    if which("man") is None:
        return None
    code, output = run_local(["man", "-P", "cat", binary], timeout=20)
    output = re.sub(r".\x08", "", output)  # overstrike bold/underline
    output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
    if code != 0 or not output.strip():
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
    except OSError:
        pass
    return output


def tool_help(tool: ToolSpec, *, refresh: bool = False) -> str | None:
    """The tool's own help text (``detect.help_cmd``, default ``<binary> --help``), cached."""
    spec = tool.detect_spec
    path = cache_dir() / HELP_DIR / f"{tool.id}.txt"
    if path.is_file() and not refresh:
        return path.read_text(encoding="utf-8", errors="replace")
    if which(spec.binary) is None:
        return None
    _, output = run_local(spec.help_cmd or [spec.binary, "--help"], timeout=15, merge_stderr=True)
    output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)  # strip colours
    if not output.strip():
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
    except OSError:
        pass
    return output
