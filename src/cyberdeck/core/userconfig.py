"""User preferences saved by Cyberdeck itself: ``~/.config/cyberdeck/config.yaml``.

Holds remembered choices (workspace root, per-tool default options, disabled tools, preferred
member of each alternatives group, wordlist overrides). Never secrets; those
belong in ``.env``. Settings read ``workspace_root`` from here (env vars and .env win).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from cyberdeck.core.config import config_dir

CONFIG_FILE = "config.yaml"


class McpConfig(BaseModel):
    """``mcp:`` in config.yaml (docs/MCP.md). Approvals for non-safe jobs can't be turned off."""

    approval: Literal["non-safe", "all"] = "non-safe"  # "all": every MCP job waits for a human
    reveal_secrets: bool = False  # allow list_findings(reveal=true) to show creds/hashes
    http_bind: str = "127.0.0.1:8765"


class LearningConfig(BaseModel):
    """``learning:`` in config.yaml (docs/LEARNING-PLAN.md "Content toggles"). Built-in learning
    content is on by default; turning a kind off hides the built-in content only, your own files
    in ``~/.config/cyberdeck/`` still load."""

    glossary: bool = True  # [[term]] links + definitions (built-in learn/glossary.yaml)
    checklists: bool = True  # built-in learn/checklists/ (L3)
    hints: bool = True  # built-in learn/patterns/ for "Stuck?" (L3)
    summaries: bool = True  # job summaries, highlights, Run-dialog teach text (L2)
    paths: bool = True  # learning path + skills view (L4)
    idle_prompt_minutes: int = Field(default=25, ge=0)  # 0 = off (L3)
    rabbit_hole_minutes: int = Field(default=30, ge=0)  # lead with no new findings; 0 = off
    disabled_ids: list[str] = Field(default_factory=list)  # single hidden items (term ids...)


Layout = Literal["beginner", "expert"]


class UserConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    workspace_root: str | None = None
    vpn_config: str | None = None
    current_target: str | None = None  # box used when there's no --target or box folder
    tool_defaults: dict[str, dict[str, Any]] = Field(default_factory=dict)
    disabled_tools: list[str] = Field(default_factory=list)  # hidden from groups/suggestions
    group_prefs: dict[str, str] = Field(default_factory=dict)  # group -> preferred tool id
    wordlists: dict[str, str] = Field(default_factory=dict)  # name -> path, overrides defaults
    auto_confirm_safe: bool = False  # `cyberdeck auto` skips the Run dialog for safe tools
    explain: bool = True  # TUI explain mode: show why + learn links for suggestions
    tui_layout: dict[str, int] = Field(default_factory=dict)  # dashboard pane sizes (cells)
    mcp: McpConfig = Field(default_factory=McpConfig)
    layout: Layout = "beginner"  # TUI dashboard: beginner (Now card + journey) or expert
    theme: str = "cyberdeck-neon"  # any Textual theme name (ui/tui/themes.py has ours)
    first_run_done: bool = False  # the TUI welcome screen has been shown
    learning: LearningConfig = Field(default_factory=LearningConfig)


def config_path() -> Path:
    return config_dir() / CONFIG_FILE


def load_user_config() -> UserConfig:
    path = config_path()
    if not path.is_file():
        return UserConfig()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return UserConfig.model_validate(raw)


def save_user_config(cfg: UserConfig) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(cfg.model_dump(exclude_none=True), sort_keys=False), encoding="utf-8"
    )
    return path
