"""Methodology content: checklists and "Stuck?" hints (docs/LEARNING-PLAN.md W4/W5, phase L3).

Both are data, like rules (ADR 0012):

- ``learn/checklists/*.yaml``: things to check, per service kind and phase. Most are manual
  (read the page source, try found passwords on SSH, ``sudo -l`` once you have a shell); some
  tick themselves (``done_when``) from the box's findings and jobs. Items can name a tool
  Cyberdeck already has (``tool:``), which then opens in the Run dialog. Knowledge, not
  automation: an item never runs anything by itself.
- ``learn/patterns/*.yaml``: general hints for when you're stuck, matched on the box's state.
  They describe what usually works on easy boxes in that situation, never a specific box.

Conditions (``applies``, ``done_when``, ``when``) use the rules' ``requires_state`` keys
(docs/RULES.md) plus the ones in :data:`EXTRA_KEYS`. The user's
``~/.config/cyberdeck/{checklists,patterns}/*.yaml`` add items or replace one with the same id.
The built-in sets can be turned off in Settings (``learning.checklists`` / ``learning.hints``);
the user's files still load. Broken entries are reported, never fatal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from cyberdeck.core.config import config_dir
from cyberdeck.core.models import Credential, FindingType
from cyberdeck.rules.engine import BoxState, state_ok
from cyberdeck.rules.schema import STATE_KEYS

# Condition keys on top of the rules' requires_state ones.
EXTRA_KEYS: dict[str, str] = {
    "foothold": "bool",  # a credential is marked as working, or the user flag is in
    "user_flag": "bool",
    "root_flag": "bool",
    "has_credentials": "bool",
    "has_hashes": "bool",
    "has_users": "bool",
    "has_urls": "bool",
    "has_shares": "bool",
    "tools_done": "list",  # every entry (a tool id or a group) has a finished job
    "not_os": "list",  # no OS guess contains any of these (true while the OS is unknown)
}
SECTIONS = ("general", "web", "smb", "services", "windows", "creds", "linux-shell", "windows-shell")
Phase = Literal["recon", "enumeration", "foothold", "privesc", "loot"]
PHASE_ORDER = {"recon": 0, "enumeration": 1, "foothold": 2, "privesc": 3, "loot": 4}


def _check_condition(value: dict[str, Any]) -> dict[str, Any]:
    for key, cond in value.items():
        kind = STATE_KEYS.get(key) or EXTRA_KEYS.get(key)
        if kind is None:
            known = ", ".join([*STATE_KEYS, *EXTRA_KEYS])
            raise ValueError(f"unknown condition {key!r} ({known})")
        if kind == "bool" and not isinstance(cond, bool):
            raise ValueError(f"{key} must be true or false")
        if kind == "list" and not isinstance(cond, list):
            raise ValueError(f"{key} must be a list")
    return value


class ChecklistItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    section: str
    phase: Phase = "enumeration"
    title: str
    why: str  # [[term]] links allowed
    how: str = ""  # a command to copy or what to do in the browser
    applies: dict[str, Any] = Field(default_factory=dict)  # shown only when this holds
    done_when: dict[str, Any] | None = None  # ticks itself when this holds
    tool: str | None = None  # a Cyberdeck tool (or group) that does it, opened in the Run dialog
    priority: int = Field(default=50, ge=0, le=100)

    @field_validator("applies", "done_when")
    @classmethod
    def _cond(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else _check_condition(value)

    @field_validator("why", "how")
    @classmethod
    def _text(cls, value: str) -> str:
        return " ".join(value.split())


class Pattern(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    when: dict[str, Any]
    title: str
    hint: str  # [[term]] links allowed; general, never box-specific
    priority: int = Field(default=50, ge=0, le=100)

    @field_validator("when")
    @classmethod
    def _cond(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _check_condition(value)

    @field_validator("hint")
    @classmethod
    def _text(cls, value: str) -> str:
        return " ".join(value.split())


class Technique(BaseModel):
    """Something you can do on a box (learn/techniques.yaml): lesson tags and path skills."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    term: str | None = None  # glossary id
    when: dict[str, Any] = Field(default_factory=dict)  # boxes where a lesson with it is relevant

    @field_validator("when")
    @classmethod
    def _cond(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _check_condition(value)


class PathStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    box: str
    stage: str = ""  # "Starting Point Tier 0", "Retired easy"...
    os: str | None = None
    skills: list[str] = Field(default_factory=list)  # technique ids


class LearningPath(BaseModel):
    """A suggested order of boxes (learn/paths/*.yaml), each with the skills it practises."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str = ""
    steps: list[PathStep]

    @field_validator("description")
    @classmethod
    def _text(cls, value: str) -> str:
        return " ".join(value.split())


@dataclass(frozen=True)
class LearnState:
    """What conditions are checked against: the rules' box state plus flags."""

    box: BoxState
    user_flag: bool = False
    root_flag: bool = False

    def holds(self, cond: dict[str, Any]) -> bool:
        rule_part = {k: v for k, v in cond.items() if k in STATE_KEYS}
        if not state_ok(rule_part, self.box):
            return False
        findings = self.box.findings
        types = {f.type for f in findings}
        verified = any(
            f.as_(Credential).verified_on for f in findings if f.type is FindingType.CREDENTIAL
        )
        for key, want in cond.items():
            if key in STATE_KEYS:
                continue
            if key == "not_os":
                families = [f.lower() for f in self.box.facts.os_families]
                if any(str(n).lower() in fam for n in want for fam in families):
                    return False
                continue
            if key == "tools_done":
                ok = all(
                    any(t in self.box.done_tools for t in self.box.groups.get(ref, [ref]))
                    for ref in want
                )
                if not ok:
                    return False
                continue
            value = {
                "foothold": verified or self.user_flag,
                "user_flag": self.user_flag,
                "root_flag": self.root_flag,
                "has_credentials": FindingType.CREDENTIAL in types,
                "has_hashes": FindingType.HASH in types,
                "has_users": FindingType.USER in types,
                "has_urls": FindingType.URL in types,
                "has_shares": FindingType.SHARE in types,
            }[key]
            if value != want:
                return False
        return True


@dataclass
class Content:
    checklist: dict[str, ChecklistItem] = field(default_factory=dict)
    patterns: dict[str, Pattern] = field(default_factory=dict)
    techniques: dict[str, Technique] = field(default_factory=dict)
    paths: dict[str, LearningPath] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def builtin_dir(kind: str) -> Path:
    from cyberdeck.plugins.manifest import package_data_dir

    return package_data_dir() / "learn" / kind


def user_dir(kind: str) -> Path:
    return config_dir() / kind


def _load(
    directory: Path, model: type[BaseModel], into: dict[str, Any], errors: list[str], skip: set[str]
) -> None:
    """Every entry of every *.yaml in ``directory`` (or of ``directory`` itself if it's a file)."""
    if directory.is_file():
        files = [directory]
    elif directory.is_dir():
        files = sorted(directory.glob("*.y*ml"))
    else:
        return
    for path in files:
        try:
            raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        if not isinstance(raw, list):
            errors.append(f"{path}: expected a list")
            continue
        for index, entry in enumerate(raw):
            try:
                item = model.model_validate(entry)
            except ValidationError as exc:
                first = exc.errors()[0]
                where = ".".join(str(p) for p in first["loc"])
                errors.append(f"{path} entry {index + 1}: {where}: {first['msg']}")
                continue
            item_id = str(getattr(item, "id"))  # noqa: B009 - both models have an id
            if item_id not in skip:
                into[item_id] = item


def load_content(
    *,
    checklists: bool | None = None,
    hints: bool | None = None,
    paths: bool | None = None,
    disabled: list[str] | None = None,
    builtin_root: Path | None = None,
    user_root: Path | None = None,
) -> Content:
    """Built-in checklists and patterns (unless turned off in Settings), then the user's."""
    if checklists is None or hints is None or paths is None or disabled is None:
        from cyberdeck.core.userconfig import load_user_config

        learning = load_user_config().learning
        checklists = learning.checklists if checklists is None else checklists
        hints = learning.hints if hints is None else hints
        paths = learning.paths if paths is None else paths
        disabled = learning.disabled_ids if disabled is None else disabled
    skip = set(disabled)
    content = Content()
    kinds: list[tuple[str, type[BaseModel], dict[str, Any], bool]] = [
        ("checklists", ChecklistItem, content.checklist, checklists),
        ("patterns", Pattern, content.patterns, hints),
        ("techniques.yaml", Technique, content.techniques, True),  # vocabulary: always on
        ("paths", LearningPath, content.paths, paths),
    ]
    for kind, model, into, wanted in kinds:
        base = builtin_root / kind if builtin_root else builtin_dir(kind)
        mine = user_root / kind if user_root else user_dir(kind)
        if wanted:
            _load(base, model, into, content.errors, skip)
        _load(mine, model, into, content.errors, skip)
    for learning_path in content.paths.values():
        for step in learning_path.steps:
            unknown = [s for s in step.skills if s not in content.techniques]
            if unknown:
                content.errors.append(
                    f"path {learning_path.id}: {step.box}: unknown technique(s) {unknown}"
                )
    return content
