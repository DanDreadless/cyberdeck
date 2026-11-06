"""Tool options, presets and argv rendering: the core behind the Run dialog (ADR 0005).

Front ends (CLI dialog now, TUI and MCP later) all build a :class:`RunPlan` and show
``plan.command_line()`` before anything runs.

Value resolution, lowest to highest priority:
tool default < dynamic default (from findings) < user default < box default < preset < edits.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

OptionType = Literal["bool", "int", "string", "choice", "path", "wordlist"]
Safety = Literal["safe", "intrusive", "bruteforce", "exploit"]


class OptionError(ValueError):
    pass


_OPT_TOKEN = re.compile(r"^\{opt\.([a-z0-9_]+)\}$")
_VAR = re.compile(r"\{([a-z0-9_.]+)\}")

WHEN_KEYS = frozenset({"software", "service", "os"})  # finding types an option's when: can test

_TRUE = frozenset({"1", "true", "yes", "y", "on"})
_FALSE = frozenset({"0", "false", "no", "n", "off"})


class OptionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    flag: str | None = None
    type: OptionType = "string"
    default: Any = None
    label: str = ""
    help: str = ""
    choices: list[str] | None = None
    render_map: dict[str, list[str]] | None = None  # choice value -> argv tokens
    joined: bool = False  # "-p" + "22,80" -> "-p22,80"
    advanced: bool = False
    requires_root: bool = False
    root_values: list[str] | None = None  # only these values need root (None = any active value)
    # Inputs (manifest ``inputs:``) are template variables (``{url}``), not flags. They are
    # editable in the Run dialog like any option.
    input: bool = False
    required: bool = False
    # Pre-fill only when findings match, e.g. {"software": ["php"]}; otherwise left unset.
    when: dict[str, list[str]] | None = None

    @field_validator("type", mode="before")
    @classmethod
    def _file_is_path(cls, value: object) -> object:
        return "path" if value == "file" else value  # `type: file` reads naturally in manifests

    @field_validator("choices", mode="before")
    @classmethod
    def _choices_as_text(cls, value: object) -> object:
        if isinstance(value, list):
            return [str(v) for v in value]
        return value

    @model_validator(mode="after")
    def _check(self) -> OptionSpec:
        if self.type == "choice":
            if not self.choices and not self.render_map:
                raise ValueError(f"option {self.id!r}: a choice needs choices")
            if self.default is not None:
                self.default = str(self.default)
        if self.when:
            unknown = set(self.when) - WHEN_KEYS
            if unknown:
                raise ValueError(
                    f"option {self.id!r}: unknown when key(s) {sorted(unknown)} "
                    f"(use {', '.join(sorted(WHEN_KEYS))})"
                )
        return self

    @property
    def title(self) -> str:
        return self.label or self.id

    def parse(self, raw: str) -> Any:
        text = raw.strip()
        if self.type == "bool":
            lowered = text.lower()
            if lowered in _TRUE:
                return True
            if lowered in _FALSE:
                return False
            raise OptionError(f"{self.title}: expected yes/no, got {raw!r}")
        if text == "" or text.lower() == "none":
            return None
        if self.type == "int":
            try:
                return int(text)
            except ValueError:
                raise OptionError(f"{self.title}: expected a number, got {raw!r}") from None
        if self.type == "choice" and self.choices is not None and text not in self.choices:
            raise OptionError(f"{self.title}: choose one of {', '.join(self.choices)}")
        return text

    def render(self, value: Any) -> list[str]:
        if value is None or value is False or value == "":
            return []
        if self.render_map is not None:
            return list(self.render_map.get(str(value), []))
        if value is True:
            return [self.flag] if self.flag else []
        if self.flag is None:
            return [str(value)]
        if self.joined:
            return [f"{self.flag}{value}"]
        return [self.flag, str(value)]

    def needs_root(self, value: Any) -> bool:
        if not self.requires_root or not self.render(value):
            return False
        return self.root_values is None or str(value) in self.root_values

    def display(self, value: Any) -> str:
        if self.type == "bool":
            return "yes" if value else "no"
        return "(off)" if value is None or value == "" else str(value)


# Free-form, lower case (e.g. recon, web, forensics, windows-ad). A manifest without one gets
# the name of the folder it lives in (plugins/manifest.py), else "util".
Category = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]*$")]


class DetectSpec(BaseModel):
    """How to tell whether a tool is installed (``plugins/detect.py``)."""

    model_config = ConfigDict(extra="forbid")

    binary: str
    version_cmd: list[str] | None = None
    version_regex: str | None = None
    help_cmd: list[str] | None = None
    apt: str | None = None  # Kali package name for the install hint


class Teach(BaseModel):
    """Beginner text shown in the Run dialog (docs/LEARNING-PLAN.md W3). ``[[term]]`` links to
    the glossary are allowed."""

    model_config = ConfigDict(extra="forbid")

    does: str = ""  # what this command does, in one or two plain sentences
    look_for: str = ""  # what matters in the output


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = ""
    binary: str
    category: Category = "util"
    group: str | None = None  # alternatives group, e.g. dir-bruteforce
    rank: int = 50  # order inside a group when the user has no preference (lower first)
    detect: DetectSpec | None = None
    safety: Safety = "safe"
    requires_root: bool = False
    ports: list[int] = Field(default_factory=list)  # needs one of these open (warned if none)
    options: list[OptionSpec] = Field(default_factory=list)
    presets: dict[str, dict[str, Any]] = Field(default_factory=dict)
    command: list[str]
    out: str | None = None  # output prefix template, available as {out}
    ingest: Literal["nmap"] | None = None
    timeout: float | None = None
    dynamic_defaults: dict[str, str] = Field(default_factory=dict)  # option id -> provider
    outputs: list[str] = Field(default_factory=list)  # templated paths the parser reads
    parser: str | None = None  # name in the parser registry (plugins/parsers.py)
    parser_config: dict[str, Any] = Field(default_factory=dict)  # for generic parsers
    learn: str | None = None
    notes: str = ""  # caveats shown in the Run dialog (e.g. "interactive: run it yourself")
    teach: Teach | None = None  # beginner explanation (Run dialog "What it does / Look for")
    source: str | None = None  # manifest file it came from (None = built in)

    @model_validator(mode="after")
    def _check_command(self) -> ToolSpec:
        ids = {o.id for o in self.options}
        if len(ids) != len(self.options):
            raise ValueError("duplicate option ids")
        for part in self.command:
            match = _OPT_TOKEN.match(part)
            if match and match.group(1) not in ids:
                raise ValueError(f"command uses {part} but there is no option {match.group(1)!r}")
        for name, values in self.presets.items():
            unknown = set(values) - ids
            if unknown:
                raise ValueError(f"preset {name!r} sets unknown option(s) {sorted(unknown)}")
        for option_id in self.dynamic_defaults:
            if option_id not in ids:
                raise ValueError(f"dynamic default for unknown option {option_id!r}")
        return self

    @property
    def detect_spec(self) -> DetectSpec:
        return self.detect or DetectSpec(binary=self.binary)

    def option(self, option_id: str) -> OptionSpec:
        for opt in self.options:
            if opt.id == option_id:
                return opt
        raise OptionError(f"{self.id} has no option {option_id!r}")

    def defaults(self) -> dict[str, Any]:
        return {opt.id: opt.default for opt in self.options}


def placeholder(input_id: str) -> str:
    """What an empty required input looks like in a draft command (``RunPlan.draft_argv``)."""
    return f"<{input_id}>"


def render_template(text: str, ctx: dict[str, str]) -> str:
    def substitute(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in ctx:
            raise OptionError(f"unknown template variable {{{key}}}")
        return ctx[key]

    return _VAR.sub(substitute, text)


def input_context(tool: ToolSpec, values: dict[str, Any]) -> dict[str, str]:
    """Template variables from the tool's inputs (``{url}``...). Raises if a required one is
    missing, with a hint on how to set it."""
    found: dict[str, str] = {}
    for opt in tool.options:
        if not opt.input:
            continue
        value = values.get(opt.id)
        if value is None or value == "":
            if opt.required:
                raise OptionError(
                    f"{opt.title} is needed: set it in the dialog or with --opt {opt.id}=..."
                )
            continue
        found[opt.id] = str(value)
    return found


def render_argv(
    tool: ToolSpec, values: dict[str, Any], extra: list[str], ctx: dict[str, str]
) -> list[str]:
    ctx = {**ctx, **input_context(tool, values)}
    argv: list[str] = []
    for part in tool.command:
        if part == "{extra}":
            argv.extend(extra)
            continue
        match = _OPT_TOKEN.match(part)
        if match:
            argv.extend(tool.option(match.group(1)).render(values.get(match.group(1))))
        else:
            argv.append(render_template(part, ctx))
    return argv


def resolve_values(
    tool: ToolSpec,
    *,
    dynamic: dict[str, Any] | None = None,
    user_defaults: dict[str, Any] | None = None,
    box_defaults: dict[str, Any] | None = None,
    preset: str | None = None,
) -> dict[str, Any]:
    values = tool.defaults()
    if preset is not None and preset not in tool.presets:
        known = ", ".join(tool.presets) or "none"
        raise OptionError(f"{tool.id} has no preset {preset!r} (available: {known})")
    layers = (dynamic, user_defaults, box_defaults, tool.presets.get(preset) if preset else None)
    for layer in layers:
        for key, value in (layer or {}).items():
            if key in values:
                values[key] = value
    return values


@dataclass
class RunPlan:
    """Everything needed to show and run one job. Mutated by the Run dialog."""

    tool: ToolSpec
    values: dict[str, Any]
    ctx: dict[str, str]
    extra: list[str] = field(default_factory=list)
    preset: str | None = None
    sudo: bool = False
    raw_argv: list[str] | None = None
    warnings: list[str] = field(default_factory=list)
    baseline: dict[str, Any] | None = None  # values before user/box defaults (for saving)

    def base_argv(self) -> list[str]:
        if self.raw_argv is not None:
            return list(self.raw_argv)
        return render_argv(self.tool, self.values, self.extra, self.ctx)

    def argv(self) -> list[str]:
        base = self.base_argv()
        return ["sudo", "-n", *base] if self.sudo else base

    def command_line(self) -> str:
        return shlex.join(self.argv())

    def missing_inputs(self) -> list[OptionSpec]:
        """Required inputs that are still empty (the command can't be rendered without them)."""
        return [
            o
            for o in self.tool.options
            if o.input and o.required and self.values.get(o.id) in (None, "")
        ]

    def draft_argv(self) -> list[str]:
        """Like :meth:`argv`, but never fails on empty required inputs: each one is shown as a
        ``<id>`` placeholder, so the command can still be previewed and edited by hand."""
        if self.raw_argv is not None:
            return self.argv()
        values = {**self.values, **{o.id: placeholder(o.id) for o in self.missing_inputs()}}
        base = render_argv(self.tool, values, self.extra, self.ctx)
        return ["sudo", "-n", *base] if self.sudo else base

    def draft_command_line(self) -> str:
        return shlex.join(self.draft_argv())

    def _expand(self, value: Any) -> Any:
        """Expand ``{wordlists.*}`` and other context variables in a string value."""
        if isinstance(value, str) and "{" in value:
            try:
                return render_template(value, self.ctx)
            except OptionError:
                return value
        return value

    def set_option(self, option_id: str, raw: str) -> None:
        self.values[option_id] = self._expand(self.tool.option(option_id).parse(raw))
        self.raw_argv = None

    def toggle(self, option_id: str) -> None:
        opt = self.tool.option(option_id)
        if opt.type != "bool":
            raise OptionError(f"{opt.title} is not a yes/no option")
        self.values[option_id] = not self.values.get(option_id)
        self.raw_argv = None

    def apply_preset(self, name: str) -> None:
        if name not in self.tool.presets:
            known = ", ".join(self.tool.presets) or "none"
            raise OptionError(f"no preset {name!r} (available: {known})")
        self.values.update({k: self._expand(v) for k, v in self.tool.presets[name].items()})
        self.preset = name
        self.raw_argv = None

    def set_extra(self, text: str) -> None:
        self.extra = shlex.split(text)
        self.raw_argv = None

    def set_raw(self, text: str) -> None:
        argv = shlex.split(text)
        if argv[:1] == ["sudo"]:
            argv = [a for a in argv[1:] if a != "-n"] if argv[1:2] == ["-n"] else argv[1:]
            self.sudo = True
        if not argv:
            raise OptionError("the command is empty")
        self.raw_argv = argv

    def problems(self, is_root: bool) -> list[str]:
        """Reasons the plan can't run as-is (shown in the dialog, enforced before running)."""
        privileged = is_root or self.sudo
        found: list[str] = []
        if self.tool.requires_root and not privileged:
            found.append(f"{self.tool.name} needs root: turn on sudo")
        for opt in self.tool.options:
            if not privileged and opt.needs_root(self.values.get(opt.id)):
                found.append(f"{opt.title} = {opt.display(self.values.get(opt.id))} needs root")
        for opt in self.tool.options:
            value = self.values.get(opt.id)
            if opt.type == "wordlist" and isinstance(value, str) and value:
                path = Path(value).expanduser()
                if path.is_absolute() and not path.is_file():
                    found.append(
                        f"wordlist not found: {value} (sudo apt install seclists, or pick another)"
                    )
        if self.raw_argv is None:
            try:
                self.base_argv()
            except OptionError as exc:
                found.append(str(exc))
        else:
            for opt in self.tool.options:
                mark = placeholder(opt.id)
                if opt.input and any(mark in part for part in self.raw_argv):
                    found.append(f"replace {mark} in the edited command with a real value")
        return found

    def full_context(self) -> dict[str, str]:
        """Template context including inputs (missing optional inputs are left out)."""
        ctx = dict(self.ctx)
        for opt in self.tool.options:
            value = self.values.get(opt.id)
            if opt.input and value is not None and value != "":
                ctx[opt.id] = str(value)
        return ctx

    def output_paths(self) -> list[str]:
        """The tool's declared output files, rendered (relative to the box folder)."""
        ctx = self.full_context()
        rendered: list[str] = []
        for path in self.tool.outputs:
            try:
                rendered.append(render_template(path, ctx))
            except OptionError:
                continue
        return rendered

    def changed_values(self) -> dict[str, Any]:
        """Values that differ from the defaults, excluding finding-derived ones and inputs
        (those belong to one box and one run)."""
        base = self.baseline if self.baseline is not None else self.tool.defaults()
        skip = set(self.tool.dynamic_defaults) | {o.id for o in self.tool.options if o.input}
        return {
            key: value
            for key, value in self.values.items()
            if value != base.get(key) and key not in skip
        }
