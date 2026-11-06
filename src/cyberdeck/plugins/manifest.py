"""Tool manifests (``plugins/tools/*.yaml``, docs/PLUGINS.md) loaded into :class:`ToolSpec`.

Built-in manifests ship with Cyberdeck; users add or override tools in
``~/.config/cyberdeck/plugins/tools/``. A manifest with the same ``id`` as a built-in replaces it.
A broken manifest never stops Cyberdeck: it is reported by ``cyberdeck tools`` and skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from cyberdeck.core.config import config_dir
from cyberdeck.core.options import ToolSpec

# Where an input's value can come from (``inputs: {url: {from: web_url}}``). Implemented in
# ``core/services.py`` (``_PROVIDERS``).
PROVIDERS: dict[str, str] = {
    "web_url": "Base URL of the first web service, by hostname when it is in /etc/hosts",
    "web_url_ip": "Base URL of the first web service, always by IP (for Host-header fuzzing)",
    "hostname": "Best known hostname of the box",
    "domain": "Best known DNS domain of the box (e.g. for FUZZ.<domain> vhost fuzzing)",
    "target_ip": "The box's IP",
    "host": "The box's hostname once /etc/hosts maps it to the box IP, else the IP",
    "open_tcp_ports": "Open TCP ports found so far, comma separated",
}

_INPUT_KEYS = frozenset({"from", "default", "label", "help", "type", "required", "advanced"})


class ManifestError(ValueError):
    pass


def package_data_dir() -> Path:
    """Built-in ``plugins/`` and ``rules/`` folders: the repo root in a dev/editable install,
    ``cyberdeck/_data`` in a wheel (see pyproject ``force-include``)."""
    here = Path(__file__).resolve()
    bundled = here.parents[1] / "_data"
    if (bundled / "plugins").is_dir():
        return bundled
    return here.parents[3]


def builtin_tools_dir() -> Path:
    return package_data_dir() / "plugins" / "tools"


def builtin_parsers_dir() -> Path:
    return package_data_dir() / "plugins" / "parsers"


def user_tools_dir() -> Path:
    return config_dir() / "plugins" / "tools"


def user_parsers_dir() -> Path:
    return config_dir() / "plugins" / "parsers"


def _inputs_to_options(inputs: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    options: list[dict[str, Any]] = []
    dynamic: dict[str, str] = {}
    for input_id, spec in inputs.items():
        spec = dict(spec or {})
        unknown = set(spec) - _INPUT_KEYS
        if unknown:
            raise ManifestError(f"input {input_id!r}: unknown key(s) {sorted(unknown)}")
        source = spec.pop("from", None)
        if source is not None:
            if source not in PROVIDERS:
                known = ", ".join(PROVIDERS)
                raise ManifestError(f"input {input_id!r}: unknown from: {source!r} ({known})")
            dynamic[input_id] = source
        spec.setdefault("required", True)
        options.append({"id": input_id, "input": True, **spec})
    return options, dynamic


def manifest_to_spec(
    raw: dict[str, Any], source: Path | None = None, *, folder_category: str | None = None
) -> ToolSpec:
    """Validate one manifest dict and turn it into a ToolSpec. ``folder_category``: the
    sub-folder it lives in (``web/``...), used when the manifest has no ``category``."""
    if not isinstance(raw, dict):
        raise ManifestError("a manifest must be a YAML mapping")
    data = dict(raw)
    detect = data.get("detect") or {}
    if "binary" not in data:
        if not isinstance(detect, dict) or not detect.get("binary"):
            raise ManifestError("detect.binary is required")
        data["binary"] = detect["binary"]
    input_opts, dynamic = _inputs_to_options(data.pop("inputs", None) or {})
    data["options"] = input_opts + list(data.get("options") or [])
    data["dynamic_defaults"] = {**dynamic, **(data.get("dynamic_defaults") or {})}
    data["outputs"] = [
        o["path"] if isinstance(o, dict) else str(o) for o in data.get("outputs") or []
    ]
    data.setdefault("description", "")
    if folder_category and "category" not in data:
        data["category"] = folder_category
    if source is not None:
        data["source"] = str(source)
    try:
        spec = ToolSpec.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'manifest'}: {err['msg']}"
            for err in exc.errors()
        )
        raise ManifestError(problems) from None
    _check_inputs_used(spec)
    return spec


# Template variables a command may use besides its inputs (docs/PLUGINS.md "Template variables").
CONTEXT_VARS = frozenset(
    {"target.ip", "target.name", "target.slug", "out", "stamp", "hostname", "domain", "lhost"}
)
_VAR = re.compile(r"\{([A-Za-z0-9_.]+)\}")


def _check_command(spec: ToolSpec) -> None:
    """Mistakes that would only show when the tool runs: unknown {variables} (e.g. ffuf's
    FUZZ keyword written as {FUZZ}) and a flag written next to an option that renders it."""
    inputs = {o.id for o in spec.options if o.input}
    for part in [*spec.command, *spec.outputs]:
        for name in _VAR.findall(part):
            if name.startswith("opt.") or name in ("extra",):
                continue
            if name in inputs or name in CONTEXT_VARS or name.startswith("wordlists."):
                continue
            raise ManifestError(
                f"command uses {{{name}}}, which isn't an input or a known variable "
                "(a literal keyword like ffuf's FUZZ is written without braces)"
            )
    for before, part in zip(spec.command, spec.command[1:], strict=False):
        if part.startswith("{opt.") and part.endswith("}"):
            opt = next((o for o in spec.options if o.id == part[5:-1]), None)
            if opt is not None and opt.flag and before == opt.flag:
                raise ManifestError(
                    f"{before!r} is written before {part}, which already renders {opt.flag}: "
                    "remove the literal flag"
                )


def _check_inputs_used(spec: ToolSpec) -> None:
    _check_command(spec)
    text = " ".join(spec.command + spec.outputs)
    for opt in spec.options:
        if opt.input and f"{{{opt.id}}}" not in text:
            raise ManifestError(f"input {opt.id!r} is never used in command: as {{{opt.id}}}")
        if not opt.input and f"{{opt.{opt.id}}}" not in spec.command:
            raise ManifestError(f"option {opt.id!r} is never used in command: as {{opt.{opt.id}}}")


@dataclass
class LoadResult:
    tools: dict[str, ToolSpec] = field(default_factory=dict)
    errors: list[tuple[Path, str]] = field(default_factory=list)
    overridden: list[str] = field(default_factory=list)  # built-in ids replaced by user files


def manifest_files(directory: Path) -> list[Path]:
    """Every ``*.yaml``/``*.yml`` under ``directory``, in any sub-folder (``web/``, ``recon/``...).
    Files or folders whose name starts with ``_`` or ``.`` are skipped (``_template.yaml``)."""
    found = []
    for path in directory.rglob("*.y*ml"):
        parts = path.relative_to(directory).parts
        if path.suffix in (".yaml", ".yml") and not any(p.startswith(("_", ".")) for p in parts):
            found.append(path)
    return sorted(found)


def load_dir(directory: Path, result: LoadResult, *, user: bool) -> None:
    if not directory.is_dir():
        return
    for path in manifest_files(directory):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            parts = path.relative_to(directory).parts
            spec = manifest_to_spec(raw, path, folder_category=parts[0] if len(parts) > 1 else None)
        except (OSError, yaml.YAMLError, ManifestError) as exc:
            result.errors.append((path, str(exc)))
            continue
        if spec.id in result.tools:
            if not user:
                result.errors.append((path, f"duplicate tool id {spec.id!r}"))
                continue
            result.overridden.append(spec.id)
        result.tools[spec.id] = spec


def load_manifests(builtin: Path | None = None, user: Path | None = None) -> LoadResult:
    result = LoadResult()
    load_dir(builtin or builtin_tools_dir(), result, user=False)
    load_dir(user or user_tools_dir(), result, user=True)
    return result
