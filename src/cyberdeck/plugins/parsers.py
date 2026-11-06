"""Parser registry: a tool's raw output on disk -> findings (docs/PLUGINS.md "Parsers").

Parsers are pure functions of a :class:`ParseContext`; they read files and return findings,
never touching the store, so a past job can be re-parsed after a parser improves.

Built-in generic parsers: ``none``, ``lines_regex`` and ``jsonl`` (configured by the manifest's
``parser_config``). Tool-specific parsers live in ``plugins/parsers/*.py`` (built in) and
``~/.config/cyberdeck/plugins/parsers/*.py`` (user), and register themselves with ``@parser``.
"""

from __future__ import annotations

import importlib.util
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from cyberdeck.core.models import PAYLOAD_TYPES, Finding, FindingType, Hostname, normalise_fqdn
from cyberdeck.core.options import OptionError, render_template


class ParserError(Exception):
    pass


@dataclass(frozen=True)
class ParseContext:
    tool_id: str
    job_id: int
    target_ip: str
    workspace: Path
    stdout: Path
    stderr: Path
    outputs: list[Path]  # declared outputs, absolute (may not exist if the tool failed)
    values: dict[str, Any] = field(default_factory=dict)  # option + input values used
    ctx: dict[str, str] = field(default_factory=dict)  # template context used
    config: dict[str, Any] = field(default_factory=dict)  # manifest parser_config

    @property
    def source(self) -> str:
        return f"job:{self.job_id}:{self.tool_id}"

    def output(self) -> Path:
        """The first declared output that exists, else stdout."""
        return next((p for p in self.outputs if p.is_file()), self.stdout)

    def read(self, path: Path | None = None) -> str:
        target = path or self.output()
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def finding(
        self, payload: Any, *, confidence: float = 1.0, tags: list[str] | None = None
    ) -> Finding:
        return Finding.of(payload, source=self.source, confidence=confidence, tags=tags or [])

    def hostname_from_url(
        self, url: str | None, origin: str, confidence: float = 0.7
    ) -> Finding | None:
        """A Hostname finding for a URL's host if it is a name (not an IP)."""
        if not url:
            return None
        host = urlsplit(url).hostname or ""
        fqdn = normalise_fqdn(host)
        if fqdn is None:
            return None
        payload = Hostname(fqdn=fqdn, ip=self.target_ip, kind="host", origins=[origin])
        return self.finding(payload, confidence=confidence)


ParserFn = Callable[[ParseContext], list[Finding]]

_REGISTRY: dict[str, ParserFn] = {}
_LOADED: set[Path] = set()


def parser(name: str) -> Callable[[ParserFn], ParserFn]:
    """Register a parser under ``name`` (referenced by a manifest's ``parser:``)."""

    def register(fn: ParserFn) -> ParserFn:
        _REGISTRY[name] = fn
        return fn

    return register


def load_parser_dir(directory: Path) -> list[tuple[Path, str]]:
    """Import every ``*.py`` in ``directory`` once. Returns (file, error) for broken ones."""
    errors: list[tuple[Path, str]] = []
    if not directory.is_dir():
        return errors
    for path in sorted(directory.glob("*.py")):
        resolved = path.resolve()
        if resolved in _LOADED or path.name.startswith("_"):
            continue
        _LOADED.add(resolved)
        module_name = f"cyberdeck_parsers_{abs(hash(resolved)):x}_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            errors.append((path, "cannot load"))
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # a broken user parser must not take Cyberdeck down
            errors.append((path, f"{type(exc).__name__}: {exc}"))
    return errors


def load_all() -> list[tuple[Path, str]]:
    from cyberdeck.plugins.manifest import builtin_parsers_dir, user_parsers_dir

    return load_parser_dir(builtin_parsers_dir()) + load_parser_dir(user_parsers_dir())


def get_parser(name: str) -> ParserFn:
    if name not in _REGISTRY:
        load_all()
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ParserError(f"no parser named {name!r}") from None


def parser_names() -> list[str]:
    load_all()
    return sorted(_REGISTRY)


def run_parser(name: str, ctx: ParseContext) -> list[Finding]:
    fn = get_parser(name)
    try:
        return fn(ctx)
    except ParserError:
        raise
    except Exception as exc:
        raise ParserError(f"parser {name!r} failed: {type(exc).__name__}: {exc}") from exc


# --- generic parsers ------------------------------------------------------------------------


@parser("none")
def parse_none(ctx: ParseContext) -> list[Finding]:
    """Keep the raw output only."""
    return []


def _build(
    ctx: ParseContext, type_name: str, fields: dict[str, Any], tags: list[str], confidence: float
) -> Finding | None:
    try:
        payload_cls = PAYLOAD_TYPES[FindingType(type_name)]
    except ValueError:
        raise ParserError(f"unknown finding type {type_name!r}") from None
    clean = {k: v for k, v in fields.items() if v is not None and v != ""}
    try:
        payload = payload_cls.model_validate(clean)
    except ValidationError:
        return None  # one odd line never sinks the whole parse
    return ctx.finding(payload, confidence=confidence, tags=tags)


def _constants(ctx: ParseContext, raw: dict[str, Any]) -> dict[str, Any]:
    full = {**ctx.ctx, **{k: str(v) for k, v in ctx.values.items() if v is not None}}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(value, str):
            try:
                value = render_template(value, full)
            except OptionError:
                continue
        out[key] = value
    return out


@parser("lines_regex")
def parse_lines_regex(ctx: ParseContext) -> list[Finding]:
    """``parser_config: {patterns: [{regex, type, set?, tags?, confidence?}]}``.

    Each line is matched against every pattern; named groups become payload fields and ``set``
    adds constant fields (templated, e.g. ``where: "{url}"``).
    """
    patterns = ctx.config.get("patterns") or []
    compiled = [(re.compile(p["regex"]), p) for p in patterns]
    found: list[Finding] = []
    for line in ctx.read().splitlines():
        for regex, pattern in compiled:
            match = regex.search(line)
            if not match:
                continue
            fields = {**_constants(ctx, pattern.get("set") or {}), **match.groupdict()}
            finding = _build(
                ctx,
                pattern["type"],
                fields,
                list(pattern.get("tags") or []),
                float(pattern.get("confidence", 0.8)),
            )
            if finding is not None:
                found.append(finding)
    return found


def json_lines(text: str) -> Iterator[dict[str, Any]]:
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            yield obj


def _dig(obj: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


@parser("jsonl")
def parse_jsonl(ctx: ParseContext) -> list[Finding]:
    """``parser_config: {type, fields: {payload_field: "json.path"}, match?: {path: value},
    set?, tags?, confidence?}``: one finding per JSON line."""
    cfg = ctx.config
    type_name = cfg.get("type")
    if not type_name:
        raise ParserError("jsonl parser needs parser_config.type")
    mapping: dict[str, str] = cfg.get("fields") or {}
    match: dict[str, Any] = cfg.get("match") or {}
    found: list[Finding] = []
    for obj in json_lines(ctx.read()):
        if any(_dig(obj, k) != v for k, v in match.items()):
            continue
        fields = {**_constants(ctx, cfg.get("set") or {})}
        fields.update({name: _dig(obj, path) for name, path in mapping.items()})
        finding = _build(
            ctx, type_name, fields, list(cfg.get("tags") or []), float(cfg.get("confidence", 0.8))
        )
        if finding is not None:
            found.append(finding)
    return found
