"""Glossary: plain-word definitions for the jargon in suggestions (docs/LEARNING-PLAN.md W7).

Text anywhere in Cyberdeck (rule ``why:``, later checklists and summaries) links a term as
``[[id]]`` or ``[[id|words shown]]``. The TUI underlines linked terms and ``g`` shows their
definitions; the CLI and MCP get the plain words (:func:`plain`).

Built-in terms live in ``learn/glossary.yaml`` (shipped as package data); the user's
``~/.config/cyberdeck/glossary.yaml`` adds terms or replaces one with the same id. The built-in
list can be turned off with ``learning.glossary: false``; the user's file still loads. Broken
entries are reported, never fatal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from rich.text import Text

from cyberdeck.core.config import config_dir

TERM_RE = re.compile(r"\[\[([^\[\]|]+?)(?:\|([^\[\]]+?))?\]\]")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]*$")
TERM_STYLE = "underline"


class Term(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    term: str
    short: str
    aliases: list[str] = Field(default_factory=list)
    learn: str | None = None
    see: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError("id must be lower case letters, digits, dots or dashes")
        return value

    @field_validator("aliases", mode="before")
    @classmethod
    def _aliases(cls, value: Any) -> Any:
        """YAML reads ``[301, 302]`` as numbers; aliases are always text."""
        if isinstance(value, list):
            return [str(v) if isinstance(v, int | float) else v for v in value]
        return value

    @field_validator("short")
    @classmethod
    def _short(cls, value: str) -> str:
        text = " ".join(value.split())
        if not text:
            raise ValueError("short must not be empty")
        return text


def _norm(name: str) -> str:
    return " ".join(name.strip().lower().split())


@dataclass
class Glossary:
    terms: dict[str, Term] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    _lookup: dict[str, str] = field(default_factory=dict)

    def add(self, term: Term, where: str) -> None:
        old = self.terms.get(term.id)
        if old is not None:  # replacing (user file): drop the old names first
            self._lookup = {k: v for k, v in self._lookup.items() if v != term.id}
        self.terms[term.id] = term
        for name in (term.id, term.term, *term.aliases):
            key = _norm(name)
            owner = self._lookup.get(key)
            if owner is not None and owner != term.id:
                self.errors.append(f"{where}: {term.id}: name {name!r} is already {owner!r}")
                continue
            self._lookup[key] = term.id

    def get(self, name: str) -> Term | None:
        term_id = self._lookup.get(_norm(name))
        return self.terms.get(term_id) if term_id else None

    def linked(self, text: str) -> list[Term]:
        """Known terms linked in ``text``, first mention first, no duplicates."""
        found: list[Term] = []
        for name in terms_in(text):
            term = self.get(name)
            if term is not None and term not in found:
                found.append(term)
        return found

    def unknown(self, text: str) -> list[str]:
        return [name for name in terms_in(text) if self.get(name) is None]

    def rich(self, text: str, style: str = "") -> Text:
        """``text`` with links rendered: known terms underlined, unknown ones as plain words."""
        out = Text(style=style)
        pos = 0
        for match in TERM_RE.finditer(text):
            out.append(text[pos : match.start()])
            shown = _shown(match)
            known = self.get(match.group(1)) is not None
            out.append(shown, style=TERM_STYLE if known else "")
            pos = match.end()
        out.append(text[pos:])
        return out


def terms_in(text: str) -> list[str]:
    """The term names linked in ``text`` (``[[name]]`` or ``[[name|shown]]``), in order."""
    return [m.group(1).strip() for m in TERM_RE.finditer(text or "")]


def plain(text: str) -> str:
    """``text`` with ``[[...]]`` links replaced by their shown words (for the CLI and MCP)."""
    return TERM_RE.sub(_shown, text or "")


def _shown(match: re.Match[str]) -> str:
    """The words a link shows: ``[[id|words]]`` -> words, a bare ``[[rabbit-hole]]`` -> the id
    with dashes as spaces ("rabbit hole")."""
    return match.group(2) or match.group(1).replace("-", " ")


def builtin_glossary_path() -> Path:
    from cyberdeck.plugins.manifest import package_data_dir

    return package_data_dir() / "learn" / "glossary.yaml"


def user_glossary_path() -> Path:
    return config_dir() / "glossary.yaml"


def _load_file(path: Path, glossary: Glossary, disabled: set[str]) -> None:
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError) as exc:
        glossary.errors.append(f"{path}: {exc}")
        return
    if not isinstance(raw, list):
        glossary.errors.append(f"{path}: expected a list of terms")
        return
    for index, entry in enumerate(raw):
        try:
            term = Term.model_validate(entry)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first["loc"])
            glossary.errors.append(f"{path} entry {index + 1}: {where}: {first['msg']}")
            continue
        if term.id not in disabled:
            glossary.add(term, path.name)


def load_glossary(
    *,
    builtin: Path | None = None,
    user: Path | None = None,
    include_builtin: bool | None = None,
    disabled: list[str] | None = None,
) -> Glossary:
    """Built-in terms (unless turned off in Settings), then the user's. ``include_builtin`` and
    ``disabled`` default to the ``learning:`` section of config.yaml."""
    if include_builtin is None or disabled is None:
        from cyberdeck.core.userconfig import load_user_config

        learning = load_user_config().learning
        include_builtin = learning.glossary if include_builtin is None else include_builtin
        disabled = learning.disabled_ids if disabled is None else disabled
    glossary = Glossary()
    skip = set(disabled)
    sources = [
        (builtin or builtin_glossary_path(), include_builtin),
        (user or user_glossary_path(), True),
    ]
    for path, wanted in sources:
        if wanted and path.is_file():
            _load_file(path, glossary, skip)
    return glossary
