"""Service classification: what a port really is (``plugins/services.yaml``, docs/PLUGINS.md).

nmap's service name is a guess from the banner: WinRM on 5985 shows up as ``http`` because it
speaks SOAP over HTTP. Rules and providers use :func:`service_kind` instead, so a WinRM endpoint
is never treated as a website. The table is data: built-in entries plus the user's
``~/.config/cyberdeck/services.yaml`` (tried first). A broken file is reported, never fatal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from cyberdeck.core.config import config_dir
from cyberdeck.core.models import Service

WEB = "web"


class KindRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    ports: list[int] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    tunnel: str | None = None

    @model_validator(mode="after")
    def _has_condition(self) -> KindRule:
        if not (self.ports or self.names or self.products or self.tunnel):
            raise ValueError(f"kind {self.kind!r}: needs ports, names, products or tunnel")
        return self

    def matches(self, svc: Service) -> bool:
        if self.ports and svc.port not in self.ports:
            return False
        if self.names and (svc.name or "").lower() not in {n.lower() for n in self.names}:
            return False
        if self.products:
            product = (svc.product or "").lower()
            if not any(p.lower() in product for p in self.products):
                return False
        return not (self.tunnel and svc.tunnel != self.tunnel)


@dataclass
class KindTable:
    rules: list[KindRule] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)

    def kind(self, svc: Service) -> str:
        for rule in self.rules:
            if rule.matches(svc):
                return rule.kind
        if svc.is_web:
            return WEB
        return (svc.name or "unknown").lower()


def builtin_kinds_file() -> Path:
    from cyberdeck.plugins.manifest import package_data_dir

    return package_data_dir() / "plugins" / "services.yaml"


def user_kinds_file() -> Path:
    return config_dir() / "services.yaml"


def _load(path: Path, table: KindTable) -> None:
    if not path.is_file():
        return
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError) as exc:
        table.errors.append((path, str(exc)))
        return
    if not isinstance(raw, list):
        table.errors.append((path, "services.yaml must be a YAML list"))
        return
    for index, item in enumerate(raw, start=1):
        try:
            table.rules.append(KindRule.model_validate(item))
        except ValidationError as exc:
            msg = "; ".join(e["msg"] for e in exc.errors())
            table.errors.append((path, f"entry #{index}: {msg}"))


_CACHE: dict[tuple[Path, Path, float, float], KindTable] = {}


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def kind_table() -> KindTable:
    """User entries first, then the built-in ones. Cached until either file changes."""
    user, builtin = user_kinds_file(), builtin_kinds_file()
    key = (user, builtin, _mtime(user), _mtime(builtin))
    if key not in _CACHE:
        table = KindTable()
        _load(user, table)
        _load(builtin, table)
        _CACHE.clear()
        _CACHE[key] = table
    return _CACHE[key]


def service_kind(svc: Service) -> str:
    return kind_table().kind(svc)
