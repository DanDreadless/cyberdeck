"""Settings and secrets loading (CLAUDE.md "Secrets and .env").

Precedence (highest first): real environment variables > ``~/.config/cyberdeck/.env`` >
``./.env`` > ``~/.config/cyberdeck/config.yaml`` (preferences Cyberdeck saves) > defaults.
Secrets are ``SecretStr`` so they never appear in reprs or logs.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from cyberdeck.core.scope import DEFAULT_SCOPE_CIDRS, Scope


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "cyberdeck"


def cache_dir() -> Path:
    """Disposable caches (tool detection, captured ``--help``). Never findings: those live only
    in each box's folder."""
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "cyberdeck"


def default_env_files() -> tuple[Path, ...]:
    """Env files in increasing priority (later files override earlier ones)."""
    return (Path.cwd() / ".env", config_dir() / ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CYBERDECK_", extra="ignore", env_ignore_empty=True
    )

    workspace_root: Path = Path("~/Documents/htb")
    vpn_config: Path | None = None  # one .ovpn file; default: machines_*.ovpn in vpn_search_dir
    vpn_dir: Path | None = None  # folder holding your .ovpn files; default: workspace_root
    hosts_file: Path = Path("/etc/hosts")
    scope_cidrs: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: list(DEFAULT_SCOPE_CIDRS)
    )
    scope_extra: Annotated[list[str], NoDecode] = Field(default_factory=list)

    mcp_token: SecretStr | None = None
    wpscan_api_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("WPSCAN_API_TOKEN", "CYBERDECK_WPSCAN_API_TOKEN"),
    )
    htb_api_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("HTB_API_TOKEN", "CYBERDECK_HTB_API_TOKEN")
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        yaml_source = YamlConfigSettingsSource(settings_cls, yaml_file=config_dir() / "config.yaml")
        return (init_settings, env_settings, dotenv_settings, yaml_source, file_secret_settings)

    @field_validator("scope_cidrs", "scope_extra", mode="before")
    @classmethod
    def _split_list(cls, value: object) -> object:
        """Accept a JSON list or a comma-separated string."""
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                return json.loads(text)
            return [part.strip() for part in text.split(",") if part.strip()]
        return value

    @property
    def root(self) -> Path:
        return self.workspace_root.expanduser()

    @property
    def vpn_search_dir(self) -> Path:
        """Where Cyberdeck looks for .ovpn files: ``CYBERDECK_VPN_DIR``, else the workspace."""
        return (self.vpn_dir or self.workspace_root).expanduser()

    def from_env(self, field: str) -> bool:
        """True when ``field`` is set by an environment variable or a .env file (so a value
        saved in config.yaml from the Settings screen would be ignored)."""
        name = f"CYBERDECK_{field.upper()}"
        if os.environ.get(name):
            return True
        for env_file in default_env_files():
            if env_file.is_file():
                for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    key, sep, value = line.partition("=")
                    if sep and key.strip() == name and value.split("#")[0].strip():
                        return True
        return False

    def scope(self) -> Scope:
        return Scope.from_cidrs([*self.scope_cidrs, *self.scope_extra])


def load_settings(env_files: Sequence[Path] | None = None) -> Settings:
    files = default_env_files() if env_files is None else tuple(env_files)
    existing = tuple(f for f in files if f.is_file())
    return Settings(_env_file=existing or None)
