"""Rule schema (docs/RULES.md): a rule turns findings and box state into a suggested tool run
or a question for the user."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyberdeck.core.models import FindingType

Phase = Literal["recon", "enumeration", "foothold", "privesc", "loot"]
AskAction = Literal["none", "hosts.add", "finding.add"]

# requires_state keys and the kind of value each takes.
STATE_KEYS: dict[str, str] = {
    "has_services": "bool",
    "has_versions": "bool",  # any service has a product/version or script output
    "has_web": "bool",  # an open service of kind web
    "has_hostname": "bool",
    "has_domain": "bool",
    "hostname_in_hosts": "bool",  # the best hostname maps to the box IP in the hosts file
    "web_ready": "bool",  # no hostname known yet, or the best one is in the hosts file
    "os": "list",  # any OS guess contains one of these (case-insensitive)
    "ports": "list",  # any of these TCP ports is open
    "services": "list",  # any nmap service name is one of these
    "kinds": "list",  # any open service is of one of these kinds (plugins/services.yaml)
    "software": "list",  # any software/product contains one of these
    "jobs_done": "list",  # every one of these tools has a finished job
}

MATCH_OPERATORS = frozenset({"regex", "exists", "not", "contains"})


def _check_match(spec: dict[str, Any], where: str) -> None:
    for field_name, cond in spec.items():
        if isinstance(cond, dict):
            unknown = set(cond) - MATCH_OPERATORS
            if unknown:
                raise ValueError(
                    f"{where}.{field_name}: unknown operator(s) {sorted(unknown)} "
                    f"(use {', '.join(sorted(MATCH_OPERATORS))})"
                )


class When(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: FindingType | None = None  # None: a box-level rule, evaluated once
    match: dict[str, Any] = Field(default_factory=dict)
    unless: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _ops(self) -> When:
        _check_match(self.match, "match")
        _check_match(self.unless, "unless")
        if (self.match or self.unless) and self.finding is None:
            raise ValueError("match/unless need a finding: type")
        return self


class SuggestTool(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    tool: str | None = None
    group: str | None = None
    with_: dict[str, str] = Field(default_factory=dict, alias="with")
    preset: str | None = None

    @field_validator("with_", mode="before")
    @classmethod
    def _text(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: str(v) for k, v in value.items()}
        return value

    @model_validator(mode="after")
    def _one(self) -> SuggestTool:
        if bool(self.tool) == bool(self.group):
            raise ValueError("suggest: needs exactly one of tool: or group:")
        return self

    @property
    def ref(self) -> str:
        return self.tool or self.group or ""


class Ask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str
    action: AskAction = "none"
    input: bool = False  # free-text answer (else yes/no)
    default: str | None = None  # pre-filled answer (templated)
    finding: dict[str, Any] | None = None  # finding.add: {type: ..., <field>: "{answer}"...}
    args: dict[str, str] = Field(default_factory=dict)  # action arguments (templated)

    @model_validator(mode="after")
    def _action(self) -> Ask:
        if self.action == "finding.add":
            if not self.finding or "type" not in self.finding:
                raise ValueError("ask.action finding.add needs finding: {type: ..., ...}")
            FindingType(self.finding["type"])
        elif self.finding:
            raise ValueError("ask.finding is only used with action: finding.add")
        return self


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    phase: Phase = "enumeration"
    when: When = Field(default_factory=When)
    requires_state: dict[str, Any] = Field(default_factory=dict)
    suggest: SuggestTool | None = None
    ask: Ask | None = None
    title: str | None = None
    why: str
    learn: str | None = None
    priority: int = Field(default=50, ge=0, le=100)
    dedupe: str | None = None  # template; default: rule id + rendered with:/prompt
    source: str | None = None  # file it came from

    @field_validator("requires_state")
    @classmethod
    def _state(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key, cond in value.items():
            kind = STATE_KEYS.get(key)
            if kind is None:
                raise ValueError(f"unknown requires_state key {key!r} ({', '.join(STATE_KEYS)})")
            if kind == "bool" and not isinstance(cond, bool):
                raise ValueError(f"requires_state.{key} must be true or false")
            if kind == "list" and not isinstance(cond, list):
                raise ValueError(f"requires_state.{key} must be a list")
        return value

    @model_validator(mode="after")
    def _shape(self) -> Rule:
        if (self.suggest is None) == (self.ask is None):
            raise ValueError("a rule needs exactly one of suggest: or ask:")
        if self.suggest is not None and not self.title:
            raise ValueError("a suggest: rule needs a title")
        return self

    @property
    def kind(self) -> Literal["tool", "ask"]:
        return "tool" if self.suggest is not None else "ask"
