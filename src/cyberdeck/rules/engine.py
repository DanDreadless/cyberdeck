"""Rule loader and matcher (docs/RULES.md).

:func:`evaluate` is pure: given the rules and a snapshot of a box (findings, jobs, hosts file),
it returns the suggestions that apply right now. The service layer stores them (with their
done/skipped/snoozed status) in the box DB and re-evaluates whenever something changes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from cyberdeck.core.classify import WEB, service_kind
from cyberdeck.core.config import config_dir
from cyberdeck.core.facts import BoxFacts, best_domain, best_hostname
from cyberdeck.core.models import Finding, FindingType, Hostname, Job, JobStatus, Service
from cyberdeck.rules.schema import Rule

_VAR = re.compile(r"\{([a-z0-9_.]+)\}")


# --- loading --------------------------------------------------------------------------------


def builtin_rules_dir() -> Path:
    from cyberdeck.plugins.manifest import package_data_dir

    return package_data_dir() / "rules"


def user_rules_dir() -> Path:
    return config_dir() / "rules"


@dataclass
class RuleSet:
    rules: dict[str, Rule] = field(default_factory=dict)
    errors: list[tuple[Path, str]] = field(default_factory=list)
    overridden: list[str] = field(default_factory=list)


def _load_file(path: Path, result: RuleSet, *, user: bool) -> None:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        result.errors.append((path, str(exc)))
        return
    if raw is None:
        return
    if not isinstance(raw, list):
        result.errors.append((path, "a rules file must be a YAML list of rules"))
        return
    for index, item in enumerate(raw):
        label = item.get("id", f"#{index + 1}") if isinstance(item, dict) else f"#{index + 1}"
        try:
            rule = Rule.model_validate({**item, "source": str(path)})
        except (ValidationError, TypeError) as exc:
            if isinstance(exc, ValidationError):
                msg = "; ".join(
                    f"{'.'.join(str(p) for p in e['loc']) or 'rule'}: {e['msg']}"
                    for e in exc.errors()
                )
            else:
                msg = "a rule must be a mapping"
            result.errors.append((path, f"rule {label}: {msg}"))
            continue
        if rule.id in result.rules:
            if not user:
                result.errors.append((path, f"duplicate rule id {rule.id!r}"))
                continue
            result.overridden.append(rule.id)
        result.rules[rule.id] = rule


def load_rules(builtin: Path | None = None, user: Path | None = None) -> RuleSet:
    """Built-in rules, then the user's (``~/.config/cyberdeck/rules/*.yaml``); a user rule with
    the same id replaces the built-in one. Broken rules are reported, never fatal."""
    result = RuleSet()
    for directory, is_user in (
        (builtin or builtin_rules_dir(), False),
        (user or user_rules_dir(), True),
    ):
        if directory.is_dir():
            for path in sorted(directory.glob("*.y*ml")):
                _load_file(path, result, user=is_user)
    return result


# --- box snapshot ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BoxState:
    ip: str
    name: str
    slug: str
    findings: list[Finding]
    jobs: list[Job] = field(default_factory=list)
    hosts: dict[str, list[str]] = field(default_factory=dict)  # parsed hosts file
    groups: dict[str, list[str]] = field(default_factory=dict)  # group -> member tool ids

    @cached_property
    def facts(self) -> BoxFacts:
        return BoxFacts.from_findings(self.findings)

    def in_hosts(self, name: str) -> bool:
        return self.ip in self.hosts.get(name.lower(), [])

    @cached_property
    def web_host(self) -> str | None:
        """The hostname web URLs should use: the best hostname once the hosts file maps it."""
        host = best_hostname(self.facts)
        return host if host and self.in_hosts(host) else None

    @cached_property
    def done_tools(self) -> set[str]:
        return {j.tool for j in self.jobs if j.status is JobStatus.DONE}


@dataclass(frozen=True)
class Candidate:
    rule: Rule
    key: str
    title: str
    values: dict[str, str]  # rendered with:
    ask: dict[str, Any]  # rendered question
    finding: str | None  # "type:key" that triggered it
    done_job: int | None  # a finished job already did this


@dataclass
class Evaluation:
    candidates: list[Candidate] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (rule id, message)


# --- matching -------------------------------------------------------------------------------


def _norm(value: Any) -> Any:
    return value.casefold() if isinstance(value, str) else value


def _match_value(value: Any, cond: Any) -> bool:
    if isinstance(cond, dict):
        ok = True
        if "exists" in cond:
            present = value is not None and value != "" and value != [] and value != {}
            ok = ok and present == bool(cond["exists"])
        if "regex" in cond:
            items = value if isinstance(value, list) else [value]
            ok = ok and any(
                v is not None and re.search(str(cond["regex"]), str(v), re.IGNORECASE)
                for v in items
            )
        if "contains" in cond:
            needle = _norm(cond["contains"])
            if isinstance(value, list):
                ok = ok and needle in [_norm(v) for v in value]
            else:
                ok = ok and isinstance(value, str) and str(needle) in value.casefold()
        if "not" in cond:
            ok = ok and not _match_value(value, cond["not"])
        return ok
    if isinstance(value, list):
        wanted = cond if isinstance(cond, list) else [cond]
        return any(_norm(v) in [_norm(w) for w in wanted] for v in value)
    if isinstance(cond, list):
        return _norm(value) in [_norm(c) for c in cond]
    return bool(_norm(value) == _norm(cond))


def _match(view: dict[str, Any], spec: dict[str, Any]) -> bool:
    return all(_match_value(view.get(name), cond) for name, cond in spec.items())


def _state_ok(requires: dict[str, Any], state: BoxState) -> bool:
    facts = state.facts
    for key, cond in requires.items():
        if key == "has_services":
            ok = bool(facts.services)
        elif key == "has_versions":
            ok = any(s.product or s.version or s.scripts for s in facts.services)
        elif key == "has_web":
            ok = bool(facts.web_services)
        elif key == "has_hostname":
            ok = best_hostname(facts) is not None
        elif key == "has_domain":
            ok = best_domain(facts) is not None
        elif key == "hostname_in_hosts":
            ok = state.web_host is not None
        elif key == "web_ready":
            ok = best_hostname(facts) is None or state.web_host is not None
        elif key == "os":
            ok = any(str(n).lower() in f.lower() for n in cond for f in facts.os_families)
        elif key == "ports":
            open_ports = {s.port for s in facts.services if s.proto == "tcp" and s.state == "open"}
            ok = any(int(p) in open_ports for p in cond)
        elif key == "kinds":
            kinds = {service_kind(s) for s in facts.services if s.state == "open"}
            ok = any(str(k).lower() in kinds for k in cond)
        elif key == "services":
            service_names = {(s.name or "").lower() for s in facts.services}
            ok = any(str(n).lower() in service_names for n in cond)
        elif key == "software":
            names = [s.name.lower() for s in facts.software] + [
                (s.product or "").lower() for s in facts.services if s.product
            ]
            ok = any(str(n).lower() in name for n in cond for name in names)
        elif key == "jobs_done":
            ok = all(tool in state.done_tools for tool in cond)
        else:  # pragma: no cover - rejected by the schema
            ok = False
        if isinstance(cond, bool):
            ok = ok == cond
        if not ok:
            return False
    return True


state_ok = _state_ok  # public name: checklists and hints use the same box-state conditions


def finding_view(finding: Finding, state: BoxState) -> dict[str, Any]:
    """A finding's fields plus computed ones rules can match on and use in templates."""
    view: dict[str, Any] = dict(finding.data)
    view.update(
        key=finding.key, tags=finding.tags, confidence=finding.confidence, sources=finding.sources
    )
    if finding.type is FindingType.SERVICE:
        svc = finding.as_(Service)
        kind = service_kind(svc)
        is_site = kind == WEB
        view.update(
            kind=kind,
            is_web=svc.is_web,  # nmap's view ("http*"); rules should match kind: web
            is_tls=svc.is_tls,
            banner=svc.banner,
            url=svc.url(state.web_host or state.ip) if is_site else None,
            url_ip=svc.url(state.ip) if is_site else None,
        )
    elif finding.type is FindingType.HOSTNAME:
        host = finding.as_(Hostname)
        web = state.facts.web_services
        view.update(
            in_hosts_file=state.in_hosts(host.fqdn),
            is_vhost="vhost" in finding.tags,
            is_best=host.fqdn == best_hostname(state.facts),
            url=web[0].url(host.fqdn) if web else None,
        )
    return view


# --- templates ------------------------------------------------------------------------------


class _Missing(Exception):
    """A template uses a variable that is known but has no value yet (skip quietly)."""


class _Unknown(Exception):
    pass


def _render(text: str, ctx: dict[str, str], empty: set[str]) -> str:
    def sub(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in ctx:
            return ctx[name]
        if name in empty:
            raise _Missing(name)
        raise _Unknown(name)

    return _VAR.sub(sub, text)


def _as_text(value: Any) -> str | None:
    if value is None or value == "" or value == [] or isinstance(value, dict):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


def _context(state: BoxState, finding: Finding | None) -> tuple[dict[str, str], set[str]]:
    ctx = {"target.ip": state.ip, "target.name": state.name, "target.slug": state.slug}
    empty: set[str] = set()
    for name, value in (
        ("hostname", best_hostname(state.facts)),
        ("domain", best_domain(state.facts)),
        ("web_host", state.web_host or state.ip),
    ):
        if value:
            ctx[name] = value
        else:
            empty.add(name)
    if finding is not None:
        prefix = finding.type.value
        for name, value in finding_view(finding, state).items():
            text = _as_text(value)
            if text is None:
                empty.add(f"{prefix}.{name}")
            else:
                ctx[f"{prefix}.{name}"] = text
    ctx["answer"] = "{answer}"  # filled in when the question is answered
    ctx["answer.user"] = "{answer.user}"  # user:password answers, split at the first colon
    ctx["answer.secret"] = "{answer.secret}"
    return ctx, empty


def _done_job(ref: str, values: dict[str, str], state: BoxState) -> int | None:
    tools = set(state.groups.get(ref, [])) | {ref}

    def same(a: Any, b: str) -> bool:
        return str(a).rstrip("/") == b.rstrip("/")

    for job in reversed(state.jobs):
        if job.tool not in tools or job.status is not JobStatus.DONE:
            continue
        used = (job.meta or {}).get("values") or {}
        if all(k in used and same(used[k], v) for k, v in values.items()):
            return job.id
    return None


def _candidate(
    rule: Rule, state: BoxState, finding: Finding | None, ctx: dict[str, str], empty: set[str]
) -> Candidate:
    values: dict[str, str] = {}
    ask: dict[str, Any] = {}
    done: int | None = None
    if rule.suggest is not None:
        values = {k: _render(v, ctx, empty) for k, v in rule.suggest.with_.items()}
        done = _done_job(rule.suggest.ref, values, state)
        title = _render(rule.title or "", ctx, empty)
        default_key = json.dumps(values, sort_keys=True)
    elif rule.ask is not None:
        prompt = _render(rule.ask.prompt, ctx, empty)
        ask = {
            "prompt": prompt,
            "action": rule.ask.action,
            "input": rule.ask.input,
            "default": _render(rule.ask.default, ctx, empty) if rule.ask.default else None,
            "args": {k: _render(v, ctx, empty) for k, v in rule.ask.args.items()},
        }
        if rule.ask.finding:
            ask["finding"] = {
                k: _render(v, ctx, empty) if isinstance(v, str) else v
                for k, v in rule.ask.finding.items()
            }
        title = _render(rule.title, ctx, empty) if rule.title else prompt
        default_key = prompt
    else:  # pragma: no cover - the schema requires one of them
        raise _Unknown("suggest/ask")
    suffix = _render(rule.dedupe, ctx, empty) if rule.dedupe else default_key
    return Candidate(
        rule=rule,
        key=f"{rule.id}|{suffix}",
        title=title,
        values=values,
        ask=ask,
        finding=f"{finding.type.value}:{finding.key}" if finding else None,
        done_job=done,
    )


def evaluate(rules: Iterable[Rule], state: BoxState) -> Evaluation:
    """Every suggestion the rules make for this box right now, highest priority first."""
    result = Evaluation()
    seen: set[str] = set()
    for rule in rules:
        if not _state_ok(rule.requires_state, state):
            continue
        if rule.when.finding is None:
            targets: list[Finding | None] = [None]
        else:
            targets = [f for f in state.findings if f.type is rule.when.finding]
        for finding in targets:
            if finding is not None:
                view = finding_view(finding, state)
                if not _match(view, rule.when.match):
                    continue
                if rule.when.unless and _match(view, rule.when.unless):
                    continue
            ctx, empty = _context(state, finding)
            try:
                cand = _candidate(rule, state, finding, ctx, empty)
            except _Missing:
                continue  # e.g. {domain} before any domain is known
            except _Unknown as exc:
                result.errors.append((rule.id, f"unknown template variable {{{exc}}}"))
                break
            if cand.key in seen:
                continue
            seen.add(cand.key)
            result.candidates.append(cand)
    result.candidates.sort(key=lambda c: -c.rule.priority)
    return result
