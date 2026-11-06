"""Phase 4: events, rules, suggestions, questions, auto mode and the hosts-file manager."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError
from rich.console import Console
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.events import EventBus, FindingsChanged, JobFinished, SuggestionsChanged, bus
from cyberdeck.core.models import (
    Finding,
    Hostname,
    Service,
    SuggestionStatus,
)
from cyberdeck.core.options import OptionError
from cyberdeck.core.tools import registry
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.plugins.detect import ToolStatus
from cyberdeck.rules.engine import BoxState, evaluate, load_rules
from cyberdeck.rules.schema import Rule
from cyberdeck.util import hosts as hostsfile

from .conftest import FIXTURES, make_ws

IP = "10.129.231.15"
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"
TOOL_FIXTURES = Path(__file__).parent / "fixtures" / "tools"
runner = CliRunner()


@pytest.fixture(autouse=True)
def fresh() -> Any:
    registry(reload=True)
    bus.clear()
    yield
    bus.clear()


@pytest.fixture
def lantern(settings: Settings) -> Workspace:
    ws = make_ws(settings, "lantern", IP)
    services.import_nmap(ws, FIXTURES / "lantern")
    return ws


def _open(ws: Workspace) -> dict[str, Any]:
    return {s.rule_id + " " + (s.values.get("url") or ""): s for s in services.list_suggestions(ws)}


def _map_hosts(settings: Settings, line: str) -> None:
    settings.hosts_file.write_text(f"127.0.0.1\tlocalhost\n{line}\n", encoding="utf-8")


def _installed(monkeypatch: pytest.MonkeyPatch, *ids: str) -> None:
    def fake(tool: Any, **_: Any) -> ToolStatus:
        path = f"/usr/bin/{tool.binary}" if tool.id in ids else None
        return ToolStatus(tool.id, tool.binary, path, "1.0" if path else None, None)

    monkeypatch.setattr(services, "detect", fake)
    monkeypatch.setattr(
        services, "detect_all", lambda tools, refresh=False: {t.id: fake(t) for t in tools}
    )


# --- events ---------------------------------------------------------------------------------


def test_event_bus_subscribe_emit_unsubscribe(tmp_path: Path) -> None:
    local = EventBus()
    seen: list[str] = []
    unsub = local.subscribe(FindingsChanged, lambda e: seen.append(e.source))
    local.subscribe(JobFinished, lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    local.emit(FindingsChanged(tmp_path, source="a"))
    local.emit(JobFinished(tmp_path))  # a failing handler is logged, not raised
    unsub()
    local.emit(FindingsChanged(tmp_path, source="b"))
    assert seen == ["a"]


def test_import_and_refresh_emit_events(settings: Settings) -> None:
    events: list[object] = []
    bus.subscribe(FindingsChanged, events.append)
    bus.subscribe(SuggestionsChanged, events.append)
    ws = make_ws(settings, "lantern", IP)
    services.import_nmap(ws, FIXTURES / "lantern")
    kinds = [type(e).__name__ for e in events]
    assert kinds[0] == "FindingsChanged" and "SuggestionsChanged" in kinds


# --- schema and loading ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"id": "x", "why": "w"}, "exactly one of suggest: or ask:"),
        ({"id": "x", "why": "w", "suggest": {"tool": "a"}}, "needs a title"),
        (
            {"id": "x", "why": "w", "title": "t", "suggest": {"tool": "a", "group": "b"}},
            "exactly one",
        ),
        (
            {"id": "x", "why": "w", "ask": {"prompt": "p"}, "requires_state": {"nope": True}},
            "unknown",
        ),
        (
            {"id": "x", "why": "w", "ask": {"prompt": "p"}, "requires_state": {"has_web": "yes"}},
            "true or false",
        ),
        ({"id": "x", "why": "w", "ask": {"prompt": "p", "action": "finding.add"}}, "needs finding"),
        (
            {"id": "x", "why": "w", "ask": {"prompt": "p"}, "when": {"match": {"a": 1}}},
            "need a finding",
        ),
        (
            {
                "id": "x",
                "why": "w",
                "ask": {"prompt": "p"},
                "when": {"finding": "url", "match": {"a": {"bad": 1}}},
            },
            "unknown operator",
        ),
        ({"id": "Bad Id", "why": "w", "ask": {"prompt": "p"}}, "pattern"),
    ],
)
def test_rule_schema_errors(raw: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Rule.model_validate(raw)


def test_builtin_rules_load_and_validate() -> None:
    rules = services.rule_set()
    assert rules.errors == []
    assert {"hosts.add", "hosts.guess", "web.fingerprint", "web.dirs", "recon.udp"} <= set(
        rules.rules
    )
    assert {
        "rpc.endpoints",
        "rpc.null-session",
        "rpc.rid-brute",
        "rpc.rpcbind",
        "smb.shares-anonymous",
        "smb.access-null",
        "ad.asrep-roast",
        "ad.kerberoast",
        "creds.smb-reuse",
        "dns.zone-transfer",
        "snmp.walk",
        "nfs.exports",
        "mysql.default-login",
        "web.wordlist",
        "web.sqli",
    } <= set(rules.rules)


def test_user_rules_override_and_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rules_dir = tmp_path / "xdg" / "cyberdeck" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "mine.yaml").write_text(
        yaml.safe_dump(
            [
                {"id": "web.nikto", "why": "mine", "title": "t", "suggest": {"tool": "nikto"}},
                {"id": "my.bad", "why": "w", "title": "t", "suggest": {"tool": "no-such-tool"}},
                {
                    "id": "my.badopt",
                    "why": "w",
                    "title": "t",
                    "suggest": {"tool": "whatweb", "with": {"x": "1"}},
                },
                {"id": "my.broken"},
            ]
        ),
        encoding="utf-8",
    )
    (rules_dir / "notalist.yaml").write_text("id: x\n", encoding="utf-8")
    rules = services.rule_set()
    assert rules.rules["web.nikto"].why == "mine" and "web.nikto" in load_rules().overridden
    errors = " | ".join(msg for _, msg in rules.errors)
    assert "unknown tool 'no-such-tool'" in errors and "no option or input 'x'" in errors
    assert "rule my.broken" in errors and "YAML list" in errors
    assert "my.bad" not in rules.rules


# --- matching -------------------------------------------------------------------------------


def _state(findings: list[Finding], hosts: dict[str, list[str]] | None = None) -> BoxState:
    return BoxState(ip=IP, name="Box", slug="box", findings=findings, hosts=hosts or {})


def _svc(**kw: Any) -> Finding:
    return Finding.of(Service(**kw), source="test")


@pytest.mark.parametrize(
    ("match", "hit"),
    [
        ({"name": "HTTP"}, True),  # case-insensitive
        ({"name": ["ssh", "http"]}, True),
        ({"port": 8080}, False),
        ({"product": {"regex": "^ngi"}}, True),
        ({"version": {"exists": False}}, True),
        ({"product": {"contains": "GINX"}}, True),
        ({"name": {"not": ["http", "https"]}}, False),
        ({"tags": {"contains": "web"}}, True),
        ({"is_web": True, "url": {"regex": "^http://10\\."}}, True),
    ],
)
def test_match_dsl(match: dict[str, Any], hit: bool) -> None:
    finding = _svc(port=80, name="http", product="nginx").model_copy(update={"tags": ["web"]})
    rule = Rule.model_validate(
        {
            "id": "t",
            "why": "w",
            "title": "t",
            "when": {"finding": "service", "match": match},
            "suggest": {"tool": "whatweb"},
        }
    )
    assert bool(evaluate([rule], _state([finding])).candidates) is hit


def test_unknown_template_variable_is_an_error_missing_value_is_skipped() -> None:
    finding = _svc(port=80, name="http")
    bad = Rule.model_validate(
        {
            "id": "bad",
            "why": "w",
            "title": "{service.nope}",
            "when": {"finding": "service"},
            "suggest": {"tool": "whatweb"},
        }
    )
    waits = Rule.model_validate(
        {
            "id": "waits",
            "why": "w",
            "title": "{domain} {service.product}",
            "suggest": {"tool": "whatweb"},
            "when": {"finding": "service"},
        }
    )
    result = evaluate([bad, waits], _state([finding]))
    assert result.candidates == [] and result.errors == [
        ("bad", "unknown template variable {service.nope}")
    ]


# --- suggestions lifecycle --------------------------------------------------------------------


def test_lantern_suggestions_follow_the_hosts_file(lantern: Workspace, settings: Settings) -> None:
    found = _open(lantern)
    assert "hosts.add " in found and "web.fingerprint http://10.129.231.15/" in found
    assert not any(k.startswith("web.dirs") for k in found)  # waits for the hosts entry
    assert found["hosts.add "].kind == "ask" and found["hosts.add "].priority == 100
    assert found["web.fingerprint http://10.129.231.15/"].safety == "safe"

    _map_hosts(settings, f"{IP} lantern.htb")
    after = _open(lantern)
    assert "hosts.add " not in after  # stale now
    assert "web.fingerprint http://lantern.htb/" in after
    assert "web.dirs http://lantern.htb/" in after and "web.nikto http://lantern.htb/" in after
    assert after["web.nikto http://lantern.htb/"].safety == "intrusive"
    vhosts = [s for s in after.values() if s.rule_id == "web.vhosts"]
    assert vhosts and vhosts[0].values == {"url": "http://10.129.231.15/", "domain": "lantern.htb"}
    stale = [s for s in services.list_suggestions(lantern, include_closed=True)]
    assert all(s.status is SuggestionStatus.OPEN for s in stale)  # stale ones are hidden


def test_skip_snooze_reopen_and_disabled(lantern: Workspace, settings: Settings) -> None:
    fp = _open(lantern)["web.fingerprint http://10.129.231.15/"]
    assert fp.id is not None
    services.set_suggestion_status(lantern, fp.id, SuggestionStatus.SKIPPED)
    assert "web.fingerprint http://10.129.231.15/" not in _open(lantern)
    services.set_suggestion_status(lantern, fp.id, SuggestionStatus.SNOOZED)
    assert "web.fingerprint http://10.129.231.15/" not in _open(lantern)
    with lantern.store() as store:  # something new turns up: snoozed ones come back
        store.upsert(Finding.of(Hostname(fqdn="dev.lantern.htb", ip=IP), source="test"))
    assert "web.fingerprint http://10.129.231.15/" in _open(lantern)

    cfg = load_user_config()
    cfg.disabled_tools = ["whatweb"]
    save_user_config(cfg)
    assert not any(s.tool == "whatweb" for s in services.list_suggestions(lantern))
    with pytest.raises(OptionError, match="no suggestion"):
        services.get_suggestion(lantern, 999)


@pytest.fixture
def fake_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        services, "RUNNER_LAUNCHER", lambda argv: [sys.executable, str(FAKE_TOOL), *argv[1:]]
    )


async def test_running_a_suggestion_marks_it_done_and_opens_new_ones(
    lantern: Workspace, settings: Settings, fake_tool: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb-redirect.json"))
    fp = _open(lantern)["web.fingerprint http://10.129.231.15/"]
    assert fp.id is not None
    sug, plan = services.plan_suggestion(lantern, fp.id, settings)
    assert plan.values["url"] == "http://10.129.231.15/"
    outcome = await services.execute_plan(lantern, settings, plan, suggestion_id=fp.id)
    assert outcome.result.ok
    done = services.get_suggestion(lantern, fp.id)
    assert done.status is SuggestionStatus.DONE and done.job_id == outcome.result.job.id
    hosts_q = _open(lantern)["hosts.add "]
    with pytest.raises(OptionError, match="question"):
        services.plan_suggestion(lantern, hosts_q.id or 0, settings)


async def test_a_job_run_by_hand_completes_the_matching_suggestion(
    lantern: Workspace, settings: Settings, fake_tool: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb.json"))
    plan = services.plan_tool(lantern, "whatweb", settings=settings)
    await services.execute_plan(lantern, settings, plan)
    closed = services.list_suggestions(lantern, include_closed=True)
    fp = next(s for s in closed if s.rule_id == "web.fingerprint")
    assert fp.status is SuggestionStatus.DONE and fp.job_id == 1


def test_hostname_question_creates_a_finding(settings: Settings) -> None:
    ws = make_ws(settings, "Box", IP)
    with ws.store() as store:
        store.upsert(Finding.of(Service(port=80, name="http"), source="test"))
    guess = next(s for s in services.list_suggestions(ws) if s.rule_id == "hosts.guess")
    assert guess.ask["default"] == "box.htb" and guess.ask["input"] is True
    with pytest.raises(OptionError, match="can't use that answer"):
        services.answer_question(ws, guess.id or 0, "not a hostname")
    result = services.answer_question(ws, guess.id or 0, "box.htb")
    assert result.created and result.created[0].key == "box.htb"
    assert result.suggestion.status is SuggestionStatus.DONE
    assert any(s.rule_id == "hosts.add" for s in services.list_suggestions(ws))


def test_saying_no_skips_a_question(lantern: Workspace) -> None:
    q = _open(lantern)["hosts.add "]
    with pytest.raises(OptionError, match="hosts_plan_add"):
        services.answer_question(lantern, q.id or 0, True)
    assert (
        services.answer_question(lantern, q.id or 0, False).suggestion.status
        is SuggestionStatus.SKIPPED
    )


def test_auto_runnable_only_safe_installed_no_root(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installed(monkeypatch, "whatweb", "nikto", "feroxbuster", "nmap-udp")
    _map_hosts(settings, f"{IP} lantern.htb")
    picked = {
        s.rule_id for s in services.auto_runnable(lantern, services.list_suggestions(lantern))
    }
    assert "web.fingerprint" in picked and "web.dirs" in picked
    assert "web.nikto" not in picked  # intrusive
    assert "web.vhosts" not in picked  # ffuf not installed
    assert "recon.udp" not in picked  # needs root (and not open yet)


# --- hosts file -----------------------------------------------------------------------------


def test_plan_add_creates_updates_and_warns(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    path.write_text(
        "127.0.0.1\tlocalhost\n10.10.11.5 old.htb lantern.htb\n"
        "10.129.1.1\tlantern.htb other.htb\t# cyberdeck:other\n",
        encoding="utf-8",
    )
    change = hostsfile.plan_add(path, IP, ["lantern.htb", "Dev.Lantern.htb"], "lantern")
    assert change.changed and change.added == ["lantern.htb", "dev.lantern.htb"]
    assert f"{IP}\tlantern.htb dev.lantern.htb\t# cyberdeck:lantern" in change.after
    assert "10.129.1.1\tother.htb\t# cyberdeck:other" in change.after  # name moved off other box
    assert change.removed == ["lantern.htb"]
    assert "10.10.11.5 old.htb lantern.htb" in change.after  # the user's line is untouched
    assert any("line 2 maps lantern.htb to 10.10.11.5" in w for w in change.warnings)
    assert "+10.129.231.15" in change.diff()
    assert path.read_text(encoding="utf-8") == change.before  # planning writes nothing

    path.write_text(change.after, encoding="utf-8")
    again = hostsfile.plan_add(path, IP, ["lantern.htb"], "lantern")
    assert not again.changed and again.added == []
    moved = hostsfile.plan_add(path, "10.129.9.9", [], "lantern")  # set-ip: same line, new IP
    assert "10.129.9.9\tlantern.htb dev.lantern.htb\t# cyberdeck:lantern" in moved.after
    assert IP not in moved.after

    removed = hostsfile.plan_remove(path, "lantern")
    assert "cyberdeck:lantern" not in removed.after and "cyberdeck:other" in removed.after
    everything = hostsfile.plan_remove(path, None)
    assert "cyberdeck:" not in everything.after and "localhost" in everything.after


def test_hosts_apply_backs_up_refuses_stale_plans_and_refreshes(
    lantern: Workspace, settings: Settings
) -> None:
    assert services.box_hostnames(lantern) == ["lantern.htb"]
    lines, missing = services.hosts_status(lantern, settings)
    assert lines == [] and missing == ["lantern.htb"]
    change = services.hosts_plan_add(lantern, settings=settings)
    assert not services.hosts_needs_sudo(settings)  # a temp file: no sudo in tests
    backup = services.hosts_apply(change, lantern, settings)
    assert backup is not None and backup.read_text(encoding="utf-8") == change.before
    assert hostsfile.resolves_to(settings.hosts_file, "lantern.htb", IP)
    assert "web.dirs http://lantern.htb/" in _open(lantern)  # suggestions refreshed

    stale = services.hosts_plan_remove(lantern, settings)
    settings.hosts_file.write_text("changed\n", encoding="utf-8")
    with pytest.raises(services.HostsError, match="changed since"):
        services.hosts_apply(stale, lantern, settings)
    assert services.hosts_apply(services.hosts_plan_remove(lantern, settings)) is None  # no-op


# --- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def cli_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "console", Console(width=200))
    monkeypatch.setattr(cli, "err_console", Console(width=200, stderr=True))
    monkeypatch.setattr(cli, "have_binary", lambda name: True)
    monkeypatch.setattr(cli, "is_root", lambda: False)

    from cyberdeck.util.vpn import Tunnel, VpnStatus

    monkeypatch.setattr(
        services,
        "vpn_check",
        lambda s, ip: VpnStatus(ip, True, [Tunnel("tun0", "10.10.14.7")], route_dev="tun0"),
    )


def test_cli_suggest_hosts_flow(lantern: Workspace, settings: Settings, cli_ready: None) -> None:
    t = ["-t", str(lantern.path)]
    listing = runner.invoke(cli.app, ["suggest", *t])
    assert listing.exit_code == 0, listing.output
    assert "Add lantern.htb (10.129.231.15) to /etc/hosts?" in listing.output
    assert "question" in listing.output and "whatweb" in listing.output
    q = _open(lantern)["hosts.add "]

    declined = runner.invoke(cli.app, ["suggest", "run", str(q.id), *t], input="n\n")
    assert declined.exit_code == 0 and "Not changed." in declined.output
    assert not hostsfile.resolves_to(settings.hosts_file, "lantern.htb", IP)

    accepted = runner.invoke(cli.app, ["suggest", "run", str(q.id), *t], input="y\n")
    assert accepted.exit_code == 0, accepted.output
    added_line = next(line for line in accepted.output.splitlines() if line.startswith("+10."))
    assert added_line.split() == ["+10.129.231.15", "lantern.htb", "#", "cyberdeck:lantern"]
    assert hostsfile.resolves_to(settings.hosts_file, "lantern.htb", IP)
    assert services.get_suggestion(lantern, q.id or 0).status is SuggestionStatus.DONE

    shown = runner.invoke(cli.app, ["hosts", *t])
    assert "# cyberdeck:lantern" in shown.output and "Not mapped" not in shown.output
    gone = runner.invoke(cli.app, ["hosts", "remove", "--yes", *t])
    assert gone.exit_code == 0 and not hostsfile.resolves_to(settings.hosts_file, "lantern.htb", IP)
    assert "Nothing to remove" in runner.invoke(cli.app, ["hosts", "remove", "-y", *t]).output

    added = runner.invoke(cli.app, ["hosts", "add", "lantern.htb", "extra.htb", "-y", *t])
    assert added.exit_code == 0 and hostsfile.resolves_to(settings.hosts_file, "extra.htb", IP)
    assert "extra.htb" in services.box_hostnames(lantern)
    bad = runner.invoke(cli.app, ["hosts", "add", "not_a name", "-y", *t])
    assert bad.exit_code == 1 and "not a usable hostname" in bad.output

    fp = _open(lantern)["web.fingerprint http://lantern.htb/"]
    skipped = runner.invoke(cli.app, ["suggest", "skip", str(fp.id), *t])
    assert skipped.exit_code == 0 and "skipped" in skipped.output
    every = runner.invoke(cli.app, ["suggest", "--all", "-e", *t])
    assert "skipped" in every.output and "Learn:" in every.output
    assert runner.invoke(cli.app, ["suggest", "reopen", str(fp.id), *t]).exit_code == 0
    assert runner.invoke(cli.app, ["suggest", "run", "999", *t]).exit_code == 1


def test_cli_hostname_question(settings: Settings, cli_ready: None) -> None:
    ws = make_ws(settings, "Box", IP)
    with ws.store() as store:
        store.upsert(Finding.of(Service(port=80, name="http"), source="test"))
    guess = next(s for s in services.list_suggestions(ws) if s.rule_id == "hosts.guess")
    result = runner.invoke(
        cli.app, ["suggest", "run", str(guess.id), "-t", str(ws.path)], input="\n"
    )
    assert result.exit_code == 0, result.output
    assert "recorded hostname box.htb" in result.output and "cyberdeck hosts add" in result.output


def test_cli_auto_chains_safe_steps_only(
    lantern: Workspace,
    settings: Settings,
    cli_ready: None,
    fake_tool: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _installed(monkeypatch, "whatweb", "nikto")
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb-redirect.json"))
    result = runner.invoke(
        cli.app, ["auto", "--dont-ask", "--rounds", "2", "-t", str(lantern.path)]
    )
    assert result.exit_code == 0, result.output
    assert "Auto round 1/2" in result.output and "$ whatweb" in result.output
    assert "nikto" not in result.output.split("Waiting for you")[0]
    assert "Waiting for you" in result.output and "question" in result.output
    jobs = services.list_jobs(lantern)
    assert jobs and all(j.origin == "auto" and j.tool == "whatweb" for j in jobs)


def test_cli_auto_dialog_no_marks_skipped(
    lantern: Workspace, cli_ready: None, fake_tool: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installed(monkeypatch, "whatweb")
    result = runner.invoke(cli.app, ["auto", "-t", str(lantern.path)], input="q\n")
    assert result.exit_code == 0, result.output
    assert "Skipped WhatWeb" in result.output and "ran 0 job(s)" in result.output
    closed = services.list_suggestions(lantern, include_closed=True)
    assert (
        next(s for s in closed if s.rule_id == "web.fingerprint").status is SuggestionStatus.SKIPPED
    )


def test_cli_set_ip_moves_the_hosts_line(
    lantern: Workspace, settings: Settings, cli_ready: None
) -> None:
    services.hosts_apply(services.hosts_plan_add(lantern, settings=settings), lantern, settings)
    result = runner.invoke(cli.app, ["set-ip", "10.129.9.9", "-t", str(lantern.path)], input="y\n")
    assert result.exit_code == 0, result.output
    assert hostsfile.resolves_to(settings.hosts_file, "lantern.htb", "10.129.9.9")
    assert not hostsfile.resolves_to(settings.hosts_file, "lantern.htb", IP)
