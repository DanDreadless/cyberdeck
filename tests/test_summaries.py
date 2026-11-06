"""Learning track L2 (docs/LEARNING-PLAN.md W3): job summaries, highlights, failure
explanations, the password spotter and its question, Run-dialog teach text."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from textual.widgets import RichLog, Static
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import credscan, glossary, services
from cyberdeck.core.config import Settings
from cyberdeck.core.events import bus
from cyberdeck.core.models import (
    Credential,
    Finding,
    FindingType,
    Hash,
    Hostname,
    JobStatus,
    Note,
    Service,
    Share,
    Software,
    Url,
    User,
)
from cyberdeck.core.summarize import POSSIBLE_CREDENTIAL, explain_failure, summarize
from cyberdeck.core.tools import all_tools, get_tool, registry
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.ui import run_dialog as terminal_dialog
from cyberdeck.ui.tui.app import CyberdeckApp
from cyberdeck.ui.tui.dashboard import DashboardScreen
from cyberdeck.ui.tui.run_dialog import RunDialog
from cyberdeck.util.vpn import Tunnel, VpnStatus

from .conftest import FIXTURES, make_ws

IP = "10.129.231.15"
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"
TOOL_FIXTURES = Path(__file__).parent / "fixtures" / "tools"
SIZE = (160, 50)
runner = CliRunner()

CONFIG_DUMP = """\
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'W0rdPr3ss!2024');
$table_prefix = 'wp_';
<input type="password" name="password">
"""


@pytest.fixture(autouse=True)
def fresh(monkeypatch: pytest.MonkeyPatch) -> Any:
    registry(reload=True)
    bus.clear()
    monkeypatch.setattr(
        services,
        "vpn_check",
        lambda s, ip: VpnStatus(ip, True, [Tunnel("tun0", "10.10.14.7")], route_dev="tun0"),
    )
    monkeypatch.setattr(
        services, "RUNNER_LAUNCHER", lambda argv: [sys.executable, str(FAKE_TOOL), *argv[1:]]
    )
    yield
    bus.clear()


@pytest.fixture
def lantern(settings: Settings) -> Workspace:
    ws = make_ws(settings, "lantern", IP)
    services.import_nmap(ws, FIXTURES / "lantern")
    return ws


def _f(payload: Any, tags: list[str] | None = None) -> Finding:
    return Finding.of(payload, source="job:1:test", tags=tags or [])


def _kinds(summary: Any) -> list[str]:
    return [h.kind for h in summary.highlights]


# -- summaries --------------------------------------------------------------------------------


def test_summary_explains_each_kind_of_finding() -> None:
    created = [
        _f(Service(port=22, name="ssh", product="OpenSSH", version="8.9p1")),
        _f(Service(port=80, name="http", product="nginx", version="1.18.0")),
        _f(Software(name="Joomla", version="4.2.6", where="http://dev.box.htb/")),
        _f(Hostname(fqdn="dev.box.htb", ip=IP), tags=["vhost"]),
        _f(Url(url="http://box.htb/admin", status=302, redirect="http://box.htb/login")),
        _f(Url(url="http://box.htb/backup", status=403)),
        _f(Url(url="http://box.htb/about", status=200)),
        _f(User(name="logan")),
        _f(Credential(user="lewis", secret="P4ssw0rd!")),
        _f(Hash(value="$2y$10$abcdefghijklmnopqrstuv")),
        _f(Share(host=IP, name="dev", perms="READ, WRITE")),
        _f(Note(text="Default password is the device serial number"), tags=["hint"]),
    ]
    summary = summarize("whatever", JobStatus.DONE, created, new_suggestions=3)
    text = glossary.plain(summary.text)
    assert summary.headline == "whatever found 12 new thing(s)."
    assert "Open ports: 22 (ssh), 80 (http)" in text
    assert "OpenSSH 8.9p1" in text and "Joomla 4.2.6" in text
    assert "/admin (302 → /login)" in text and "/backup (403: exists but forbidden)" in text
    assert "/about" not in text.split("Worth a look first:")[1]  # not an interesting name
    assert "Usernames: logan" in text and "3 new next step(s)" in text
    assert "P4ssw0rd!" not in text and "P4ssw0rd!" not in str(summary.highlights)
    kinds = _kinds(summary)
    for kind in ("version", "vhost", "users", "credential", "hash", "share", "hint"):
        assert kind in kinds, kind
    assert glossary.load_glossary().unknown(summary.text) == []
    for hl in summary.highlights:
        assert glossary.load_glossary().unknown(hl.meaning) == []


def test_summary_when_nothing_was_found_or_it_failed() -> None:
    empty = summarize("gobuster dir", JobStatus.DONE, [])
    assert empty.headline == "gobuster dir found nothing new."
    assert "rule it out" in empty.text and not empty.highlights

    failed = summarize(
        "whatweb",
        JobStatus.FAILED,
        [],
        output_tail="ERROR Opening: http://box.htb/ - getaddrinfo: Name or service not known",
    )
    assert failed.headline == "whatweb failed."
    assert "/etc/hosts" in glossary.plain(failed.text)

    silent = summarize(  # exit code 0, but the output says what went wrong
        "WhatWeb",
        JobStatus.DONE,
        [],
        output_tail="ERROR Opening: http://nonexistent.htb:8799/ - no address for nonexistent.htb",
    )
    assert "points to a problem" in silent.text and "rule it out" not in silent.text
    assert glossary.plain("a [[rabbit-hole]] and [[vhost|vhosts]]") == "a rabbit hole and vhosts"

    slow = summarize(
        "feroxbuster", JobStatus.TIMEOUT, [_f(Url(url="http://x.htb/dev", status=200))]
    )
    assert "time limit" in slow.text and "found something before it stopped" in slow.text


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (
            "Error: the server returns a status code that matches the provided options for non "
            "existing urls",
            "wildcard",
        ),
        ("You requested a scan type which requires root privileges.", "sudo"),
        ("curl: (7) Failed to connect to 10.129.1.1 port 8080: Connection refused", "refused"),
        ("connect to host 10.129.1.1 port 22: No route to host", "VPN"),
        ("NT_STATUS_ACCESS_DENIED listing \\*", "login was refused"),
    ],
)
def test_failure_explanations(output: str, expected: str) -> None:
    message = explain_failure(output)
    assert message is not None and expected in glossary.plain(message)
    assert explain_failure("all fine") is None


# -- password spotting ------------------------------------------------------------------------


def test_credscan_finds_real_passwords_and_ignores_noise() -> None:
    text = CONFIG_DUMP + "\n".join(
        [
            "DB_USERNAME=admin",
            "DB_PASSWORD=S3cret2024",
            "mysql://root:toor123@127.0.0.1/app",
            "Enter your password, please",
            "bypass=1",
            "password = request.form['password']",
            "pwd: $PASS",
            "password: ********",
            "password_hash = abcdef",
            "compass: north",
        ]
    )
    found = {(c.user, c.secret) for c in credscan.find_candidates(text)}
    assert found == {
        ("wpuser", "W0rdPr3ss!2024"),
        ("admin", "S3cret2024"),
        ("root", "toor123"),
    }


async def test_password_in_output_becomes_a_question_and_then_loot(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dump = tmp_path / "wp-config.php"
    dump.write_text(CONFIG_DUMP, encoding="utf-8")
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "feroxbuster.json"))
    monkeypatch.setenv("FAKE_TOOL_STDOUT", str(dump))
    plan = services.plan_tool(lantern, "feroxbuster", settings=settings)
    plan.set_option("url", "http://lantern.htb/")
    outcome = await services.execute_plan(lantern, settings, plan)

    assert [f.type for f in outcome.possible_credentials] == [FindingType.NOTE]
    note = outcome.possible_credentials[0]
    assert POSSIBLE_CREDENTIAL in note.tags and note.data["text"] == "wpuser:W0rdPr3ss!2024"
    assert services.mask_finding(note)["data"]["text"].startswith("<hidden")
    assert outcome.summary is not None and "password?" in _kinds(outcome.summary)
    assert "W0rdPr3ss" not in outcome.summary.text

    question = next(
        s for s in services.list_suggestions(lantern) if s.rule_id == "creds.possible-password"
    )
    assert "W0rdPr3ss" not in question.title and "W0rdPr3ss" not in question.ask["prompt"]
    assert question.ask["default"] == "wpuser:W0rdPr3ss!2024"
    result = services.answer_question(lantern, question.id or 0, "wpuser:W0rdPr3ss!2024")
    cred = result.created[0].as_(Credential)
    assert (cred.user, cred.secret) == ("wpuser", "W0rdPr3ss!2024")

    # Seen again (a re-run, or the same config elsewhere): already in Loot, not asked again.
    again = await services.execute_plan(lantern, settings, plan)
    assert again.possible_credentials == []


async def test_job_summary_of_a_past_job(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "feroxbuster.json"))
    plan = services.plan_tool(lantern, "feroxbuster", settings=settings)
    plan.set_option("url", "http://lantern.htb/")
    outcome = await services.execute_plan(lantern, settings, plan)
    job_id = outcome.result.job.id or 0

    past = services.job_summary(lantern, job_id)
    assert outcome.summary is not None and past.headline == outcome.summary.headline
    assert "new path(s)" in past.text

    out = runner.invoke(cli.app, ["job", str(job_id), "-t", str(lantern.path)])
    assert out.exit_code == 0, out.output
    assert "▶ feroxbuster found" in out.output and "[[" not in out.output


# -- teach text -------------------------------------------------------------------------------


def test_teach_text_is_valid_and_links_resolve() -> None:
    gloss = glossary.load_glossary()
    taught = [t for t in all_tools() if t.teach is not None]
    assert len(taught) >= 20
    for tool in taught:
        assert tool.teach is not None and tool.teach.does and tool.teach.look_for, tool.id
        assert gloss.unknown(tool.teach.does + tool.teach.look_for) == [], tool.id
    assert get_tool("nmap-services").teach is not None


def test_terminal_run_dialog_shows_teach_text_unless_turned_off(
    lantern: Workspace, settings: Settings
) -> None:
    plan = services.plan_tool(lantern, "whatweb", settings=settings)
    console = Console(record=True, width=160)
    terminal_dialog.render(plan, console, show_advanced=False, is_root=False)
    shown = console.export_text()
    assert "What it does:" in shown and "Look for:" in shown and "[[" not in shown

    cfg = load_user_config()
    cfg.learning.summaries = False
    save_user_config(cfg)
    console = Console(record=True, width=160)
    terminal_dialog.render(plan, console, show_advanced=False, is_root=False)
    assert "What it does:" not in console.export_text()


async def test_tui_run_dialog_teach_and_job_summary(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = load_user_config()
    cfg.first_run_done = True
    save_user_config(cfg)
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb-redirect.json"))
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.pause()
        dashboard = app.screen
        assert isinstance(dashboard, DashboardScreen)
        dashboard.tools_flow(("whatweb",))
        await pilot.pause()
        await pilot.pause()
        dialog = app.screen
        assert isinstance(dialog, RunDialog)
        teach = str(dialog.query_one("#teach", Static).render())
        assert "What it does:" in teach and "[[" not in teach
        await pilot.press("ctrl+r")
        await app.workers.wait_for_complete()
        await pilot.pause()
        log = dashboard.query_one("#log", RichLog)
        logged = "\n".join(str(line.text) for line in log.lines)
        assert "▶ WhatWeb found" in logged
        assert dashboard._fresh  # new findings are starred until the next job
