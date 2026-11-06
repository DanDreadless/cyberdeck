"""Learning track L4 (journal, lessons, write-up, playbook, path, skills) and the .env-only
paths (CYBERDECK_VPN_DIR, Settings lock)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from mcp.client.client import Client
from textual.widgets import DataTable, Input, SelectionList, Static
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import glossary, services
from cyberdeck.core.config import Settings, load_settings
from cyberdeck.core.events import bus
from cyberdeck.core.models import Credential, Finding, Hash
from cyberdeck.core.tools import registry
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.mcp_server.server import build_server
from cyberdeck.ui.tui.app import CyberdeckApp
from cyberdeck.ui.tui.dashboard import DashboardScreen
from cyberdeck.ui.tui.journal import JournalScreen, LessonModal, ProgressScreen
from cyberdeck.ui.tui.learning import SettingsScreen
from cyberdeck.ui.tui.modals import InputModal
from cyberdeck.util.vpn import Tunnel, VpnStatus

from .conftest import FIXTURES, make_ws

IP = "10.129.231.15"
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"
TOOL_FIXTURES = Path(__file__).parent / "fixtures" / "tools"
SIZE = (160, 50)
FLAG = "0123456789abcdef0123456789abcdef"
runner = CliRunner()
REAL_VPN_CHECK = services.vpn_check


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


def _loot(ws: Workspace) -> None:
    with ws.store() as store:
        store.upsert(Finding.of(Credential(user="lewis", secret="P4ss-W0rd!"), source="user"))
        store.upsert(Finding.of(Hash(value="$2y$10$abcdefghijklmnopqrstuv"), source="user"))


async def _run_whatweb(ws: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb-redirect.json"))
    plan = services.plan_tool(ws, "whatweb", settings=settings)
    plan.set_option("url", f"http://{IP}/")
    await services.execute_plan(ws, settings, plan)


# -- content ----------------------------------------------------------------------------------


def test_techniques_and_paths_load_cleanly() -> None:
    content = services.load_methodology()
    assert content.errors == []
    assert len(content.techniques) >= 20 and content.paths
    gloss = glossary.load_glossary()
    for tech in content.techniques.values():
        assert tech.term is None or gloss.get(tech.term) is not None, tech.id
    steps = content.paths["htb-beginner"].steps
    assert steps[0].box == "Meow" and all(s.skills for s in steps)


# -- lessons, journal, write-up ---------------------------------------------------------------


async def test_journal_tells_the_story(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _run_whatweb(lantern, settings, monkeypatch)
    services.start_lead(lantern, "the login page")
    services.stuck_report(lantern, 2)
    assert services.record_flag(lantern, "user", FLAG)
    assert lantern.meta.flags.user_at is not None
    services.record_lesson(
        lantern,
        "user",
        "reused DB password",
        "read configs first",
        ["password-reuse", "config-file-creds"],
    )
    with pytest.raises(services.OptionError, match="unknown technique"):
        services.record_lesson(lantern, "user", "", "", ["telepathy"])

    entries = services.journal(lantern)
    kinds = [e.kind for e in entries]
    assert kinds[0] == "box" and {"job", "lead", "help", "flag", "lesson"} <= set(kinds)
    assert entries == sorted(entries, key=lambda e: e.at)
    texts = " | ".join(e.text for e in entries)
    assert "WhatWeb found" in texts and "User flag captured" in texts
    lesson = next(e for e in entries if e.kind == "lesson")
    assert "What got me in: reused DB password" in lesson.details


def test_writeup_masks_loot_and_personal_paths(lantern: Workspace, settings: Settings) -> None:
    _loot(lantern)
    services.record_flag(lantern, "root", FLAG)
    services.append_note(
        lantern, f"lewis / P4ss-W0rd! worked. Box at {lantern.path}/loot", author="me"
    )
    text = services.writeup(lantern, settings)
    assert "# lantern: write-up" in text and "| 22/tcp | ssh |" in text
    assert "P4ss-W0rd!" not in text and FLAG not in text and "$2y$10$abc" not in text
    assert "‹hidden›" in text
    assert str(lantern.path) not in text and str(settings.root) not in text
    assert "./loot" in text  # the box folder shows as "."
    revealed = services.writeup(lantern, settings, reveal=True)
    assert "P4ss-W0rd!" in revealed and FLAG not in revealed  # flags: only when, never the value
    assert str(lantern.path) not in revealed  # paths stay neutral even then

    path = services.export_writeup(lantern, settings)
    assert path == lantern.path / "writeup.md" and "P4ss-W0rd!" not in path.read_text()


def test_writeup_file_any_case_and_export_never_clobbers(
    lantern: Workspace, settings: Settings
) -> None:
    assert services.writeup_file(lantern) == lantern.path / "writeup.md"
    assert services.read_writeup(lantern) == ""
    hand = lantern.path / "WRITEUP.md"  # e.g. written by Claude over MCP
    hand.write_text("# Lantern: my own write-up\n", encoding="utf-8")
    assert services.writeup_file(lantern).name == "WRITEUP.md"
    assert "my own write-up" in services.read_writeup(lantern)
    with pytest.raises(services.WriteupExistsError):
        services.export_writeup(lantern, settings)
    assert "my own write-up" in hand.read_text()
    services.save_writeup(lantern, "# edited\n")
    assert hand.read_text() == "# edited\n" and not (lantern.path / "writeup.md").exists()
    path = services.export_writeup(lantern, settings, overwrite=True)
    assert path.name == "WRITEUP.md" and "# lantern: write-up" in path.read_text()


# -- playbook, seen before, path, skills ------------------------------------------------------


def test_playbook_seen_before_path_and_skills(settings: Settings, lantern: Workspace) -> None:
    soccer = make_ws(settings, "soccer", "10.129.1.20")
    services.record_lesson(
        soccer, "user", "dev. vhost had the app", "fuzz vhosts early", ["vhost-fuzzing"]
    )
    services.record_lesson(soccer, "root", "sudo -l showed doas", "", ["sudo-misconfig"])
    services.record_lesson(lantern, "note", "nothing yet", "", ["vhost-fuzzing"])

    everything = services.playbook(settings)
    assert [e.box for e in everything][:1] == ["lantern"]  # newest first
    assert [e.lesson.got_in for e in services.playbook(settings, "doas")] == ["sudo -l showed doas"]

    seen = services.seen_before(lantern, settings)
    assert [e.box for e in seen] == ["soccer"]  # vhost-fuzzing fits lantern; sudo needs a shell
    assert seen[0].lesson.got_in == "dev. vhost had the app"
    assert services.stuck_report(lantern, 1, log=False).seen_before == seen

    meow = make_ws(settings, "Meow", "10.129.1.21")
    services.record_flag(meow, "root", FLAG)
    make_ws(settings, "fawn", "10.129.1.22")
    ((_, steps),) = services.learning_paths(settings)
    status = {s.step.box: s.status for s in steps}
    assert status["Meow"] == "root" and status["Fawn"] == "started" and status["Lame"] == "todo"

    counts = {s.technique.id: s.boxes for s in services.skills(settings)}
    assert counts["vhost-fuzzing"] == ["lantern", "soccer"] and counts["sudo-misconfig"] == [
        "soccer"
    ]

    cfg = load_user_config()
    cfg.learning.paths = False
    save_user_config(cfg)
    assert services.learning_paths(settings) == []


# -- CLI and MCP ------------------------------------------------------------------------------


def test_cli_lesson_journal_writeup_playbook_path_skills(lantern: Workspace) -> None:
    t = ["-t", str(lantern.path)]
    _loot(lantern)
    out = runner.invoke(cli.app, ["flag", "user", FLAG, *t])
    assert out.exit_code == 0 and "cyberdeck lesson --kind user" in out.output  # not a TTY
    out = runner.invoke(
        cli.app,
        ["lesson", "--kind", "user", *t],
        input="creds in a backup\n\nhash-cracking, nope\n",
    )
    assert out.exit_code == 0, out.output
    assert "Ignoring unknown: nope" in out.output
    assert services.list_lessons(lantern)[0].techniques == ["hash-cracking"]

    journal = runner.invoke(cli.app, ["journal", *t])
    assert "User flag captured" in journal.output and "creds in a backup" in journal.output
    shown = runner.invoke(cli.app, ["writeup", *t, "--stdout"])
    assert "P4ss-W0rd!" not in shown.output and "‹hidden›" in shown.output
    saved = runner.invoke(cli.app, ["writeup", *t])
    assert saved.exit_code == 0 and (lantern.path / "writeup.md").is_file()
    again = runner.invoke(cli.app, ["writeup", *t])
    assert again.exit_code == 1 and "--force" in again.output
    forced = runner.invoke(cli.app, ["writeup", *t, "--force"])
    assert forced.exit_code == 0, forced.output
    assert "creds in a backup" in runner.invoke(cli.app, ["playbook", "backup"]).output
    path = runner.invoke(cli.app, ["path"])
    assert path.exit_code == 0 and "Meow" in path.output and "rooted" in path.output
    skills = runner.invoke(cli.app, ["skills"])
    assert "Cracking a hash" in skills.output and "lantern" in skills.output


async def test_mcp_journal_and_playbook(lantern: Workspace, settings: Settings) -> None:
    services.record_lesson(lantern, "note", "found the hostname", "", ["vhost-fuzzing"])
    server = build_server(settings, str(lantern.path))
    async with Client(server) as client:
        journal = await client.call_tool("get_journal", {})
        items = (journal.structured_content or {})["result"]
        assert items[0]["kind"] == "box" and any(i["kind"] == "lesson" for i in items)
        playbook = await client.call_tool("get_playbook", {"query": "hostname"})
        found = (playbook.structured_content or {})["result"]
        assert found[0]["box"] == "lantern" and found[0]["techniques"] == ["vhost-fuzzing"]


# -- .env-only paths --------------------------------------------------------------------------


def test_vpn_dir_and_env_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lantern: Workspace
) -> None:
    vpn = tmp_path / "vpn"
    vpn.mkdir()
    (vpn / "machines_us-1.ovpn").write_text("client\n")
    monkeypatch.setenv("CYBERDECK_VPN_DIR", str(vpn))
    settings = load_settings()
    assert settings.vpn_search_dir == vpn
    seen: list[Path] = []

    def fake_status(ip: str, root: Path, explicit: Path | None = None) -> VpnStatus:
        seen.append(root)
        return VpnStatus(ip, True)

    monkeypatch.setattr(services, "vpn_status", fake_status)
    REAL_VPN_CHECK(settings, IP)  # the fixture replaced services.vpn_check; use the real one
    assert seen == [vpn]

    assert settings.from_env("vpn_dir")
    assert not settings.from_env("vpn_config")
    monkeypatch.delenv("CYBERDECK_VPN_DIR")
    Path(".env").write_text("CYBERDECK_WORKSPACE_ROOT=~/boxes   # mine\n", encoding="utf-8")
    assert load_settings().from_env("workspace_root")


async def test_settings_locks_workspace_set_in_env(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = load_user_config()
    cfg.first_run_done = True
    save_user_config(cfg)
    app = CyberdeckApp(load_settings())  # CYBERDECK_WORKSPACE_ROOT is set by conftest
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.press("comma")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)
        assert screen.query_one("#root", Input).disabled
        await pilot.press("ctrl+s")
        await pilot.pause()
    assert load_user_config().workspace_root is None  # nothing saved over the .env value


# -- TUI --------------------------------------------------------------------------------------


async def test_tui_flag_questions_journal_and_progress(
    lantern: Workspace, settings: Settings
) -> None:
    cfg = load_user_config()
    cfg.first_run_done = True
    save_user_config(cfg)
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.pause()
        dashboard = app.screen
        assert isinstance(dashboard, DashboardScreen)
        dashboard.flag_flow()
        await pilot.pause()
        await pilot.press("enter")  # "User flag" in the picker
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, InputModal)
        modal.query_one(Input).value = FLAG
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()
        lesson = app.screen
        assert isinstance(lesson, LessonModal)
        lesson.query_one("#got-in", Input).value = "default creds on the admin page"
        lesson.query_one("#techniques", SelectionList).select("default-creds")
        await pilot.press("ctrl+s")
        await pilot.pause()
        saved = services.list_lessons(lantern)
        assert saved[0].kind == "user" and saved[0].techniques == ["default-creds"]

        await pilot.press("o")
        await pilot.pause()
        journal = app.screen
        assert isinstance(journal, JournalScreen)
        assert "default creds on the admin page" in str(
            journal.query_one("#journal-body", Static).render()
        )
        await pilot.press("e")
        await pilot.pause()
        assert (lantern.path / "writeup.md").is_file()
        await pilot.press("escape")
        await pilot.press("escape")  # back to the boxes
        await pilot.pause()
        await pilot.press("p")
        await pilot.pause()
        progress = app.screen
        assert isinstance(progress, ProgressScreen)
        table: DataTable[Any] = progress.query_one("#path-table", DataTable)
        assert table.row_count >= 20
