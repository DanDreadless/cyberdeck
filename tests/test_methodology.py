"""Learning track L3 (docs/LEARNING-PLAN.md W4/W5): checklists, Stuck? levels 1-2, leads and
the rabbit-hole timer."""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from mcp.client.client import Client
from textual.widgets import DataTable, Static
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import glossary, methodology, services
from cyberdeck.core.config import Settings
from cyberdeck.core.events import bus
from cyberdeck.core.models import Finding, OsGuess, utcnow
from cyberdeck.core.tools import registry
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.mcp_server.server import build_server
from cyberdeck.ui.tui.app import CyberdeckApp
from cyberdeck.ui.tui.dashboard import DashboardScreen
from cyberdeck.ui.tui.methodology import ChecklistScreen, StuckModal
from cyberdeck.ui.tui.modals import InputModal
from cyberdeck.ui.tui.run_dialog import RunDialog
from cyberdeck.util.vpn import Tunnel, VpnStatus

from .conftest import FIXTURES, make_ws

IP = "10.129.231.15"
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"
TOOL_FIXTURES = Path(__file__).parent / "fixtures" / "tools"
SIZE = (160, 50)
runner = CliRunner()


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


def _states(ws: Workspace) -> dict[str, str]:
    return {e.item.id: e.state for e in services.checklist(ws)}


# -- content ----------------------------------------------------------------------------------


def test_builtin_content_is_valid() -> None:
    content = services.load_methodology()
    assert content.errors == []
    assert len(content.checklist) >= 40 and len(content.patterns) >= 12
    gloss = glossary.load_glossary()
    reg = registry()
    for item in content.checklist.values():
        assert item.section in methodology.SECTIONS, item.id
        assert gloss.unknown(item.why) == [], item.id
        if item.tool:
            assert item.tool in reg.tools or item.tool in reg.groups(), (item.id, item.tool)
    for pattern in content.patterns.values():
        assert gloss.unknown(pattern.hint) == [], pattern.id


def test_user_content_overrides_toggles_and_errors(tmp_path: Path) -> None:
    (tmp_path / "checklists").mkdir()
    (tmp_path / "checklists" / "mine.yaml").write_text(
        yaml.safe_dump(
            [
                {"id": "web.robots", "section": "web", "title": "My robots check", "why": "x"},
                {"id": "my.one", "section": "general", "title": "Mine", "why": "y"},
                {"id": "bad", "section": "web", "title": "t", "why": "w", "applies": {"nope": 1}},
            ]
        ),
        encoding="utf-8",
    )
    both = methodology.load_content(checklists=True, hints=True, disabled=[], user_root=tmp_path)
    assert both.checklist["web.robots"].title == "My robots check"
    assert "my.one" in both.checklist and "bad" not in both.checklist
    assert any("unknown condition 'nope'" in e for e in both.errors)

    off = methodology.load_content(checklists=False, hints=False, disabled=[], user_root=tmp_path)
    assert set(off.checklist) == {"web.robots", "my.one"} and off.patterns == {}
    hidden = methodology.load_content(
        checklists=True, hints=True, disabled=["web.git"], user_root=tmp_path
    )
    assert "web.git" not in hidden.checklist


# -- checklist --------------------------------------------------------------------------------


async def test_checklist_applies_ticks_and_marks(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    states = _states(lantern)
    assert states["general.all-ports"] == "auto"  # an imported scan counts
    assert states["general.versions"] == "auto"
    assert states["web.fingerprint"] == "open" and states["web.robots"] == "open"
    assert "smb.shares" not in states  # lantern has no SMB
    assert "shell.sudo" not in states  # no foothold yet

    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb.json"))
    plan = services.plan_tool(lantern, "whatweb", settings=settings)
    plan.set_option("url", "http://lantern.htb/")
    await services.execute_plan(lantern, settings, plan)
    assert _states(lantern)["web.fingerprint"] == "auto"  # ticked by the finished job

    services.mark_checklist(lantern, "web.robots", "done")
    services.mark_checklist(lantern, "web.git", "na")
    states = _states(lantern)
    assert states["web.robots"] == "done" and states["web.git"] == "na"
    done, total = services.coverage(services.checklist(lantern))["web"]
    assert done >= 3 and total >= done
    services.mark_checklist(lantern, "web.robots", "open")
    assert _states(lantern)["web.robots"] == "open"
    with pytest.raises(services.OptionError, match="no checklist item"):
        services.mark_checklist(lantern, "nope", "done")


def test_shell_items_follow_the_foothold_and_os(settings: Settings, lantern: Workspace) -> None:
    services.record_flag(lantern, "user", "a" * 32)
    states = _states(lantern)
    assert states["shell.sudo"] == "open" and "winshell.privs" not in states  # lantern: Linux

    win = make_ws(settings, "winbox", "10.129.1.30")
    with win.store() as store:
        store.upsert(Finding.of(OsGuess(family="Windows"), source="test"))
    services.record_flag(win, "user", "b" * 32)
    states = _states(win)
    assert "winshell.privs" in states and "shell.sudo" not in states


# -- Stuck? and leads -------------------------------------------------------------------------


def test_stuck_levels_and_help_log(lantern: Workspace) -> None:
    one = services.stuck_report(lantern, 1)
    assert one.untried and one.hints == []
    assert any(e.item.id == "web.robots" for e in one.untried)
    two = services.stuck_report(lantern, 2)
    ids = [p.id for p in two.hints]
    assert "hint.hostname" in ids and "hint.only-ssh-and-web" in ids
    assert ids == sorted(ids, key=lambda i: -services.load_methodology().patterns[i].priority)
    with lantern.store() as store:
        assert [h.kind for h in store.help_log()] == ["stuck-1", "stuck-2"]


def test_leads_and_rabbit_hole_timer(lantern: Workspace) -> None:
    first = services.start_lead(lantern, "  the /upload   page ")
    assert first.title == "the /upload page" and services.active_lead(lantern) == first
    second = services.start_lead(lantern, "vhosts")
    leads = {lead.id: lead.status for lead in services.list_leads(lantern)}
    assert leads == {first.id: "parked", second.id: "active"}

    assert services.rabbit_hole_check(lantern) is None  # just started
    later = utcnow() + timedelta(minutes=31)
    warned = services.rabbit_hole_check(lantern, later)
    assert warned is not None and warned.lead.id == second.id and warned.minutes_quiet >= 30
    assert services.rabbit_hole_check(lantern, later) is None  # only once per lead

    services.end_lead(lantern, "done")
    assert services.active_lead(lantern) is None
    resumed = services.end_lead(lantern, "active", first.id)
    assert resumed.status == "active" and not resumed.warned
    report = services.stuck_report(lantern, 1, log=False)
    assert report.parked == []  # first was resumed, second is done
    with pytest.raises(services.OptionError):
        services.start_lead(lantern, "   ")
    with pytest.raises(services.OptionError, match="no lead #99"):
        services.end_lead(lantern, "parked", 99)


# -- CLI and MCP ------------------------------------------------------------------------------


def test_cli_checklist_stuck_and_lead(lantern: Workspace) -> None:
    t = ["-t", str(lantern.path)]
    listing = runner.invoke(cli.app, ["checklist", *t])
    assert listing.exit_code == 0, listing.output
    assert "Website" in listing.output and "web.robots" in listing.output
    assert "general.all-ports" not in listing.output  # done: only with --all
    assert "general.all-ports" in runner.invoke(cli.app, ["checklist", *t, "--all"]).output
    assert runner.invoke(cli.app, ["checklist", "done", "web.robots", *t]).exit_code == 0
    assert _states(lantern)["web.robots"] == "done"
    assert runner.invoke(cli.app, ["checklist", "done", "nope", *t]).exit_code == 1

    stuck = runner.invoke(cli.app, ["stuck", *t, "--hint"])
    assert stuck.exit_code == 0, stuck.output
    assert "What haven't you tried?" in stuck.output and "The site wants its name" in stuck.output
    assert "[[" not in stuck.output

    assert runner.invoke(cli.app, ["lead", "start", "the admin page", *t]).exit_code == 0
    leads = runner.invoke(cli.app, ["lead", *t])
    assert "the admin page" in leads.output and "min on it" in leads.output
    assert runner.invoke(cli.app, ["lead", "park", *t]).exit_code == 0
    assert services.active_lead(lantern) is None


async def test_mcp_checklist_and_stuck(lantern: Workspace, settings: Settings) -> None:
    server = build_server(settings, str(lantern.path))
    async with Client(server) as client:
        result = await client.call_tool("get_checklist", {})
        data = result.structured_content or {}
        assert data["items"] and all(i["state"] == "open" for i in data["items"])
        assert "web" in data["coverage"]
        stuck = (await client.call_tool("stuck_report", {"level": 2})).structured_content or {}
        assert stuck["untried_checks"] and stuck["hints"]
        assert all("[[" not in h["hint"] for h in stuck["hints"])
        prompt = await client.get_prompt("stuck", {"target": "lantern"})
        assert "smallest useful nudge" in str(prompt)


# -- TUI --------------------------------------------------------------------------------------


def _skip_welcome() -> None:
    cfg = load_user_config()
    cfg.first_run_done = True
    save_user_config(cfg)


async def test_tui_checklist_stuck_and_lead(lantern: Workspace, settings: Settings) -> None:
    _skip_welcome()
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.pause()
        dashboard = app.screen
        assert isinstance(dashboard, DashboardScreen)

        await pilot.press("k")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ChecklistScreen)
        table: DataTable[Any] = screen.query_one("#checklist", DataTable)
        keys = [str(k.value) for k in table.rows]
        table.move_cursor(row=keys.index("web.robots"))
        await pilot.press("space")
        await pilot.pause()
        assert _states(lantern)["web.robots"] == "done"
        assert "Why:" in str(screen.query_one("#check-detail", Static).render())
        keys = [str(k.value) for k in screen.query_one("#checklist", DataTable).rows]
        screen.query_one("#checklist", DataTable).move_cursor(row=keys.index("web.fingerprint"))
        await pilot.press("r")  # its tool opens in the Run dialog, back on the dashboard
        await pilot.pause()
        await pilot.pause()
        assert isinstance(app.screen, RunDialog) and app.screen.plan.tool.id == "whatweb"
        await pilot.press("escape")
        await pilot.pause()

        await pilot.press("exclamation_mark")
        await pilot.pause()
        stuck = app.screen
        assert isinstance(stuck, StuckModal)
        assert "Checks you haven't done" in str(stuck.query_one("#stuck-body", Static).render())
        await pilot.press("h")
        await pilot.pause()
        assert "Hints (general" in str(stuck.query_one("#stuck-body", Static).render())
        await pilot.press("escape")
        await pilot.pause()

        await pilot.press("w")
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, InputModal)
        modal.query_one("Input").value = "the /admin page"  # type: ignore[attr-defined]
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()
        assert services.active_lead(lantern) is not None
        assert "Working on: the /admin page" in str(
            dashboard.query_one("#journey", Static).render()
        )
