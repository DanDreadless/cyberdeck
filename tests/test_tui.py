"""Phase 5: the Textual TUI, driven headless with Textual's Pilot (no Kali tools needed)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from textual.widgets import (
    Checkbox,
    ContentSwitcher,
    DataTable,
    Input,
    Markdown,
    Select,
    Static,
    TextArea,
    Tree,
)
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.events import bus
from cyberdeck.core.models import Credential, Finding, FindingType, Hash, Service, SuggestionStatus
from cyberdeck.core.tools import registry
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.ui.tui.app import CyberdeckApp
from cyberdeck.ui.tui.dashboard import DashboardScreen
from cyberdeck.ui.tui.jobs import JobScreen
from cyberdeck.ui.tui.loot import LootScreen
from cyberdeck.ui.tui.menu import MenuScreen
from cyberdeck.ui.tui.modals import ConfirmModal, HostsModal, InputModal
from cyberdeck.ui.tui.notes import NotesScreen
from cyberdeck.ui.tui.run_dialog import RunDialog
from cyberdeck.ui.tui.tools import ToolsScreen
from cyberdeck.ui.tui.writeup import WriteupScreen
from cyberdeck.util import hosts as hostsfile
from cyberdeck.util.vpn import Tunnel, VpnStatus

from .conftest import FIXTURES, make_ws

IP = "10.129.231.15"
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"
TOOL_FIXTURES = Path(__file__).parent / "fixtures" / "tools"
SIZE = (160, 50)


@pytest.fixture(autouse=True)
def fresh(monkeypatch: pytest.MonkeyPatch) -> Any:
    registry(reload=True)
    bus.clear()
    cfg = load_user_config()  # past the first-run welcome screen (tested in test_learning.py)
    cfg.first_run_done = True
    save_user_config(cfg)
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


def _table(screen: Any, selector: str) -> DataTable[Any]:
    return screen.query_one(selector, DataTable)


def _rows(table: DataTable[Any]) -> list[list[str]]:
    return [[str(c) for c in table.get_row_at(i)] for i in range(table.row_count)]


async def _dashboard(app: CyberdeckApp, pilot: Any) -> DashboardScreen:
    await pilot.pause()
    screen = app.screen
    assert isinstance(screen, DashboardScreen), screen
    return screen


async def test_menu_lists_boxes_and_opens_the_dashboard(
    lantern: Workspace, settings: Settings
) -> None:
    make_ws(settings, "other", "10.129.1.2")
    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)
        rows = _rows(_table(app.screen, "#boxes"))
        assert {r[1] for r in rows} == {"lantern", "other"}
        table = _table(app.screen, "#boxes")
        table.move_cursor(row=[r[1] for r in rows].index("lantern"))
        await pilot.press("enter")
        dash = await _dashboard(app, pilot)
        assert load_user_config().current_target == str(lantern.path)

        head = str(dash.query_one("#box-head", Static).render())
        assert "Stage 1: all TCP ports" in head and "OS: Linux" in head
        tree = dash.query_one("#services", Tree)
        labels = [str(n.label) for n in tree.root.children]
        assert any(label.startswith("80/tcp web (http)") for label in labels)
        steps = _rows(_table(dash, "#suggestions"))
        assert steps[0][1] == f"Add lantern.htb ({IP}) to /etc/hosts?" and steps[0][2] == "question"
        assert any("Fingerprint the web stack" in r[1] for r in steps)
        software = _rows(_table(dash, "#t-hosts"))
        assert software[0][0] == "lantern.htb"
        why = str(dash.query_one("#why", Static).render())
        assert "name-based virtual hosts" in why  # explain mode is on by default

        await pilot.press("x")
        assert load_user_config().explain is False and not dash.query_one("#why").display
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)


async def test_hosts_question_shows_the_diff_and_writes(
    lantern: Workspace, settings: Settings
) -> None:
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        dash = await _dashboard(app, pilot)
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, HostsModal)
        assert "+10.129.231.15\tlantern.htb\t# cyberdeck:lantern" in app.screen.change.diff()
        await pilot.click("#yes")
        await pilot.pause()
        await app.workers.wait_for_complete()
        assert hostsfile.resolves_to(settings.hosts_file, "lantern.htb", IP)
        steps = _rows(_table(dash, "#suggestions"))
        assert not any("/etc/hosts" in r[1] for r in steps)
        assert any("http://lantern.htb/" in r[1] for r in steps)  # switched to the hostname


async def test_run_dialog_edits_options_and_runs_the_job(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb-redirect.json"))
    fp = next(s for s in services.list_suggestions(lantern) if s.rule_id == "web.fingerprint")
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        dash = await _dashboard(app, pilot)
        table = _table(dash, "#suggestions")
        table.move_cursor(row=[r[0] for r in _rows(table)].index(str(fp.id)))
        await pilot.press("a")
        await pilot.pause()
        dialog = app.screen
        assert isinstance(dialog, RunDialog)
        preview = lambda: str(dialog.query_one("#preview", Static).render())  # noqa: E731
        assert "whatweb -a 3" in preview() and f"http://{IP}/" in preview()

        dialog.query_one("#opt-aggression", Select).value = "1"
        await pilot.pause()
        assert "whatweb -a 1" in preview()
        dialog.query_one("#preset", Select).value = "heavy"
        await pilot.pause()
        assert "whatweb -a 4" in preview()
        dialog.query_one("#extra", Input).value = "--max-threads 5"
        await pilot.pause()
        assert "--max-threads 5" in preview()
        dialog.query_one("#opt-url", Input).value = ""
        await pilot.pause()
        assert "URL is needed" in str(dialog.query_one("#notes", Static).render())
        assert dialog.query_one("#run").disabled
        assert "<url>" in preview()
        # editing the command with a required input empty used to crash (OptionError)
        dialog.action_edit()
        await pilot.pause()
        assert isinstance(app.screen, InputModal)
        assert "<url>" in app.screen.query_one("#answer", Input).value
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is dialog
        dialog.query_one("#opt-url", Input).value = f"http://{IP}/"
        await pilot.pause()

        await pilot.press("ctrl+r")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        jobs = _rows(_table(dash, "#jobs"))
        assert jobs[0][1] == "whatweb" and jobs[0][2] == "done"
        assert services.get_suggestion(lantern, fp.id or 0).status is SuggestionStatus.DONE
        argv = services.list_jobs(lantern)[0].argv
        assert argv[:3] == ["whatweb", "-a", "4"] and "--max-threads" in argv
        assert any(f.type is FindingType.SOFTWARE for f in services.list_findings(lantern))

        await pilot.press("j")
        await pilot.pause()
        assert isinstance(app.screen, JobScreen)
        assert "whatweb -a 4" in str(app.screen.query_one("#job-head", Static).render())
        await pilot.press("p")
        await pilot.pause()
        # r: back to the dashboard with the Run dialog filled in from this job
        await pilot.press("r")
        await pilot.pause()
        again = app.screen
        assert isinstance(again, RunDialog)
        assert str(again.plan.values["aggression"]) == "4" and "--max-threads" in again.plan.extra
        await pilot.press("ctrl+r")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        jobs_now = services.list_jobs(lantern)
        assert len(jobs_now) == 2 and jobs_now[0].argv[:3] == ["whatweb", "-a", "4"]


async def test_skipping_the_run_dialog_runs_nothing(lantern: Workspace, settings: Settings) -> None:
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        dash = await _dashboard(app, pilot)
        dash.tools_flow(("nmap-allports", "nmap-services"))
        await pilot.pause()
        assert isinstance(app.screen, RunDialog)
        sudo = app.screen.query_one("#sudo", Checkbox)
        sudo.value = True
        await pilot.pause()
        assert app.screen.plan.sudo is True
        await pilot.press("escape")
        await pilot.pause()
        await app.workers.wait_for_complete()
        assert isinstance(app.screen, DashboardScreen)  # stage 2 isn't offered after a skip
        assert services.list_jobs(lantern) == []


async def test_hostname_question_input(settings: Settings) -> None:
    ws = make_ws(settings, "Box", IP)
    with ws.store() as store:
        store.upsert(Finding.of(Service(port=80, name="http"), source="test"))
    app = CyberdeckApp(settings, box=str(ws.path))
    async with app.run_test(size=SIZE) as pilot:
        dash = await _dashboard(app, pilot)
        table = _table(dash, "#suggestions")
        titles = [r[1] for r in _rows(table)]
        table.move_cursor(row=titles.index("Tell Cyberdeck the box's hostname"))
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, InputModal)
        assert app.screen.query_one(Input).value == "box.htb"
        await pilot.press("enter")
        await pilot.pause()
        await app.workers.wait_for_complete()
        assert "box.htb" in services.box_hostnames(ws)


async def test_tools_screen_toggles_and_prefers(settings: Settings) -> None:
    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.press("t")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ToolsScreen)
        table = _table(screen, "#tools")
        ids = [
            str(table.coordinate_to_cell_key((i, 0)).row_key.value) for i in range(table.row_count)
        ]
        table.move_cursor(row=ids.index("gobuster-dir"))
        await pilot.press("e")
        assert "gobuster-dir" in load_user_config().disabled_tools
        await pilot.press("e")
        assert "gobuster-dir" not in load_user_config().disabled_tools
        await pilot.press("p")
        assert load_user_config().group_prefs["dir-bruteforce"] == "gobuster-dir"
        await pilot.press("escape")


async def test_loot_masks_secrets_and_records_cracked(
    lantern: Workspace, settings: Settings
) -> None:
    with lantern.store() as store:
        store.upsert(Finding.of(Credential(user="admin", secret="hunter22"), source="test"))
        store.upsert(
            Finding.of(Hash(value="5f4dcc3b5aa765d61d8327deb882cf99", user="bob"), source="test")
        )
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await _dashboard(app, pilot)
        await pilot.press("l")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, LootScreen)
        table = _table(screen, "#loot")
        assert "hunter22" not in str(_rows(table))  # masked
        await pilot.press("v")
        assert "hunter22" in str(_rows(table))
        rows = _rows(table)
        table.move_cursor(row=[r[0] for r in rows].index("hash"))
        await pilot.press("k")
        await pilot.pause()
        assert isinstance(app.screen, InputModal)
        app.screen.query_one(Input).value = "password"
        await pilot.press("enter")
        await pilot.pause()
        await app.workers.wait_for_complete()
        hashes = services.list_findings(lantern, FindingType.HASH)
        assert hashes[0].data["cracked"] == "password"
        table.move_cursor(row=[r[0] for r in _rows(table)].index("cred"))
        await pilot.press("m")
        await pilot.pause()
        await pilot.press("enter")  # default "ssh"
        await pilot.pause()
        await app.workers.wait_for_complete()
        cred = services.list_findings(lantern, FindingType.CREDENTIAL)[0]
        assert cred.data["verified_on"] == ["ssh"]


async def test_notes_editor_saves(lantern: Workspace, settings: Settings) -> None:
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await _dashboard(app, pilot)
        await pilot.press("n")
        await pilot.pause()
        assert isinstance(app.screen, NotesScreen)
        area = app.screen.query_one(TextArea)
        area.load_text("# lantern\n- creds in backup.zip\n")
        await pilot.press("escape")  # saves and goes back
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)
    assert "creds in backup.zip" in services.read_notes(lantern)


async def test_menu_changes_a_box_ip(lantern: Workspace, settings: Settings) -> None:
    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)
        await pilot.press("i")
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, InputModal)
        assert modal.query_one(Input).value == IP  # the current IP, ready to edit
        modal.query_one(Input).value = "10.129.231.99"
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)  # no hosts line: nothing to move
        table: DataTable[Any] = app.screen.query_one("#boxes", DataTable)
        assert "10.129.231.99" in [str(c) for c in table.get_row_at(0)]
    reopened = Workspace.open(lantern.path)
    assert reopened.meta.ip == "10.129.231.99"
    assert "IP changed 10.129.231.15 -> 10.129.231.99" in reopened.notes_file.read_text()
    assert services.list_findings(reopened)  # findings kept


async def test_menu_ip_change_refuses_out_of_scope(lantern: Workspace, settings: Settings) -> None:
    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.press("i")
        await pilot.pause()
        app.screen.query_one(Input).value = "8.8.8.8"
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)
    assert Workspace.open(lantern.path).meta.ip == IP


async def test_menu_ip_change_moves_the_hosts_line(lantern: Workspace, settings: Settings) -> None:
    services.hosts_apply(
        services.hosts_plan_add(lantern, ["lantern.htb"], settings), lantern, settings
    )
    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.press("i")
        await pilot.pause()
        app.screen.query_one(Input).value = "10.129.231.99"
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)  # offer to move the hosts line
        await pilot.press("y")
        await pilot.pause()
        await pilot.pause()
        assert isinstance(app.screen, HostsModal)  # the box opened, the diff is shown
        await pilot.click("#yes")
        await pilot.pause()
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)
    assert hostsfile.resolves_to(settings.hosts_file, "lantern.htb", "10.129.231.99")


async def test_writeup_screen_shows_and_edits_existing_file(
    lantern: Workspace, settings: Settings
) -> None:
    hand = lantern.path / "WRITEUP.md"
    hand.write_text("# Lantern\n\nGot in via **backup.zip**.\n", encoding="utf-8")
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await _dashboard(app, pilot)
        await pilot.press("W")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, WriteupScreen)
        assert "WRITEUP.md" in screen.title and "preview" in screen.title
        assert "backup.zip" in screen.query_one(Markdown).source
        await pilot.press("ctrl+e")
        await pilot.pause()
        assert screen.query_one(ContentSwitcher).current == "writeup-edit"
        area = screen.query_one(TextArea)
        area.load_text(area.text + "\nRoot via sudo tar.\n")
        await pilot.press("ctrl+e")  # back to the preview, re-rendered
        await pilot.pause()
        assert "sudo tar" in screen.query_one(Markdown).source
        await pilot.press("escape")  # saves and goes back
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)
    assert "Root via sudo tar." in hand.read_text()
    assert not (lantern.path / "writeup.md").exists()


async def test_writeup_screen_drafts_from_journal_when_empty(
    lantern: Workspace, settings: Settings
) -> None:
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await _dashboard(app, pilot)
        await pilot.press("W")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, WriteupScreen)
        assert "No write-up" in screen.query_one(Markdown).source
        await pilot.press("escape")  # nothing typed: no file is created
        await pilot.pause()
        assert not (lantern.path / "writeup.md").exists()
        await pilot.press("W")
        await pilot.pause()
        await pilot.press("ctrl+g")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, WriteupScreen)
        assert "# lantern: write-up" in screen.query_one(TextArea).text
        await pilot.press("ctrl+s")
        await pilot.pause()
    assert "# lantern: write-up" in (lantern.path / "writeup.md").read_text()


async def test_dashboard_refreshes_when_another_process_writes(
    lantern: Workspace, settings: Settings
) -> None:
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        dash = await _dashboard(app, pilot)
        with lantern.store() as store:  # e.g. the CLI in another terminal
            store.upsert(Finding.of(Service(port=445, name="microsoft-ds"), source="other"))
        dash._poll()
        await pilot.pause()
        labels = [str(n.label) for n in dash.query_one("#services", Tree).root.children]
        assert any(label.startswith("445/tcp") for label in labels)


def test_cli_tui_entry_points(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str | None] = []
    monkeypatch.setattr("cyberdeck.ui.tui.app.run_tui", lambda box=None: opened.append(box))
    runner = CliRunner()
    assert runner.invoke(cli.app, ["tui", "-t", "lantern"]).exit_code == 0
    assert opened == ["lantern"]
    plain = runner.invoke(cli.app, [])  # not a terminal: banner + hint instead of the TUI
    assert "A CTF Companion Tool" in plain.output and opened == ["lantern"]


def test_terminal_dialog_survives_an_empty_required_input(
    lantern: Workspace, settings: Settings
) -> None:
    from rich.console import Console

    from cyberdeck.ui.run_dialog import render

    plan = services.plan_tool(lantern, "whatweb", settings=settings)
    plan.set_option("url", "none")
    console = Console(record=True, width=200)
    render(plan, console, show_advanced=False, is_root=False)
    out = console.export_text()
    assert "set the options marked *" in out and "URL is needed" in out


async def test_quitting_with_a_running_job_asks_first(settings: Settings) -> None:
    from cyberdeck.ui.tui.modals import ConfirmModal

    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        app.running_jobs = 1
        await pilot.press("q")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("n")
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)
        app.running_jobs = 0
        await pilot.press("q")
        await pilot.pause()
    assert app.return_code == 0


@pytest.mark.parametrize("size", [(100, 24), (160, 50)])
async def test_tool_picker_fits_the_screen(
    lantern: Workspace, settings: Settings, size: tuple[int, int]
) -> None:
    """Regression: the "Run a tool" list ran past the dialog, hiding the last tool and Cancel."""
    from textual.widgets import OptionList

    from cyberdeck.ui.tui.dashboard import PickModal

    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=size) as pilot:
        await _dashboard(app, pilot)
        await pilot.press("r")
        await pilot.pause()
        picker = app.screen
        assert isinstance(picker, PickModal)
        dialog = picker.query_one(".dialog").region
        options = picker.query_one(OptionList)
        cancel = picker.query_one("#cancel").region
        assert dialog.right <= size[0] and dialog.bottom <= size[1]
        assert options.region.bottom <= dialog.bottom and cancel.bottom <= dialog.bottom
        await pilot.press("end")
        await pilot.pause()
        assert options.highlighted == options.option_count - 1
        assert options.scroll_y == options.max_scroll_y  # scrolled to the very end


async def test_tool_lists_are_alphabetical_and_grouped(
    lantern: Workspace, settings: Settings
) -> None:
    from textual.widgets import OptionList

    from cyberdeck.ui.tui.dashboard import PickModal

    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await _dashboard(app, pilot)
        await pilot.press("r")
        await pilot.pause()
        picker = app.screen
        assert isinstance(picker, PickModal)
        options = picker.query_one(OptionList)
        entries = [options.get_option_at_index(i) for i in range(options.option_count)]
        headings = [str(o.prompt).split()[0] for o in entries if o.disabled]
        assert headings == sorted(headings) and "web" in headings and "recon" in headings
        assert not entries[options.highlighted or 0].disabled  # starts on a tool, not a heading
        section: list[str] = []
        for option in [*entries, None]:
            if option is None or option.disabled:
                assert section == sorted(section)
                section = []
            else:
                section.append(str(option.id))
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("t")
        await pilot.pause()
        tools = _table(app.screen, "#tools")
        ids = [str(tools.get_row_at(i)[0]).rstrip(" *") for i in range(tools.row_count)]
        assert ids == sorted(ids)


async def test_dashboard_panes_resize_and_remember(lantern: Workspace, settings: Settings) -> None:
    from cyberdeck.ui.tui.splitter import Splitter

    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        dash = await _dashboard(app, pilot)

        def width(sel: str) -> int:
            return int(dash.query_one(sel).outer_size.width)

        def height(sel: str) -> int:
            return int(dash.query_one(sel).outer_size.height)

        assert width("#left") == 38 and height("#bottom") == 10
        # drag the side divider 12 cells right, the job panel divider 5 rows up
        await pilot.mouse_down("#split-left")
        await pilot.hover("#split-left", offset=(12, 0))
        await pilot.mouse_up("#split-left")
        await pilot.pause()
        assert width("#left") == 50
        await pilot.mouse_down("#split-bottom")
        await pilot.hover("#split-bottom", offset=(0, -5))
        await pilot.mouse_up("#split-bottom")
        await pilot.pause()
        assert height("#bottom") == 15
        # the dividers inside the panes work the same way
        before = height("#next")
        await pilot.mouse_down("#split-next")
        await pilot.hover("#split-next", offset=(0, -3))
        await pilot.mouse_up("#split-next")
        await pilot.pause()
        assert height("#next") == before + 3
        await pilot.mouse_down("#split-jobs")
        await pilot.hover("#split-jobs", offset=(-10, 0))
        await pilot.mouse_up("#split-jobs")
        await pilot.pause()
        assert width("#jobs") == 30
        # keys, and a limit that keeps the other panes usable
        await pilot.press("ctrl+left")
        await pilot.pause()
        assert width("#left") == 48
        dash.query_one("#split-left", Splitter).set_size(500)
        await pilot.pause()
        assert width("#left") == SIZE[0] - 1 - 40
        await pilot.press("ctrl+up")
        await pilot.pause()
        assert height("#bottom") == 16
        layout = load_user_config().tui_layout
        assert layout["left"] == SIZE[0] - 41 and layout["bottom"] == 16 and layout["jobs"] == 30

    # a new dashboard comes back with the saved sizes; = resets them
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        dash = await _dashboard(app, pilot)
        await pilot.pause()
        assert dash.query_one("#bottom").outer_size.height == 16
        assert dash.query_one("#jobs").outer_size.width == 30
        await pilot.press("equals_sign")
        await pilot.pause()
        assert dash.query_one("#left").outer_size.width == 38
        assert dash.query_one("#bottom").outer_size.height == 10
        assert load_user_config().tui_layout == {}


async def test_run_dialog_wordlist_picker_and_man_page(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cyberdeck.ui.tui.wordlist_picker import WordlistPicker

    custom = lantern.path / "loot" / "words.txt"
    custom.parent.mkdir(exist_ok=True)
    custom.write_text("admin\nWelcome1\n", encoding="utf-8")
    monkeypatch.setattr(services, "man_text", lambda tool_id: f"MAN PAGE FOR {tool_id}")
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        dash = await _dashboard(app, pilot)
        dash.tools_flow(("feroxbuster",))
        await pilot.pause()
        dialog = app.screen
        assert isinstance(dialog, RunDialog)
        # Browse... next to the wordlist opens the picker; choosing a file fills the field
        dialog.query_one("#pick-wordlist").press()
        await pilot.pause()
        picker = app.screen
        assert isinstance(picker, WordlistPicker)
        picker.dismiss(str(custom))
        await pilot.pause()
        assert app.screen is dialog
        assert dialog.plan.values["wordlist"] == str(custom)
        assert str(custom) in str(dialog.query_one("#preview", Static).render())
        # F2: the tool's man page
        await pilot.press("f2")
        await pilot.pause()
        assert "MAN PAGE FOR feroxbuster" in str(
            app.screen.query_one(".text-body Static", Static).render()
        )
        await pilot.press("escape")
        await pilot.press("escape")
        await pilot.pause()
        await app.workers.wait_for_complete()


def test_man_page_strips_overstrike(monkeypatch: pytest.MonkeyPatch) -> None:
    from cyberdeck.plugins import detect as detect_mod

    monkeypatch.setattr(detect_mod, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        detect_mod,
        "run_local",
        lambda argv, timeout=10, **kw: (0, "N\x08NA\x08AM\x08ME\x08E\n  tool"),
    )
    text = detect_mod.man_page(registry().tools["feroxbuster"], refresh=True)
    assert text is not None and text.startswith("NAME")
    monkeypatch.setattr(detect_mod, "run_local", lambda argv, timeout=10, **kw: (16, ""))
    assert detect_mod.man_page(registry().tools["impacket-rpcdump"], refresh=True) is None


async def test_loot_add_your_own(lantern: Workspace, settings: Settings) -> None:
    from cyberdeck.ui.tui.loot import AddLootModal, loot_payload

    assert loot_payload("user", {"user": " bob ", "realm": ""}) == (
        FindingType.USER,
        {"name": "bob", "realm": None},
    )
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await _dashboard(app, pilot)
        await pilot.press("l")
        await pilot.pause()
        loot = app.screen
        assert isinstance(loot, LootScreen)
        await pilot.press("a")
        await pilot.pause()
        form = app.screen
        assert isinstance(form, AddLootModal)
        # a credential without a password is refused, the form stays open
        form.query_one("#f-user", Input).value = "svc_web"
        form.action_save()
        await pilot.pause()
        assert app.screen is form
        assert "Password" in str(form.query_one("#add-error", Static).render())
        form.query_one("#f-secret", Input).value = "Welcome1"
        form.query_one("#f-where", Input).value = "ssh"
        form.action_save()
        await pilot.pause()
        assert app.screen is loot
        creds = services.list_findings(lantern, FindingType.CREDENTIAL)
        assert [(c.data["user"], c.data["secret"], c.data["verified_on"]) for c in creds] == [
            ("svc_web", "Welcome1", ["ssh"])
        ]
        assert creds[0].sources == ["user"]
        # a hash with its hashcat mode
        await pilot.press("a")
        await pilot.pause()
        form = app.screen
        assert isinstance(form, AddLootModal)
        form.query_one("#kind", Select).value = "hash"
        await pilot.pause()
        assert not form.query_one("#row-secret").display
        form.query_one("#f-value", Input).value = "5f4dcc3b5aa765d61d8327deb882cf99"
        form.query_one("#f-mode", Input).value = "0"
        form.action_save()
        await pilot.pause()
        hashes = services.list_findings(lantern, FindingType.HASH)
        assert hashes[0].data["hashcat_mode"] == 0
        table = _table(loot, "#loot")
        assert table.row_count == 2


async def test_loot_edit_and_delete(lantern: Workspace, settings: Settings) -> None:
    from cyberdeck.ui.tui.loot import AddLootModal
    from cyberdeck.ui.tui.modals import ConfirmModal

    services.add_finding(
        lantern,
        FindingType.HASH,
        {"value": "5f4dcc3b5aa765d61d8327deb882cf99", "hash_types": ["MD5"]},
        source="job:3:hashid",
        confidence=0.8,
    )
    services.add_finding(
        lantern,
        FindingType.CREDENTIAL,
        {"user": "svc", "secret": "typo"},
        source="user",
        confidence=1.0,
    )
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await _dashboard(app, pilot)
        await pilot.press("l")
        await pilot.pause()
        loot = app.screen
        assert isinstance(loot, LootScreen)
        table = _table(loot, "#loot")
        table.move_cursor(row=[r[0] for r in _rows(table)].index("cred"))
        await pilot.press("e")
        await pilot.pause()
        form = app.screen
        assert isinstance(form, AddLootModal)
        assert form.query_one("#kind", Select).disabled
        assert form.query_one("#f-secret", Input).value == "typo"
        form.query_one("#f-secret", Input).value = "Welcome1"
        form.action_save()
        await pilot.pause()
        assert app.screen is loot
        creds = services.list_findings(lantern, FindingType.CREDENTIAL)
        assert [c.data["secret"] for c in creds] == ["Welcome1"]

        # edit the hash: set a mode and a cracked value, keep the detected types
        table.move_cursor(row=[r[0] for r in _rows(table)].index("hash"))
        await pilot.press("e")
        await pilot.pause()
        form = app.screen
        assert isinstance(form, AddLootModal)
        form.query_one("#f-mode", Input).value = "0"
        form.query_one("#f-cracked", Input).value = "password"
        form.action_save()
        await pilot.pause()
        h = services.list_findings(lantern, FindingType.HASH)[0]
        assert (h.data["hashcat_mode"], h.data["cracked"], h.data["hash_types"]) == (
            0,
            "password",
            ["MD5"],
        )

        # delete the credential (asks first; "Keep" leaves it alone)
        table.move_cursor(row=[r[0] for r in _rows(table)].index("cred"))
        await pilot.press("d")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("n")
        await pilot.pause()
        assert len(services.list_findings(lantern, FindingType.CREDENTIAL)) == 1
        await pilot.press("d")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        assert services.list_findings(lantern, FindingType.CREDENTIAL) == []
        assert "cred" not in [r[0] for r in _rows(table)]
