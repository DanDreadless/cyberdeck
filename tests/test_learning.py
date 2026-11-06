"""Learning track L1 (docs/LEARNING-PLAN.md): glossary, setup check, journey, welcome screen,
Settings screen, beginner layout."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from textual.widgets import Checkbox, Input, Select, Static
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import doctor, glossary, services
from cyberdeck.core.config import Settings
from cyberdeck.core.events import bus
from cyberdeck.core.tools import registry
from cyberdeck.core.userconfig import LearningConfig, load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.plugins.manifest import package_data_dir
from cyberdeck.ui.tui.app import CyberdeckApp
from cyberdeck.ui.tui.dashboard import DashboardScreen
from cyberdeck.ui.tui.learning import GlossaryModal, SettingsScreen, WelcomeScreen
from cyberdeck.ui.tui.menu import MenuScreen
from cyberdeck.util.vpn import Tunnel, VpnStatus

from .conftest import FIXTURES, make_ws

IP = "10.129.231.15"
SIZE = (160, 50)
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"
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


def _skip_welcome() -> None:
    cfg = load_user_config()
    cfg.first_run_done = True
    save_user_config(cfg)


def _static_text(screen: Any, selector: str) -> str:
    return str(screen.query_one(selector, Static).render())


# -- glossary ---------------------------------------------------------------------------------


def test_builtin_glossary_loads_cleanly() -> None:
    gloss = glossary.load_glossary()
    assert gloss.errors == []
    assert len(gloss.terms) >= 40
    assert gloss.get("vhosts") is gloss.terms["vhost"]  # aliases, case-insensitive
    assert gloss.get("Reverse Shell") is gloss.terms["reverse-shell"]
    for term in gloss.terms.values():  # "see" points at real terms, links inside resolve
        assert all(ref in gloss.terms for ref in term.see), term.id
        assert gloss.unknown(term.short) == [], term.id


def test_every_linked_term_in_the_rules_exists() -> None:
    gloss = glossary.load_glossary()
    linked = 0
    for path in sorted((package_data_dir() / "rules").glob("*.yaml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            why = rule.get("why", "")
            assert gloss.unknown(why) == [], (path.name, rule["id"])
            linked += len(glossary.terms_in(why))
    assert linked >= 30


def test_journey_and_doctor_text_links_exist() -> None:
    gloss = glossary.load_glossary()
    for _, hint in services.JOURNEY:
        assert gloss.unknown(hint) == []


def test_plain_and_rich_rendering() -> None:
    gloss = glossary.load_glossary()
    text = "Add it to [[etc-hosts|/etc/hosts]] and fuzz [[vhost|vhosts]] ([[nonsense]])."
    assert glossary.plain(text) == "Add it to /etc/hosts and fuzz vhosts (nonsense)."
    rich = gloss.rich(text)
    assert rich.plain == glossary.plain(text)
    underlined = {rich.plain[s.start : s.end] for s in rich.spans if "underline" in str(s.style)}
    assert underlined == {"/etc/hosts", "vhosts"}  # unknown terms aren't underlined
    assert [t.id for t in gloss.linked(text)] == ["etc-hosts", "vhost"]


def test_user_glossary_adds_replaces_and_toggles(tmp_path: Path) -> None:
    user = tmp_path / "glossary.yaml"
    user.write_text(
        yaml.safe_dump(
            [
                {"id": "vhost", "term": "Vhost (mine)", "short": "My own words."},
                {"id": "pivot", "term": "Pivot", "short": "Reaching further via a box."},
                {"id": "Bad Id", "term": "x", "short": "y"},
                {"id": "dup", "term": "Dup", "short": "z", "aliases": ["pivot"]},
            ]
        ),
        encoding="utf-8",
    )
    gloss = glossary.load_glossary(user=user, include_builtin=True, disabled=[])
    assert gloss.terms["vhost"].term == "Vhost (mine)"
    assert gloss.get("subdomains") is None  # the replaced term's old aliases are gone
    assert gloss.get("pivot") is gloss.terms["pivot"]
    assert any("Bad Id" in e or "entry 3" in e for e in gloss.errors)
    assert any("'pivot' is already" in e for e in gloss.errors)

    off = glossary.load_glossary(user=user, include_builtin=False, disabled=[])
    assert set(off.terms) == {"vhost", "pivot", "dup"}  # built-in off, yours still load
    hidden = glossary.load_glossary(user=user, include_builtin=True, disabled=["sudo"])
    assert "sudo" not in hidden.terms and "suid" in hidden.terms


def test_learning_defaults_are_all_on() -> None:
    cfg = load_user_config()
    assert cfg.layout == "beginner" and not cfg.first_run_done
    learning = cfg.learning
    assert learning == LearningConfig()
    assert all([learning.glossary, learning.checklists, learning.hints])
    assert learning.summaries and learning.paths and learning.idle_prompt_minutes == 25

    cfg.learning.glossary = False
    save_user_config(cfg)
    assert services.load_glossary().terms == {}  # the toggle reaches the loader


def test_cli_glossary() -> None:
    one = runner.invoke(cli.app, ["glossary", "vhosts"])
    assert one.exit_code == 0, one.output
    assert "Virtual host" in one.output and "[[" not in one.output
    everything = runner.invoke(cli.app, ["glossary"])
    assert everything.exit_code == 0 and "GTFOBins" in everything.output
    missing = runner.invoke(cli.app, ["glossary", "zzzz"])
    assert missing.exit_code == 1


def test_cli_suggestions_show_plain_words(lantern: Workspace) -> None:
    listing = runner.invoke(cli.app, ["suggest", "-t", str(lantern.path)])
    assert listing.exit_code == 0, listing.output
    assert "virtual hosts" in listing.output and "[[" not in listing.output


# -- setup check (doctor) ---------------------------------------------------------------------


def _fake_system(monkeypatch: pytest.MonkeyPatch, *, missing: set[str], vpn: VpnStatus) -> None:
    monkeypatch.setattr(doctor, "have_binary", lambda name: name not in missing)
    monkeypatch.setattr(doctor, "vpn_status", lambda ip, root, explicit=None: vpn)
    monkeypatch.setattr(doctor, "run_local", lambda argv, timeout=10: (0, "yes\n"))


def test_doctor_reports_problems_with_fixes(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, tmp_path: Path
) -> None:
    _fake_system(monkeypatch, missing={"nmap", "whatweb"}, vpn=VpnStatus("", True))
    zipped = tmp_path / "rockyou.txt.gz"
    zipped.write_bytes(b"x")
    monkeypatch.setattr(doctor, "ROCKYOU_GZ", zipped)
    monkeypatch.setattr(doctor.wl, "resolve", lambda name, overrides=None: None)
    checks = {c.id: c for c in doctor.run_checks(settings)}

    assert checks["workspace"].level is doctor.Level.WARN  # tmp htb folder doesn't exist yet
    assert checks["workspace"].fix == f"mkdir -p {settings.root}"
    assert checks["vpn-config"].level is doctor.Level.FAIL
    assert "app.hackthebox.com" in (checks["vpn-config"].fix or "")
    assert checks["vpn-up"].level is doctor.Level.WARN
    assert checks["tool-nmap"].level is doctor.Level.FAIL
    assert checks["tool-nmap"].fix == "sudo apt install nmap"
    assert checks["tool-whatweb"].level is doctor.Level.WARN
    assert checks["rockyou"].fix == f"sudo gunzip -k {zipped}"
    assert checks["clock"].level is doctor.Level.OK
    assert "problem" in doctor.summary(list(checks.values()))


def test_doctor_all_good(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    settings.root.mkdir(parents=True)
    (settings.root / "machines_us-1.ovpn").write_text("client\n", encoding="utf-8")
    vpn = VpnStatus("", True, [Tunnel("tun0", "10.10.14.7")], configs=[settings.root / "m.ovpn"])
    _fake_system(monkeypatch, missing=set(), vpn=vpn)
    checks = {c.id: c for c in doctor.run_checks(settings)}
    for cid in ("workspace", "vpn-config", "vpn-up", "tool-nmap", "clock"):
        assert checks[cid].level is doctor.Level.OK, checks[cid]
    assert "10.10.14.7" in checks["vpn-up"].detail


def test_cli_doctor(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    bad = doctor.Check(
        "tool-nmap",
        "nmap",
        doctor.Level.FAIL,
        "not installed",
        "[[nmap]] x",
        "sudo apt install nmap",
    )
    monkeypatch.setattr(services, "setup_checks", lambda s=None: [bad])
    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 1
    assert "sudo apt install nmap" in result.output and "[[" not in result.output

    ok = doctor.Check("clock", "Clock", doctor.Level.OK, "synchronised", "p")
    monkeypatch.setattr(services, "setup_checks", lambda s=None: [ok])
    created = runner.invoke(cli.app, ["doctor", "--create-folder"])
    assert created.exit_code == 0, created.output
    assert "Everything looks ready" in created.output
    assert Path(load_settings_root()).is_dir()


def load_settings_root() -> Path:
    from cyberdeck.core.config import load_settings

    return load_settings().root


# -- journey ----------------------------------------------------------------------------------


def test_journey_follows_the_box(settings: Settings, lantern: Workspace) -> None:
    empty = make_ws(settings, "empty", "10.129.1.9")
    assert [s.state for s in services.journey(empty)] == ["current"] + ["todo"] * 4

    stages = services.journey(lantern)
    assert [s.label for s in stages] == ["Scan", "Enumerate", "Foothold", "User flag", "Root flag"]
    assert [s.state for s in stages] == ["done", "current", "todo", "todo", "todo"]

    services.record_flag(lantern, "user", "a" * 32)
    states = [s.state for s in services.journey(lantern)]
    assert states == ["done", "done", "done", "done", "current"]


# -- TUI --------------------------------------------------------------------------------------


async def test_welcome_screen_on_first_run(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(services, "setup_checks", lambda s=None: [])
    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, WelcomeScreen)
        text = _static_text(app.screen, "#checks")
        assert "Everything looks ready" in text
        app.screen.query_one("#layout", Select).value = "expert"
        await pilot.click("#done")
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)
    cfg = load_user_config()
    assert cfg.first_run_done and cfg.layout == "expert" and not cfg.explain

    again = CyberdeckApp(settings)  # not shown a second time
    async with again.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert isinstance(again.screen, MenuScreen)


async def test_beginner_dashboard_now_card_journey_and_glossary(
    lantern: Workspace, settings: Settings
) -> None:
    _skip_welcome()
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, DashboardScreen)
        now = screen.query_one("#now", Static)
        journey = screen.query_one("#journey", Static)
        assert now.display and journey.display
        now_text = _static_text(screen, "#now")
        assert "Next:" in now_text and "[[" not in now_text
        assert "● Enumerate" in _static_text(screen, "#journey")

        await pilot.press("g")
        await pilot.pause()
        assert isinstance(app.screen, GlossaryModal)
        assert app.screen.only  # just the terms in what you were reading
        await pilot.press("escape")
        await pilot.pause()

        await pilot.press("b")
        await pilot.pause()
        assert not now.display and not journey.display
        assert load_user_config().layout == "expert"


async def test_empty_box_now_card_says_scan(settings: Settings) -> None:
    _skip_welcome()
    ws = make_ws(settings, "fresh", "10.129.1.10")
    app = CyberdeckApp(settings, box=str(ws.path))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.pause()
        assert "Scan the box: press c" in _static_text(app.screen, "#now")


async def test_settings_screen_saves_learning_toggles(settings: Settings) -> None:
    _skip_welcome()
    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.press("comma")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)
        assert all(cb.value for cb in screen.query(Checkbox) if cb.id and "learn-" in cb.id)
        screen.query_one("#learn-glossary", Checkbox).value = False
        screen.query_one("#learn-hints", Checkbox).value = False
        screen.query_one("#idle", Input).value = "0"
        screen.query_one("#layout", Select).value = "expert"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert isinstance(app.screen, MenuScreen)
    cfg = load_user_config()
    assert not cfg.learning.glossary and not cfg.learning.hints
    assert cfg.learning.checklists and cfg.learning.summaries  # untouched ones stay on
    assert cfg.learning.idle_prompt_minutes == 0 and cfg.layout == "expert"
