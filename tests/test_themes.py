"""Cyberdeck's own themes: registered, readable, switchable from anywhere (ctrl+t)."""

from __future__ import annotations

import pytest
from textual.color import Color
from textual.theme import Theme
from textual.widgets import OptionList, Select

from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.userconfig import UserConfig, load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.ui.tui.app import CyberdeckApp
from cyberdeck.ui.tui.dashboard import DashboardScreen
from cyberdeck.ui.tui.learning import SettingsScreen
from cyberdeck.ui.tui.theme_picker import ThemePicker
from cyberdeck.ui.tui.themes import CYBERDECK_THEMES, DEFAULT_THEME, theme_choices

from .conftest import FIXTURES, make_ws

NAMES = [t.name for t in CYBERDECK_THEMES]
SIZE = (140, 45)


@pytest.fixture(autouse=True)
def past_welcome() -> None:
    cfg = load_user_config()
    cfg.first_run_done = True
    save_user_config(cfg)


@pytest.fixture
def lantern(settings: Settings) -> Workspace:
    ws = make_ws(settings, "lantern", "10.129.231.15")
    services.import_nmap(ws, FIXTURES / "lantern")
    return ws


def _luminance(hex_colour: str) -> float:
    def channel(value: int) -> float:
        c = value / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = Color.parse(hex_colour).rgb
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def _contrast(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


@pytest.mark.parametrize("theme", CYBERDECK_THEMES, ids=NAMES)
def test_theme_is_readable(theme: Theme) -> None:
    assert theme.background and theme.foreground
    assert _contrast(theme.foreground, theme.background) >= 7  # body text: WCAG AAA
    for colour in (
        theme.primary,
        theme.secondary,
        theme.accent,
        theme.success,
        theme.warning,
        theme.error,
    ):
        assert colour and _contrast(colour, theme.background) >= 4.5, (theme.name, colour)
    for surface in (theme.surface, theme.panel):
        assert surface and _contrast(theme.foreground, surface) >= 7


def test_default_and_choice_order() -> None:
    assert UserConfig().theme == DEFAULT_THEME
    choices = theme_choices(["nord", "textual-dark", *reversed(NAMES), "dracula"])
    assert choices == [*NAMES, "dracula", "nord", "textual-dark"]


async def test_every_theme_applies_and_settings_lists_them(settings: Settings) -> None:
    app = CyberdeckApp(settings)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert app.theme == DEFAULT_THEME
        for name in theme_choices(app.available_themes):
            app.theme = name
            await pilot.pause()
            assert app.current_theme.name == name
        app.theme = DEFAULT_THEME
        await pilot.press("comma")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)
        select: Select[str] = app.screen.query_one("#theme", Select)
        offered = [str(value) for _, value in select._options]
        assert offered[: len(NAMES)] == NAMES and "dracula" in offered


async def test_ctrl_t_previews_saves_and_cancels(lantern: Workspace, settings: Settings) -> None:
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)
        await pilot.press("ctrl+t")
        await pilot.pause()
        picker = app.screen
        assert isinstance(picker, ThemePicker)
        options = picker.query_one(OptionList)
        options.highlighted = options.get_option_index("cyberdeck-phosphor")
        await pilot.pause()
        assert app.theme == "cyberdeck-phosphor"  # live preview
        await pilot.press("escape")  # cancel puts the old theme back
        await pilot.pause()
        assert app.theme == DEFAULT_THEME and isinstance(app.screen, DashboardScreen)
        assert load_user_config().theme == DEFAULT_THEME

        app.action_change_theme()  # what ctrl+p -> Theme runs too
        await pilot.pause()
        picker = app.screen
        assert isinstance(picker, ThemePicker)
        options = picker.query_one(OptionList)
        options.highlighted = options.get_option_index("dracula")
        await pilot.press("enter")
        await pilot.pause()
        assert app.theme == "dracula" and isinstance(app.screen, DashboardScreen)
    assert load_user_config().theme == "dracula"
