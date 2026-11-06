"""The logo: block art generated from assets/cyberdeck.png, in the menu and the CLI."""

from __future__ import annotations

import re
from pathlib import Path

from textual.widgets import Static
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core.config import Settings
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.ui.banner import TAGLINE, logo_markup, logo_text
from cyberdeck.ui.logo import LOGO, LOGO_HEIGHT, LOGO_WIDTH
from cyberdeck.ui.tui.app import CyberdeckApp

ROOT = Path(__file__).resolve().parents[1]
MARKUP = re.compile(r"\[/?(\$[a-z-]+)?\]")


def test_generated_art_is_rectangular_and_themed() -> None:
    lines = LOGO.split("\n")
    assert len(lines) == LOGO_HEIGHT
    assert {len(MARKUP.sub("", line)) for line in lines} == {LOGO_WIDTH}
    assert "[$foreground]" in LOGO and "[$accent]" in LOGO  # follows the theme
    for name in ("cyberdeck.png", "logo-dark.png", "logo-light.png"):
        assert (ROOT / "assets" / name).is_file(), name


def test_narrow_fallback_and_cli_text() -> None:
    assert LOGO in logo_markup(LOGO_WIDTH) and TAGLINE in logo_markup(LOGO_WIDTH)
    narrow = logo_markup(LOGO_WIDTH - 1)
    assert LOGO not in narrow and "CYBER" in narrow
    text = logo_text()
    assert "$" not in text.plain and TAGLINE in text.plain


def test_cli_prints_the_logo_when_not_a_terminal() -> None:
    out = CliRunner().invoke(cli.app, [])
    assert out.exit_code == 0 and "█" in out.output and TAGLINE in out.output


async def test_menu_switches_logo_with_width(settings: Settings) -> None:
    cfg = load_user_config()
    cfg.first_run_done = True
    save_user_config(cfg)
    app = CyberdeckApp(settings)
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause()
        assert "█" in str(app.screen.query_one("#banner", Static).render())
        await pilot.resize_terminal(60, 30)
        await pilot.pause()
        shown = str(app.screen.query_one("#banner", Static).render())
        assert "CYBERDECK" in shown and "█" not in shown
