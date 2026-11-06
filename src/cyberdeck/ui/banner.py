"""The Cyberdeck logo for the TUI and the CLI. The block-character art comes from
assets/cyberdeck.png via scripts/render_logo.py (see ``cyberdeck.ui.logo``)."""

from __future__ import annotations

from rich.text import Text

from cyberdeck.ui.logo import LOGO, LOGO_WIDTH

TAGLINE = "recon handler for hack the box"
# Narrow terminals can't fit the art: the name in the same two colours instead.
LOGO_NARROW = "[b $foreground]CYBER[/][b $accent]DECK[/]"


def logo_markup(width: int) -> str:
    """Textual markup for the logo at ``width`` cells, with the tagline under it."""
    art = LOGO if width >= LOGO_WIDTH else LOGO_NARROW
    return f"{art}\n[$text-muted]{TAGLINE}[/]"


def logo_text() -> Text:
    """The logo for Rich output (the CLI), in the PNG's own colours: white and cyan."""
    markup = LOGO.replace("[$foreground]", "[bold white]").replace("[$accent]", "[bold cyan]")
    text = Text.from_markup(markup)
    text.append("\n" + TAGLINE, style="dim")
    return text
