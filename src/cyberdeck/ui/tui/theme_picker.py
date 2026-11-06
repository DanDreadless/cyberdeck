"""Theme picker (ctrl+t anywhere, or ctrl+p -> Theme): every theme with colour swatches,
previews live as you move, enter keeps it (saved to config.yaml), esc puts the old one back."""

from __future__ import annotations

from rich.color import Color, ColorParseError
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.theme import Theme
from textual.widgets import Label, OptionList, Static
from textual.widgets.option_list import Option

from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.ui.tui.themes import CYBERDECK_THEMES, theme_choices

OURS = {t.name for t in CYBERDECK_THEMES}


def _style(colour: str | None) -> str:
    """The colour, or "dim" for empty values and names Rich can't draw (textual-ansi's
    ``ansi_default``)."""
    if not colour:
        return "dim"
    try:
        Color.parse(colour)
    except ColorParseError:
        return "dim"
    return colour


def swatch(theme: Theme) -> Text:
    """The theme's name and a strip of its colours."""
    text = Text()
    for colour in (theme.background, theme.primary, theme.secondary, theme.accent):
        text.append("██", style=_style(colour))
    for colour in (theme.success, theme.warning, theme.error):
        text.append("▌", style=_style(colour))
    text.append(f"  {theme.name}")
    return text


class ThemePicker(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self) -> None:
        super().__init__()
        self.original = ""

    def compose(self) -> ComposeResult:
        themes = self.app.available_themes
        options: list[Option | None] = []
        names = theme_choices(themes)
        for i, name in enumerate(names):
            if i == 0 and name in OURS:
                options.append(Option(Text("Cyberdeck", style="bold"), disabled=True))
            if name not in OURS and (i == 0 or names[i - 1] in OURS):
                options.append(None)
                options.append(Option(Text("Textual", style="bold"), disabled=True))
            options.append(Option(swatch(themes[name]), id=name))
        with Vertical(classes="dialog tall", id="theme-picker"):
            yield Label("Theme", classes="dialog-title")
            yield Static(
                Text(
                    "Moving previews it. enter keeps it (saved for next time), esc goes back. "
                    "ctrl+t opens this from any screen.",
                    style="dim",
                )
            )
            yield OptionList(*options, id="themes")

    def on_mount(self) -> None:
        self.original = self.app.theme
        option_list = self.query_one(OptionList)
        try:
            option_list.highlighted = option_list.get_option_index(self.original)
        except Exception:  # current theme isn't in the list (unknown name): start at the top
            option_list.highlighted = 1
        option_list.focus()

    @on(OptionList.OptionHighlighted)
    def _preview(self, event: OptionList.OptionHighlighted) -> None:
        if event.option.id:
            self.app.theme = event.option.id

    @on(OptionList.OptionSelected)
    def _choose(self, event: OptionList.OptionSelected) -> None:
        name = event.option.id
        if not name:
            return
        self.app.theme = name
        cfg = load_user_config()
        cfg.theme = name
        save_user_config(cfg)
        self.app.notify(f"Theme: {name}")
        self.dismiss(name)

    def action_cancel(self) -> None:
        self.app.theme = self.original
        self.dismiss(None)
