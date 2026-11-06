"""Write-up viewer/editor: the box's writeup.md (or WRITEUP.md, any case) rendered as
Markdown, with an editor (docs/UI.md). ctrl+e switches preview/edit, ctrl+s saves, leaving
saves too, ctrl+g drafts one from the journal (loot and paths masked)."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Footer, Header, Markdown, TextArea

from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.workspace import Workspace

EMPTY = (
    "*No write-up for this box yet.*\n\n"
    "- **ctrl+g** drafts one from the journal (passwords, flags and your paths masked)\n"
    "- **ctrl+e** opens the editor to write your own\n\n"
    "A `writeup.md` or `WRITEUP.md` dropped in the box folder (by you or by Claude over MCP) "
    "shows up here."
)


class WriteupScreen(Screen[None]):
    BINDINGS = [
        Binding("ctrl+e", "switch_mode", "Edit / preview", priority=True),
        Binding("ctrl+s", "save", "Save", priority=True),
        Binding("ctrl+g", "draft", "Draft from journal", priority=True),
        Binding("escape", "back", "Save and back", priority=True),
    ]

    def __init__(self, ws: Workspace, settings: Settings) -> None:
        super().__init__()
        self.ws = ws
        self.settings = settings
        self._saved = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with ContentSwitcher(initial="writeup-preview", id="writeup-switcher"):
            with VerticalScroll(id="writeup-preview"):
                yield Markdown(id="writeup-md")
            yield TextArea(id="writeup-edit", tab_behavior="indent", show_line_numbers=True)
        yield Footer()

    def on_mount(self) -> None:
        self._saved = services.read_writeup(self.ws)
        self.query_one(TextArea).load_text(self._saved)
        self._set_title()
        self._render_preview()
        self.query_one("#writeup-preview").focus()

    @property
    def editing(self) -> bool:
        return self.query_one(ContentSwitcher).current == "writeup-edit"

    def _set_title(self) -> None:
        mode = "editing" if self.editing else "preview"
        name = services.writeup_file(self.ws).name
        self.title = f"Write-up: {self.ws.meta.name}  ({name}, {mode})"

    def _render_preview(self) -> None:
        text = self.query_one(TextArea).text
        self.query_one("#writeup-md", Markdown).update(text if text.strip() else EMPTY)

    def action_switch_mode(self) -> None:
        switcher = self.query_one(ContentSwitcher)
        if self.editing:
            self._render_preview()
            switcher.current = "writeup-preview"
            self.query_one("#writeup-preview").focus()
        else:
            switcher.current = "writeup-edit"
            self.query_one(TextArea).focus()
        self._set_title()

    def action_save(self) -> None:
        text = self.query_one(TextArea).text
        if text == self._saved:
            return
        path = services.save_writeup(self.ws, text)
        self._saved = text
        self._set_title()
        self.notify(f"Saved {path.name}")

    def action_draft(self) -> None:
        def answered(replace: bool | None) -> None:
            if replace:
                self._load_draft()

        if self.query_one(TextArea).text.strip():
            from cyberdeck.ui.tui.modals import ConfirmModal

            self.app.push_screen(
                ConfirmModal(
                    "Replace this write-up with a draft from the journal?",
                    "The draft goes in the editor; nothing is saved until ctrl+s or esc. "
                    "Loot and your paths are masked in it.",
                    yes="Replace",
                    no="Keep mine",
                ),
                answered,
            )
        else:
            self._load_draft()

    def _load_draft(self) -> None:
        self.query_one(TextArea).load_text(services.writeup(self.ws, self.settings))
        if not self.editing:
            self.action_switch_mode()
        self.notify("Draft from the journal loaded; edit it, then ctrl+s")

    def action_back(self) -> None:
        self.action_save()
        self.app.pop_screen()
