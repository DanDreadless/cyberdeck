"""Notes editor: the box's notes.md (docs/UI.md screen 6). ctrl+s saves; leaving saves too."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, TextArea

from cyberdeck.core import services
from cyberdeck.core.workspace import Workspace


class NotesScreen(Screen[None]):
    BINDINGS = [
        Binding("ctrl+s", "save", "Save", priority=True),
        Binding("escape", "back", "Save and back", priority=True),
    ]

    def __init__(self, ws: Workspace) -> None:
        super().__init__()
        self.ws = ws
        self._saved = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield TextArea(id="notes", tab_behavior="indent", show_line_numbers=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"Notes: {self.ws.meta.name}  ({self.ws.notes_file.name}, markdown)"
        self._saved = services.read_notes(self.ws)
        area = self.query_one(TextArea)
        area.load_text(self._saved)
        area.focus()

    def action_save(self) -> None:
        text = self.query_one(TextArea).text
        if text != self._saved:
            services.save_notes(self.ws, text)
            self._saved = text
            self.notify(f"Saved {self.ws.notes_file.name}")

    def action_back(self) -> None:
        self.action_save()
        self.app.pop_screen()
