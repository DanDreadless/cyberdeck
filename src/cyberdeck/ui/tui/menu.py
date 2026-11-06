"""Main menu: banner + box picker (docs/UI.md screen 1) and the new-box form."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Input, Label, Static

from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.scope import ScopeError
from cyberdeck.core.userconfig import load_user_config
from cyberdeck.core.workspace import Workspace, WorkspaceError
from cyberdeck.ui.banner import logo_markup
from cyberdeck.ui.tui.modals import ConfirmModal

_SHORT = ["ports", "versions", "udp", "hosts", "user", "root"]


def progress_text(ws: Workspace) -> Text:
    progress = services.target_progress(ws)
    text = Text()
    for name, step in zip(_SHORT, progress.steps, strict=True):
        text.append(name + " ", style="green" if step.done else "dim")
    return text


class NewBoxModal(ModalScreen[tuple[str, str, str] | None]):
    """Box name, IP and folder. Returns (name, ip, root) or None."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, root: str) -> None:
        super().__init__()
        self.root = root

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("New box", classes="dialog-title")
            yield Label("Box name (the HTB machine name)")
            yield Input(id="name", placeholder="soccer")
            yield Label("Target IP")
            yield Input(id="ip", placeholder="10.129.x.x")
            yield Label("Workspace folder")
            yield Input(self.root, id="root")
            with Horizontal(classes="buttons"):
                yield Button("Create", variant="primary", id="create")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#name", Input).focus()

    def _submit(self) -> None:
        values = [self.query_one(f"#{k}", Input).value.strip() for k in ("name", "ip", "root")]
        if not values[0] or not values[1]:
            self.notify("Name and IP are needed", severity="error")
            return
        self.dismiss((values[0], values[1], values[2]))

    def on_input_submitted(self) -> None:
        self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "create":
            self._submit()
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class MenuScreen(Screen[None]):
    BINDINGS = [
        Binding("enter,o", "open", "Open box"),
        Binding("n", "new", "New box"),
        Binding("t", "tools", "Tools"),
        Binding("p", "progress", "Progress"),
        Binding("d", "app.setup_check", "Setup check"),
        Binding("g", "app.glossary", "Glossary"),
        Binding("comma", "app.settings_screen", "Settings"),
        Binding("ctrl+r", "refresh", "Refresh", show=False),
        Binding("q", "app.quit", "Quit"),
        Binding("question_mark", "app.toggle_help", "Keys"),
    ]

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self._boxes: dict[str, Workspace] = {}

    def on_resize(self) -> None:
        """The block-art logo when it fits, the plain name when it doesn't."""
        banner = self.query_one("#banner", Static)
        banner.update(logo_markup(self.size.width - 4))  # #banner has 2 cells of padding a side

    def compose(self) -> ComposeResult:
        yield Static(logo_markup(0), id="banner")  # the real art once the width is known
        yield Label("Boxes (most recently opened first)", classes="section")
        yield DataTable(id="boxes", cursor_type="row")
        yield Static(id="loose", classes="dim")
        yield Static(
            Text(
                "New here? d = setup check (VPN, tools, wordlists), g = glossary, "
                "p = learning path and skills, n = start a box. Free first boxes: Starting "
                "Point Tier 0 (Meow, Fawn, Dancing).",
                style="dim",
            ),
            id="menu-hint",
        )
        yield Footer()

    def on_mount(self) -> None:
        table: DataTable[Any] = self.query_one("#boxes", DataTable)
        table.add_columns("", "Box", "IP", "Last opened", "Progress")
        self.refresh_boxes()
        table.focus()

    def on_screen_resume(self) -> None:
        self.refresh_boxes()

    def refresh_boxes(self) -> None:
        table: DataTable[Any] = self.query_one("#boxes", DataTable)
        table.clear()
        never = datetime.min.replace(tzinfo=UTC)
        boxes = services.list_targets(self.settings)
        boxes.sort(key=lambda w: w.meta.last_opened or w.meta.created_at or never, reverse=True)
        current = load_user_config().current_target
        self._boxes = {}
        for ws in boxes:
            key = str(ws.path)
            self._boxes[key] = ws
            opened = ws.meta.last_opened or ws.meta.created_at
            table.add_row(
                "*" if current == key else "",
                ws.meta.name,
                ws.meta.ip,
                opened.astimezone().strftime("%Y-%m-%d %H:%M") if opened else "-",
                progress_text(ws),
                key=key,
            )
        loose = services.list_unmanaged(self.settings)
        note = self.query_one("#loose", Static)
        if not boxes:
            note.update(f"No boxes under {self.settings.root} yet: n = new box.")
        elif loose:
            names = ", ".join(p.name for p in loose)
            note.update(f"Folders not set up yet: {names} (n, same name, to adopt one)")
        else:
            note.update("")

    def action_refresh(self) -> None:
        self.refresh_boxes()

    @on(DataTable.RowSelected, "#boxes")
    def _selected(self) -> None:
        self.action_open()

    def action_open(self) -> None:
        table: DataTable[Any] = self.query_one("#boxes", DataTable)
        if not table.row_count:
            self.action_new()
            return
        key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        self.open_box(self._boxes[key])

    def open_box(self, ws: Workspace, *, offer_scan: bool = False) -> None:
        from cyberdeck.ui.tui.dashboard import DashboardScreen

        opened = services.open_target(self.settings, str(ws.path))
        services.use_target(opened)
        dashboard = DashboardScreen(opened, self.settings)
        self.app.push_screen(dashboard)
        if offer_scan:
            dashboard.call_after_refresh(dashboard.action_scan)

    def action_progress(self) -> None:
        from cyberdeck.ui.tui.journal import ProgressScreen

        self.app.push_screen(ProgressScreen(self.settings))

    def action_tools(self) -> None:
        from cyberdeck.ui.tui.tools import ToolsScreen

        self.app.push_screen(ToolsScreen())

    @work
    async def action_new(self) -> None:
        answer = await self.app.push_screen_wait(NewBoxModal(str(self.settings.root)))
        if answer is None:
            return
        name, ip, root = answer
        from pathlib import Path

        try:
            ws = services.create_target(self.settings, name, ip, Path(root).expanduser())
        except (ScopeError, WorkspaceError) as exc:
            self.notify(str(exc), severity="error")
            return
        self.notify(f"Created {ws.path}")
        self.refresh_boxes()
        scan = await self.app.push_screen_wait(
            ConfirmModal(
                "Run the initial nmap scan now?", "Both stages, each through the Run dialog."
            )
        )
        self.open_box(ws, offer_scan=scan)
