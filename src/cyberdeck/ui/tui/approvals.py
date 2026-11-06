"""Approvals: requests from MCP clients that wait for a human (ADR 0007, docs/UI.md).

The screen only lists and picks; the dashboard carries out the decision (it owns the job log
and the sudo/hosts flows).
"""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Label, Static

from cyberdeck.core import services
from cyberdeck.core.models import Approval
from cyberdeck.core.workspace import Workspace
from cyberdeck.ui.tui.run_dialog import SAFETY_STYLE

Decision = tuple[str, int]  # ("approve" | "deny", approval id)


class ApprovalsScreen(Screen[Decision | None]):
    BINDINGS = [
        Binding("a,enter", "decide('approve')", "Approve..."),
        Binding("d", "decide('deny')", "Deny"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, ws: Workspace) -> None:
        super().__init__()
        self.ws = ws
        self._rows: dict[str, Approval] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Requests from MCP clients waiting for you", classes="section")
        yield DataTable(id="approvals", cursor_type="row")
        yield Static(id="approval-detail")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"Approvals: {self.ws.meta.name}"
        table: DataTable[Any] = self.query_one("#approvals", DataTable)
        table.add_columns("#", "Kind", "Request", "Safety", "Asked")
        for a in services.list_approvals(self.ws):
            key = str(a.id)
            self._rows[key] = a
            table.add_row(
                key,
                a.kind,
                a.title,
                Text(a.safety, style=SAFETY_STYLE.get(a.safety, "yellow")),
                a.created_at.astimezone().strftime("%H:%M"),
                key=key,
            )
        if not table.row_count:
            self.query_one("#approval-detail", Static).update("Nothing waiting.")
        table.focus()
        self._show()

    def on_data_table_row_highlighted(self) -> None:
        self._show()

    def _current(self) -> Approval | None:
        table: DataTable[Any] = self.query_one("#approvals", DataTable)
        if not table.row_count:
            return None
        return self._rows.get(
            str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        )

    def _show(self) -> None:
        a = self._current()
        if a is None:
            return
        text = Text()
        if a.kind == "job":
            text.append(f"$ {a.payload.get('command', '')}\n", style="bold cyan")
            text.append(f"Needs approval because {a.payload.get('why_approval', 'requested')}.\n")
        else:
            text.append(str(a.payload.get("diff", "")))
        if a.reason:
            text.append(f"Reason given: {a.reason}\n", style="dim")
        self.query_one("#approval-detail", Static).update(text)

    def action_decide(self, verb: str) -> None:
        a = self._current()
        if a is not None and a.id is not None:
            self.dismiss((verb, a.id))

    def action_back(self) -> None:
        self.dismiss(None)
