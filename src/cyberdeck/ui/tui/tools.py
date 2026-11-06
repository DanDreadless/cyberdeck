"""Tools screen: installed or not, version, enabled, group preference (docs/UI.md screen 3)."""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Label, Static

from cyberdeck.core import services
from cyberdeck.core.options import OptionError
from cyberdeck.ui.tui.modals import TextModal
from cyberdeck.ui.tui.run_dialog import SAFETY_STYLE


class ToolsScreen(Screen[None]):
    BINDINGS = [
        Binding("e", "toggle_enabled", "Enable/disable"),
        Binding("p", "prefer", "Prefer in group"),
        Binding("h", "help", "Tool --help"),
        Binding("w", "wordlists", "Wordlists"),
        Binding("d", "detect", "Re-detect"),
        Binding("escape", "back", "Back"),
        Binding("question_mark", "app.toggle_help", "Keys"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Tools: * = the one used when you run its group", classes="section")
        yield DataTable(id="tools", cursor_type="row")
        yield Static(id="errors")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Tools"
        table: DataTable[Any] = self.query_one("#tools", DataTable)
        table.add_columns("Tool", "Group / category", "Safety", "Installed", "Version", "Enabled")
        self.fill()
        table.focus()

    def fill(self, *, refresh: bool = False) -> None:
        table: DataTable[Any] = self.query_one("#tools", DataTable)
        keep = table.cursor_row
        table.clear()
        infos = services.tool_infos(refresh=refresh)
        for info in sorted(infos, key=lambda i: i.tool.id):  # A-Z; the category is a column
            tool, status = info.tool, info.status
            installed = (
                Text("yes", style="green")
                if status.installed
                else Text(f"no: {status.install_hint}", style="red")
            )
            table.add_row(
                tool.id + (" *" if info.preferred else ""),
                tool.group or tool.category,
                Text(tool.safety, style=SAFETY_STYLE.get(tool.safety, "red")),
                installed,
                status.version or "-",
                Text("yes") if info.enabled else Text("no", style="yellow"),
                key=tool.id,
            )
        if table.row_count:
            table.move_cursor(row=min(keep, table.row_count - 1))
        errors = Text()
        for path, error in services.tool_load_errors():
            errors.append(f"✗ {path}: {error}\n", style="red")
        self.query_one("#errors", Static).update(errors)

    def _tool_id(self) -> str | None:
        table: DataTable[Any] = self.query_one("#tools", DataTable)
        if not table.row_count:
            return None
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

    def action_toggle_enabled(self) -> None:
        tool_id = self._tool_id()
        if tool_id is None:
            return
        info = next(i for i in services.tool_infos() if i.tool.id == tool_id)
        services.set_tool_enabled(tool_id, not info.enabled)
        self.notify(f"{tool_id} {'disabled' if info.enabled else 'enabled'}")
        self.fill()

    def action_prefer(self) -> None:
        tool_id = self._tool_id()
        if tool_id is None:
            return
        try:
            group, _ = services.prefer_tool(tool_id)
        except OptionError as exc:
            self.notify(str(exc), severity="warning")
            return
        self.notify(f"{tool_id} is now used for {group}")
        self.fill()

    def action_help(self) -> None:
        tool_id = self._tool_id()
        if tool_id is None:
            return
        text = services.help_text(tool_id)
        if text:
            self.app.push_screen(TextModal(f"{tool_id} --help", text))
        else:
            self.notify("No help text (is it installed?)", severity="warning")

    def action_wordlists(self) -> None:
        lines = []
        for wl in services.wordlist_status():
            mark = "✓" if wl.exists else "✗ missing"
            mine = " (yours)" if wl.overridden else ""
            lines.append(f"{wl.name:<14} {mark:<10} {wl.path}{mine}\n    {wl.purpose}")
        lines.append(
            "\nMissing lists: sudo apt install seclists, or set your own under wordlists: "
            "in config.yaml"
        )
        self.app.push_screen(TextModal("Wordlists", "\n".join(lines)))

    @work(thread=True)
    def action_detect(self) -> None:
        self.app.call_from_thread(self.notify, "Re-checking installed tools...")
        services.tool_infos(refresh=True)
        self.app.call_from_thread(self.fill)
        self.app.call_from_thread(self.notify, "Tool detection refreshed")

    def action_back(self) -> None:
        self.app.pop_screen()
