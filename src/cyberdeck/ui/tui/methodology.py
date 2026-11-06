"""Checklist screen and the "Stuck?" dialog (docs/LEARNING-PLAN.md W4/W5, phase L3)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Label, Static

from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.options import OptionError
from cyberdeck.core.workspace import Workspace

NEWLINE = chr(10)
MARK = {
    "done": Text("✓", style="green"),
    "auto": Text("✓", style="green"),
    "na": Text("–", style="dim"),
    "open": Text("·"),
}


class ChecklistScreen(Screen[None]):
    """The box's methodology checklist: what to check per service and phase. Tick items you've
    done; items with a tool open it in the Run dialog (``r``)."""

    BINDINGS = [
        Binding("space,d", "toggle_done", "Done / not done"),
        Binding("n", "not_applicable", "Doesn't apply"),
        Binding("r", "run_tool", "Run its tool"),
        Binding("a", "toggle_all", "Show done too"),
        Binding("escape", "back", "Back"),
        Binding("question_mark", "app.toggle_help", "Keys"),
    ]

    def __init__(
        self, ws: Workspace, settings: Settings, on_run: Callable[[str], object] | None = None
    ) -> None:
        super().__init__()
        self.ws = ws
        self.settings = settings
        self.on_run = on_run
        self.show_all = True
        self.gloss = services.load_glossary()
        self._entries: dict[str, services.ChecklistEntry] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(id="checklist-head", classes="section")
        yield DataTable(id="checklist", cursor_type="row")
        yield VerticalScroll(Static(id="check-detail"), id="check-detail-scroll")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"Checklist: {self.ws.meta.name}"
        table: DataTable[Any] = self.query_one("#checklist", DataTable)
        table.add_columns("", "Check", "Phase")
        self.fill()
        table.focus()

    def fill(self) -> None:
        table: DataTable[Any] = self.query_one("#checklist", DataTable)
        keep = table.cursor_row
        table.clear()
        entries = services.checklist(self.ws, self.settings)
        cover = services.coverage(entries)
        self._entries = {}
        section = None
        for entry in entries:
            if not self.show_all and entry.state != "open":
                continue
            item = entry.item
            if item.section != section:
                section = item.section
                done, total = cover[section]
                name = services.SECTION_TITLES.get(section, section)
                table.add_row(
                    "",
                    Text(f"{name}  {done}/{total}", style="bold yellow"),
                    "",
                    key=f"section:{section}",
                )
            style = "dim" if entry.state != "open" else ""
            title = Text(item.title, style=style)
            if entry.state == "auto":
                title.append("  (ticked by itself)", style="dim italic")
            if item.tool and entry.state == "open":
                title.append(f"  r: {item.tool}", style="cyan")
            self._entries[item.id] = entry
            table.add_row(MARK[entry.state], title, item.phase, key=item.id)
        opened = sum(e.state == "open" for e in entries)
        head = self.query_one("#checklist-head", Label)
        if not entries:
            head.update(
                "Nothing applies yet: scan the box first (or checklists are off in Settings)."
            )
        else:
            head.update(
                f"{opened} open of {len(entries)}. Manual checks matter as much as tools: tick "
                "them as you go."
            )
        if table.row_count:
            table.move_cursor(row=min(keep, table.row_count - 1))
        self._show_detail()

    def _current(self) -> services.ChecklistEntry | None:
        table: DataTable[Any] = self.query_one("#checklist", DataTable)
        if not table.row_count:
            return None
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        return self._entries.get(str(key))

    def _show_detail(self) -> None:
        detail = self.query_one("#check-detail", Static)
        entry = self._current()
        if entry is None:
            detail.update(Text("Pick an item to see why it matters and how to do it.", style="dim"))
            return
        item = entry.item
        text = Text(item.title, style="bold")
        text.append(NEWLINE + "Why: ", style="bold")
        text.append_text(self.gloss.rich(item.why))
        if item.how:
            text.append(NEWLINE + "How: ", style="bold")
            text.append(item.how, style="cyan")
        if item.tool:
            text.append(NEWLINE + f"r runs it with {item.tool} (Run dialog first).", style="dim")
        detail.update(text)

    @on(DataTable.RowHighlighted, "#checklist")
    def _highlighted(self) -> None:
        self._show_detail()

    def _mark(self, status: Literal["done", "na", "open"] | None) -> None:
        """``None`` toggles done."""
        entry = self._current()
        if entry is None:
            return
        if status is None:
            if entry.state == "auto":
                self.notify("This one ticked itself (the tool already ran).")
                return
            status = "open" if entry.state in ("done", "na") else "done"
        try:
            services.mark_checklist(self.ws, entry.item.id, status)
        except OptionError as exc:
            self.notify(str(exc), severity="error")
            return
        self.fill()

    def action_toggle_done(self) -> None:
        self._mark(None)

    def action_not_applicable(self) -> None:
        self._mark("na")

    def action_toggle_all(self) -> None:
        self.show_all = not self.show_all
        self.fill()

    def action_run_tool(self) -> None:
        entry = self._current()
        if entry is None or not entry.item.tool:
            self.notify("This check has no tool: do it by hand (see How), then tick it.")
            return
        if self.on_run is None:
            self.notify("Run it from the box dashboard", severity="warning")
            return
        tool = entry.item.tool
        self.app.pop_screen()
        self.on_run(tool)

    def action_back(self) -> None:
        self.app.pop_screen()


class StuckModal(ModalScreen[str | None]):
    """Stuck? Level 1: what you haven't tried. "Give me a hint": level 2, general hints for the
    situation. Returns "checklist" to open the checklist, else None."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("h", "hint", "Give me a hint"),
        Binding("k", "checklist", "Checklist"),
    ]

    def __init__(self, ws: Workspace, settings: Settings) -> None:
        super().__init__()
        self.ws = ws
        self.settings = settings
        self.gloss = services.load_glossary()

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide tall", id="stuck"):
            yield Label("Stuck? Here's what you haven't tried yet", classes="dialog-title")
            yield VerticalScroll(Static(id="stuck-body"), id="stuck-scroll")
            with Horizontal(classes="buttons"):
                yield Button("Give me a hint  h", variant="primary", id="hint")
                yield Button("Open the checklist  k", id="open-checklist")
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        self.show(services.stuck_report(self.ws, 1, self.settings))

    def show(self, report: services.StuckReport) -> None:
        text = Text()

        def heading(title: str) -> None:
            text.append(("" if not text.plain else NEWLINE) + title + NEWLINE, style="bold yellow")

        if report.level >= 2:  # asked for a hint: hints first, the lists below
            heading("Hints (general, no spoilers)")
            if not report.hints:
                text.append("None for this situation (or hints are off in Settings)." + NEWLINE)
            for pattern in report.hints[:4]:
                text.append(f"★ {pattern.title}" + NEWLINE, style="bold")
                text.append("  ")
                text.append_text(self.gloss.rich(pattern.hint))
                text.append(NEWLINE)
            self.query_one("#hint", Button).disabled = True
            self.query_one("#stuck-scroll", VerticalScroll).scroll_home(animate=False)
        heading("Checks you haven't done")
        if report.untried:
            for entry in report.untried[:10]:
                item = entry.item
                area = services.SECTION_TITLES.get(item.section, item.section)
                text.append(f"· {item.title}", style="bold")
                text.append(f"  ({area})" + NEWLINE, style="dim")
                if item.how:
                    text.append(f"    {item.how}" + NEWLINE, style="cyan")
            if len(report.untried) > 10:
                text.append(f"  ...and {len(report.untried) - 10} more (k)" + NEWLINE, style="dim")
        else:
            text.append("Every check that applies is done. Look at what you set aside." + NEWLINE)
        if report.suggestions:
            heading("Open next steps")
            for sug in report.suggestions[:5]:
                text.append(f"· {sug.title}" + NEWLINE)
        if report.set_aside:
            heading("You set these aside: worth a second look?")
            for sug in report.set_aside[:5]:
                text.append(f"· {sug.title}  ({sug.status.value})" + NEWLINE)
        if report.parked:
            heading("Parked leads")
            for lead in report.parked:
                text.append(f"· {lead.title}" + NEWLINE)
        if report.seen_before:
            heading("You've seen this before")
            for seen in report.seen_before:
                lesson = seen.lesson
                text.append(f"· On {seen.box}: ", style="bold")
                text.append((lesson.got_in or ", ".join(lesson.techniques)) + NEWLINE)
                if lesson.sooner:
                    text.append(f"    Your note: {lesson.sooner}" + NEWLINE, style="dim")
        self.query_one("#stuck-body", Static).update(text)

    def action_hint(self) -> None:
        self.show(services.stuck_report(self.ws, 2, self.settings))

    def action_checklist(self) -> None:
        self.dismiss("checklist")

    def action_close(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "hint":
            self.action_hint()
        elif event.button.id == "open-checklist":
            self.action_checklist()
        else:
            self.action_close()
