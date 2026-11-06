"""Journal, flag questions, and the Progress screen (path, skills, playbook): learning L4."""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
)

from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.workspace import Workspace

NEWLINE = chr(10)
LessonAnswer = tuple[str, str, list[str]]
STATUS_MARK = {
    "root": Text("✓ root", style="green"),
    "user": Text("◐ user", style="yellow"),
    "started": Text("· started", style="cyan"),
    "todo": Text(""),
}


class LessonModal(ModalScreen[LessonAnswer | None]):
    """The three flag questions. Every answer is optional; Skip saves nothing."""

    BINDINGS = [Binding("escape", "skip", "Skip"), Binding("ctrl+s", "save", "Save")]

    def __init__(self, headline: str) -> None:
        super().__init__()
        self.headline = headline

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide tall", id="lesson"):
            yield Label(self.headline, classes="dialog-title")
            yield Static(
                Text(
                    "Three quick questions while it's fresh. They go in the box's journal and "
                    'your playbook, so next time Cyberdeck can say "you\'ve seen this before".',
                    style="dim",
                )
            )
            yield Label("What got you in?")
            yield Input(
                placeholder="e.g. the DB password in config.php worked for SSH", id="got-in"
            )
            yield Label("What would you check sooner next time?")
            yield Input(placeholder="e.g. read config files before running linpeas", id="sooner")
            yield Label("Techniques you used (space to tick)")
            yield SelectionList[str](
                *[(t.title, t.id) for t in services.techniques().values()], id="techniques"
            )
            with Horizontal(classes="buttons"):
                yield Button("Save  ctrl+s", variant="primary", id="save")
                yield Button("Skip", id="skip")

    def on_mount(self) -> None:
        self.query_one("#got-in", Input).focus()

    def action_save(self) -> None:
        got_in = self.query_one("#got-in", Input).value
        sooner = self.query_one("#sooner", Input).value
        picked = list(self.query_one("#techniques", SelectionList).selected)
        self.dismiss((got_in, sooner, [str(p) for p in picked]))

    def action_skip(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self.action_save()
        else:
            self.action_skip()


class JournalScreen(Screen[None]):
    """The box's story, built from what it recorded; export it as a write-up."""

    BINDINGS = [
        Binding("e", "export", "Export write-up"),
        Binding("w", "writeup", "Open write-up"),
        Binding("l", "lesson", "Add a lesson"),
        Binding("escape", "back", "Back"),
        Binding("question_mark", "app.toggle_help", "Keys"),
    ]

    def __init__(self, ws: Workspace, settings: Settings) -> None:
        super().__init__()
        self.ws = ws
        self.settings = settings

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(
            "Journal: everything this box recorded, oldest first. e = export a write-up "
            "(passwords, flags and your paths masked), w = read/edit the write-up.",
            classes="section",
        )
        yield VerticalScroll(Static(id="journal-body"), id="journal-scroll")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"Journal: {self.ws.meta.name}"
        self.fill()

    def fill(self) -> None:
        gloss = services.load_glossary()
        text = Text()
        for entry in services.journal(self.ws):
            stamp = entry.at.astimezone().strftime("%m-%d %H:%M")
            style = {"flag": "bold green", "lesson": "bold cyan", "help": "yellow"}.get(
                entry.kind, ""
            )
            text.append(f"{stamp}  ", style="dim")
            text.append_text(gloss.rich(entry.text, style=style))
            for detail in entry.details:
                text.append(NEWLINE + "               " + detail, style="dim")
            text.append(NEWLINE)
        self.query_one("#journal-body", Static).update(text)

    def action_export(self) -> None:
        existing = services.writeup_file(self.ws)
        if not existing.exists():
            self._export()
            return
        from cyberdeck.ui.tui.modals import ConfirmModal

        def answered(replace: bool | None) -> None:
            if replace:
                self._export()

        self.app.push_screen(
            ConfirmModal(
                f"{existing.name} already exists. Replace it?",
                "It is overwritten with a fresh write-up from the journal and any edits in it "
                "are lost. Press w instead to open it, then ctrl+g to draft into the editor.",
                yes="Replace",
                no="Keep it",
            ),
            answered,
        )

    def _export(self) -> None:
        path = services.export_writeup(self.ws, self.settings, overwrite=True)
        self.notify(f"Write-up saved: {path.name} in the box folder (loot and paths masked)")

    def action_writeup(self) -> None:
        from cyberdeck.ui.tui.writeup import WriteupScreen

        self.app.push_screen(WriteupScreen(self.ws, self.settings))

    def action_lesson(self) -> None:
        def answered(answer: LessonAnswer | None) -> None:
            if answer is not None:
                services.record_lesson(self.ws, "note", *answer)
                self.fill()

        self.app.push_screen(LessonModal("What have you learned so far?"), answered)

    def action_back(self) -> None:
        self.app.pop_screen()


class ProgressScreen(Screen[None]):
    """Learning path, skills and your playbook (lessons from every box)."""

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("question_mark", "app.toggle_help", "Keys"),
    ]

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="progress"):
            with TabPane("Path", id="tab-path"):
                yield Static(id="path-head")
                yield DataTable(id="path-table", cursor_type="row")
            with TabPane("Skills", id="tab-skills"):
                yield DataTable(id="skills-table", cursor_type="row")
            with TabPane("Playbook", id="tab-playbook"):
                yield Input(
                    placeholder="Search your lessons: vhost, sudo, a box name...", id="pb-search"
                )
                yield VerticalScroll(Static(id="pb-body"), id="pb-scroll")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Progress"
        path_table: DataTable[Any] = self.query_one("#path-table", DataTable)
        path_table.add_columns("Box", "Stage", "OS", "You", "Practises")
        skills_table: DataTable[Any] = self.query_one("#skills-table", DataTable)
        skills_table.add_columns("Technique", "Boxes", "Where")
        titles = {t.id: t.title for t in services.techniques().values()}
        head = Text()
        for learning_path, steps in services.learning_paths(self.settings):
            done = sum(s.status == "root" for s in steps)
            head.append(
                f"{learning_path.title}  {done}/{len(steps)} rooted" + NEWLINE, style="bold"
            )
            head.append(learning_path.description + NEWLINE, style="dim")
            for s in steps:
                path_table.add_row(
                    s.step.box,
                    s.step.stage,
                    s.step.os or "",
                    STATUS_MARK[s.status],
                    ", ".join(titles.get(k, k) for k in s.step.skills),
                )
        if not head.plain:
            head.append(
                "No learning path (turned off in Settings, or none installed).", style="dim"
            )
        self.query_one("#path-head", Static).update(head)
        for skill in services.skills(self.settings):
            count = len(skill.boxes)
            skills_table.add_row(
                Text(skill.technique.title, style="bold" if count else "dim"),
                Text(str(count) if count else "·", style="green" if count else "dim"),
                ", ".join(skill.boxes),
            )
        self._fill_playbook("")

    @on(Input.Changed, "#pb-search")
    def _search(self, event: Input.Changed) -> None:
        self._fill_playbook(event.value)

    def _fill_playbook(self, query: str) -> None:
        entries = services.playbook(self.settings, query)
        text = Text()
        if not entries:
            text.append(
                "No lessons yet. They're asked when you record a flag (f), or add one from a "
                "box's journal (o, then l).",
                style="dim",
            )
        for entry in entries:
            lesson = entry.lesson
            text.append(f"{entry.box}  ", style="bold")
            text.append(
                f"({lesson.kind}, {lesson.at.astimezone():%Y-%m-%d})" + NEWLINE, style="dim"
            )
            if lesson.got_in:
                text.append(f"  Got in: {lesson.got_in}" + NEWLINE)
            if lesson.sooner:
                text.append(f"  Next time: {lesson.sooner}" + NEWLINE)
            if lesson.techniques:
                text.append(f"  {', '.join(lesson.techniques)}" + NEWLINE, style="cyan")
        self.query_one("#pb-body", Static).update(text)

    def action_back(self) -> None:
        self.app.pop_screen()
