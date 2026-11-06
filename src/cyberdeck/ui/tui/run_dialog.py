"""TUI Run dialog (ADR 0005): every job's flags are shown, editable, and previewed as the exact
command before it runs. Same :class:`RunPlan` as the terminal dialog (``ui/run_dialog.py``)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import Button, Checkbox, Input, Label, Select, Static

from cyberdeck.core import services
from cyberdeck.core.options import OptionError, OptionSpec, RunPlan
from cyberdeck.plugins.wordlists import Wordlist
from cyberdeck.ui.tui.modals import InputModal, TextModal
from cyberdeck.ui.tui.wordlist_picker import WordlistPicker

NEWLINE = chr(10)
SAFETY_STYLE = {"safe": "green", "intrusive": "yellow", "bruteforce": "red", "exploit": "red"}


class RunDialog(ModalScreen[RunPlan | None]):
    """Returns the (edited) plan to run, or None if skipped."""

    BINDINGS = [
        Binding("ctrl+r", "run", "Run", priority=True),
        Binding("escape", "cancel", "Skip"),
        Binding("f1", "tool_help", "Tool --help"),
        Binding("f2", "man_page", "man page"),
    ]

    def __init__(
        self,
        plan: RunPlan,
        *,
        is_root: bool,
        save_user: Callable[[RunPlan], str],
        save_box: Callable[[RunPlan], str],
        show_help: Callable[[RunPlan], str | None],
        show_man: Callable[[RunPlan], str | None] | None = None,
        wordlists: Callable[[], list[Wordlist]] | None = None,
        box_dir: Path | None = None,
    ) -> None:
        super().__init__()
        self.plan = plan
        self.is_root = is_root
        self.save_user = save_user
        self.save_box = save_box
        self.show_help = show_help
        self.show_man = show_man
        self.wordlists = wordlists
        self.box_dir = box_dir
        self.show_advanced = False

    # -- layout ----------------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        tool = self.plan.tool
        title = Text(f"Run: {tool.name}  ")
        title.append(tool.safety, style=SAFETY_STYLE.get(tool.safety, "red"))
        with Vertical(classes="dialog wide tall", id="run-dialog"):
            yield Label(title, classes="dialog-title")
            yield Static(Text(tool.description), classes="dim")
            teach = services.teaching(tool)
            if teach is not None:
                gloss = services.load_glossary()
                text = Text()
                if teach.does:
                    text.append("What it does: ", style="bold")
                    text.append_text(gloss.rich(teach.does))
                if teach.look_for:
                    text.append(NEWLINE if teach.does else "")
                    text.append("Look for: ", style="bold")
                    text.append_text(gloss.rich(teach.look_for))
                yield Static(text, id="teach")
            if tool.presets:
                yield Select(
                    [(name, name) for name in tool.presets],
                    prompt="preset: default",
                    value=self.plan.preset if self.plan.preset else Select.NULL,
                    id="preset",
                    compact=True,
                )
            with VerticalScroll(id="form"):
                yield from self._rows()
            with Horizontal(classes="row"):
                yield Label("Extra args", classes="opt-label")
                yield Input(
                    " ".join(self.plan.extra),
                    placeholder="flags not listed above",
                    id="extra",
                    compact=True,
                )
            with Horizontal(classes="row"):
                advanced = sum(1 for o in tool.options if o.advanced)
                yield Checkbox(
                    f"Show advanced ({advanced})", self.show_advanced, id="advanced", compact=True
                )
                yield Checkbox("Run with sudo", self.plan.sudo, id="sudo", compact=True)
            yield Static(id="notes")
            yield Static(id="preview")
            with Horizontal(classes="buttons"):
                yield Button("Run  ctrl+r", variant="primary", id="run", compact=True)
                yield Button("Edit command", id="edit", compact=True)
                yield Button("--help  F1", id="help", compact=True)
                yield Button("man page  F2", id="man", compact=True)
                yield Button("Save as my default", id="save-user", compact=True)
                yield Button("Save for this box", id="save-box", compact=True)
                yield Button("Skip  esc", id="cancel", compact=True)

    def _rows(self) -> list[Widget]:
        rows: list[Widget] = []
        for opt in self.plan.tool.options:
            if opt.advanced and not self.show_advanced:
                continue
            value = self.plan.values.get(opt.id)
            label = opt.title + (" *" if opt.input and opt.required else "")
            row: list[Widget] = [Label(label, classes="opt-label"), self._editor(opt, value)]
            if opt.type == "wordlist":
                row.append(Button("Browse…", id=f"pick-{opt.id}", classes="pick", compact=True))
            parts: list[Widget] = [Horizontal(*row, classes="row")]
            if opt.help:
                parts.append(Static(Text(opt.help), classes="dim opt-help"))
            rows.append(Vertical(*parts, classes="opt"))
        return rows

    @staticmethod
    def _editor(opt: OptionSpec, value: object) -> Checkbox | Select[str] | Input:
        wid = f"opt-{opt.id}"
        if opt.type == "bool":
            return Checkbox("", bool(value), id=wid, classes="opt-bool", compact=True)
        choices = opt.choices or list(opt.render_map or {})
        if opt.type == "choice" and choices:
            select: Select[str] = Select(
                [(c, c) for c in choices], id=wid, allow_blank=True, compact=True
            )
            if value is not None and str(value) in choices:
                select.value = str(value)
            return select
        return Input("" if value is None else opt.display(value), id=wid, compact=True)

    def on_mount(self) -> None:
        self.update_preview()

    async def rebuild_form(self) -> None:
        form = self.query_one("#form", VerticalScroll)
        await form.remove_children()
        await form.mount_all(self._rows())
        self.update_preview()

    # -- state -> view ---------------------------------------------------------------------
    def update_preview(self) -> None:
        plan = self.plan
        notes = Text()
        for warning in plan.warnings:
            notes.append(f"! {warning}\n", style="yellow")
        problems = plan.problems(self.is_root)
        for problem in problems:
            notes.append(f"✗ {problem}\n", style="red")
        if plan.raw_argv is not None:
            notes.append("Command edited by hand; changing an option resets it.\n", style="yellow")
        if plan.tool.binary == "nmap" and not self.is_root and not plan.sudo:
            notes.append(
                "Not root: nmap uses a connect scan (-sT). Tick sudo for SYN/UDP/OS.\n", style="dim"
            )
        if plan.tool.notes:
            notes.append(f"Note: {plan.tool.notes}\n", style="yellow")
        if plan.tool.learn:
            notes.append(f"Learn more: {plan.tool.learn}\n", style="dim")
        self.query_one("#notes", Static).update(notes)
        try:
            preview = Text("$ " + plan.command_line(), style="bold cyan")
        except (OptionError, ValueError):
            try:
                preview = Text("$ " + plan.draft_command_line(), style="dim cyan")
                preview.append("\n  (fill in the fields marked *)", style="dim")
            except (OptionError, ValueError):
                preview = Text("$ (fill in the fields marked * to see the command)", style="dim")
        self.query_one("#preview", Static).update(preview)
        self.query_one("#run", Button).disabled = bool(problems)

    def _set(self, option_id: str, raw: str) -> None:
        try:
            self.plan.set_option(option_id, raw if raw.strip() else "none")
        except (OptionError, ValueError) as exc:
            self.notify(str(exc), severity="error")
        self.update_preview()

    # -- events ----------------------------------------------------------------------------
    @on(Input.Changed)
    def _input_changed(self, event: Input.Changed) -> None:
        wid = event.input.id or ""
        if wid == "extra":
            try:
                self.plan.set_extra(event.value)
            except ValueError as exc:  # unbalanced quotes while typing
                self.query_one("#notes", Static).update(Text(str(exc), style="red"))
                return
            self.update_preview()
        elif wid.startswith("opt-"):
            option_id = wid[4:]
            opt = next(o for o in self.plan.tool.options if o.id == option_id)
            current = self.plan.values.get(option_id)
            shown = "" if current is None else opt.display(current)
            if event.value != shown:
                self._set(option_id, event.value)

    @on(Checkbox.Changed)
    async def _checkbox_changed(self, event: Checkbox.Changed) -> None:
        wid = event.checkbox.id or ""
        if wid == "advanced":
            self.show_advanced = event.value
            await self.rebuild_form()
        elif wid == "sudo":
            self.plan.sudo = event.value
            self.update_preview()
        elif wid.startswith("opt-") and bool(self.plan.values.get(wid[4:])) != event.value:
            self._set(wid[4:], "yes" if event.value else "no")

    @on(Select.Changed)
    async def _select_changed(self, event: Select.Changed) -> None:
        wid = event.select.id or ""
        value = event.value
        if wid == "preset":
            if value is not Select.NULL and value != self.plan.preset:
                try:
                    self.plan.apply_preset(str(value))
                except OptionError as exc:
                    self.notify(str(exc), severity="error")
                await self.rebuild_form()
        elif wid.startswith("opt-"):
            text = "" if value is Select.NULL else str(value)
            current = self.plan.values.get(wid[4:])
            if text != ("" if current is None else str(current)):
                self._set(wid[4:], text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions: dict[str, Callable[[], None]] = {
            "run": self.action_run,
            "cancel": self.action_cancel,
            "help": self.action_tool_help,
            "edit": self.action_edit,
            "save-user": lambda: self.notify(
                f"Saved as your default in {self.save_user(self.plan)}"
            ),
            "save-box": lambda: self.notify(f"Saved for this box in {self.save_box(self.plan)}"),
        }
        button_id = event.button.id or ""
        if button_id.startswith("pick-"):
            self.pick_wordlist(button_id[5:])
            return
        actions["man"] = self.action_man_page
        action = actions.get(button_id)
        if action:
            action()

    def pick_wordlist(self, option_id: str) -> None:
        """Choose a wordlist from the named lists or by browsing; it fills the field."""
        opt = next(o for o in self.plan.tool.options if o.id == option_id)
        current = self.plan.values.get(option_id)

        def chosen(path: str | None) -> None:
            if path:
                self.query_one(f"#opt-{option_id}", Input).value = path

        named = self.wordlists() if self.wordlists else []
        self.app.push_screen(
            WordlistPicker(
                f"{opt.title}: choose a wordlist", str(current or ""), named, self.box_dir
            ),
            chosen,
        )

    def action_man_page(self) -> None:
        binary = self.plan.tool.detect_spec.binary
        text = self.show_man(self.plan) if self.show_man else None
        if text:
            self.app.push_screen(TextModal(f"man {binary}", text))
            return
        learn = f" Learn more: {self.plan.tool.learn}" if self.plan.tool.learn else ""
        self.notify(f"{binary} has no man page; showing its --help.{learn}", severity="warning")
        self.action_tool_help()

    # -- actions ---------------------------------------------------------------------------
    def action_run(self) -> None:
        problems = self.plan.problems(self.is_root)
        if problems:
            self.notify("; ".join(problems), title="Fix these first", severity="error")
            return
        self.dismiss(self.plan)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_tool_help(self) -> None:
        text = self.show_help(self.plan)
        if text:
            self.app.push_screen(TextModal(f"{self.plan.tool.name} --help", text))
        else:
            self.notify("No help text available (is the tool installed?)", severity="warning")

    def action_edit(self) -> None:
        def done(raw: str | None) -> None:
            if raw and raw.strip():
                try:
                    self.plan.set_raw(raw)
                except (OptionError, ValueError) as exc:
                    self.notify(str(exc), severity="error")
                self.update_preview()

        try:
            current = self.plan.draft_command_line()
        except (OptionError, ValueError) as exc:
            self.notify(str(exc), severity="error")
            return
        self.app.push_screen(InputModal("Edit the exact command", current), done)
