"""Small modal dialogs shared by the TUI screens."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from cyberdeck.util.hosts import HostsChange


class ConfirmModal(ModalScreen[bool]):
    """Yes/no question. Returns True for yes."""

    BINDINGS = [
        Binding("y", "answer(True)", "Yes"),
        Binding("n,escape", "answer(False)", "No"),
    ]

    def __init__(
        self, question: str, detail: str = "", *, yes: str = "Yes", no: str = "No"
    ) -> None:
        super().__init__()
        self.question = question
        self.detail = detail
        self.yes_label = yes
        self.no_label = no

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self.question, classes="dialog-title")
            if self.detail:
                yield Static(Text(self.detail), classes="dim")
            with Horizontal(classes="buttons"):
                yield Button(self.yes_label, variant="primary", id="yes")
                yield Button(self.no_label, id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_answer(self, value: bool) -> None:
        self.dismiss(value)


class InputModal(ModalScreen[str | None]):
    """Ask for one line of text. Returns None if cancelled."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, prompt: str, default: str = "", *, password: bool = False) -> None:
        super().__init__()
        self.prompt = prompt
        self.default = default
        self.password = password

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self.prompt, classes="dialog-title")
            yield Input(value=self.default, password=self.password, id="answer")
            with Horizontal(classes="buttons"):
                yield Button("OK", variant="primary", id="ok")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(self.query_one(Input).value if event.button.id == "ok" else None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class TextModal(ModalScreen[None]):
    """Scrollable read-only text (a tool's --help, a job's output, an explanation)."""

    BINDINGS = [Binding("escape,q", "close", "Close")]

    def __init__(self, title: str, text: str) -> None:
        super().__init__()
        self.title_text = title
        self.body = text

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Label(self.title_text, classes="dialog-title")
            with VerticalScroll(classes="text-body"):
                yield Static(Text(self.body))
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


def diff_text(change: HostsChange) -> Text:
    text = Text()
    for line in change.diff().splitlines():
        style = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim"
        text.append(line + "\n", style=style)
    for warning in change.warnings:
        text.append(f"! {warning}\n", style="yellow")
    return text


class HostsModal(ModalScreen[bool]):
    """Shows the exact /etc/hosts change (CLAUDE.md rule 7). True = write it."""

    BINDINGS = [Binding("escape,n", "answer(False)", "Cancel")]

    def __init__(self, change: HostsChange, needs_sudo: bool) -> None:
        super().__init__()
        self.change = change
        self.needs_sudo = needs_sudo

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Label(f"Change {self.change.path}?", classes="dialog-title")
            with VerticalScroll(classes="text-body"):
                yield Static(diff_text(self.change), id="diff")
            if self.needs_sudo:
                yield Static(
                    "Needs sudo: Cyberdeck steps aside so you can type your password into sudo "
                    "itself (never into Cyberdeck).",
                    classes="dim",
                )
            with Horizontal(classes="buttons"):
                yield Button("Write it", variant="warning", id="yes")
                yield Button("Cancel", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_answer(self, value: bool) -> None:
        self.dismiss(value)
