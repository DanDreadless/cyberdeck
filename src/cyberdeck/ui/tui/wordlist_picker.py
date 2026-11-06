"""Wordlist picker for the Run dialog: Cyberdeck's named lists plus a file browser over the
usual wordlist folders (SecLists, Kali's lists, the box's loot/, home)."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Label, OptionList, Select, Static
from textual.widgets.option_list import Option

from cyberdeck.plugins.wordlists import KALI_LISTS, SECLISTS, Wordlist


def _size(path: Path) -> str:
    try:
        size: float = path.stat().st_size
    except OSError:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return "?"


def browse_roots(box_dir: Path | None) -> list[tuple[str, Path]]:
    """Folders the picker can browse, the ones that exist, most useful first."""
    roots = [("SecLists", SECLISTS), ("Kali wordlists", KALI_LISTS)]
    if box_dir is not None:
        roots.append(("This box (loot/)", box_dir / "loot"))
    roots.append(("Home", Path.home()))
    return [(label, path) for label, path in roots if path.is_dir()]


class WordlistPicker(ModalScreen[str | None]):
    """Returns the chosen file's path, or None."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self, title: str, current: str | None, named: list[Wordlist], box_dir: Path | None
    ) -> None:
        super().__init__()
        self.title_text = title
        self.current = current or ""
        self.named = named
        self.roots = browse_roots(box_dir)

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide tall", id="wordlist-picker"):
            yield Label(self.title_text, classes="dialog-title")
            yield Static(Text(f"Current: {self.current or '(none)'}"), classes="dim")
            yield Label("Named lists", classes="section")
            options = []
            for w in self.named:
                text = Text(f"{w.name:<14}", style="bold")
                text.append(f"{w.path}  ")
                text.append(
                    _size(w.path) if w.exists else "missing", style="dim" if w.exists else "red"
                )
                options.append(Option(text, id=str(w.path), disabled=not w.exists))
            yield OptionList(*options, id="named")
            if self.roots:
                with Horizontal(classes="row"):
                    yield Label("Browse", classes="section")
                    yield Select(
                        [(label, str(path)) for label, path in self.roots],
                        value=str(self.roots[0][1]),
                        allow_blank=False,
                        id="root",
                        compact=True,
                    )
                yield DirectoryTree(self.roots[0][1], id="tree")
            yield Static(id="picked", classes="dim")
            with Horizontal(classes="buttons"):
                yield Button("Cancel  esc", id="cancel", compact=True)

    @on(OptionList.OptionSelected, "#named")
    def _named(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.dismiss(event.option.id)

    @on(Select.Changed, "#root")
    def _root(self, event: Select.Changed) -> None:
        if event.value is not Select.NULL:
            self.query_one("#tree", DirectoryTree).path = Path(str(event.value))

    @on(DirectoryTree.FileSelected)
    def _file(self, event: DirectoryTree.FileSelected) -> None:
        self.dismiss(str(event.path))

    @on(DirectoryTree.NodeHighlighted)
    def _highlight(self, event: DirectoryTree.NodeHighlighted[object]) -> None:
        data = event.node.data
        path = getattr(data, "path", None)
        if isinstance(path, Path) and path.is_file():
            self.query_one("#picked", Static).update(
                Text(f"{path}  {_size(path)}  (enter to use it)")
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
