"""Draggable dividers between dashboard panes. Textual has no built-in split pane, so a
``Splitter`` is a one-cell bar that resizes one neighbouring pane (its ``target``) when dragged
with the mouse, or through :meth:`Splitter.nudge` from a key binding."""

from __future__ import annotations

from typing import Literal

from textual import events
from textual.message import Message
from textual.widget import Widget


class Splitter(Widget):
    """A divider that sets the width (``axis="x"``) or height (``axis="y"``) of the pane with
    id ``target``. ``after=True`` when the pane is after the bar (right of it / below it), so
    dragging towards the pane makes it smaller."""

    DEFAULT_CSS = """
    Splitter { background: $panel; }
    Splitter.-x { width: 1; height: 1fr; }
    Splitter.-y { height: 1; width: 1fr; }
    Splitter:hover, Splitter.-dragging { background: $accent; }
    """

    class Resized(Message):
        """Posted when a drag ends, so the screen can save the layout."""

        def __init__(self, splitter: Splitter, size: int) -> None:
            super().__init__()
            self.splitter = splitter
            self.size = size

    def __init__(
        self,
        target: str,
        *,
        axis: Literal["x", "y"],
        after: bool = False,
        min_size: int = 4,
        min_other: int = 4,
        id: str | None = None,  # noqa: A002 (Textual's own name)
    ) -> None:
        super().__init__(id=id, classes=f"-{axis}")
        self.target = target
        self.axis = axis
        self.after = after
        self.min_size = min_size
        self.min_other = min_other  # cells left for everything else in the pane's parent
        self.value: int | None = None  # last size set through this splitter
        self._drag: tuple[int, int] | None = None  # (mouse position, pane size) at mouse down

    def render(self) -> str:
        return ""

    @property
    def pane(self) -> Widget:
        return self.screen.query_one(f"#{self.target}", Widget)

    def current(self) -> int:
        size = self.pane.outer_size
        return size.width if self.axis == "x" else size.height

    def limits(self) -> tuple[int, int]:
        parent = self.pane.parent
        total = 0
        if isinstance(parent, Widget):
            total = parent.size.width if self.axis == "x" else parent.size.height
        return self.min_size, max(self.min_size, total - 1 - self.min_other)

    def set_size(self, size: int) -> int:
        """Resize the pane, kept between ``min_size`` and what leaves ``min_other`` free."""
        low, high = self.limits()
        size = max(low, min(high, size))
        if self.axis == "x":
            self.pane.styles.width = size
        else:
            self.pane.styles.height = size
        self.value = size
        return size

    def nudge(self, delta: int) -> int:
        return self.set_size((self.value or self.current()) + delta)

    def reset(self) -> None:
        """Back to the size from the stylesheet."""
        if self.axis == "x":
            self.pane.styles.width = None
        else:
            self.pane.styles.height = None
        self.value = None

    def _position(self, event: events.MouseEvent) -> int:
        return int(event.screen_x if self.axis == "x" else event.screen_y)

    def on_mouse_down(self, event: events.MouseDown) -> None:
        self._drag = (self._position(event), self.value or self.current())
        self.capture_mouse()
        self.add_class("-dragging")
        event.stop()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if self._drag is None:
            return
        start, size = self._drag
        delta = self._position(event) - start
        self.set_size(size - delta if self.after else size + delta)
        event.stop()

    def on_mouse_up(self, event: events.MouseUp) -> None:
        if self._drag is None:
            return
        self._drag = None
        self.release_mouse()
        self.remove_class("-dragging")
        self.post_message(self.Resized(self, self.value or self.current()))
        event.stop()
