"""Draggable dividers between dashboard panes. Textual has no built-in split pane, so a
``Splitter`` is a one-cell bar that resizes one neighbouring pane (its ``target``) when dragged
with the mouse, or through :meth:`Splitter.nudge` from a key binding."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from textual import events
from textual.message import Message
from textual.widget import Widget


class Splitter(Widget):
    """A divider that sets the width (``axis="x"``) or height (``axis="y"``) of the pane with
    id ``target``. ``after=True`` when the pane is after the bar (right of it / below it), so
    dragging towards the pane makes it smaller.

    ``flex`` is the sibling that takes up the rest of the space; it always keeps ``min_other``
    cells. Other visible siblings (a header, a banner) keep their own size, so they are taken
    off the space first. ``preferred`` is the size the user chose: it is saved, and
    :meth:`fit` re-applies it within what the current terminal allows, so a small window
    squeezes the pane without forgetting the choice."""

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
        min_other: int | Callable[[], int] = 4,
        flex: str | None = None,
        id: str | None = None,  # noqa: A002 (Textual's own name)
    ) -> None:
        super().__init__(id=id, classes=f"-{axis}")
        self.target = target
        self.axis = axis
        self.after = after
        self.min_size = min_size
        self.min_other = min_other  # cells always left for the flex sibling (or how to work it out)
        self.flex = flex
        self.value: int | None = None  # size in effect now (after fitting)
        self.preferred: int | None = None  # size the user chose (saved)
        self._drag: tuple[int, int] | None = None  # (mouse position, pane size) at mouse down

    def render(self) -> str:
        return ""

    @property
    def pane(self) -> Widget:
        return self.screen.query_one(f"#{self.target}", Widget)

    def current(self) -> int:
        size = self.pane.outer_size
        return size.width if self.axis == "x" else size.height

    def _extent(self, widget: Widget) -> int:
        size = widget.outer_size
        return size.width if self.axis == "x" else size.height

    def limits(self) -> tuple[int, int]:
        """(smallest, largest) size for the pane: the largest leaves the flex sibling
        ``min_other`` cells after every other visible sibling has its own size."""
        pane = self.pane
        parent = pane.parent
        total = 0
        if isinstance(parent, Widget):
            total = parent.size.width if self.axis == "x" else parent.size.height
            for sibling in parent.children:
                if sibling is pane or sibling is self or not sibling.display:
                    continue
                if self.flex is not None and sibling.id == self.flex:
                    continue
                if isinstance(sibling, Splitter) or self.flex is not None:
                    total -= self._extent(sibling)
        total -= 1  # this bar
        keep = self.min_other() if callable(self.min_other) else self.min_other
        return self.min_size, max(self.min_size, total - keep)

    def set_size(self, size: int, *, remember: bool = True) -> int:
        """Resize the pane within :meth:`limits`. ``remember`` makes it the user's choice."""
        low, high = self.limits()
        fitted = max(low, min(high, size))
        if self.axis == "x":
            self.pane.styles.width = fitted
        else:
            self.pane.styles.height = fitted
        self.value = fitted
        if remember:
            self.preferred = fitted
        return fitted

    def fit(self) -> None:
        """Re-apply the preferred size within what the pane's parent allows right now."""
        if self.preferred is not None:
            self.set_size(self.preferred, remember=False)

    def nudge(self, delta: int) -> int:
        return self.set_size((self.value or self.current()) + delta)

    def reset(self) -> None:
        """Back to the size from the stylesheet."""
        if self.axis == "x":
            self.pane.styles.width = None
        else:
            self.pane.styles.height = None
        self.value = None
        self.preferred = None

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
        self.post_message(self.Resized(self, self.preferred or self.current()))
        event.stop()
