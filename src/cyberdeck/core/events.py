"""In-process event bus (docs/ARCHITECTURE.md "Events").

The service layer emits events when findings change, jobs start or finish, and suggestions
change; front ends (the TUI's live panes, later the MCP server) subscribe to refresh. Handlers
run synchronously in the emitting thread; a failing handler is logged and never breaks the
emitter. Events are notifications only: the box's DB stays the single source of truth.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from cyberdeck.core.models import Finding, Job

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Event:
    box: Path  # the box folder the event is about


@dataclass(frozen=True)
class FindingsChanged(Event):
    created: list[Finding] = field(default_factory=list)
    updated: list[Finding] = field(default_factory=list)
    source: str = ""  # job:<id>:<tool>, import:<file>, hosts, answer...


@dataclass(frozen=True)
class JobStarted(Event):
    job: Job | None = None


@dataclass(frozen=True)
class JobFinished(Event):
    job: Job | None = None


@dataclass(frozen=True)
class SuggestionsChanged(Event):
    opened: list[Any] = field(default_factory=list)  # list[Suggestion] newly open


E = TypeVar("E", bound=Event)
Handler = Callable[[Any], None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: list[tuple[type[Event], Handler]] = []

    def subscribe(self, kind: type[E], handler: Callable[[E], None]) -> Callable[[], None]:
        """Call ``handler`` for every event of ``kind`` (or a subclass). Returns an
        unsubscribe function."""
        entry = (kind, handler)
        self._handlers.append(entry)

        def unsubscribe() -> None:
            if entry in self._handlers:
                self._handlers.remove(entry)

        return unsubscribe

    def emit(self, event: Event) -> None:
        for kind, handler in list(self._handlers):
            if not isinstance(event, kind):
                continue
            try:
                handler(event)
            except Exception:  # a broken subscriber must not break a scan
                log.exception("event handler %r failed on %s", handler, type(event).__name__)

    def clear(self) -> None:
        self._handlers.clear()


bus = EventBus()
