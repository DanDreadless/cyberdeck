"""Job detail: exact command, output (stdout or stderr), re-parse, run again (docs/UI.md)."""

from __future__ import annotations

from collections.abc import Callable

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from cyberdeck.core import services
from cyberdeck.core.models import JobStatus
from cyberdeck.core.options import OptionError
from cyberdeck.core.runner import CancelError, cancel_job
from cyberdeck.core.termsafe import terminal_safe_text
from cyberdeck.core.workspace import Workspace
from cyberdeck.ui.tui.modals import ConfirmModal

NEWLINE = chr(10)


class JobScreen(Screen[None]):
    BINDINGS = [
        Binding("e", "toggle_stream", "stdout/stderr"),
        Binding("p", "reparse", "Re-parse"),
        Binding("r", "rerun", "Run again"),
        Binding("k", "kill", "Kill job"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(
        self, ws: Workspace, job_id: int, on_rerun: Callable[[int], object] | None = None
    ) -> None:
        super().__init__()
        self.ws = ws
        self.job_id = job_id
        self.on_rerun = on_rerun  # opens the Run dialog for this job (set by the dashboard)
        self.show_err = False
        self.running = False

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="job-head")
        with VerticalScroll(id="job-output"):
            yield Static(id="job-text")
        yield Footer()

    def on_mount(self) -> None:
        self.fill()
        self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        """Follow a running job's output; one last refresh once it ends."""
        if self.running:
            self.fill()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action == "kill":
            return self.running
        return True

    def fill(self) -> None:
        job, cmd, out, err = services.job_files(self.ws, self.job_id)
        self.title = f"Job #{job.id} {job.tool}"
        was_running = self.running
        self.running = job.status is JobStatus.RUNNING
        if was_running != self.running:
            self.refresh_bindings()
        head = Text()
        head.append(
            f"#{job.id} {job.tool}  {job.status.value}  origin={job.origin}\n", style="bold"
        )
        if cmd.is_file():
            head.append(cmd.read_text(encoding="utf-8"), style="cyan")
        if services.summaries_enabled() and job.id is not None:
            gloss = services.load_glossary()
            summary = services.job_summary(self.ws, job.id)
            head.append(f"▶ {summary.headline}", style="bold")
            for line in summary.lines:
                head.append(NEWLINE + "  ")
                head.append_text(gloss.rich(line))
            for hl in summary.highlights:
                head.append(NEWLINE + "  ★ " + hl.title + ": ", style="bold yellow")
                head.append_text(gloss.rich(hl.meaning))
            head.append(NEWLINE)
        self.query_one("#job-head", Static).update(head)
        path = err if self.show_err else out
        body = (
            path.read_text(encoding="utf-8", errors="replace")
            if path.is_file()
            else f"(no {path.name})"
        )
        lines = body.splitlines()
        shown = "\n".join(lines[-2000:])
        cut = ", last 2000" if len(lines) > 2000 else ""
        prefix = f"--- {path.name} ({len(lines)} lines{cut}) ---\n"
        body_text = Text(prefix)
        body_text.append_text(Text.from_ansi(terminal_safe_text(shown)))
        scroll = self.query_one("#job-output", VerticalScroll)
        at_end = scroll.is_vertical_scroll_end
        self.query_one("#job-text", Static).update(body_text)
        if at_end:
            scroll.call_after_refresh(scroll.scroll_end, animate=False)

    def action_toggle_stream(self) -> None:
        self.show_err = not self.show_err
        self.fill()

    def action_reparse(self) -> None:
        try:
            report = services.reparse_job(self.ws, self.job_id)
        except OptionError as exc:
            self.notify(str(exc), severity="error")
            return
        if report.error:
            self.notify(report.error, severity="warning")
        else:
            self.notify(f"{len(report.created)} new findings, {len(report.updated)} updated")

    def action_rerun(self) -> None:
        """Back to the dashboard and open the Run dialog with this job's command, to edit or
        run as it is."""
        if self.on_rerun is None:
            self.notify("Run it again from the box dashboard", severity="warning")
            return
        self.app.pop_screen()
        self.on_rerun(self.job_id)

    def action_kill(self) -> None:
        if not self.running:
            return

        def answered(yes: bool | None) -> None:
            if yes:
                self._kill()

        self.app.push_screen(
            ConfirmModal(
                f"Kill job #{self.job_id}?",
                "The tool is stopped now. Output so far stays in raw/ and the job is marked"
                " cancelled.",
                yes="Kill",
                no="Keep running",
            ),
            answered,
        )

    @work(thread=True, exclusive=True, group="kill")
    def _kill(self) -> None:
        try:
            cancel_job(self.ws, self.job_id)
        except CancelError as exc:
            self.app.call_from_thread(self.notify, str(exc), severity="error")
            return
        self.app.call_from_thread(self.notify, f"Job #{self.job_id} killed")

    def action_back(self) -> None:
        self.app.pop_screen()
