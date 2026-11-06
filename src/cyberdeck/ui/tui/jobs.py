"""Job detail: exact command, output (stdout or stderr), re-parse, run again (docs/UI.md)."""

from __future__ import annotations

from collections.abc import Callable

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from cyberdeck.core import services
from cyberdeck.core.options import OptionError
from cyberdeck.core.workspace import Workspace

NEWLINE = chr(10)


class JobScreen(Screen[None]):
    BINDINGS = [
        Binding("e", "toggle_stream", "stdout/stderr"),
        Binding("p", "reparse", "Re-parse"),
        Binding("r", "rerun", "Run again"),
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

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="job-head")
        with VerticalScroll(id="job-output"):
            yield Static(id="job-text")
        yield Footer()

    def on_mount(self) -> None:
        self.fill()

    def fill(self) -> None:
        job, cmd, out, err = services.job_files(self.ws, self.job_id)
        self.title = f"Job #{job.id} {job.tool}"
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
        self.query_one("#job-text", Static).update(Text(prefix + shown))

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

    def action_back(self) -> None:
        self.app.pop_screen()
