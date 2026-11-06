"""Box dashboard: services | findings | next steps | jobs + live log (docs/UI.md screen 2).

Everything goes through ``core/services.py``. Jobs run as async workers in the app's event loop;
their output streams into the log. The screen refreshes on events from ``core/events.bus`` and
when the box's DB changes on disk (a CLI in another terminal, later the MCP server).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Literal

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    OptionList,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)
from textual.widgets.option_list import Option

from cyberdeck.core import glossary, services
from cyberdeck.core.classify import WEB, service_kind
from cyberdeck.core.config import Settings
from cyberdeck.core.events import Event, FindingsChanged, JobFinished, JobStarted, bus
from cyberdeck.core.glossary import Term
from cyberdeck.core.models import (
    Finding,
    FindingType,
    JobStatus,
    Suggestion,
    SuggestionStatus,
    utcnow,
)
from cyberdeck.core.options import OptionError, RunPlan, ToolSpec
from cyberdeck.core.runner import is_root, sudo_cached, sudo_validate
from cyberdeck.core.scope import ScopeError
from cyberdeck.core.summarize import POSSIBLE_CREDENTIAL, JobSummary
from cyberdeck.core.tools import SCAN_STAGES, all_tools, get_tool
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.ui.tui.app import CyberdeckApp
from cyberdeck.ui.tui.modals import ConfirmModal, HostsModal, InputModal
from cyberdeck.ui.tui.run_dialog import SAFETY_STYLE, RunDialog
from cyberdeck.ui.tui.splitter import Splitter

NEWLINE = chr(10)

# Findings tabs: (tab title, finding types, columns, row builder)
Row = list[str]


def _url_row(f: Finding) -> Row:
    d = f.data
    return [
        d.get("url", ""),
        str(d.get("status") or ""),
        d.get("title") or "",
        d.get("redirect") or "",
    ]


def _secret(value: str, reveal: bool) -> str:
    return value if reveal or not value else "•" * min(len(value), 8)


FINDING_TABS: list[tuple[str, tuple[FindingType, ...], list[str]]] = [
    ("Software", (FindingType.SOFTWARE,), ["Name", "Version", "Where", "Found by"]),
    ("Hosts", (FindingType.HOSTNAME,), ["Name", "Kind", "IP", "Found by"]),
    ("URLs", (FindingType.URL,), ["URL", "Status", "Title", "Redirect"]),
    (
        "Loot",
        (FindingType.USER, FindingType.CREDENTIAL, FindingType.HASH),
        ["Type", "Who", "Value", "Notes"],
    ),
    ("Vulns", (FindingType.VULN,), ["Id", "Title", "Where", "Severity"]),
    (
        "Other",
        (FindingType.OS, FindingType.SHARE, FindingType.NOTE),
        ["Type", "Key", "Details", "Found by"],
    ),
]


def finding_row(f: Finding, reveal: bool = False) -> Row:
    d = f.data
    found_by = ", ".join(f.sources[:2])
    if f.type is FindingType.SOFTWARE:
        return [d["name"], d.get("version") or "?", d.get("where") or "", found_by]
    if f.type is FindingType.HOSTNAME:
        return [
            d["fqdn"],
            d.get("kind", "host"),
            d.get("ip") or "",
            ", ".join(d.get("origins") or []),
        ]
    if f.type is FindingType.URL:
        return _url_row(f)
    if f.type is FindingType.USER:
        return ["user", d["name"], d.get("realm") or "", "valid" if d.get("valid") else ""]
    if f.type is FindingType.CREDENTIAL:
        verified = ", ".join(d.get("verified_on") or [])
        return [
            "cred",
            d["user"],
            _secret(d["secret"], reveal),
            f"works on: {verified}" if verified else "",
        ]
    if f.type is FindingType.HASH:
        cracked = d.get("cracked")
        note = (
            f"cracked: {_secret(cracked, reveal)}"
            if cracked
            else ", ".join(d.get("hash_types") or [])
        )
        return ["hash", d.get("user") or "", d["value"][:40], note]
    if f.type is FindingType.VULN:
        return [d["id"], d.get("title") or "", d.get("where") or "", d.get("severity") or ""]
    if POSSIBLE_CREDENTIAL in f.tags and not reveal:
        return ["password?", d.get("title") or "", "answer it in Next steps", found_by]
    details = ", ".join(f"{k}={v}" for k, v in d.items() if v not in (None, "", [], {}))
    return [f.type.value, f.key, details[:80], found_by]


class PickModal(ModalScreen[str | None]):
    """Pick one of several options. Returns its id, or None. An entry whose id is None is a
    heading: shown, but never highlighted or chosen."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, options: Sequence[tuple[str | None, str]]) -> None:
        super().__init__()
        self.title_text = title
        self.choices = options

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide picker"):
            yield Label(self.title_text, classes="dialog-title")
            yield OptionList(
                *[
                    Option(Text.from_markup(label), id=oid, disabled=oid is None)
                    for oid, label in self.choices
                ]
            )
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self._fit()
        options = self.query_one(OptionList)
        first = next((i for i, (oid, _) in enumerate(self.choices) if oid is not None), None)
        if first is not None:
            options.highlighted = first
        options.focus()

    def on_resize(self) -> None:
        self._fit()

    def _fit(self) -> None:
        """Keep the whole list inside the dialog (it scrolls) so the last entry and the Cancel
        button are always reachable, whatever the terminal height."""
        # title (2) + buttons (4) + dialog border/padding (4) + list border (2) + margin (2)
        self.query_one(OptionList).styles.max_height = max(4, self.app.size.height - 14)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class DashboardScreen(Screen[None]):
    BINDINGS = [
        Binding("enter,a", "accept", "Do next step", show=True),
        Binding("s", "skip", "Skip"),
        Binding("z", "snooze", "Snooze"),
        Binding("x", "explain", "Explain"),
        Binding("c", "scan", "Scan"),
        Binding("r", "run_tool", "Run tool"),
        Binding("h", "hosts", "Hosts"),
        Binding("f", "flag", "Flag"),
        Binding("l", "loot", "Loot"),
        Binding("n", "notes", "Notes"),
        Binding("t", "tools", "Tools"),
        Binding("j", "job", "Job"),
        Binding("R", "rerun", "Run job again", show=False),
        Binding("p", "approvals", "Approvals"),
        Binding("g", "glossary", "Glossary"),
        Binding("k", "checklist", "Checklist"),
        Binding("exclamation_mark", "stuck", "Stuck?"),
        Binding("w", "lead", "Working on"),
        Binding("o", "journal", "Journal"),
        Binding("W", "writeup", "Write-up"),
        Binding("b", "toggle_layout", "Beginner/expert", show=False),
        Binding("comma", "settings", "Settings"),
        Binding("ctrl+r", "refresh", "Refresh", show=False),
        Binding("escape", "back", "Boxes"),
        Binding("question_mark", "app.toggle_help", "Keys"),
        Binding("ctrl+left", "resize('split-left', -2)", "Narrower side panel", show=False),
        Binding("ctrl+right", "resize('split-left', 2)", "Wider side panel", show=False),
        Binding("ctrl+up", "resize('split-bottom', 1)", "Taller job panel", show=False),
        Binding("ctrl+down", "resize('split-bottom', -1)", "Shorter job panel", show=False),
        Binding("equals_sign", "reset_layout", "Reset pane sizes", show=False),  # also ctrl+p
        Binding("ctrl+l", "app.redraw", "Redraw the screen", show=False),
    ]

    def __init__(self, ws: Workspace, settings: Settings) -> None:
        super().__init__()
        self.ws = ws
        self.settings = settings
        cfg = load_user_config()
        self.explain = cfg.explain
        self.layout_mode = cfg.layout
        self.gloss = services.load_glossary()
        self._now_body = ""
        self._fresh: set[str] = set()  # "<type>:<key>" of findings the last job created
        self._opened_at = utcnow()  # idle nudge: quiet time counts from here at the earliest
        self._idle_mark: object = None  # newest finding time when the idle nudge was shown
        self._suggestions: dict[str, Suggestion] = {}
        self._marker: tuple[float, ...] = ()
        self._unsubscribe: list[Callable[[], None]] = []

    # -- layout ----------------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield Static(id="box-head")
                yield Tree("Services", id="services")
            yield Splitter(
                "left", axis="x", min_size=16, min_other=40, flex="right", id="split-left"
            )
            with Vertical(id="right"):
                yield Static(id="journey")
                yield Static(id="now")
                yield Static(id="approvals-banner")
                with TabbedContent(id="findings"):
                    for title, _, columns in FINDING_TABS:
                        with TabPane(title, id=f"tab-{title.lower()}"):
                            table: DataTable[str] = DataTable(
                                id=f"t-{title.lower()}", cursor_type="row"
                            )
                            table.add_columns(*columns)
                            yield table
                yield Splitter(
                    "next",
                    axis="y",
                    after=True,
                    min_size=4,
                    min_other=6,  # the findings tabs keep a few rows
                    flex="findings",
                    id="split-next",
                )
                with Vertical(id="next"):
                    yield Label("Next steps", classes="section")
                    yield DataTable(id="suggestions", cursor_type="row")
                    yield Static(id="why")
        yield Splitter(
            "bottom",
            axis="y",
            after=True,
            min_size=3,
            min_other=self._main_needs,  # findings + next steps keep room above the jobs
            flex="main",
            id="split-bottom",
        )
        with Horizontal(id="bottom"):
            yield DataTable(id="jobs", cursor_type="row")
            yield Splitter("jobs", axis="x", min_size=16, min_other=20, flex="log", id="split-jobs")
            yield RichLog(id="log", wrap=True, markup=False, max_lines=2000)
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"{self.ws.meta.name}  {self.ws.meta.ip}"
        self.call_after_refresh(self._restore_layout)
        sug: DataTable[Any] = self.query_one("#suggestions", DataTable)
        sug.add_columns("#", "Next step", "Tool", "Safety")
        jobs: DataTable[Any] = self.query_one("#jobs", DataTable)
        jobs.add_columns("#", "Tool", "Status", "Took")
        for kind in (FindingsChanged, JobStarted, JobFinished):
            self._unsubscribe.append(bus.subscribe(kind, self._on_event))
        self.query_one("#log", RichLog).write(
            Text(
                "Job output streams here. a = do the next step, c = scan, r = run any tool.",
                style="dim",
            )
        )
        self._apply_layout()
        self.refresh_data()
        self.set_interval(2.0, self._poll)
        self.set_interval(60.0, self._learning_tick)
        sug.focus()

    def on_unmount(self) -> None:
        for unsubscribe in self._unsubscribe:
            unsubscribe()

    # -- data -> view ----------------------------------------------------------------------
    def _on_event(self, event: Event) -> None:
        if event.box == self.ws.path:
            self.call_later(self.refresh_data)

    def _poll(self) -> None:
        if services.box_change_marker(self.ws) != self._marker:
            self.refresh_data()

    def refresh_data(self) -> None:
        summary = services.target_summary(self.ws)
        progress = services.target_progress(self.ws)
        self.ws.meta = summary.meta
        head = Text()
        head.append(f"{summary.meta.name}  {summary.meta.ip}\n", style="bold")
        head.append(f"OS: {summary.best_os or 'unknown'}\n")
        for step in progress.steps:
            head.append("✓ " if step.done else "· ", style="green" if step.done else "dim")
            head.append(step.label + (f"  {step.detail}" if step.detail else "") + "\n")
        self.query_one("#box-head", Static).update(head)
        self._fill_journey()
        self._fill_services(summary)
        self._fill_findings()
        self._fill_suggestions()
        self._fill_now(summary, progress)
        self._fill_jobs()
        self.call_after_refresh(self._fit_layout)  # the Now card may have changed height
        pending = len(services.list_approvals(self.ws))
        banner = self.query_one("#approvals-banner", Static)
        banner.display = bool(pending)
        banner.update(
            Text(
                f" {pending} request(s) from an MCP client waiting for you: p = review ",
                style="bold black on yellow",
            )
        )
        self._marker = services.box_change_marker(self.ws)

    def _fill_services(self, summary: services.TargetSummary) -> None:
        tree: Tree[str] = self.query_one("#services", Tree)
        tree.clear()
        tree.root.expand()
        hosts = [h.fqdn for h in summary.hostnames if h.kind == "host"]
        for svc in summary.services:
            kind = service_kind(svc)
            name = svc.name or "?"
            label = f"{svc.port}/{svc.proto} {kind}" + (f" ({name})" if kind != name else "")
            if svc.banner:
                label += f"  {svc.banner}"
            node = tree.root.add(label, expand=True)
            if kind == WEB:
                for host in hosts:
                    url = svc.url(host)
                    if url:
                        node.add_leaf(url)
        if not summary.services:
            tree.root.add_leaf("Nothing scanned yet.")
            tree.root.add_leaf("c = run the nmap scan")
            tree.root.add_leaf("(open ports and what runs on them")
            tree.root.add_leaf(" show up here)")

    def _fill_findings(self) -> None:
        findings = services.list_findings(self.ws)
        for title, types, _ in FINDING_TABS:
            table: DataTable[Any] = self.query_one(f"#t-{title.lower()}", DataTable)
            table.clear()
            for f in findings:
                if f.type in types:
                    key = f"{f.type.value}:{f.key}"
                    cells: list[Any] = list(finding_row(f))
                    if key in self._fresh:  # new from the last job: starred and bold
                        cells = [Text(f"★ {cells[0]}", style="bold yellow")] + [
                            Text(str(c), style="bold") for c in cells[1:]
                        ]
                    table.add_row(*cells, key=key)

    def _fill_suggestions(self) -> None:
        table: DataTable[Any] = self.query_one("#suggestions", DataTable)
        keep = table.cursor_row
        table.clear()
        self._suggestions = {}
        for sug in services.list_suggestions(self.ws):
            if sug.kind == "ask":
                tool = Text("question", style="magenta")
                safety = Text("-")
            else:
                tool = Text(sug.tool or "?")
                safety = Text(sug.safety, style=SAFETY_STYLE.get(sug.safety, "red"))
            key = str(sug.id)
            self._suggestions[key] = sug
            table.add_row(key, sug.title, tool, safety, key=key)
        if table.row_count:
            table.move_cursor(row=min(keep, table.row_count - 1))
        self._show_why()

    def _fill_jobs(self) -> None:
        table: DataTable[Any] = self.query_one("#jobs", DataTable)
        table.clear()
        colours = {JobStatus.DONE: "green", JobStatus.FAILED: "red", JobStatus.TIMEOUT: "red"}
        for job in reversed(services.list_jobs(self.ws)[-50:]):
            took = "-" if job.duration is None else f"{job.duration:.0f}s"
            status = Text(job.status.value, style=colours.get(job.status, "yellow"))
            badge = f" ({job.origin})" if job.origin not in ("cli", "tui") else ""
            table.add_row(str(job.id), job.tool + badge, status, took, key=str(job.id))

    # -- beginner layout: journey bar + "Now" card (docs/LEARNING-PLAN.md W2) -------------
    def _apply_layout(self) -> None:
        beginner = self.layout_mode == "beginner"
        self.query_one("#journey", Static).display = beginner
        self.query_one("#now", Static).display = beginner

    def _fill_journey(self) -> None:
        stages = services.journey(self.ws)
        text = Text()
        for i, stage in enumerate(stages):
            if i:
                text.append("  ›  ", style="dim")
            if stage.state == "done":
                text.append(f"✓ {stage.label}", style="green")
            elif stage.state == "current":
                text.append(f"● {stage.label}", style="bold reverse")
            else:
                text.append(f"○ {stage.label}", style="dim")
        current = next((s for s in stages if s.state == "current"), None)
        if current is not None:
            text.append(NEWLINE)
            text.append_text(self.gloss.rich(current.hint, style="dim"))
        lead = services.active_lead(self.ws)
        if lead is not None:
            status = services.lead_status(self.ws, lead)
            text.append(NEWLINE + "Working on: ", style="bold")
            text.append(lead.title)
            quiet = f"{status.minutes_quiet:.0f} min since the last new finding"
            text.append(f"  ({status.minutes_on:.0f} min, {quiet}; w to park it)", style="dim")
        self.query_one("#journey", Static).update(text)

    def _now_source(
        self, summary: services.TargetSummary, progress: services.TargetProgress
    ) -> tuple[str, str]:
        """(headline, explanation) for the Now card; the explanation may hold [[term]] links."""
        top = next(iter(self._suggestions.values()), None)
        if not summary.services:
            return (
                "Scan the box: press c",
                "Every box starts with nmap. Stage 1 finds the open [[port|ports]] fast; stage 2 "
                "asks each one what it is ([[version-detection]]). You'll see the exact command "
                "and every flag explained before it runs.",
            )
        if top is not None:
            keys = "a = do it, s = skip, z = later"
            return (f"Next: {top.title}", top.why + NEWLINE + keys + ". g = what words mean")
        if progress.steps[5].done:
            return ("Box complete. Nice work!", "Write down what got you in while it's fresh (n).")
        stage = next((s for s in services.journey(self.ws) if s.state == "current"), None)
        return (
            "No automatic suggestions right now",
            (stage.hint + " " if stage else "")
            + "Work through the checklist (k), read the pages yourself (view source!), check Loot "
            "(l), or press r to run any tool. Stuck? Press ! for what you haven't tried yet.",
        )

    def _fill_now(self, summary: services.TargetSummary, progress: services.TargetProgress) -> None:
        headline, body = self._now_source(summary, progress)
        self._now_body = body
        text = Text()
        text.append("▶ ", style="bold cyan")
        text.append(headline, style="bold")
        text.append(NEWLINE)
        text.append_text(self.gloss.rich(body))
        self.query_one("#now", Static).update(text)

    def action_glossary(self) -> None:
        from cyberdeck.ui.tui.learning import GlossaryModal

        sug = self._current()
        texts = [self._now_body] + ([sug.why] if sug else [])
        terms: list[Term] = []
        for text in texts:
            for term in self.gloss.linked(text):
                if term not in terms:
                    terms.append(term)
        self.app.push_screen(GlossaryModal(self.gloss, terms or None))

    # -- methodology: checklist, Stuck?, leads, timers (learning L3) ------------------------
    def action_checklist(self) -> None:
        from cyberdeck.ui.tui.methodology import ChecklistScreen

        self.app.push_screen(
            ChecklistScreen(self.ws, self.settings, on_run=lambda tool: self.tools_flow((tool,)))
        )

    def action_stuck(self) -> None:
        from cyberdeck.ui.tui.methodology import StuckModal

        def closed(choice: str | None) -> None:
            if choice == "checklist":
                self.action_checklist()

        self.app.push_screen(StuckModal(self.ws, self.settings), closed)

    def action_lead(self) -> None:
        self.lead_flow()

    @work(group="flows")
    async def lead_flow(self) -> None:
        lead = services.active_lead(self.ws)
        if lead is None:
            sug = self._current()
            title = await self.app.push_screen_wait(
                InputModal(
                    "What are you working on? (the timer warns when it stops giving results)",
                    sug.title if sug else "",
                )
            )
            if not title:
                return
            try:
                lead = services.start_lead(self.ws, title)
            except OptionError as exc:
                self.notify(str(exc), severity="error")
                return
            self.notify(f"Working on: {lead.title}")
        else:
            choice = await self.app.push_screen_wait(
                PickModal(
                    f"Working on: {lead.title}",
                    [
                        ("parked", "Park it: set it aside for later (it shows up under Stuck?)"),
                        ("done", "Done: it led somewhere, or I've ruled it out"),
                        ("new", "Switch to something else (parks this one)"),
                    ],
                )
            )
            if choice in ("parked", "done"):
                services.end_lead(self.ws, "parked" if choice == "parked" else "done", lead.id)
                self.notify(f"{lead.title}: {choice}")
            elif choice == "new":
                services.end_lead(self.ws, "parked", lead.id)
                self.refresh_data()
                self.lead_flow()
                return
        self.refresh_data()

    def _learning_tick(self) -> None:
        """Once a minute: the rabbit-hole warning for the active lead, and the idle nudge."""
        rabbit = services.rabbit_hole_check(self.ws)
        if rabbit is not None:
            self.notify(
                f"No new findings for {rabbit.minutes_quiet:.0f} min on: {rabbit.lead.title}. "
                "w to park it, ! for what you haven't tried yet.",
                title="Rabbit hole?",
                severity="warning",
                timeout=30,
            )
        minutes = load_user_config().learning.idle_prompt_minutes
        if not minutes:
            return
        newest = services.last_finding_at(self.ws)
        since = max(newest, self._opened_at) if newest else self._opened_at
        quiet = (utcnow() - since).total_seconds() / 60
        if quiet >= minutes and self._idle_mark != newest:
            self._idle_mark = newest
            services.log_help(self.ws, "idle-nudge", f"{quiet:.0f} min")
            self.notify(
                f"No new findings for {quiet:.0f} minutes. That's normal; press ! to see what "
                "you haven't tried yet.",
                title="Want a nudge?",
                timeout=20,
            )

    def action_journal(self) -> None:
        from cyberdeck.ui.tui.journal import JournalScreen

        self.app.push_screen(JournalScreen(self.ws, self.settings))

    def action_writeup(self) -> None:
        from cyberdeck.ui.tui.writeup import WriteupScreen

        self.app.push_screen(WriteupScreen(self.ws, self.settings))

    def action_toggle_layout(self) -> None:
        cfg = load_user_config()
        cfg.layout = "expert" if self.layout_mode == "beginner" else "beginner"
        self.layout_mode = cfg.layout
        save_user_config(cfg)
        self._apply_layout()
        self.notify(f"{self.layout_mode.capitalize()} layout (b switches back, , opens Settings)")

    def action_settings(self) -> None:
        from cyberdeck.ui.tui.learning import SettingsScreen

        self.app.push_screen(SettingsScreen(self.settings))

    def on_screen_resume(self) -> None:
        """Back from Settings (or any screen): pick up changed preferences."""
        cfg = load_user_config()
        self.explain, self.layout_mode = cfg.explain, cfg.layout
        self.gloss = services.load_glossary()
        self._apply_layout()
        self.refresh_data()

    def _current(self) -> Suggestion | None:
        table: DataTable[Any] = self.query_one("#suggestions", DataTable)
        if not table.row_count:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        return self._suggestions.get(str(row_key.value))

    def _show_why(self) -> None:
        why = self.query_one("#why", Static)
        sug = self._current()
        if not self.explain or sug is None:
            why.update("")
            why.display = False
            return
        text = self.gloss.rich(sug.why, style="dim")
        if sug.learn:
            text.append(f"\nLearn: {sug.learn}", style="dim italic")
        why.update(text)
        why.display = True

    @on(DataTable.RowHighlighted, "#suggestions")
    def _highlighted(self) -> None:
        self._show_why()

    @on(DataTable.RowSelected, "#suggestions")
    def _selected(self) -> None:
        self.action_accept()

    @on(DataTable.RowSelected, "#jobs")
    def _job_selected(self, event: DataTable.RowSelected) -> None:
        self._open_job(int(str(event.row_key.value)))

    # -- actions ---------------------------------------------------------------------------
    def action_refresh(self) -> None:
        self.refresh_data()

    def action_back(self) -> None:
        self.app.pop_screen()

    # -- pane sizes (drag a divider, ctrl+arrows, = to reset) ---------------------------
    FINDINGS_MIN = 6  # rows the findings tabs always keep (tab bar, header, a few rows)
    NEXT_MIN = 4

    def _main_needs(self) -> int:
        """Rows the top half needs: whatever shows above the findings (journey bar, Now
        card, approvals banner), the findings, the divider and the smallest Next steps."""
        above = sum(
            w.outer_size.height
            for w in self.query("#journey, #now, #approvals-banner")
            if w.display
        )
        return above + self.FINDINGS_MIN + 1 + self.NEXT_MIN

    _OUTER_SPLITS = ("split-bottom", "split-left", "split-jobs")
    _INNER_SPLITS = ("split-next",)  # inside #right, so fitted once #right has its size

    def _restore_layout(self) -> None:
        saved = load_user_config().tui_layout
        for splitter in self.query(Splitter):
            if splitter.target in saved:
                splitter.preferred = saved[splitter.target]
        self._fit_layout()

    def _fit_layout(self) -> None:
        """Apply the saved pane sizes as far as this terminal allows, outer panes first, so a
        job panel made tall to read long output can't squeeze the findings away."""
        for splitter_id in self._OUTER_SPLITS:
            self.query_one(f"#{splitter_id}", Splitter).fit()
        self.call_after_refresh(self._fit_inner)

    NOW_MAX = 8  # the Now card's usual cap (app CSS); less when the terminal is short

    def _fit_inner(self) -> None:
        # A short terminal can't hold a full Now card above the findings and Next steps: cap
        # it to what's left, so the right column never overflows (and so never scrolls).
        right = self.query_one("#right")
        now = self.query_one("#now")
        others = sum(
            w.outer_size.height for w in self.query("#journey, #approvals-banner") if w.display
        )
        room = right.size.height - others - self.FINDINGS_MIN - 1 - self.NEXT_MIN
        now.styles.max_height = max(3, min(self.NOW_MAX, room))
        for splitter_id in self._INNER_SPLITS:
            self.query_one(f"#{splitter_id}", Splitter).fit()

    def on_resize(self) -> None:
        self.call_after_refresh(self._fit_layout)

    def _save_layout(self) -> None:
        cfg = load_user_config()
        cfg.tui_layout = {
            s.target: s.preferred for s in self.query(Splitter) if s.preferred is not None
        }
        save_user_config(cfg)

    def on_splitter_resized(self, message: Splitter.Resized) -> None:
        self._save_layout()
        self.call_after_refresh(self._fit_inner)

    def action_resize(self, splitter_id: str, delta: int) -> None:
        self.query_one(f"#{splitter_id}", Splitter).nudge(delta)
        self._save_layout()
        if splitter_id in self._OUTER_SPLITS:
            self.call_after_refresh(self._fit_inner)

    def action_reset_layout(self) -> None:
        for splitter in self.query(Splitter):
            splitter.reset()
        self._save_layout()
        self.notify("Pane sizes reset")

    def action_explain(self) -> None:
        self.explain = not self.explain
        cfg = load_user_config()
        cfg.explain = self.explain
        save_user_config(cfg)
        self._show_why()
        self.notify(f"Explain mode {'on' if self.explain else 'off'}")

    def _set_status(self, status: SuggestionStatus, verb: str) -> None:
        sug = self._current()
        if sug is None or sug.id is None:
            return
        services.set_suggestion_status(self.ws, sug.id, status)
        self.notify(f"{verb}: {sug.title}")
        self.refresh_data()

    def action_skip(self) -> None:
        self._set_status(SuggestionStatus.SKIPPED, "Skipped")

    def action_snooze(self) -> None:
        self._set_status(SuggestionStatus.SNOOZED, "Snoozed until something new is found")

    def action_accept(self) -> None:
        sug = self._current()
        if sug is None:
            self.notify("No suggestions right now. c = scan, r = run any tool.")
            return
        self.suggestion_flow(sug)

    def action_scan(self) -> None:
        options = [
            ("all", "Both stages: all TCP ports, then scripts + versions"),
            ("nmap-allports", "Stage 1: all TCP ports"),
            ("nmap-services", "Stage 2: scripts + versions on the open ports"),
            ("nmap-udp", "UDP top ports [dim](needs root)[/]"),
        ]

        def picked(choice: str | None) -> None:
            if choice:
                tools = SCAN_STAGES if choice == "all" else (choice,)
                self.tools_flow(tools)

        self.app.push_screen(PickModal("Scan", options), picked)

    def action_run_tool(self) -> None:
        """Every tool, under its category (the plugins/tools/ folder), A-Z within each."""
        by_category: dict[str, list[ToolSpec]] = {}
        for tool in all_tools():
            by_category.setdefault(tool.category, []).append(tool)
        options: list[tuple[str | None, str]] = []
        for category in sorted(by_category):
            tools = sorted(by_category[category], key=lambda t: t.id)
            options.append((None, f"[bold yellow]{category}[/]  [dim]({len(tools)})[/]"))
            for tool in tools:
                style = SAFETY_STYLE.get(tool.safety, "red")
                group = f" ({tool.group})" if tool.group else ""
                options.append(
                    (
                        tool.id,
                        f"  {tool.id}{group}  [{style}]{tool.safety}[/]  "
                        f"[dim]{tool.description}[/]",
                    )
                )

        def picked(choice: str | None) -> None:
            if choice:
                self.tools_flow((choice,))

        self.app.push_screen(PickModal("Run a tool", options), picked)

    def action_hosts(self) -> None:
        self.hosts_flow(None)

    def action_flag(self) -> None:
        self.flag_flow()

    def action_loot(self) -> None:
        from cyberdeck.ui.tui.loot import LootScreen

        self.app.push_screen(LootScreen(self.ws))

    def action_notes(self) -> None:
        from cyberdeck.ui.tui.notes import NotesScreen

        self.app.push_screen(NotesScreen(self.ws))

    def action_tools(self) -> None:
        from cyberdeck.ui.tui.tools import ToolsScreen

        self.app.push_screen(ToolsScreen())

    def _selected_job(self) -> int | None:
        table: DataTable[Any] = self.query_one("#jobs", DataTable)
        if not table.row_count:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        return int(str(row_key.value))

    def action_job(self) -> None:
        job_id = self._selected_job()
        if job_id is not None:
            self._open_job(job_id)

    def action_rerun(self) -> None:
        job_id = self._selected_job()
        if job_id is None:
            self.notify("No jobs yet", severity="warning")
            return
        self.rerun_flow(job_id)

    def action_approvals(self) -> None:
        from cyberdeck.ui.tui.approvals import ApprovalsScreen

        def decided(choice: tuple[str, int] | None) -> None:
            if choice:
                self.approval_flow(*choice)

        self.app.push_screen(ApprovalsScreen(self.ws), decided)

    def _open_job(self, job_id: int) -> None:
        from cyberdeck.ui.tui.jobs import JobScreen

        self.app.push_screen(JobScreen(self.ws, job_id, on_rerun=self.rerun_flow))

    # -- flows (workers, so they can wait for dialogs) -------------------------------------
    @work(group="flows")
    async def suggestion_flow(self, sug: Suggestion) -> None:
        sid = sug.id or 0
        if sug.kind == "ask":
            await self._answer(sug)
            return
        try:
            _, plan = services.plan_suggestion(self.ws, sid, self.settings)
        except OptionError as exc:
            self.notify(str(exc), severity="error")
            return
        await self._dialog_and_run(plan, suggestion_id=sid)

    @work(group="flows")
    async def rerun_flow(self, job_id: int) -> None:
        """Run dialog pre-filled from a past job (same options/command, new output folder)."""
        try:
            plan = services.plan_rerun(self.ws, job_id, self.settings)
        except OptionError as exc:
            self.notify(str(exc), severity="error")
            return
        await self._dialog_and_run(plan)

    @work(group="flows")
    async def tools_flow(self, tool_ids: tuple[str, ...]) -> None:
        for tool_id in tool_ids:
            try:
                tool = services.resolve_tool(tool_id)
                plan = services.plan_tool(self.ws, tool.id, settings=self.settings)
            except OptionError as exc:
                self.notify(str(exc), severity="error")
                return
            if not await self._dialog_and_run(plan, wait=True):
                return  # skipped: don't go on to the next stage

    @work(group="flows")
    async def hosts_flow(self, names: list[str] | None, suggestion_id: int | None = None) -> None:
        await self._hosts(names, suggestion_id)

    @work(group="flows")
    async def approval_flow(self, verb: str, approval_id: int) -> None:
        try:
            approval = services.get_approval(self.ws, approval_id)
            if verb == "deny":
                services.deny_approval(self.ws, approval_id)
                self.notify(f"Denied: {approval.title}")
                self.refresh_data()
                return
            if approval.kind == "hosts":
                change = services.approval_hosts_change(self.ws, approval_id, self.settings)
            else:
                plan = services.approval_plan(self.ws, approval_id)
        except OptionError as exc:
            self.notify(str(exc), severity="error")
            return
        if approval.kind == "hosts":
            if not change.changed:
                services.deny_approval(self.ws, approval_id, "already in the hosts file")
                self.notify("The hosts file already has these names")
                self.refresh_data()
                return
            needs_sudo = services.hosts_needs_sudo(self.settings)
            if not await self.app.push_screen_wait(HostsModal(change, needs_sudo)):
                self.notify("Left pending")
                return
            if needs_sudo and not self._sudo():
                return
            try:
                services.approve_hosts(self.ws, approval_id, change, self.settings)
            except services.HostsError as exc:
                self.notify(str(exc), severity="error")
                return
            self.notify(f"{change.path} updated")
            self.refresh_data()
            return
        detail = f"$ {plan.command_line()}"
        if approval.reason:
            detail += f"\nReason given: {approval.reason}"
        go = await self.app.push_screen_wait(
            ConfirmModal(
                f"Run exactly this {plan.tool.safety} {plan.tool.name} command?",
                detail,
                yes="Run it",
                no="Not now",
            )
        )
        if not go:
            self.notify("Left pending (d on the Approvals screen denies it)")
            return
        if plan.sudo and not self._sudo():
            return
        self.run_job(plan, None, approval_id)

    @work(group="flows")
    async def flag_flow(self) -> None:
        kind = await self.app.push_screen_wait(
            PickModal("Record a flag", [("user", "User flag"), ("root", "Root flag")])
        )
        if kind not in ("user", "root"):
            return
        value = await self.app.push_screen_wait(InputModal(f"{kind} flag (32 hex characters)"))
        if not value:
            return
        flag: Literal["user", "root"] = "user" if kind == "user" else "root"
        ok = services.record_flag(self.ws, flag, value)
        if not ok:
            self.notify(f"{kind} flag saved (it doesn't look like an HTB flag: 32 hex characters)")
        else:
            cheer = "User flag! Halfway there." if flag == "user" else "Root flag! Box done."
            self.notify(cheer, title="🚩 Nice work", timeout=10)
        self.refresh_data()
        from cyberdeck.ui.tui.journal import LessonModal

        answer = await self.app.push_screen_wait(
            LessonModal(f"{kind.capitalize()} flag: what did you learn?")
        )
        if answer is not None and any([answer[0].strip(), answer[1].strip(), answer[2]]):
            services.record_lesson(self.ws, flag, *answer)
            self.notify("Saved to the journal and your playbook")

    async def _answer(self, sug: Suggestion) -> None:
        sid = sug.id or 0
        action = sug.ask.get("action", "none")
        prompt = str(sug.ask.get("prompt") or sug.title)
        if action == "hosts.add":
            await self._hosts(None, sid)
            return
        answer: str | bool | None
        if sug.ask.get("input"):
            answer = await self.app.push_screen_wait(
                InputModal(prompt, str(sug.ask.get("default") or ""))
            )
            if answer is None:
                return
        else:
            answer = await self.app.push_screen_wait(ConfirmModal(prompt, glossary.plain(sug.why)))
        try:
            result = services.answer_question(self.ws, sid, answer)
        except OptionError as exc:
            self.notify(str(exc), severity="error")
            return
        self.notify(result.message or ("Skipped" if answer is False else "Answered"))
        self.refresh_data()

    async def _hosts(self, names: list[str] | None, suggestion_id: int | None) -> None:
        change = services.hosts_plan_add(self.ws, names, self.settings)
        if not change.changed:
            self.notify(f"{change.path} already maps the box's names to {self.ws.meta.ip}")
            if suggestion_id is not None:
                services.complete_suggestion(self.ws, suggestion_id)
            self.refresh_data()
            return
        needs_sudo = services.hosts_needs_sudo(self.settings)
        if not await self.app.push_screen_wait(HostsModal(change, needs_sudo)):
            self.notify("Hosts file not changed")
            return
        if needs_sudo and not self._sudo():
            return
        try:
            backup = services.hosts_apply(change, self.ws, self.settings)
        except services.HostsError as exc:
            self.notify(str(exc), severity="error")
            return
        if suggestion_id is not None:
            services.complete_suggestion(self.ws, suggestion_id)
        saved = f" (old file saved as {backup.relative_to(self.ws.path)})" if backup else ""
        self.notify(f"{change.path} updated{saved}")
        self.refresh_data()

    def _sudo(self) -> bool:
        """Get a sudo timestamp: step out of the TUI so sudo can ask on the real terminal."""
        if is_root() or sudo_cached():
            return True
        with self.app.suspend():
            print("sudo needs your password (typed into sudo itself, never into Cyberdeck):")
            ok = sudo_validate()
        if not ok:
            self.notify("sudo failed", severity="error")
        return ok

    async def _dialog_and_run(
        self, plan: RunPlan, *, suggestion_id: int | None = None, wait: bool = False
    ) -> bool:
        """Run dialog, VPN check, sudo, then run. True if a job ran (``wait``) or started."""
        root = is_root()
        chosen = await self.app.push_screen_wait(
            RunDialog(
                plan,
                is_root=root,
                save_user=lambda p: str(services.save_plan_defaults(self.ws, p, "user")),
                save_box=lambda p: str(services.save_plan_defaults(self.ws, p, "box")),
                show_help=lambda p: services.help_text(p.tool.id),
                show_man=lambda p: services.man_text(p.tool.id),
                wordlists=services.wordlist_status,
                box_dir=self.ws.path,
            )
        )
        if chosen is None:
            self.notify(f"Skipped {plan.tool.name}")
            return False
        vpn = services.vpn_check(self.settings, self.ws.meta.ip)
        if vpn.applicable and vpn.checked and not vpn.routed_via_tunnel:
            go = await self.app.push_screen_wait(
                ConfirmModal(
                    f"{self.ws.meta.ip} isn't routed through a VPN tunnel. Run anyway?",
                    "Start the HTB VPN first (cyberdeck vpn shows how).",
                    no="Don't run",
                )
            )
            if not go:
                return False
        if chosen.sudo and not self._sudo():
            return False
        if wait:
            return await self._execute(chosen, suggestion_id)
        self.run_job(chosen, suggestion_id)
        return True

    @work(group="jobs")
    async def run_job(
        self, plan: RunPlan, suggestion_id: int | None, approval_id: int | None = None
    ) -> None:
        await self._execute(plan, suggestion_id, approval_id)

    async def _execute(
        self, plan: RunPlan, suggestion_id: int | None, approval_id: int | None = None
    ) -> bool:
        log = self.query_one("#log", RichLog)
        name = plan.tool.id
        log.write(Text(f"$ {plan.command_line()}", style="bold cyan"))

        def on_line(stream: str, line: str) -> None:
            if line.strip():
                log.write(Text(f"[{name}] {line}", style="red" if stream == "err" else ""))

        app = self.app if isinstance(self.app, CyberdeckApp) else None
        if app is not None:
            app.running_jobs += 1
        try:
            if approval_id is not None:
                outcome = await services.run_approved_job(
                    self.ws, self.settings, approval_id, on_line=on_line
                )
            else:
                outcome = await services.execute_plan(
                    self.ws,
                    self.settings,
                    plan,
                    on_line=on_line,
                    origin="tui",
                    suggestion_id=suggestion_id,
                )
        except ScopeError as exc:
            self.notify(str(exc), severity="error")
            return False
        finally:
            if app is not None:
                app.running_jobs -= 1
        job = outcome.result.job
        tool_name = get_tool(job.tool).name if job.tool else name
        if outcome.result.ok:
            parts = []
            if outcome.parse_report is not None and not outcome.parse_report.error:
                parts.append(f"{len(outcome.parse_report.created)} new findings")
            if outcome.import_report is not None:
                parts.append(f"{len(outcome.import_report.created)} new findings")
            if outcome.suggestions:
                parts.append(f"{len(outcome.suggestions)} new suggestions")
            self.notify(f"{tool_name} finished (job #{job.id}). " + ", ".join(parts))
        else:
            self.notify(
                f"{tool_name}: {job.status.value} {job.note or ''} (job #{job.id})",
                severity="warning",
            )
        for note in outcome.notes:
            self.notify(note, severity="warning")
        log.write(Text(f"[{name}] {job.status.value} (job #{job.id})", style="bold"))
        if outcome.summary is not None and services.summaries_enabled():
            self._show_summary(outcome.summary)
            created = [
                *(outcome.parse_report.created if outcome.parse_report else []),
                *(outcome.import_report.created if outcome.import_report else []),
                *outcome.possible_credentials,
            ]
            self._fresh = {f"{f.type.value}:{f.key}" for f in created}
        self.refresh_data()
        return outcome.result.ok

    def _show_summary(self, summary: JobSummary) -> None:
        """The "so what?" of a finished job: in the log, a toast per highlight, and the new
        findings starred in their tables until the next job (learning L2)."""
        log = self.query_one("#log", RichLog)
        log.write(Text(f"▶ {summary.headline}", style="bold cyan"))
        for line in summary.lines:
            log.write(self.gloss.rich("  " + line))
        for hl in summary.highlights:
            text = Text("  ★ ", style="bold yellow")
            text.append(hl.title, style="bold yellow")
            text.append(": ")
            text.append_text(self.gloss.rich(hl.meaning))
            log.write(text)
        for hl in summary.highlights[:3]:
            self.notify(
                glossary.plain(hl.meaning),
                title=f"★ {hl.title}",
                severity="information",
                timeout=12,
            )
