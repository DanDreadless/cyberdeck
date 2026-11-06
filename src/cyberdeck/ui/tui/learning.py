"""Learning aids in the TUI (docs/LEARNING-PLAN.md L1): glossary, setup check, welcome screen,
Settings screen. Everything goes through ``core/services.py`` and ``core/userconfig.py``."""

from __future__ import annotations

from collections.abc import Sequence

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    Select,
    Static,
)
from textual.widgets.option_list import Option

from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.doctor import Check, Level, summary
from cyberdeck.core.glossary import Glossary, Term
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.ui.tui.themes import theme_choices

LEVEL_MARK = {Level.OK: ("✓", "green"), Level.WARN: ("!", "yellow"), Level.FAIL: ("✗", "red")}


def term_text(term: Term, gloss: Glossary) -> Text:
    text = Text()
    text.append(term.term + "\n", style="bold")
    text.append_text(gloss.rich(term.short))
    if term.learn:
        text.append(f"\nLearn more: {term.learn}", style="dim italic")
    related = [gloss.terms[r].term for r in term.see if r in gloss.terms]
    if related:
        text.append(f"\nSee also: {', '.join(related)}", style="dim")
    return text


class GlossaryModal(ModalScreen[None]):
    """Definitions. With ``terms`` it shows just those (the ones in the text you were reading);
    without, every term with a search box."""

    BINDINGS = [Binding("escape,g,q", "close", "Close")]

    def __init__(self, gloss: Glossary, terms: Sequence[Term] | None = None) -> None:
        super().__init__()
        self.gloss = gloss
        self.only = list(terms) if terms else None

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide tall", id="glossary"):
            title = "Terms in this text" if self.only else "Glossary"
            yield Label(title, classes="dialog-title")
            if self.only is None:
                yield Input(placeholder="Search: vhost, hash, sudo...", id="gloss-search")
                yield OptionList(id="gloss-list")
            yield VerticalScroll(Static(id="gloss-body"), id="gloss-scroll")
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        if self.only is not None:
            body = Text()
            for i, term in enumerate(self.only):
                if i:
                    body.append("\n\n")
                body.append_text(term_text(term, self.gloss))
            self.query_one("#gloss-body", Static).update(body)
            return
        self._fill("")
        self.query_one("#gloss-search", Input).focus()

    def _fill(self, query: str) -> None:
        options = self.query_one("#gloss-list", OptionList)
        options.clear_options()
        q = query.strip().lower()
        terms = sorted(self.gloss.terms.values(), key=lambda t: t.term.lower())
        shown = [
            t
            for t in terms
            if not q
            or q in t.term.lower()
            or any(q in a.lower() for a in t.aliases)
            or q in t.short.lower()
        ]
        for term in shown:
            options.add_option(Option(term.term, id=term.id))
        if shown:
            options.highlighted = 0
            self._show(shown[0].id)
        else:
            self.query_one("#gloss-body", Static).update(
                Text(
                    "No matching term."
                    if self.gloss.terms
                    else "The glossary is turned off in Settings (,).",
                    style="dim",
                )
            )

    def _show(self, term_id: str) -> None:
        term = self.gloss.terms.get(term_id)
        if term is not None:
            self.query_one("#gloss-body", Static).update(term_text(term, self.gloss))

    @on(Input.Changed, "#gloss-search")
    def _search(self, event: Input.Changed) -> None:
        self._fill(event.value)

    @on(OptionList.OptionHighlighted, "#gloss-list")
    def _highlight(self, event: OptionList.OptionHighlighted) -> None:
        if event.option.id:
            self._show(event.option.id)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


def checks_text(checks: Sequence[Check], gloss: Glossary) -> Text:
    text = Text()
    for check in checks:
        mark, style = LEVEL_MARK[check.level]
        text.append(f" {mark} ", style=f"bold {style}")
        text.append(check.title, style="bold")
        text.append(f"  {check.detail}\n")
        if check.level is not Level.OK:
            text.append("     ")
            text.append_text(gloss.rich(check.purpose, style="dim"))
            text.append("\n")
            if check.fix:
                text.append(f"     fix: {check.fix}\n", style="cyan")
    text.append(f"\n{summary(list(checks))}", style="bold")
    return text


class SetupCheckScreen(Screen[None]):
    """``cyberdeck doctor`` in the TUI: what's ready, what isn't, and the command that fixes it."""

    BINDINGS = [
        Binding("r", "recheck", "Check again"),
        Binding("escape", "back", "Back"),
        Binding("question_mark", "app.toggle_help", "Keys"),
    ]

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Setup check: is this Kali ready for HTB?", classes="section")
        yield VerticalScroll(Static(id="checks"), id="checks-scroll")
        with Horizontal(classes="buttons", id="check-buttons"):
            yield Button("Check again", id="recheck")
            yield Button("Create workspace folder", id="mkroot")
            yield Button("Back", variant="primary", id="back")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Setup check"
        self.action_recheck()

    def action_recheck(self) -> None:
        checks = services.setup_checks(self.settings)
        self.query_one("#checks", Static).update(checks_text(checks, services.load_glossary()))
        self.query_one("#mkroot", Button).display = not self.settings.root.is_dir()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "recheck":
            self.action_recheck()
        elif event.button.id == "mkroot":
            root = services.create_workspace_root(self.settings)
            self.notify(f"Created {root}")
            self.action_recheck()
        else:
            self.action_back()

    def action_back(self) -> None:
        self.app.pop_screen()


WELCOME = """\
Cyberdeck helps you work through Hack The Box machines from Kali. Give it a box name and IP and
it scans the box, explains what it finds and suggests the next step, with the reason why.
Nothing intrusive ever runs without you seeing the exact command first.

How a box goes: Scan > Enumerate > Foothold > User flag > Root flag. The bar at the top of a
box shows where you are. Underlined words are in the glossary: press g to read them.
"""

FIRST_BOXES = """\
First time on HTB? Start with the free Starting Point machines (Tier 0). Each teaches one
service in one step:
  • Meow: telnet with a blank password
  • Fawn: anonymous FTP
  • Dancing: SMB shares open to guests
  • Redeemer: a Redis database without a password
Spawn one on app.hackthebox.com, then press n (new box) with its name and IP.
"""


class WelcomeScreen(Screen[None]):
    """First run: what Cyberdeck is, layout choice, learning aids, setup check, first boxes."""

    BINDINGS = [
        Binding("enter", "done", "Let's go"),
        Binding("r", "recheck", "Check again"),
        Binding("escape", "done", "Close"),
    ]

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="welcome"):
            yield Label("Welcome to Cyberdeck", classes="section")
            yield Static(Text(WELCOME), classes="para")
            yield Label("How much help do you want?", classes="section")
            yield Select(
                [
                    ("Beginner: one clear next step, journey bar, explanations on", "beginner"),
                    ("Expert: the full dashboard, explanations off", "expert"),
                ],
                value=load_user_config().layout,
                allow_blank=False,
                id="layout",
            )
            yield Static(
                Text(
                    "Learning aids (glossary, checklists, hints) are all on. Change any of "
                    "them any time in Settings (, key).",
                    style="dim",
                ),
                classes="para",
            )
            yield Label("Setup check", classes="section")
            yield Static(id="checks", classes="para")
            yield Label("Your first box", classes="section")
            yield Static(Text(FIRST_BOXES), classes="para")
        with Horizontal(classes="buttons", id="welcome-buttons"):
            yield Button("Let's go", variant="primary", id="done")
            yield Button("Check again", id="recheck")
            yield Button("Create workspace folder", id="mkroot")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Welcome"
        self.action_recheck()
        self.query_one("#done", Button).focus()

    def action_recheck(self) -> None:
        checks = services.setup_checks(self.settings)
        self.query_one("#checks", Static).update(checks_text(checks, services.load_glossary()))
        self.query_one("#mkroot", Button).display = not self.settings.root.is_dir()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "recheck":
            self.action_recheck()
        elif event.button.id == "mkroot":
            self.notify(f"Created {services.create_workspace_root(self.settings)}")
            self.action_recheck()
        else:
            self.action_done()

    def action_done(self) -> None:
        cfg = load_user_config()
        layout = self.query_one("#layout", Select).value
        if layout in ("beginner", "expert"):
            cfg.layout = layout
            cfg.explain = layout == "beginner"
        cfg.first_run_done = True
        save_user_config(cfg)
        self.app.pop_screen()


LEARNING_TOGGLES: list[tuple[str, str]] = [
    ("glossary", "Glossary: underline jargon, g shows the meaning"),
    ("summaries", "Explanations: what each tool does, what each job found, password spotting"),
    ("checklists", "Methodology checklists per service (k)"),
    ("hints", "General hints in Stuck? (!, level 2)"),
    ("paths", "Learning path and skills (p on the box list)"),
]


class SettingsScreen(Screen[None]):
    """Preferences from config.yaml, so nobody has to edit YAML (docs/UI.md)."""

    BINDINGS = [
        Binding("ctrl+s", "save", "Save"),
        Binding("escape", "back", "Back"),
        Binding("question_mark", "app.toggle_help", "Keys"),
    ]

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    def compose(self) -> ComposeResult:
        cfg = load_user_config()
        yield Header()
        with VerticalScroll(id="settings"):
            yield Label("Layout", classes="section")
            yield Select(
                [
                    ("Beginner: Now card + journey bar", "beginner"),
                    ("Expert: full dashboard only", "expert"),
                ],
                value=cfg.layout,
                allow_blank=False,
                id="layout",
            )
            yield Checkbox(
                "Explain mode: show why + learn link under the next steps",
                cfg.explain,
                id="explain",
            )
            yield Label(
                "Learning aids (built-in content; your own files always load)", classes="section"
            )
            for key, label in LEARNING_TOGGLES:
                yield Checkbox(label, bool(getattr(cfg.learning, key)), id=f"learn-{key}")
            with Horizontal(classes="row"):
                yield Label(
                    "Nudge after N minutes without new findings (0 = off)",
                    classes="opt-label wide-label",
                )
                yield Input(str(cfg.learning.idle_prompt_minutes), id="idle", type="integer")
            with Horizontal(classes="row"):
                yield Label(
                    "Rabbit-hole warning after N quiet minutes on a lead (0 = off)",
                    classes="opt-label wide-label",
                )
                yield Input(str(cfg.learning.rabbit_hole_minutes), id="rabbit", type="integer")
            yield Label("Boxes", classes="section")
            with Horizontal(classes="row"):
                yield Label("Workspace folder", classes="opt-label")
                locked = self.settings.from_env("workspace_root")
                yield Input(
                    str(self.settings.workspace_root)
                    if locked
                    else cfg.workspace_root or str(self.settings.workspace_root),
                    id="root",
                    disabled=locked,
                )
            if locked:
                yield Static(
                    Text(
                        "Set by CYBERDECK_WORKSPACE_ROOT in your .env: change it there.",
                        style="dim",
                    ),
                    classes="para",
                )
            yield Checkbox(
                "Auto mode runs safe tools without the Run dialog (cyberdeck auto)",
                cfg.auto_confirm_safe,
                id="auto-confirm",
            )
            yield Label("Look", classes="section")
            themes = theme_choices(self.app.available_themes)
            if cfg.theme not in themes:
                themes = [cfg.theme, *themes]
            yield Select([(t, t) for t in themes], value=cfg.theme, allow_blank=False, id="theme")
            yield Static(
                Text(
                    "Saved in ~/.config/cyberdeck/config.yaml. Secrets (API keys, MCP token) stay "
                    "in .env. ctrl+t switches theme from any screen.",
                    style="dim",
                ),
                classes="para",
            )
        with Horizontal(classes="buttons", id="settings-buttons"):
            yield Button("Save", variant="primary", id="save")
            yield Button("Cancel", id="cancel")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Settings"

    @on(Select.Changed, "#theme")
    def _preview_theme(self, event: Select.Changed) -> None:
        if isinstance(event.value, str):
            self.app.theme = event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self.action_save()
        else:
            self.action_back()

    def action_save(self) -> None:
        cfg = load_user_config()
        layout = self.query_one("#layout", Select).value
        if layout in ("beginner", "expert"):
            cfg.layout = layout
        cfg.explain = self.query_one("#explain", Checkbox).value
        for key, _ in LEARNING_TOGGLES:
            setattr(cfg.learning, key, self.query_one(f"#learn-{key}", Checkbox).value)
        idle = self.query_one("#idle", Input).value.strip()
        cfg.learning.idle_prompt_minutes = max(0, int(idle)) if idle.isdigit() else 0
        rabbit = self.query_one("#rabbit", Input).value.strip()
        cfg.learning.rabbit_hole_minutes = max(0, int(rabbit)) if rabbit.isdigit() else 0
        root_input = self.query_one("#root", Input)
        root = "" if root_input.disabled else root_input.value.strip()
        moved = bool(root) and root != (cfg.workspace_root or str(self.settings.workspace_root))
        if root:
            cfg.workspace_root = root
        cfg.auto_confirm_safe = self.query_one("#auto-confirm", Checkbox).value
        theme = self.query_one("#theme", Select).value
        if isinstance(theme, str):
            cfg.theme = theme
        path = save_user_config(cfg)
        self.notify(
            f"Saved to {path}"
            + (". The new workspace folder applies next time you start Cyberdeck." if moved else "")
        )
        self.app.pop_screen()

    def action_back(self) -> None:
        self.app.theme = load_user_config().theme  # undo a previewed theme
        self.app.pop_screen()
