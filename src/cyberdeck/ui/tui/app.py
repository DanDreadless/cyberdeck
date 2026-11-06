"""The Cyberdeck TUI app (docs/UI.md). Runs in a terminal (``cyberdeck``) or a browser
(``cyberdeck --web`` via textual-serve). All work goes through ``core/services.py``."""

from __future__ import annotations

from collections.abc import Iterable

from textual.app import App, SystemCommand
from textual.binding import Binding
from textual.screen import Screen

from cyberdeck.core import services
from cyberdeck.core.config import Settings, load_settings
from cyberdeck.core.workspace import WorkspaceError
from cyberdeck.ui.tui.themes import CYBERDECK_THEMES, DEFAULT_THEME

CSS = """
Screen { background: $background; }
#banner { padding: 1 2 0 2; margin-bottom: 1; height: auto; }
.section { color: $accent; text-style: bold; padding: 0 1; }
.dim { color: $text-muted; }
#boxes { height: 1fr; }
#loose { padding: 0 1; height: auto; }

#main { height: 1fr; }
#left { width: 38; }
#box-head { padding: 0 1; height: auto; }
#services { height: 1fr; }
#right { width: 1fr; }
#findings { height: 1fr; }
#next { height: 14; }
#suggestions { height: 1fr; }
#approvals-banner { height: auto; display: none; }
#why { padding: 0 1; height: auto; max-height: 4; color: $text-muted; }
#bottom { height: 10; }
#jobs { width: 40; }
#log { width: 1fr; }

.dialog {
    width: 72; max-width: 95%; height: auto; max-height: 90%;
    border: thick $accent; background: $surface; padding: 1 2;
}
.dialog.wide { width: 110; }
.dialog.tall { height: 90%; }
.picker OptionList { height: auto; }
ModalScreen { align: center middle; }
.dialog-title { text-style: bold; margin-bottom: 1; }
.buttons { height: auto; margin-top: 1; }
.buttons Button { margin-right: 2; }
.text-body { height: auto; max-height: 30; }
#form { height: 1fr; min-height: 4; }
.row { height: auto; }
.opt { height: auto; margin-bottom: 1; }
.opt-label { width: 26; }
.opt-help { padding-left: 26; }
.row Input, .row Select { width: 1fr; }
.row .pick { width: auto; margin-left: 1; }
#wordlist-picker #named { height: auto; max-height: 12; }
#add-loot { width: 80; }
#add-loot .row { margin-top: 0; }
#add-error { height: auto; }
#wordlist-picker #tree { height: 1fr; }
#preview { height: auto; }
#run-dialog .row { margin-top: 1; }
#run-dialog .opt .row { margin-top: 0; }
#notes { height: auto; }
#theme-picker OptionList { height: 1fr; }
#writeup-switcher { height: 1fr; }
#writeup-preview { height: 1fr; padding: 0 1; }
#writeup-edit { height: 1fr; }
#job-head { height: auto; max-height: 50%; padding: 0 1; }
#job-output { height: 1fr; padding: 0 1; }

#journey { height: auto; padding: 0 1; background: $boost; }
#now { height: auto; max-height: 8; padding: 0 1; border: round $accent; }
#welcome, #settings { height: 1fr; padding: 0 2; }
#welcome .section, #settings .section { margin-top: 1; padding: 0; }
.para { height: auto; margin-bottom: 1; }
#settings Checkbox { height: auto; border: none; }
#settings Select { width: 70; }
#settings .row { height: auto; margin-top: 1; }
#settings .wide-label { width: 52; }
#checks-scroll { height: 1fr; padding: 0 1; }
#welcome-buttons, #settings-buttons, #check-buttons {
    height: auto; padding: 0 2; dock: bottom; margin-bottom: 1;
}
#gloss-list { height: 12; }
#gloss-scroll { height: 1fr; min-height: 6; }
#menu-hint { padding: 0 1; height: auto; }
#checklist { height: 2fr; }
#check-detail-scroll { height: 1fr; min-height: 6; padding: 0 1; border-top: solid $accent; }
#checklist-head { height: auto; }
#stuck-scroll { height: 1fr; }
#journal-scroll, #pb-scroll { height: 1fr; padding: 0 1; }
#lesson Input { margin-bottom: 1; }
#techniques { height: 1fr; min-height: 6; }
#path-head { height: auto; padding: 0 1; }
"""


class CyberdeckApp(App[None]):
    TITLE = "Cyberdeck"
    SUB_TITLE = "recon handler for Hack The Box"
    CSS = CSS
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=False),
        Binding("ctrl+t", "change_theme", "Theme", show=False),
    ]

    def __init__(self, settings: Settings | None = None, box: str | None = None) -> None:
        super().__init__()
        self.settings = settings or load_settings()
        self.box = box
        from cyberdeck.core.userconfig import load_user_config

        for theme in CYBERDECK_THEMES:
            self.register_theme(theme)
        cfg = load_user_config()
        try:
            self.theme = cfg.theme
        except Exception:  # an unknown theme name in config.yaml shouldn't stop the app
            self.theme = DEFAULT_THEME
        self.first_run = not cfg.first_run_done
        self.running_jobs = 0  # jobs started from this TUI that haven't finished

    def on_mount(self) -> None:
        from cyberdeck.ui.tui.menu import MenuScreen

        menu = MenuScreen(self.settings)
        self.push_screen(menu)
        if self.first_run and not self.box:
            from cyberdeck.ui.tui.learning import WelcomeScreen

            self.push_screen(WelcomeScreen(self.settings))
        if self.box:
            try:
                ws = services.open_target(self.settings, self.box)
            except WorkspaceError as exc:
                self.notify(str(exc), severity="error")
                return
            menu.call_after_refresh(menu.open_box, ws)

    async def action_quit(self) -> None:
        """Ask first if jobs are still running: quitting stops them (recorded as cancelled)."""
        if self.running_jobs:
            from cyberdeck.ui.tui.modals import ConfirmModal

            def answered(quit_now: bool | None) -> None:
                if quit_now:
                    self.exit()

            self.push_screen(
                ConfirmModal(
                    f"{self.running_jobs} job(s) still running. Quit and stop them?",
                    "Stopped jobs are recorded as cancelled; output so far is kept and parsed.",
                    yes="Quit",
                    no="Keep running",
                ),
                answered,
            )
            return
        self.exit()

    def action_change_theme(self) -> None:
        """ctrl+t, and Textual's own "Theme" palette command: our picker, which saves."""
        from cyberdeck.ui.tui.theme_picker import ThemePicker

        if not isinstance(self.screen, ThemePicker):
            self.push_screen(ThemePicker())

    def action_toggle_help(self) -> None:
        if self.screen.query("HelpPanel"):
            self.action_hide_help_panel()
        else:
            self.action_show_help_panel()

    def get_system_commands(self, screen: Screen[object]) -> Iterable[SystemCommand]:
        """Extra command-palette (ctrl+p) entries for the current screen."""
        yield from super().get_system_commands(screen)
        from cyberdeck.ui.tui.dashboard import DashboardScreen

        if isinstance(screen, DashboardScreen):
            for title, help_text, action in (
                ("Do the next step", "Open the top suggestion", screen.action_accept),
                ("Scan", "nmap stages through the Run dialog", screen.action_scan),
                ("Run a tool", "Pick any tool or group", screen.action_run_tool),
                (
                    "Hosts file",
                    "Add the box's names to /etc/hosts (diff first)",
                    screen.action_hosts,
                ),
                (
                    "Toggle explain mode",
                    "Show why + learn links for suggestions",
                    screen.action_explain,
                ),
                ("Loot", "Users, credentials, hashes", screen.action_loot),
                ("Notes", "Edit the box's notes.md", screen.action_notes),
                ("Record a flag", "User or root flag", screen.action_flag),
                ("Tools", "Installed tools, enable/disable, preferences", screen.action_tools),
                ("Glossary", "What the underlined words mean", screen.action_glossary),
                ("Checklist", "What to check, per service and phase", screen.action_checklist),
                ("I'm stuck", "What you haven't tried yet, then hints", screen.action_stuck),
                ("Working on...", "Start or park a lead (rabbit-hole timer)", screen.action_lead),
                ("Journal", "The box's story; export a write-up", screen.action_journal),
                (
                    "Write-up",
                    "Read and edit the box's writeup.md / WRITEUP.md",
                    screen.action_writeup,
                ),
                (
                    "Beginner / expert layout",
                    "Show or hide the journey bar and Now card",
                    screen.action_toggle_layout,
                ),
            ):
                yield SystemCommand(title, help_text, action)
        else:
            yield SystemCommand("Tools", "Installed tools, enable/disable", self._tools)
        yield SystemCommand(
            "Settings", "Layout, learning aids, workspace, theme", self.action_settings_screen
        )
        yield SystemCommand(
            "Setup check", "VPN, tools, wordlists, sudo, clock", self.action_setup_check
        )
        yield SystemCommand("Glossary (all terms)", "Search every term", self.action_glossary)
        yield SystemCommand(
            "Progress", "Learning path, skills and your playbook", self.action_progress
        )

    def action_progress(self) -> None:
        from cyberdeck.ui.tui.journal import ProgressScreen

        self.push_screen(ProgressScreen(self.settings))

    def action_settings_screen(self) -> None:
        from cyberdeck.ui.tui.learning import SettingsScreen

        self.push_screen(SettingsScreen(self.settings))

    def action_setup_check(self) -> None:
        from cyberdeck.ui.tui.learning import SetupCheckScreen

        self.push_screen(SetupCheckScreen(self.settings))

    def action_glossary(self) -> None:
        from cyberdeck.ui.tui.learning import GlossaryModal

        self.push_screen(GlossaryModal(services.load_glossary()))

    def _tools(self) -> None:
        from cyberdeck.ui.tui.tools import ToolsScreen

        self.push_screen(ToolsScreen())


def run_tui(box: str | None = None) -> None:
    CyberdeckApp(box=box).run()
