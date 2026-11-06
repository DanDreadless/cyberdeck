"""Terminal Run dialog (ADR 0005): review and change a tool's flags before it runs.

The TUI has its own version (``ui/tui/run_dialog.py``) over the same :class:`RunPlan`.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cyberdeck.core import glossary, services
from cyberdeck.core.options import OptionError, OptionSpec, RunPlan

SaveCallback = Callable[[RunPlan], str]
HelpCallback = Callable[[RunPlan], str | None]

KEYS_HELP = (
    "[bold]Enter[/] run   [bold]1-9[/] change option   [bold]p[/] preset   "
    "[bold]x[/] extra args   [bold]e[/] edit command   [bold]u[/] sudo on/off   "
    "[bold]a[/] advanced   [bold]h[/] tool's own --help   [bold]s[/] save as my default   "
    "[bold]b[/] save for this box   [bold]q[/] skip"
)
_SAFETY_STYLE = {"safe": "green", "intrusive": "yellow", "bruteforce": "red", "exploit": "red"}


def _visible(plan: RunPlan, show_advanced: bool) -> list[OptionSpec]:
    return [o for o in plan.tool.options if show_advanced or not o.advanced]


def render(plan: RunPlan, console: Console, *, show_advanced: bool, is_root: bool) -> None:
    tool = plan.tool
    title = f"Run: {tool.name}" + (f"  (preset: {plan.preset})" if plan.preset else "")
    title += f"  [{_SAFETY_STYLE.get(tool.safety, 'white')}]{tool.safety}[/]"
    table = Table(show_header=True, header_style="bold", expand=False)
    table.add_column("#", justify="right")
    table.add_column("Option")
    table.add_column("Value", overflow="fold")
    table.add_column("What it does", style="dim", max_width=60)
    for index, opt in enumerate(_visible(plan, show_advanced), start=1):
        value = plan.values.get(opt.id)
        label = Text(opt.title + (" *" if opt.input and opt.required else ""))
        table.add_row(str(index), label, Text(opt.display(value)), Text(opt.help))
    hidden = sum(1 for o in tool.options if o.advanced) if not show_advanced else 0
    console.print(Panel(table, title=title, title_align="left", subtitle=tool.description))
    teach = services.teaching(tool)
    if teach is not None:
        if teach.does:
            console.print(f"  [bold]What it does:[/] {escape(glossary.plain(teach.does))}")
        if teach.look_for:
            console.print(f"  [bold]Look for:[/] {escape(glossary.plain(teach.look_for))}")
    if hidden:
        console.print(f"  [dim]{hidden} advanced options hidden (a to show)[/]")
    if plan.extra:
        console.print(Text(f"  Extra args: {' '.join(plan.extra)}"))
    if plan.raw_argv is not None:
        console.print("  [yellow]Command edited by hand; changing an option resets it.[/]")
    try:
        console.print(Text("  $ " + plan.command_line(), style="bold cyan"))
    except (OptionError, ValueError):
        try:
            console.print(Text("  $ " + plan.draft_command_line(), style="dim cyan"))
            console.print("  [dim](set the options marked * to fill in the <placeholders>)[/]")
        except (OptionError, ValueError):
            console.print("  [dim]$ (set the options marked * to see the command)[/]")
    privilege = "root" if is_root else ("sudo" if plan.sudo else "not root")
    console.print(f"  [dim]Running as: {privilege}.[/]", end="")
    if tool.binary == "nmap" and not is_root and not plan.sudo:
        console.print(" [dim]nmap will use a connect scan (-sT); u = use sudo for SYN/UDP/OS.[/]")
    else:
        console.print()
    if tool.notes:
        console.print(f"  [yellow]Note:[/] {escape(tool.notes)}")
    if tool.learn:
        console.print(f"  [dim]Learn more: {tool.learn}[/]")
    for warning in plan.warnings:
        console.print(f"  [yellow]![/] {warning}")
    for problem in plan.problems(is_root):
        console.print(f"  [red]✗[/] {problem}")
    console.print(f"  {KEYS_HELP}")


def run_dialog(
    plan: RunPlan,
    console: Console,
    *,
    is_root: bool,
    save_user: SaveCallback,
    save_box: SaveCallback,
    show_help: HelpCallback | None = None,
) -> RunPlan | None:
    """Loop until the user runs (returns the plan) or skips (returns None)."""
    show_advanced = False
    while True:
        render(plan, console, show_advanced=show_advanced, is_root=is_root)
        choice = console.input("[bold]> [/]").strip()
        key = choice.lower()
        try:
            if key == "":
                problems = plan.problems(is_root)
                if not problems:
                    return plan
                console.print("[red]Fix the problems above first.[/]")
            elif key == "q":
                return None
            elif key.isdigit():
                visible = _visible(plan, show_advanced)
                index = int(key) - 1
                if not 0 <= index < len(visible):
                    console.print("[red]No option with that number.[/]")
                    continue
                opt = visible[index]
                if opt.type == "bool":
                    plan.toggle(opt.id)
                else:
                    hint = f" ({'/'.join(opt.choices)})" if opt.choices else ""
                    current = opt.display(plan.values.get(opt.id))
                    raw = console.input(f"{opt.title}{hint} [{current}], 'none' clears: ")
                    if raw.strip():
                        plan.set_option(opt.id, raw)
            elif key == "p":
                names = ", ".join(plan.tool.presets) or "none"
                name = console.input(f"Preset ({names}): ").strip()
                if name:
                    plan.apply_preset(name)
            elif key == "x":
                current = " ".join(plan.extra)
                raw = console.input(f"Extra args [{current}] ('-' clears): ")
                if raw.strip() == "-":
                    plan.set_extra("")
                elif raw.strip():
                    plan.set_extra(raw)
            elif key == "e":
                console.print(Text("Current: " + plan.draft_command_line()))
                raw = console.input("New command (empty keeps it): ")
                if raw.strip():
                    plan.set_raw(raw)
            elif key == "u":
                plan.sudo = not plan.sudo
            elif key == "a":
                show_advanced = not show_advanced
            elif key == "h":
                text = show_help(plan) if show_help else None
                if text:
                    with console.pager():
                        console.print(text, markup=False, highlight=False)
                else:
                    console.print("[yellow]No help text available for this tool.[/]")
            elif key == "s":
                console.print(f"[green]✓[/] Saved as your default in {save_user(plan)}")
            elif key == "b":
                console.print(f"[green]✓[/] Saved for this box in {save_box(plan)}")
            else:
                console.print("[red]Unknown key.[/]")
        except (OptionError, ValueError) as exc:
            console.print(f"[red]{exc}[/]")
