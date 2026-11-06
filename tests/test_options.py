from __future__ import annotations

import pytest

from cyberdeck.core.options import (
    OptionError,
    OptionSpec,
    RunPlan,
    ToolSpec,
    render_argv,
    render_template,
    resolve_values,
)
from cyberdeck.core.tools import (
    NMAP_ALLPORTS,
    NMAP_SERVICES,
    NMAP_UDP,
    get_tool,
    parse_discovered,
    parse_progress,
)

CTX = {"target.ip": "10.129.231.15", "target.slug": "lantern", "target.name": "Lantern"}


def _ctx(tool: ToolSpec) -> dict[str, str]:
    ctx = dict(CTX)
    if tool.out:
        ctx["out"] = render_template(tool.out, ctx)
    return ctx


def test_option_render_and_parse() -> None:
    joined = OptionSpec(id="ports", flag="-p", joined=True)
    assert joined.render("-") == ["-p-"]
    assert joined.render(None) == []
    spaced = OptionSpec(id="rate", flag="--min-rate", type="int")
    assert spaced.render(5000) == ["--min-rate", "5000"]
    assert spaced.parse(" 100 ") == 100
    assert spaced.parse("none") is None
    with pytest.raises(OptionError):
        spaced.parse("fast")
    flag = OptionSpec(id="pn", flag="-Pn", type="bool")
    assert flag.render(True) == ["-Pn"] and flag.render(False) == []
    assert flag.parse("yes") is True
    choice = OptionSpec(
        id="t", type="choice", choices=["a", "b"], render_map={"a": [], "b": ["-B"]}
    )
    assert choice.render("b") == ["-B"] and choice.render("a") == []
    with pytest.raises(OptionError):
        choice.parse("c")


def test_stage1_default_command() -> None:
    values = resolve_values(NMAP_ALLPORTS)
    argv = render_argv(NMAP_ALLPORTS, values, [], _ctx(NMAP_ALLPORTS))
    assert argv == [
        "nmap", "-p-", "--min-rate", "5000", "-Pn", "--reason", "-T4", "-v",
        "--stats-every", "10s", "-oA", "nmap/lantern-allports", "10.129.231.15",
    ]  # fmt: skip


def test_resolution_order() -> None:
    values = resolve_values(
        NMAP_ALLPORTS,
        user_defaults={"min_rate": 3000, "timing": "3"},
        box_defaults={"min_rate": 2000},
        preset="quick",
    )
    assert values["min_rate"] == 2000  # box beats user
    assert values["timing"] == "3"  # user beats tool default
    assert values["ports"] is None and values["top_ports"] == 1000  # preset applied last
    with pytest.raises(OptionError, match="no preset"):
        resolve_values(NMAP_ALLPORTS, preset="nope")


def test_plan_edits_and_sudo() -> None:
    plan = RunPlan(NMAP_SERVICES, resolve_values(NMAP_SERVICES), _ctx(NMAP_SERVICES))
    plan.set_option("ports", "22,80")
    plan.toggle("scripts")
    plan.set_extra("--script vuln")
    line = plan.command_line()
    assert (
        "-p22,80" in line
        and "-sC" not in line
        and line.endswith("--script vuln -oA nmap/lantern 10.129.231.15")
    )
    plan.sudo = True
    assert plan.argv()[:3] == ["sudo", "-n", "nmap"]
    plan.set_raw("sudo nmap -p 22 10.129.231.15")
    assert plan.sudo and plan.base_argv() == ["nmap", "-p", "22", "10.129.231.15"]
    plan.set_option("timing", "3")  # editing an option drops the hand-edited command
    assert plan.raw_argv is None
    with pytest.raises(OptionError):
        plan.toggle("ports")


def test_problems_need_root() -> None:
    udp = RunPlan(NMAP_UDP, resolve_values(NMAP_UDP), _ctx(NMAP_UDP))
    assert udp.problems(is_root=False)
    assert not udp.problems(is_root=True)
    udp.sudo = True
    assert not udp.problems(is_root=False)

    svc = RunPlan(NMAP_SERVICES, resolve_values(NMAP_SERVICES), _ctx(NMAP_SERVICES))
    assert not svc.problems(is_root=False)
    svc.toggle("os_detect")
    assert any("OS detection" in p for p in svc.problems(is_root=False))
    svc.toggle("os_detect")
    svc.set_option("scan_type", "syn")
    assert svc.problems(is_root=False)
    svc.set_option("scan_type", "connect")
    assert not svc.problems(is_root=False) and "-sT" in svc.argv()


def test_changed_values_excludes_dynamic() -> None:
    svc = RunPlan(
        NMAP_SERVICES,
        resolve_values(NMAP_SERVICES, dynamic={"ports": "22,80"}),
        _ctx(NMAP_SERVICES),
    )
    svc.set_option("timing", "3")
    assert svc.changed_values() == {"timing": "3"}


def test_template_errors_and_registry() -> None:
    with pytest.raises(OptionError, match="unknown template variable"):
        render_template("{nope}", CTX)
    with pytest.raises(OptionError, match="unknown tool"):
        get_tool("no-such-tool")


def test_nmap_live_output_parsing() -> None:
    progress = parse_progress(
        "SYN Stealth Scan Timing: About 23.45% done; ETC: 10:02 (0:00:33 remaining)"
    )
    assert progress is not None
    assert (progress.phase, progress.percent, progress.remaining) == (
        "SYN Stealth Scan",
        23.45,
        "0:00:33",
    )
    assert parse_progress("Service scan Timing: About 50.00% done") is not None
    assert parse_progress("PORT   STATE SERVICE") is None
    assert parse_discovered("Discovered open port 8080/tcp on 10.129.1.1") == (8080, "tcp")


def test_draft_command_with_empty_required_input() -> None:
    """Editing the command while a required input is empty used to crash the TUI."""
    from cyberdeck.plugins.manifest import manifest_to_spec

    tool = manifest_to_spec(
        {
            "id": "lookup",
            "name": "lookup",
            "detect": {"binary": "lookup"},
            "inputs": {"query": {"label": "Search terms"}},
            "options": [{"id": "dos", "flag": "--exclude=dos", "type": "bool", "default": True}],
            "command": ["lookup", "{opt.dos}", "{extra}", "{query}"],
        }
    )
    plan = RunPlan(tool, resolve_values(tool), {})
    with pytest.raises(OptionError):
        plan.command_line()
    assert [o.id for o in plan.missing_inputs()] == ["query"]
    assert plan.draft_command_line() == "lookup --exclude=dos '<query>'"
    # editing it by hand without replacing the placeholder must not be runnable
    plan.set_raw(plan.draft_command_line())
    assert any("<query>" in p for p in plan.problems(is_root=False))
    plan.set_raw("lookup --exclude=dos 'vsftpd 2.3.4'")
    assert plan.problems(is_root=False) == []
    assert plan.argv() == ["lookup", "--exclude=dos", "vsftpd 2.3.4"]
