"""Phase 6: the MCP server (ADR 0007, docs/MCP.md), driven through a real MCP client.

The guardrails are the point: previews fix the argv, only safe no-root tools run directly,
everything else and every /etc/hosts edit waits for a human, scope applies, loot is masked.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from rich.console import Console
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import services
from cyberdeck.core.config import Settings, load_settings
from cyberdeck.core.events import bus
from cyberdeck.core.models import ApprovalState, Credential, Finding, Service
from cyberdeck.core.tools import registry
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.mcp_server.server import BearerAuth, build_server
from cyberdeck.util import hosts as hostsfile
from cyberdeck.util.vpn import Tunnel, VpnStatus

from .conftest import FIXTURES, make_ws

IP = "10.129.231.15"
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"
TOOL_FIXTURES = Path(__file__).parent / "fixtures" / "tools"


@pytest.fixture(autouse=True)
def fresh(monkeypatch: pytest.MonkeyPatch) -> Any:
    registry(reload=True)
    bus.clear()
    monkeypatch.setattr(
        services,
        "vpn_check",
        lambda s, ip: VpnStatus(ip, True, [Tunnel("tun0", "10.10.14.7")], route_dev="tun0"),
    )
    monkeypatch.setattr(
        services, "RUNNER_LAUNCHER", lambda argv: [sys.executable, str(FAKE_TOOL), *argv[1:]]
    )
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb-redirect.json"))
    yield
    bus.clear()


@pytest.fixture
def lantern(settings: Settings) -> Workspace:
    ws = make_ws(settings, "lantern", IP)
    services.import_nmap(ws, FIXTURES / "lantern")
    return ws


class Mcp:
    """Thin wrapper: call a tool, get its data back (or raise with the error text)."""

    def __init__(self, client: Client) -> None:
        self.client = client

    async def __call__(self, tool: str, /, **args: Any) -> Any:
        result = await self.client.call_tool(tool, args)
        text = "\n".join(getattr(c, "text", "") for c in result.content)
        if result.is_error:
            raise AssertionError(text)
        sc = result.structured_content
        if sc is not None:
            return sc["result"] if set(sc) == {"result"} else sc
        return json.loads(text)

    async def error(self, tool: str, /, **args: Any) -> str:
        result = await self.client.call_tool(tool, args)
        assert result.is_error, result
        return "\n".join(getattr(c, "text", "") for c in result.content)


async def _with_client(settings: Settings, target: str | None, body: Any) -> Any:
    server = build_server(settings, target)
    async with Client(server) as client:
        return await body(Mcp(client))


async def _wait_job(call: Mcp, job_id: int) -> dict[str, Any]:
    for _ in range(600):  # up to 30 s: the full suite can be slow
        status = await call("job_status", job_id=job_id)
        if status["ended"]:
            return dict(status)
        await asyncio.sleep(0.05)
    raise AssertionError("job didn't finish")


# --- discovery ------------------------------------------------------------------------------


async def test_tools_resources_and_prompts_are_listed(
    lantern: Workspace, settings: Settings
) -> None:
    server = build_server(settings, str(lantern.path))
    async with Client(server) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {
            "list_targets",
            "target_summary",
            "list_findings",
            "list_suggestions",
            "preview_command",
            "run_tool",
            "job_status",
            "request_hosts_entry",
            "list_approvals",
        } <= names
        templates = {
            t.uri_template for t in (await client.list_resource_templates()).resource_templates
        }
        assert "cyberdeck://target/{name}/summary" in templates
        prompts = {p.name for p in (await client.list_prompts()).prompts}
        assert {"next-steps", "stuck"} <= prompts
        summary = await client.read_resource("cyberdeck://target/lantern/summary")
        assert '"kind": "web"' in summary.contents[0].text  # type: ignore[union-attr]
        prompt = await client.get_prompt("next-steps", {"target": "lantern"})
        assert "Don't run anything I haven't seen" in prompt.messages[0].content.text  # type: ignore[union-attr]


async def test_summary_progress_suggestions(lantern: Workspace, settings: Settings) -> None:
    async def body(call: Mcp) -> None:
        boxes = await call("list_targets")
        assert [b["name"] for b in boxes] == ["lantern"]
        summary = await call("target_summary")
        assert {s["port"]: s["kind"] for s in summary["services"]}[80] == "web"
        assert summary["hostnames"][0]["fqdn"] == "lantern.htb"
        progress = await call("target_progress")
        assert progress["pending_approvals"] == 0
        steps = await call("list_suggestions")
        assert steps[0]["kind"] == "ask" and "lantern.htb" in steps[0]["question"]
        fp = next(s for s in steps if s["tool"] == "whatweb")
        assert fp["safety"] == "safe" and fp["why"]

    await _with_client(settings, str(lantern.path), body)


# --- preview -> run ---------------------------------------------------------------------------


async def test_safe_tool_previews_then_runs_with_origin_mcp(
    lantern: Workspace, settings: Settings
) -> None:
    async def body(call: Mcp) -> None:
        steps = await call("list_suggestions")
        fp = next(s for s in steps if s["tool"] == "whatweb")
        preview = await call("preview_suggestion", suggestion_id=fp["id"])
        assert preview["argv"][0] == "whatweb" and preview["needs_approval"] is None
        assert f"http://{IP}/" in preview["command"]
        started = await call("run_tool", preview_id=preview["preview_id"])
        assert started["status"] == "running" and started["job_id"] == 1
        done = await _wait_job(call, 1)
        assert done["status"] == "done" and done["origin"] == "mcp"
        assert any(f["type"] == "software" for f in done["findings"])
        out = await call("job_output", job_id=1)
        assert "fake tool ran" in out["output"]
        # one preview, one run: the preview is used up
        assert "unknown or expired" in await call.error(
            "run_tool", preview_id=preview["preview_id"]
        )
        closed = await call("list_suggestions", include_closed=True)
        assert next(s for s in closed if s["id"] == fp["id"])["status"] == "done"

    await _with_client(settings, str(lantern.path), body)
    assert services.list_jobs(lantern)[0].origin == "mcp"


async def test_run_tool_wait_and_explicit_inputs(lantern: Workspace, settings: Settings) -> None:
    async def body(call: Mcp) -> None:
        preview = await call(
            "preview_command",
            tool="whatweb",
            inputs={"url": "http://lantern.htb/"},
            options={"aggression": "1"},
        )
        assert (
            preview["argv"][:3] == ["whatweb", "-a", "1"]
            and "http://lantern.htb/" in preview["argv"]
        )
        result = await call("run_tool", preview_id=preview["preview_id"], wait=True)
        assert result["status"] == "done" and result["new_findings"]
        assert "no input/option" in await call.error(
            "preview_command", tool="whatweb", options={"nope": "1"}
        )
        assert "unknown tool" in await call.error("preview_command", tool="no-such-tool")
        bad = await call("preview_command", tool="whatweb", inputs={"url": ""})
        assert bad["preview_id"] is None and bad["problems"]

    await _with_client(settings, str(lantern.path), body)


async def test_scope_guard_applies_to_mcp_jobs(lantern: Workspace, settings: Settings) -> None:
    async def body(call: Mcp) -> None:
        preview = await call("preview_command", tool="whatweb", inputs={"url": "http://8.8.8.8/"})
        error = await call.error("run_tool", preview_id=preview["preview_id"])
        assert "8.8.8.8" in error and "scope" in error.lower()

    await _with_client(settings, str(lantern.path), body)
    assert services.list_jobs(lantern) == []


# --- approvals --------------------------------------------------------------------------------


async def test_non_safe_and_root_jobs_wait_for_a_human(
    lantern: Workspace, settings: Settings
) -> None:
    async def body(call: Mcp) -> dict[str, Any]:
        nikto = await call("preview_command", tool="nikto")
        assert nikto["safety"] == "intrusive" and "intrusive" in nikto["needs_approval"]
        queued = await call(
            "run_tool", preview_id=nikto["preview_id"], reason="check for old software"
        )
        assert queued["status"] == "awaiting_approval"
        udp = await call("start_scan", stage="udp")
        assert "root" in udp["needs_approval"]
        queued_udp = await call("run_tool", preview_id=udp["preview_id"])
        pending = await call("list_approvals")
        assert [a["id"] for a in pending] == [queued["approval_id"], queued_udp["approval_id"]]
        assert pending[0]["command"] == nikto["command"]
        return dict(queued)

    queued = await _with_client(settings, str(lantern.path), body)
    assert services.list_jobs(lantern) == []  # nothing ran

    approval = services.get_approval(lantern, queued["approval_id"])
    plan = services.approval_plan(lantern, queued["approval_id"])
    assert plan.argv() == approval.payload["argv"]  # exactly what was previewed
    outcome = await services.run_approved_job(lantern, settings, queued["approval_id"])
    assert (
        outcome.result.job.origin == "mcp" and outcome.result.job.argv == approval.payload["argv"]
    )
    done = services.get_approval(lantern, queued["approval_id"])
    assert done.state is ApprovalState.APPROVED and done.job_id == outcome.result.job.id
    with pytest.raises(services.OptionError, match="already approved"):
        services.approval_plan(lantern, queued["approval_id"])


async def test_approval_all_mode_queues_safe_tools_too(
    lantern: Workspace, settings: Settings
) -> None:
    cfg = load_user_config()
    cfg.mcp.approval = "all"
    save_user_config(cfg)

    async def body(call: Mcp) -> None:
        preview = await call("preview_command", tool="whatweb")
        assert "approval is 'all'" in preview["needs_approval"]
        assert (await call("run_tool", preview_id=preview["preview_id"]))[
            "status"
        ] == "awaiting_approval"

    await _with_client(settings, str(lantern.path), body)
    assert services.list_jobs(lantern) == []


async def test_hosts_edits_are_always_queued(lantern: Workspace, settings: Settings) -> None:
    async def body(call: Mcp) -> int:
        question = (await call("list_suggestions"))[0]
        queued = await call("answer_question", suggestion_id=question["id"], answer="yes")
        assert queued["status"] == "awaiting_approval"
        assert "+10.129.231.15\tlantern.htb\t# cyberdeck:lantern" in queued["diff"]
        return int(queued["approval_id"])

    approval_id = await _with_client(settings, str(lantern.path), body)
    assert not hostsfile.resolves_to(settings.hosts_file, "lantern.htb", IP)  # not written yet
    change = services.approval_hosts_change(lantern, approval_id, settings)
    services.approve_hosts(lantern, approval_id, change, settings)
    assert hostsfile.resolves_to(settings.hosts_file, "lantern.htb", IP)
    question = next(
        s
        for s in services.list_suggestions(lantern, include_closed=True)
        if s.rule_id == "hosts.add"
    )
    assert question.status.value == "done"

    async def again(call: Mcp) -> None:
        assert "already maps" in await call.error("request_hosts_entry")
        extra = await call("request_hosts_entry", names=["dev.lantern.htb"], reason="vhost found")
        assert extra["status"] == "awaiting_approval"

    await _with_client(settings, str(lantern.path), again)


def test_cli_approvals_list_approve_deny(
    lantern: Workspace, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "console", Console(width=200))
    monkeypatch.setattr(cli, "have_binary", lambda name: True)
    plan = services.plan_tool(lantern, "nikto", settings=settings)
    first = services.request_job_approval(lantern, plan, reason="old apache?")
    second = services.request_job_approval(lantern, plan)
    runner = CliRunner()
    t = ["-t", str(lantern.path)]
    listing = runner.invoke(cli.app, ["approvals", *t])
    assert listing.exit_code == 0 and "nikto" in listing.output and "old apache?" in listing.output
    everywhere = runner.invoke(cli.app, ["approvals", "--all"])
    assert "lantern" in everywhere.output
    declined = runner.invoke(cli.app, ["approvals", "approve", str(first.id), *t], input="n\n")
    assert "Left pending" in declined.output
    approved = runner.invoke(cli.app, ["approvals", "approve", str(first.id), *t, "-y"])
    assert approved.exit_code == 0, approved.output
    assert "$ nikto" in approved.output
    assert services.get_approval(lantern, first.id or 0).state is ApprovalState.APPROVED
    denied = runner.invoke(cli.app, ["approvals", "deny", str(second.id), *t])
    assert (
        denied.exit_code == 0
        and services.get_approval(lantern, second.id or 0).state is ApprovalState.DENIED
    )
    again = runner.invoke(cli.app, ["approvals", "deny", str(second.id), *t])
    assert again.exit_code == 1 and "already denied" in again.output


async def test_tui_shows_and_runs_approvals(lantern: Workspace, settings: Settings) -> None:
    from cyberdeck.ui.tui.app import CyberdeckApp
    from cyberdeck.ui.tui.approvals import ApprovalsScreen
    from cyberdeck.ui.tui.dashboard import DashboardScreen
    from cyberdeck.ui.tui.modals import ConfirmModal

    plan = services.plan_tool(lantern, "whatweb", settings=settings)
    approval = services.request_job_approval(lantern, plan)
    app = CyberdeckApp(settings, box=str(lantern.path))
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        dash = app.screen
        assert isinstance(dash, DashboardScreen)
        assert dash.query_one("#approvals-banner").display
        await pilot.press("p")
        await pilot.pause()
        assert isinstance(app.screen, ApprovalsScreen)
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal) and "whatweb" in app.screen.detail
        await pilot.press("y")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert not dash.query_one("#approvals-banner").display
    done = services.get_approval(lantern, approval.id or 0)
    assert done.state is ApprovalState.APPROVED and done.job_id


# --- findings, notes, masking, pinning ------------------------------------------------------


async def test_loot_is_masked_unless_the_user_allows_it(
    lantern: Workspace, settings: Settings
) -> None:
    with lantern.store() as store:
        store.upsert(Finding.of(Credential(user="admin", secret="hunter22"), source="test"))

    async def body(call: Mcp) -> None:
        creds = await call("list_findings", type="credential")
        assert creds["findings"][0]["data"]["secret"] == "<hidden: 8 chars>"
        asked = await call("list_findings", type="credential", reveal=True)
        assert "hunter22" not in json.dumps(asked) and "reveal_secrets" in asked["note"]
        assert "unknown type" in await call.error("list_findings", type="nope")
        hits = await call("list_findings", query="nginx")
        assert hits["count"] >= 1

    await _with_client(settings, str(lantern.path), body)
    cfg = load_user_config()
    cfg.mcp.reveal_secrets = True
    save_user_config(cfg)

    async def revealed(call: Mcp) -> None:
        creds = await call("list_findings", type="credential", reveal=True)
        assert creds["findings"][0]["data"]["secret"] == "hunter22"

    await _with_client(settings, str(lantern.path), revealed)


async def test_add_finding_note_and_question_answers(settings: Settings) -> None:
    ws = make_ws(settings, "Box", IP)
    with ws.store() as store:
        store.upsert(Finding.of(Service(port=80, name="http"), source="test"))

    async def body(call: Mcp) -> None:
        guess = next(
            s
            for s in await call("list_suggestions")
            if s["question"] and "hostname" in s["title"].lower()
        )
        assert guess["default_answer"] == "box.htb"
        answered = await call("answer_question", suggestion_id=guess["id"], answer="box.htb")
        assert answered["status"] == "done"
        added = await call("add_finding", type="hostname", data={"fqdn": "dev.box.htb", "ip": IP})
        assert added["key"] == "dev.box.htb" and added["sources"] == ["mcp"]
        assert "invalid hostname" in await call.error(
            "add_finding", type="hostname", data={"fqdn": "x"}
        )
        await call("add_note", text="Login at /admin uses default creds?")
        flag = await call("record_flag", kind="user", value="0" * 32)
        assert flag["looks_like_htb_flag"] is True

    await _with_client(settings, str(ws.path), body)
    assert {"box.htb", "dev.box.htb"} <= set(services.box_hostnames(ws))
    assert "(mcp)" in services.read_notes(ws) and "default creds" in services.read_notes(ws)


async def test_pinned_server_stays_on_its_box(lantern: Workspace, settings: Settings) -> None:
    make_ws(settings, "other", "10.129.1.2")

    async def body(call: Mcp) -> None:
        assert [b["name"] for b in await call("list_targets")] == ["lantern"]
        assert "pinned to lantern" in await call.error("target_summary", target="other")
        assert "pinned" in await call.error("create_target", name="new", ip="10.129.9.9")

    await _with_client(settings, str(lantern.path), body)

    async def unpinned(call: Mcp) -> None:
        assert {b["name"] for b in await call("list_targets")} == {"lantern", "other"}
        assert (await call("target_summary", target="other"))["ip"] == "10.129.1.2"
        assert "8.8.8.8" in await call.error("create_target", name="bad", ip="8.8.8.8")
        created = await call("create_target", name="newbox", ip="10.129.9.9")
        assert created["name"] == "newbox"

    await _with_client(settings, None, unpinned)


# --- transports -------------------------------------------------------------------------------


async def test_stdio_server_end_to_end(lantern: Workspace) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "cyberdeck", "mcp", "-t", str(lantern.path)],
        env=dict(os.environ),
    )
    async with Client(params) as client:
        result = await client.call_tool("target_summary", {})
        assert not result.is_error
        assert result.structured_content and result.structured_content["name"] == "lantern"


async def test_http_needs_the_bearer_token() -> None:
    async def inner(scope: dict[str, Any], receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = BearerAuth(inner, "s3cret")

    async def status(auth: bytes | None) -> int:
        sent: list[dict[str, Any]] = []
        headers = [(b"authorization", auth)] if auth is not None else []
        scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": headers}

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b""}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        await app(scope, receive, send)
        return int(sent[0]["status"])

    assert await status(None) == 401
    assert await status(b"Bearer nope") == 401
    assert await status(b"Bearer s3cret") == 200


def test_cli_mcp_http_refuses_remote_and_generates_a_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from cyberdeck.mcp_server import server as mcp_server

    served: list[tuple[str, int, str]] = []
    monkeypatch.setattr(
        mcp_server, "run_http", lambda h, p, tok, t=None: served.append((h, p, tok))
    )
    runner = CliRunner()
    remote = runner.invoke(cli.app, ["mcp", "--http", "0.0.0.0:8765"])
    assert remote.exit_code == 1 and "refusing" in remote.output
    local = runner.invoke(cli.app, ["mcp", "--http", "127.0.0.1:8765"])
    assert local.exit_code == 0, local.output
    env_file = tmp_path / "xdg" / "cyberdeck" / ".env"
    token = served[0][2]
    assert f"CYBERDECK_MCP_TOKEN={token}" in env_file.read_text()
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert token not in local.output  # never printed
    assert load_settings().mcp_token is not None  # picked up next time
