from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.models import JobStatus
from cyberdeck.core.scope import ScopeError
from cyberdeck.core.userconfig import load_user_config
from cyberdeck.core.workspace import WorkspaceNotFoundError
from cyberdeck.util.vpn import Tunnel, VpnStatus

from .conftest import FIXTURES, make_ws

IP = "10.129.231.15"
FAKE_NMAP = Path(__file__).parent / "fake_nmap.py"
runner = CliRunner()


def test_reap_interrupted_jobs(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    with ws.store() as store:
        orphan = store.create_job("nmap-allports", ["nmap"], str(ws.path), "cli")
        store.save_job(orphan.model_copy(update={"status": JobStatus.RUNNING, "pid": 999999}))
        live = store.create_job("nmap-services", ["nmap"], str(ws.path), "mcp")
        store.save_job(live.model_copy(update={"status": JobStatus.RUNNING, "pid": 4242}))
        reaped = store.reap_interrupted(lambda pid: pid == 4242)
        assert [j.id for j in reaped] == [orphan.id]
        statuses = {j.id: j.status for j in store.jobs()}
    assert statuses == {orphan.id: JobStatus.INTERRUPTED, live.id: JobStatus.RUNNING}


def test_open_records_last_opened_and_current_fallback(settings: Settings, tmp_path: Path) -> None:
    ws = make_ws(settings, "lantern", IP)
    assert ws.meta.last_opened is None
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    with pytest.raises(WorkspaceNotFoundError):
        services.open_target(settings, cwd=elsewhere)

    services.use_target(ws)
    opened = services.open_target(settings, cwd=elsewhere)
    assert opened.path == ws.path and opened.resolved_via == "current"
    assert opened.meta.last_opened is not None
    assert services.open_target(settings, cwd=ws.nmap_dir).resolved_via == "cwd"
    with pytest.raises(WorkspaceNotFoundError):  # an explicit name never falls back
        services.open_target(settings, "missing", cwd=elsewhere)


def test_set_ip_and_flags(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    assert services.set_ip(settings, ws, "10.129.99.1") == IP
    assert ws.meta.ip == "10.129.99.1" and "IP changed" in ws.notes_file.read_text()
    with pytest.raises(ScopeError):
        services.set_ip(settings, ws, "8.8.8.8")
    assert services.record_flag(ws, "user", "0123456789abcdef0123456789abcdef")
    assert not services.record_flag(ws, "root", "not-a-flag")
    reopened = services.open_target(settings, str(ws.path))
    assert reopened.meta.flags.user and reopened.meta.flags.root == "not-a-flag"


def test_progress_follows_the_box(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    fresh = services.target_progress(ws)
    assert not any(step.done for step in fresh.steps)
    assert fresh.next_tools == ("nmap-allports", "nmap-services")

    services.import_nmap(ws, FIXTURES / "lantern" / "lantern-allports.xml")
    half = services.target_progress(ws)
    assert half.steps[0].done and not half.steps[1].done
    assert half.next_tools == ("nmap-services",)

    services.import_nmap(ws, FIXTURES / "lantern" / "lantern.xml")  # hand-run scans count too
    full = services.target_progress(ws)
    assert full.steps[1].done and full.steps[3].done and full.next_tools == ()
    services.record_flag(ws, "user", "0" * 32)
    assert "privilege escalation" in services.target_progress(ws).next_hint


def test_unmanaged_folders(settings: Settings) -> None:
    make_ws(settings, "lantern", IP)
    (settings.root / "alert" / "nmap").mkdir(parents=True)
    (settings.root / ".hidden").mkdir()
    assert [p.name for p in services.list_unmanaged(settings)] == ["alert"]


# --- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cli, "console", Console(width=200))
    monkeypatch.setattr(cli, "err_console", Console(width=200, stderr=True))
    fixtures = tmp_path / "fake-fixtures"
    fixtures.mkdir()
    shutil.copy(FIXTURES / "lantern" / "lantern-allports.xml", fixtures / "allports.xml")
    shutil.copy(FIXTURES / "lantern" / "lantern.xml", fixtures / "services.xml")
    monkeypatch.setenv("FAKE_NMAP_FIXTURES", str(fixtures))
    monkeypatch.setattr(
        services,
        "RUNNER_LAUNCHER",
        lambda argv: [sys.executable, str(FAKE_NMAP), *argv[1:]] if argv[0] == "nmap" else argv,
    )
    monkeypatch.setattr(cli, "have_binary", lambda name: True)
    monkeypatch.setattr(cli, "is_root", lambda: False)
    monkeypatch.setattr(
        services,
        "vpn_check",
        lambda settings, ip: VpnStatus(ip, True, [Tunnel("tun0", "10.10.14.7")], route_dev="tun0"),
    )
    return tmp_path / "htb"


def test_cli_resume_flow(cli_env: Path) -> None:
    assert runner.invoke(cli.app, ["new", "lantern", "--ip", IP, "--no-scan"]).exit_code == 0
    ledger = runner.invoke(cli.app, ["new", "ledger", "--ip", "10.129.40.20", "--no-scan"])
    assert ledger.exit_code == 0
    (cli_env / "alert").mkdir()
    assert load_user_config().current_target == str(cli_env / "ledger")  # newest box is current

    listing = runner.invoke(cli.app, ["list"]).output
    assert "lantern" in listing and "ledger" in listing
    assert "Folders not set up yet: alert" in listing

    status = runner.invoke(cli.app, ["status"]).output  # no -t, not in a box folder: current box
    assert "the current box" in status and "ledger" in status and "Next:" in status

    result = runner.invoke(cli.app, ["resume", "lantern", "--yes"])
    assert result.exit_code == 0, result.output
    assert "Open TCP ports: 22,80,9091" in result.output
    assert load_user_config().current_target == str(cli_env / "lantern")

    after = runner.invoke(cli.app, ["status"]).output
    assert "Box complete" not in after and "cyberdeck suggest" in after

    assert runner.invoke(cli.app, ["flag", "user", "0" * 32]).exit_code == 0
    assert "work on privilege escalation" in runner.invoke(cli.app, ["status"]).output
    assert runner.invoke(cli.app, ["flag", "admin", "x"]).exit_code == 1

    moved = runner.invoke(cli.app, ["set-ip", "10.129.231.99"])
    assert moved.exit_code == 0 and "10.129.231.15 -> 10.129.231.99" in moved.output
    assert runner.invoke(cli.app, ["set-ip", "8.8.8.8"]).exit_code == 1

    assert "Current box: ledger" in runner.invoke(cli.app, ["use", "ledger"]).output


def test_a_starting_job_is_not_reaped(settings: Settings) -> None:
    """Regression: a job created but not yet started had no pid, so another process opening
    the box (e.g. MCP job_status polling) marked it interrupted."""
    import os

    from cyberdeck.core.runner import pid_alive
    from cyberdeck.core.workspace import Workspace

    ws = Workspace.create(settings.root, "race", "10.129.1.9", settings.scope())
    with ws.store() as store:
        job = store.create_job("whatweb", ["whatweb", "x"], str(ws.path), "mcp", pid=os.getpid())
        assert store.reap_interrupted(pid_alive) == []
        current = store.get_job(job.id)
    assert current is not None and current.status.value == "queued"
