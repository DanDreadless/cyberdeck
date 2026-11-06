from __future__ import annotations

import asyncio
import sys

import pytest

from cyberdeck.core.config import Settings
from cyberdeck.core.models import JobStatus
from cyberdeck.core.runner import CancelError, JobRequest, Runner, cancel_job
from cyberdeck.core.scope import Scope, ScopeError, check_argv_scope

from .conftest import make_ws

IP = "10.129.231.15"


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


async def test_success_records_everything(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    lines: list[tuple[str, str]] = []
    runner = Runner(ws, settings.scope())
    argv = _py(f"import sys; print('hello {IP}'); print('oops', file=sys.stderr)")
    result = await runner.run(
        JobRequest("echo", argv, IP, ws.path), on_line=lambda s, ln: lines.append((s, ln))
    )
    assert result.ok and result.job.exit_code == 0 and result.job.duration is not None
    assert ("out", f"hello {IP}") in lines and ("err", "oops") in lines
    assert result.out_path.read_text().strip() == f"hello {IP}"
    assert result.cmd_path.name == "0001-echo.cmd" and IP in result.cmd_path.read_text()
    with ws.store() as store:
        (job,) = store.jobs()
    assert job.status is JobStatus.DONE and job.argv == argv


async def test_failure_timeout_missing_binary(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    runner = Runner(ws, settings.scope())
    failed = await runner.run(JobRequest("bad", _py("raise SystemExit(3)"), IP, ws.path))
    assert failed.job.status is JobStatus.FAILED and failed.job.exit_code == 3

    slow = await runner.run(
        JobRequest("slow", _py("import time; time.sleep(30)"), IP, ws.path, timeout=0.5)
    )
    assert slow.job.status is JobStatus.TIMEOUT and "timed out" in (slow.job.note or "")

    missing = await runner.run(JobRequest("ghost", ["definitely-not-a-tool-xyz"], IP, ws.path))
    assert missing.job.status is JobStatus.FAILED and "could not start" in (missing.job.note or "")


async def test_cancel_marks_job(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    runner = Runner(ws, settings.scope())
    task = asyncio.create_task(
        runner.run(JobRequest("slow", _py("import time; time.sleep(30)"), IP, ws.path))
    )
    await asyncio.sleep(0.5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with ws.store() as store:
        (job,) = store.jobs()
    assert job.status is JobStatus.CANCELLED


async def test_scope_refusal_before_anything_runs(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    runner = Runner(ws, settings.scope())
    with pytest.raises(ScopeError):
        await runner.run(JobRequest("x", ["nmap", "8.8.8.8"], IP, ws.path))
    with pytest.raises(ScopeError):
        await runner.run(JobRequest("x", ["nmap", IP], "8.8.8.8", ws.path))
    with ws.store() as store:
        assert store.jobs() == []


def test_check_argv_scope() -> None:
    scope = Scope.from_cidrs(["10.129.0.0/16"])
    check_argv_scope(["nmap", "-p-", "--min-rate", "5000", "-T4", "nmap/box", "10.129.1.2"], scope)
    check_argv_scope(["ffuf", "-u", "http://10.129.1.2/FUZZ", "10.129.0.0/24"], scope)
    for bad in (["http://8.8.8.8/"], ["--target=1.1.1.1"], ["10.0.0.0/8"], ["::1"]):
        with pytest.raises(ScopeError):
            check_argv_scope(bad, scope)


async def test_cancel_job_kills_a_running_job(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    runner = Runner(ws, settings.scope())
    task = asyncio.create_task(
        runner.run(
            JobRequest(
                "slow",
                _py("print('started', flush=True); import time; time.sleep(30)"),
                IP,
                ws.path,
            )
        )
    )
    for _ in range(50):
        await asyncio.sleep(0.1)
        with ws.store() as store:
            jobs = store.jobs()
        if jobs and jobs[0].meta.get("child_pid"):
            break
    job_id = jobs[0].id
    await asyncio.to_thread(cancel_job, ws, job_id, grace=2.0)
    result = await asyncio.wait_for(task, timeout=10)
    assert result.job.status is JobStatus.CANCELLED and result.job.note == "killed"
    with pytest.raises(CancelError, match="not running"):
        cancel_job(ws, job_id)
    with pytest.raises(CancelError, match="no job"):
        cancel_job(ws, 999)
