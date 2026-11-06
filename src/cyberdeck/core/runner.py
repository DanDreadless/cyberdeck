"""Job runner. Every target-facing command goes through :class:`Runner` (CLAUDE.md).

Each job: scope check, a row in the ``jobs`` table, the exact command plus stdout and stderr
written to ``raw/<id>-<tool>.{cmd,out,err}``, timeout and cancellation handling.

Small local helpers (sudo, ``ip``, ``pgrep``) that never touch the target also live here, so
all subprocess use is in one module.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from cyberdeck.core.events import JobFinished, JobStarted, bus
from cyberdeck.core.models import Job, JobStatus, utcnow
from cyberdeck.core.scope import Scope, check_argv_scope
from cyberdeck.core.workspace import Workspace

LineCallback = Callable[[str, str], None]  # (stream "out"|"err", line)
StartCallback = Callable[[Job], None]  # called once the job row exists and the job is running
Launcher = Callable[[list[str]], list[str]]  # rewrites argv before exec (tests use a fake nmap)

_STREAM_LIMIT = 1 << 20


def tool_env() -> dict[str, str]:
    """Environment for external tools: Cyberdeck's own virtualenv removed.

    Under ``uv run`` (or any venv) the venv's ``bin/`` is first on PATH, so Python-based Kali
    tools with ``#!/usr/bin/env python3`` (dirsearch, impacket, ...) would start with Cyberdeck's
    interpreter and miss their system packages.
    """
    env = dict(os.environ)
    if sys.prefix == sys.base_prefix:
        return env
    venv_bin = str(Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin"))
    parts = [p for p in env.get("PATH", "").split(os.pathsep) if p and p != venv_bin]
    env["PATH"] = os.pathsep.join(parts)
    env.pop("VIRTUAL_ENV", None)
    env.pop("PYTHONHOME", None)
    return env


@dataclass(frozen=True)
class JobRequest:
    tool: str
    argv: list[str]
    target_ip: str
    cwd: Path
    timeout: float | None = None
    origin: str = "cli"
    meta: dict[str, Any] = field(default_factory=dict)  # stored with the job (re-parse)


@dataclass(frozen=True)
class JobResult:
    job: Job
    cmd_path: Path
    out_path: Path
    err_path: Path

    @property
    def ok(self) -> bool:
        return self.job.status is JobStatus.DONE


def raw_paths(ws: Workspace, job_id: int, tool: str) -> tuple[Path, Path, Path]:
    base = ws.raw_dir / f"{job_id:04d}-{tool}"
    return (
        base.with_name(base.name + ".cmd"),
        base.with_name(base.name + ".out"),
        base.with_name(base.name + ".err"),
    )


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except TimeoutError:
        proc.kill()
        await proc.wait()


class Runner:
    def __init__(
        self,
        ws: Workspace,
        scope: Scope,
        *,
        max_concurrent: int = 2,
        launcher: Launcher | None = None,
    ) -> None:
        self.ws = ws
        self.scope = scope
        self._sem = asyncio.Semaphore(max_concurrent)
        self._launcher = launcher

    async def run(
        self,
        req: JobRequest,
        on_line: LineCallback | None = None,
        on_start: StartCallback | None = None,
    ) -> JobResult:
        if not req.argv:
            raise ValueError("empty command")
        self.scope.check(req.target_ip)
        check_argv_scope(req.argv, self.scope)
        async with self._sem:
            return await self._run(req, on_line, on_start)

    def _save(self, job: Job) -> Job:
        with self.ws.store() as store:
            store.save_job(job)
        return job

    async def _run(
        self, req: JobRequest, on_line: LineCallback | None, on_start: StartCallback | None
    ) -> JobResult:
        self.ws.raw_dir.mkdir(exist_ok=True)
        with self.ws.store() as store:
            job = store.create_job(
                req.tool, req.argv, str(req.cwd), req.origin, req.meta, pid=os.getpid()
            )
        cmd_path, out_path, err_path = raw_paths(self.ws, job.id, req.tool)
        started = utcnow()
        cmd_path.write_text(
            f"# job {job.id} | {req.tool} | origin={req.origin}\n"
            f"# cwd: {req.cwd}\n# started: {started.isoformat()}\n{shlex.join(req.argv)}\n",
            encoding="utf-8",
        )
        job = self._save(
            job.model_copy(update={"status": JobStatus.RUNNING, "started_at": started})
        )
        bus.emit(JobStarted(self.ws.path, job))
        if on_start is not None:
            on_start(job)
        argv = self._launcher(list(req.argv)) if self._launcher else list(req.argv)

        def finish(status: JobStatus, code: int | None, note: str | None) -> JobResult:
            done = job.model_copy(
                update={"status": status, "exit_code": code, "ended_at": utcnow(), "note": note}
            )
            saved = self._save(done)
            bus.emit(JobFinished(self.ws.path, saved))
            return JobResult(saved, cmd_path, out_path, err_path)

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=req.cwd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=_STREAM_LIMIT,
                env=tool_env(),
            )
        except OSError as exc:
            note = f"could not start {argv[0]}: {exc}"
            out_path.write_text("", encoding="utf-8")
            err_path.write_text(note + "\n", encoding="utf-8")
            return finish(JobStatus.FAILED, None, note)

        job = self._save(job.model_copy(update={"pid": os.getpid()}))  # who owns this job
        with (
            out_path.open("w", encoding="utf-8") as out_fh,
            err_path.open("w", encoding="utf-8") as err_fh,
        ):

            async def pump(stream: asyncio.StreamReader | None, fh: TextIO, name: str) -> None:
                if stream is None:
                    return
                while True:
                    raw = await stream.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="replace")
                    fh.write(line)
                    fh.flush()
                    if on_line is not None:
                        on_line(name, line.rstrip("\r\n"))

            work = asyncio.gather(
                pump(proc.stdout, out_fh, "out"), pump(proc.stderr, err_fh, "err"), proc.wait()
            )
            try:
                await asyncio.wait_for(work, timeout=req.timeout)
            except TimeoutError:
                await _terminate(proc)
                return finish(JobStatus.TIMEOUT, proc.returncode, f"timed out after {req.timeout}s")
            except asyncio.CancelledError:
                await _terminate(proc)
                finish(JobStatus.CANCELLED, proc.returncode, "cancelled")
                raise
        code = proc.returncode
        return finish(JobStatus.DONE if code == 0 else JobStatus.FAILED, code, None)


# --- local helpers (never target-facing) ----------------------------------------------------


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid is not None and geteuid() == 0)


def which(name: str) -> str | None:
    """Locate a tool the way it will be run (on the cleaned PATH, see :func:`tool_env`)."""
    return shutil.which(name, path=tool_env().get("PATH"))


def have_binary(name: str) -> bool:
    return which(name) is not None


def sudo_cached() -> bool:
    """True if sudo works right now without a password prompt."""
    if not have_binary("sudo"):
        return False
    result = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False, timeout=10)
    return result.returncode == 0


def sudo_validate() -> bool:
    """Ask the user for their sudo password on the real terminal (``sudo -v``).

    Cyberdeck never sees, stores or pipes the password.
    """
    if not have_binary("sudo"):
        return False
    return subprocess.run(["sudo", "-v"], check=False).returncode == 0


def fix_ownership(paths: Sequence[Path]) -> None:
    """Give files written by a ``sudo`` job back to the invoking user."""
    existing = [str(p) for p in paths if p.exists()]
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if not existing or getuid is None or getgid is None:
        return
    owner = f"{getuid()}:{getgid()}"
    subprocess.run(["sudo", "-n", "chown", owner, *existing], check=False, timeout=30)


def run_local(
    argv: Sequence[str], timeout: float = 10, *, merge_stderr: bool = False
) -> tuple[int, str]:
    """Run a quick local, non-target command (version probe, ``--help``, ``ip route``) and
    return (exit code, stdout). ``merge_stderr`` appends stderr, for tools that print help there.
    """
    try:
        result = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=tool_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    output = result.stdout + (result.stderr if merge_stderr else "")
    return result.returncode, output


def pid_alive(pid: int) -> bool:
    """POSIX liveness check. On Windows, os.kill would *terminate* the process, so assume alive."""
    if os.name != "posix":
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def needs_privilege(path: Path) -> bool:
    """True if writing ``path`` needs sudo (e.g. the real /etc/hosts)."""
    if path.exists():
        return not os.access(path, os.W_OK)
    return not os.access(path.parent, os.W_OK)


def write_file_privileged(path: Path, content: str) -> tuple[bool, str]:
    """Overwrite a local system file in place (only the hosts file, via ``util/hosts.py``).

    Writes directly when the file is writable (tests, ``CYBERDECK_HOSTS_FILE``), otherwise pipes
    the content to ``sudo -n tee``; call :func:`sudo_validate` first so sudo asks for the
    password on the terminal. Returns (ok, message).
    """
    if not needs_privilege(path):
        try:
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            return False, str(exc)
        return True, f"wrote {path}"
    if not have_binary("sudo"):
        return False, f"{path} is not writable and sudo is not available"
    try:
        result = subprocess.run(
            ["sudo", "-n", "tee", str(path)],
            input=content,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if result.returncode != 0:
        return False, result.stderr.strip() or f"sudo tee exited {result.returncode}"
    return True, f"wrote {path} (sudo)"
