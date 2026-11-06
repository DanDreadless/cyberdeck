"""Tool output must never carry terminal control into the TUI (sqlmap/curses broke the screen)."""

from __future__ import annotations

import sys

from cyberdeck.core.config import Settings
from cyberdeck.core.runner import JobRequest, Runner, tool_env
from cyberdeck.core.termsafe import terminal_safe, terminal_safe_text

from .conftest import make_ws

IP = "10.129.231.15"

# What sqlmap's curses fallback wrote into its stdout pipe (captured on Kali).
CURSES = (
    "\x1b[?1049h\x1b[22;0;0t\x1b[1;24r\x1b(B\x1b[m\x1b[4l\x1b[?7h\x1b[24;1H"
    "\x1b[?1049l\x1b[23;0;0t\r\x1b[?1l\x1b>        ___"
)


def test_screen_control_is_removed() -> None:
    cleaned = terminal_safe(CURSES)
    assert cleaned == "        ___"


def test_colour_kept_unless_asked() -> None:
    line = "[\x1b[32mINFO\x1b[0m] testing"
    assert terminal_safe(line) == line
    assert terminal_safe(line, colour=False) == "[INFO] testing"


def test_other_escapes_and_controls() -> None:
    assert terminal_safe("a\x1b]0;title\x07b") == "ab"  # window title (OSC)
    assert terminal_safe("a\x1bPdata\x1b\\b") == "ab"  # DCS string
    assert terminal_safe("a\x07\x08\x0cb\tc") == "ab\tc"  # bell, backspace, form feed; tab stays
    assert terminal_safe("trailing esc\x1b") == "trailing esc"
    assert terminal_safe("progress 10%\rprogress 100%\r\n") == "progress 100%"
    assert terminal_safe_text("one\x1b[2J\ntwo\x1b[H") == "one\ntwo"


def test_tool_env_has_a_terminal_size() -> None:
    env = tool_env()
    assert env["COLUMNS"].isdigit() and env["LINES"].isdigit()


async def test_runner_cleans_live_lines_but_keeps_raw_file(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    lines: list[tuple[str, str]] = []
    code = f"import sys; sys.stdout.write({CURSES!r} + chr(10)); print(chr(27) + '[2Jdone')"
    result = await Runner(ws, settings.scope()).run(
        JobRequest("echo", [sys.executable, "-c", code], IP, ws.path),
        on_line=lambda s, ln: lines.append((s, ln)),
    )
    assert result.ok, result.err_path.read_text()
    assert ("out", "done") in lines
    assert ("out", "        ___") in lines
    assert "\x1b[?1049h" in result.out_path.read_text()  # the raw record is untouched
