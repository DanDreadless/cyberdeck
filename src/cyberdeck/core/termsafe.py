"""Make tool output safe to show inside the TUI or a terminal.

Tools write whatever they like to stdout: colours, progress bars redrawn with ``\r``, and
sometimes full terminal control. sqlmap, for one, falls back to curses when it can't read the
terminal size, and curses writes "switch to the alternate screen", "set the scroll region" and
cursor moves into the pipe. Passed through to the TUI, those codes reach the real terminal and
wreck the layout until the terminal is closed. Only colour (SGR) codes are kept.
"""

from __future__ import annotations

import re

# One alternation, tried left to right: CSI, OSC, DCS/SOS/PM/APC strings, two-byte escapes,
# a lone ESC, then C0 controls other than tab (newline and \r are handled before this).
_CONTROL = re.compile(
    r"(?P<csi>\x1b\[[0-?]*[ -/]*[@-~])"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b[PX^_][^\x1b]*(?:\x1b\\)?"
    r"|\x1b[ -/]*[0-~]"
    r"|\x1b"
    r"|[\x00-\x08\x0b-\x1f\x7f\x9b]"
)


def _keep_colour(match: re.Match[str]) -> str:
    csi = match.group("csi")
    return csi if csi is not None and csi.endswith("m") else ""


def terminal_safe(line: str, *, colour: bool = True) -> str:
    """One line of tool output with every terminal-control code removed.

    Text after the last ``\r`` wins (a progress bar redrawn in place shows its final state).
    With ``colour=False`` the SGR colour codes go too.
    """
    line = line.rstrip("\r\n")
    if "\r" in line:
        parts = [p for p in line.split("\r") if p]
        line = parts[-1] if parts else ""
    if colour:
        return _CONTROL.sub(_keep_colour, line)
    return _CONTROL.sub("", line)


def terminal_safe_text(text: str, *, colour: bool = True) -> str:
    """:func:`terminal_safe` applied to every line of ``text``."""
    return "\n".join(terminal_safe(line, colour=colour) for line in text.split("\n"))
