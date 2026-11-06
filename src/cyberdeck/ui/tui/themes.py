"""Cyberdeck's own Textual themes: neon cyberpunk palettes on near-black backgrounds.

Registered by the app at start, so they show in Settings and the command palette ("Change
theme") next to Textual's built-in ones. ``cyberdeck-neon`` is the default for new installs
(``UserConfig.theme``). Semantic colours (success / warning / error) stay green / yellow / red
in every theme so safety tags and job states keep their meaning; tests check contrast.
"""

from __future__ import annotations

from collections.abc import Iterable

from textual.theme import Theme


def _theme(
    name: str,
    *,
    primary: str,
    secondary: str,
    accent: str,
    foreground: str,
    background: str,
    surface: str,
    panel: str,
    success: str,
    warning: str,
    error: str,
) -> Theme:
    return Theme(
        name=name,
        primary=primary,
        secondary=secondary,
        accent=accent,
        foreground=foreground,
        background=background,
        surface=surface,
        panel=panel,
        success=success,
        warning=warning,
        error=error,
        dark=True,
        variables={
            "footer-key-foreground": accent,
            "input-selection-background": f"{secondary} 35%",
            "block-cursor-text-style": "bold",
            "border": primary,
            "scrollbar": panel,
            "scrollbar-hover": secondary,
            "scrollbar-active": primary,
        },
    )


CYBERDECK_THEMES: list[Theme] = [
    # Hot magenta and cyan on deep indigo: the classic neon-city look.
    _theme(
        "cyberdeck-neon",
        primary="#ff2a6d",
        secondary="#05d9e8",
        accent="#05d9e8",
        foreground="#e0f7ff",
        background="#0b0418",
        surface="#140a26",
        panel="#22103d",
        success="#00ff9f",
        warning="#f9f002",
        error="#ff3860",
    ),
    # Hazard yellow with cyan and red on black: warning-tape industrial.
    _theme(
        "cyberdeck-hazard",
        primary="#fcee0a",
        secondary="#ff4f7b",
        accent="#00f0ff",
        foreground="#f2f2f2",
        background="#0a0a0c",
        surface="#15141a",
        panel="#24222b",
        success="#39ff14",
        warning="#ff9e00",
        error="#ff003c",
    ),
    # Synthwave: pink, orange and violet on a dark purple sky.
    _theme(
        "cyberdeck-synthwave",
        primary="#ff007c",
        secondary="#ff9f1c",
        accent="#b967ff",
        foreground="#f7f7ff",
        background="#0f0221",
        surface="#1b0638",
        panel="#2b0c52",
        success="#72f1b8",
        warning="#fede5d",
        error="#fe4450",
    ),
    # Ice: cold cyan and violet on navy, a netrunner's console.
    _theme(
        "cyberdeck-ice",
        primary="#00e5ff",
        secondary="#9d8cff",
        accent="#9d8cff",
        foreground="#d6f4ff",
        background="#020812",
        surface="#071425",
        panel="#0d2036",
        success="#00ffa3",
        warning="#ffcc00",
        error="#ff2e63",
    ),
    # Phosphor: green CRT with a cyan highlight.
    _theme(
        "cyberdeck-phosphor",
        primary="#33ff66",
        secondary="#2ed9ff",
        accent="#2ed9ff",
        foreground="#b8ffc8",
        background="#050805",
        surface="#0b120b",
        panel="#112011",
        success="#33ff66",
        warning="#ffd23f",
        error="#ff4d4d",
    ),
]

DEFAULT_THEME = "cyberdeck-neon"


def theme_choices(available: Iterable[str]) -> list[str]:
    """Every theme name to offer: Cyberdeck's first (in order), then the rest A-Z."""
    names = set(available)
    ours = [t.name for t in CYBERDECK_THEMES if t.name in names]
    return ours + sorted(names - set(ours))
