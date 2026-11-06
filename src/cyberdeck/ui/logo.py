# ruff: noqa: E501
"""The Cyberdeck logo as Unicode quadrant blocks in Textual markup ("Cyber" in
$foreground, "deck" in $accent). Generated from assets/cyberdeck.png by
scripts/render_logo.py: edit the PNG and re-run it, don't edit this file."""

LOGO = "\n".join(
    (
        "[$foreground]▗▟███████▌        ▐█▌                          [/][$accent]▐█                █▌     [/]",
        "[$foreground]██        ██    █▌▐█▛▀▀▀▜█▖▄█▀▀▀▀█▌▗█▛▀▀▀[/][$accent]▟█▀▀▀▀▜█ ▟▛▀▀▀▜█ ▟█▀▀▀▀▘█▌▗▟█▀ [/]",
        "[$foreground]██        ██    █▌▐█▌   ▐█▌██▀▀▀▀▀▘▐█▌   [/][$accent]██    ▐█ █▛▀▀▀▀▀ █▌     ████▖  [/]",
        "[$foreground]▝▜███████▌▝▜█████▌▐██████▀ ▝▜█████▌▐█▘   [/][$accent]▝▜██████ ▀██████ ▀▜████▘█▌ ▝▜█▖[/]",
        "          [$foreground]▗▄▄▄▄▟▛▘                                                      [/]",
    )
)
LOGO_WIDTH = 72
LOGO_HEIGHT = 5
