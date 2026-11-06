"""Wordlist resolver: named lists (``{wordlists.dirs_medium}``) to files on disk.

Defaults point at SecLists (``apt install seclists``) with Kali's own lists as fallbacks. Users
override any name in ``config.yaml`` under ``wordlists:``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SECLISTS = Path("/usr/share/seclists")
KALI_LISTS = Path("/usr/share/wordlists")
INSTALL_HINT = "sudo apt install seclists"

# name -> (what it is for, candidates in order of preference)
DEFAULTS: dict[str, tuple[str, tuple[Path, ...]]] = {
    "dirs_small": (
        "Directory names, quick",
        (
            SECLISTS / "Discovery/Web-Content/common.txt",
            KALI_LISTS / "dirb/common.txt",
        ),
    ),
    "dirs_medium": (
        "Directory names, thorough",
        (
            SECLISTS / "Discovery/Web-Content/raft-medium-directories.txt",
            KALI_LISTS / "dirbuster/directory-list-2.3-medium.txt",
            KALI_LISTS / "dirb/big.txt",
        ),
    ),
    "files_medium": (
        "File names (with extensions)",
        (SECLISTS / "Discovery/Web-Content/raft-medium-files.txt",),
    ),
    "vhosts": (
        "Subdomain / virtual host names",
        (
            SECLISTS / "Discovery/DNS/subdomains-top1million-5000.txt",
            KALI_LISTS / "amass/subdomains-top1mil-5000.txt",
        ),
    ),
    "vhosts_large": (
        "Subdomain / virtual host names, thorough",
        (SECLISTS / "Discovery/DNS/subdomains-top1million-20000.txt",),
    ),
    "users": (
        "Usernames",
        (
            SECLISTS / "Usernames/xato-net-10-million-usernames.txt",
            SECLISTS / "Usernames/Names/names.txt",
        ),
    ),
    "passwords": (
        "Passwords (rockyou)",
        (KALI_LISTS / "rockyou.txt", SECLISTS / "Passwords/Leaked-Databases/rockyou.txt"),
    ),
}


@dataclass(frozen=True)
class Wordlist:
    name: str
    purpose: str
    path: Path  # the file to use (the preferred candidate when none exists)
    exists: bool
    overridden: bool


def resolve(name: str, overrides: dict[str, str] | None = None) -> Wordlist | None:
    """The file for a named list, or None for an unknown name."""
    override = (overrides or {}).get(name)
    purpose, candidates = DEFAULTS.get(name, ("Custom list", ()))
    if override:
        path = Path(override).expanduser()
        return Wordlist(name, purpose, path, path.is_file(), True)
    if not candidates:
        return None
    for path in candidates:
        if path.is_file():
            return Wordlist(name, purpose, path, True, False)
    return Wordlist(name, purpose, candidates[0], False, False)


def all_wordlists(overrides: dict[str, str] | None = None) -> list[Wordlist]:
    names = list(DEFAULTS) + [n for n in (overrides or {}) if n not in DEFAULTS]
    found = (resolve(n, overrides) for n in names)
    return [w for w in found if w is not None]


def context(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """``wordlists.<name>`` template variables."""
    return {f"wordlists.{w.name}": str(w.path) for w in all_wordlists(overrides)}
