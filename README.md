<div align="center">

```
  _____      _                  _           _
 / ____|    | |                | |         | |
| |    _   _| |__   ___ _ __ __| | ___  ___| | __
| |   | | | | '_ \ / _ \ '__/ _` |/ _ \/ __| |/ /
| |___| |_| | |_) |  __/ | | (_| |  __/ (__|   <
 \_____\__, |_.__/ \___|_|  \__,_|\___|\___|_|\_\
        __/ |
       |___/
```

**A recon handler for Hack The Box, run from Kali Linux.**

Point it at a box. It scans, runs the right Kali tools, keeps track of everything it finds,
and tells you what to try next and *why*.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Platform: Kali Linux](https://img.shields.io/badge/platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)
![TUI: Textual](https://img.shields.io/badge/TUI-Textual-ff2a6d)
![MCP server](https://img.shields.io/badge/MCP-Claude%20Code-05d9e8)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

![The Cyberdeck dashboard](assets/screenshots/dashboard.png)

</div>

> [!NOTE]
> Cyberdeck is in early, active development. It works end to end on real boxes, but expect
> rough edges and changes between versions.

## Why Cyberdeck?

Most of a box is enumeration: run nmap, read the output, decide which tool to run next, remember
the flags, copy the vhost into `/etc/hosts`, try the creds you found somewhere else... Cyberdeck
does the bookkeeping and the "what next?" so you can focus on the box.

- **It orchestrates, it doesn't reinvent.** Cyberdeck drives the tools you already have
  (nmap, feroxbuster, ffuf, netexec, smbmap, hashcat, searchsploit and 40 more) and parses
  their output.
- **You always see the command.** Every job opens a Run dialog with presets, explained flags
  and a live preview of the exact command line before anything touches the target.
- **It explains itself.** Every suggestion comes with a short *why* and a link to learn more,
  which makes it useful for beginners and quick for everyone else.
- **Everything is kept.** Raw output, exact commands and findings live in the box's folder, so
  you can close it and pick up later, or re-parse old output.

## Features

| | |
|---|---|
| 🛰️ **Guided recon** | New-box wizard, HTB VPN check, two-stage nmap (all ports, then scripts and versions on the open ones), automatic import. |
| 🧩 **Tool plugins** | 45+ Kali tools described in YAML: web, SMB/AD, RPC, creds, forensics, exploit research. Add your own without writing Python. |
| 🧠 **Next-step suggestions** | Rules turn findings into ranked next steps with a *why*. They cover fingerprinting a site, adding vhosts to `/etc/hosts` (diff shown first), fuzzing, SMB/AD enumeration and exploit lookups. |
| 🗃️ **Per-box findings store** | Services, versions, hostnames, URLs, users, credentials, hashes and flags, each with where it came from. Secrets are masked in the UI. |
| 🖥️ **TUI and browser UI** | A keyboard-driven Textual dashboard. `cyberdeck --web` serves the same UI in your browser. |
| 🎓 **Learning aids** | Beginner layout with a journey bar, plain-English job summaries, a glossary, per-service checklists, a graded "I'm stuck" flow and a rabbit-hole timer. |
| 📓 **Journal and write-ups** | The box's story builds itself from what you did. Draft a write-up (loot and your paths masked), then read and edit it in the app. |
| 🤖 **Claude Code over MCP** | `cyberdeck mcp` lets Claude Code read findings, preview commands and run safe tools. Anything riskier waits for your approval. |
| 🌆 **Cyberpunk themes** | Five neon palettes plus every Textual theme. `ctrl+t` switches theme from any screen, with live preview. |

<div align="center">

![The theme picker](assets/screenshots/themes.png)

</div>

## Requirements

- **Kali Linux** (or another Linux with the tools you want installed)
- **Python 3.11+** and [uv](https://docs.astral.sh/uv/)
- **nmap**, plus whichever Kali tools you want Cyberdeck to drive. It detects what's installed
  and only offers those. `cyberdeck doctor` tells you what's missing and how to fix it.
- A Hack The Box VPN connection (`.ovpn`) for HTB targets

## Install

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh        # install uv (once)
git clone https://github.com/DanDreadless/cyberdeck.git
cd cyberdeck
mkdir -p ~/.config/cyberdeck && cp .env.example ~/.config/cyberdeck/.env   # your settings
uv tool install -e .              # puts `cyberdeck` on your PATH
uv tool install -e ".[web]"       # ...or with the browser UI
```

## Quick start

```bash
cyberdeck doctor                  # check VPN, tools, wordlists, sudo and clock; shows fixes
cyberdeck                         # open the TUI
```

In the TUI, press `n` for a new box and give it a name and IP. Cyberdeck checks that the box is
routed through your VPN, then runs the nmap stages (you approve each one in the Run dialog).
On the dashboard:

| Key | Does |
|---|---|
| `a` / `enter` | Do the top suggested next step |
| `r` | Run any tool |
| `c` | Scan (nmap stages, UDP) |
| `h` | Add the box's hostnames to `/etc/hosts` (diff, confirm, sudo) |
| `l` / `n` / `W` | Loot, notes, write-up |
| `k` / `!` | Methodology checklist / "I'm stuck" |
| `f` | Record a flag |
| `ctrl+t` | Change theme |
| `?` / `ctrl+p` | Every key on this screen / search all actions |

Prefer the command line? Everything works there too:

```bash
cyberdeck new soccer --ip 10.129.x.x    # create the box, check the VPN, scan
cyberdeck suggest                       # next steps, with why
cyberdeck suggest run 1                 # run one (through the Run dialog)
cyberdeck show                          # services, versions, hostnames
```

<details>
<summary><b>Full command reference</b></summary>

```bash
# Boxes
cyberdeck new                               # wizard: name, IP, folder -> VPN check -> both nmap stages
cyberdeck new soccer --ip 10.129.x.x --yes  # same, no questions, default options
cyberdeck new soccer --ip 10.129.x.x --no-scan   # just create (or adopt an existing folder)
cyberdeck list                              # boxes, last opened first, with progress
cyberdeck resume soccer                     # make it current, show progress, offer the next step
cyberdeck status                            # what's done / interrupted / next for the current box
cyberdeck use soccer                        # set the current box (used outside box folders)
cyberdeck set-ip 10.129.x.y                 # HTB re-spawned the box; offers to move its hosts line
cyberdeck vpn                               # tunnel, LHOST, and whether the box is routed via it

# Scanning and tools
cyberdeck scan                              # both nmap stages via the Run dialog
cyberdeck scan -s 1 -p reliable             # stage 1 only, gentler preset for flaky VPNs
cyberdeck scan -s udp --sudo                # UDP top ports (needs root)
cyberdeck scan --yes -- --max-rtt-timeout 500ms   # no dialog; extra args after --
cyberdeck import [path]                     # import nmap results you ran yourself
cyberdeck run list                          # tools Cyberdeck can run, with group and safety tag
cyberdeck run whatweb                       # one tool through the Run dialog (URL filled in)
cyberdeck run dir-bruteforce -p quick       # your preferred of feroxbuster/gobuster/dirsearch
cyberdeck run feroxbuster --opt depth=3 -- --dont-filter
cyberdeck reparse 5                         # parse job 5's saved output again
cyberdeck jobs                              # every command run against the box
cyberdeck job 2 [--err] [--tail 0]          # one job's exact command and output

# Suggestions
cyberdeck suggest                           # next steps, highest priority first, with why
cyberdeck suggest run 3                     # open #3 in the Run dialog, or answer its question
cyberdeck suggest skip 3 / snooze 3 / reopen 3
cyberdeck auto                              # work through the safe suggestions
cyberdeck auto --dont-ask --rounds 2        # no dialog for safe tools (commands still printed)

# /etc/hosts
cyberdeck hosts                             # this box's hosts line(s) and unmapped names
cyberdeck hosts add [name]                  # add the box's hostnames: diff, confirm, sudo
cyberdeck hosts remove [--all]              # take Cyberdeck's lines out again

# Findings and loot
cyberdeck show                              # services, versions, hostnames, OS
cyberdeck flag user <flag>                  # record flags (progress tracks them)

# Learning
cyberdeck doctor [--create-folder]          # setup check with fixes
cyberdeck glossary [term]                   # plain-word meaning of vhost, LHOST, SUID...
cyberdeck checklist [--all]                 # what to check on this box, per service and phase
cyberdeck checklist done web.robots         # tick an item (na = doesn't apply, reset = open again)
cyberdeck stuck [--hint]                    # what you haven't tried yet; --hint adds general hints
cyberdeck lead start "the /upload page"     # rabbit-hole timer; park / done / resume
cyberdeck journal                           # the box's story
cyberdeck lesson [--kind user|root|note]    # what you learned
cyberdeck writeup [-o file] [--stdout] [--reveal] [--force]   # Markdown write-up, loot masked
cyberdeck playbook [search]                 # your lessons from every box
cyberdeck path / cyberdeck skills           # suggested boxes in order, techniques practised

# Tools
cyberdeck tools                             # installed tools, versions, group picks, problems
cyberdeck tools detect                      # re-check after installing something
cyberdeck tools prefer gobuster-dir         # use gobuster for dir-bruteforce
cyberdeck tools disable nikto               # keep a tool out of groups and suggestions
cyberdeck tools help ffuf-vhost             # the tool's own --help
cyberdeck tools wordlists                   # named wordlists and whether they exist
cyberdeck tools check plugins/tools/web/x.yaml   # validate a tool profile you're writing

# UI and MCP
cyberdeck tui -t soccer                     # straight to a box's dashboard
cyberdeck --web                             # the UI in your browser on 127.0.0.1:8000
cyberdeck mcp -t soccer                     # MCP server for Claude Code (stdio; --http for HTTP)
cyberdeck approvals [--all]                 # MCP requests waiting for you; approve <#> / deny <#>
```

Which box a command acts on: `-t <box>`, else the box folder you're in, else the current box
(`cyberdeck use`).

</details>

## How it works

1. **A folder per box.** `cyberdeck new` creates `<workspace>/<box>/` with `nmap/`, `raw/`,
   `loot/`, `notes.md`, `target.db` and `target.yaml`. Everything about the box lives there.
   There's no global database, so boxes are independent and easy to back up or delete.
2. **Scan.** Stage 1 finds all open TCP ports fast. Stage 2 runs `-sC -sV` on exactly those
   ports. Results are imported automatically.
3. **Run tools.** Each tool is a YAML manifest. Its inputs (URL, domain, wordlist) are filled in
   from what's been found, and its output is parsed into findings: URLs, versions, hostnames,
   users, credentials.
4. **Suggest.** After every step, rules look at what's known and rank the next moves. Safe
   recon can be chained automatically. Anything tagged intrusive, brute-force or exploit always
   waits for you.
5. **Learn.** Job summaries, the checklist, the "I'm stuck" hints and the questions asked when
   you capture a flag all feed a journal per box and a playbook across boxes.

## Claude Code (MCP)

```bash
claude mcp add cyberdeck -- cyberdeck mcp -t soccer
```

Claude Code can then read the box's findings and suggestions, preview commands and run **safe**
tools. You see the exact command first. Intrusive tools, anything needing sudo and every
`/etc/hosts` edit wait in an approvals queue (`p` in the TUI, or `cyberdeck approvals`), and
there's no setting to skip that. Passwords, hashes and flags are masked before they reach the
model. For a remote client, `cyberdeck mcp --http 127.0.0.1:8765` serves over HTTP with a bearer
token (`CYBERDECK_MCP_TOKEN` in `.env`); reach it through an SSH tunnel.

## Adding a tool

Copy [`plugins/tools/_template.yaml`](plugins/tools/_template.yaml) into a category folder (or
`~/.config/cyberdeck/plugins/tools/`), fill it in, and validate it:

```bash
cyberdeck tools check ~/.config/cyberdeck/plugins/tools/web/mytool.yaml
```

The template's comments explain each field. [`plugins/tools/README.md`](plugins/tools/README.md)
covers the conventions, and the existing manifests are working examples. Suggestion rules
(`rules/`) and learning content (`learn/`) can be overridden the same way, from
`~/.config/cyberdeck/`.

## Configuration

Settings live in `~/.config/cyberdeck/.env` (or `./.env`, both gitignored). `.env.example` lists
every variable with a comment. The main ones:

| Variable | What |
|---|---|
| `CYBERDECK_WORKSPACE_ROOT` | Where box folders go (default `~/Documents/htb`) |
| `CYBERDECK_VPN_DIR` / `CYBERDECK_VPN_CONFIG` | The folder with your HTB `.ovpn` files / one specific file |
| `CYBERDECK_SCOPE_EXTRA` | Extra targets to allow, beyond the HTB ranges |
| `CYBERDECK_MCP_TOKEN` | Bearer token for `cyberdeck mcp --http` |

Preferences (layout, theme, learning aids, tool choices) are set in the TUI's Settings screen
(`,`) and saved to `~/.config/cyberdeck/config.yaml`.

## Safety

> [!WARNING]
> Only use Cyberdeck against systems you are authorised to test, such as Hack The Box labs.

- A **scope guard** checks every job's target. Only the HTB lab ranges (`10.10.0.0/16`,
  `10.129.0.0/16`) are allowed by default. Anything else must be added explicitly with
  `CYBERDECK_SCOPE_EXTRA`.
- Nothing intrusive, brute-force or exploit-tagged ever runs without your explicit
  confirmation, including when Claude Code is driving.
- `/etc/hosts` changes are shown as a diff, need your sudo password, and are tagged so
  `cyberdeck hosts remove` can cleanly undo them.
- Loot (credentials, hashes, flags) stays in the box folder, is masked in the UI and in
  write-ups, and is never written to global logs.

## Development

```bash
uv sync                                      # .venv + dev dependencies from uv.lock
uv run pytest                                # tests (no Kali tools, network or VPN needed)
uv run ruff check . && uv run ruff format .  # lint + format
uv run mypy src                              # strict type checks
```

Tests use fixtures, a fake nmap and a fake tool, so they never touch the network. A hygiene test
fails if your login name or home path ends up in a committed file.

## License

[MIT](LICENSE)
