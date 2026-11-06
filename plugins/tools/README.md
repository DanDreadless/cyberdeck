# Tool profiles

One YAML file per tool, in a folder per category. Cyberdeck loads every `*.yaml` under this
folder (any depth); files and folders starting with `_` are skipped.

```
_template.yaml       copy this to add a tool (not loaded)
_drafts/             unfinished profiles (not loaded); see _drafts/README.md
recon/               whatweb, wafw00f, dig; dnsrecon, dnsenum, masscan (root), rustscan,
                     snmpwalk (intrusive)
web/                 feroxbuster, gobuster-dir, dirsearch, ffuf-dir (group dir-bruteforce),
                     ffuf-vhost (vhost-fuzz), nikto, wfuzz (intrusive), sqlmap (exploit), curl,
                     page-inspect (safe), http-probe (intrusive)
forensics/           binwalk, exiftool, file, foremost, steghide, strings, tcpdump
linux-privesc/       checksec, gdb (batch overview)
creds/               hashid, cewl; hashcat, john, hydra (bruteforce)
exploit-research/    searchsploit (offline lookup), msfvenom (exploit)
windows-ad/          smbclient, smbmap, enum4linux-ng (intrusive), netexec-smb (bruteforce),
                     impacket-GetNPUsers, impacket-GetUserSPNs (exploit)
rpc/                 impacket-rpcdump, rpcinfo (safe); rpcclient-enum, impacket-lookupsid
                     (intrusive)
services/            showmount (safe), mysql-query (intrusive, one query per run)
```
Interactive clients (ssh, ftp, nc, evil-winrm...) can't run inside Cyberdeck: jobs have no
terminal and stdin is closed. `_drafts/README.md` lists what was left out and why.

## Adding a tool
1. Copy `_template.yaml` to `<category>/<tool>.yaml` and fill it in (the comments explain each
   field). The category defaults to the folder name.
2. `cyberdeck tools check plugins/tools/<category>/<tool>.yaml` until it passes.
3. `cyberdeck tools` shows it (installed or not); `cyberdeck run <id>` opens it in the Run dialog.

Your own tools can also live in `~/.config/cyberdeck/plugins/tools/` (same layout); a file there
with the same `id` replaces the built-in one.

## Rules worth knowing
- **One profile per job, not per binary.** A tool with several modes gets one file per mode,
  named `<tool>-<mode>.yaml`: `ffuf-dir` (hidden paths) and `ffuf-vhost` (virtual hosts) both run
  `ffuf` but have their own inputs, parser, group and defaults. Detection is shared.
- **safety** decides what may run without asking: only `safe` tools are chained by
  `cyberdeck auto` or run directly by an MCP client. Use `intrusive`, `bruteforce` or `exploit`
  for anything noisy, credential-guessing or exploiting.
- **group** is only for interchangeable alternatives (`dir-bruteforce`: feroxbuster, gobuster,
  dirsearch, ffuf-dir); `cyberdeck run <group>` uses your preferred installed one. Leave it out
  otherwise. Tools in a group need a parser so suggestions get findings.
- Put each option in the command as one whole item `"{opt.<id>}"`; it renders its own flag.
- Inputs pre-fill from findings with `from:` (`web_url`, `web_url_ip`, `host`, `hostname`,
  `domain`, `target_ip`, `open_tcp_ports`); a `type: path` (or `file`) input is a local file,
  relative to the box folder.
- `notes:` is shown in the Run dialog (caveats such as "interactive: run it yourself").

Every field is explained in the comments of `_template.yaml`; the manifests in each
category folder are working examples.
