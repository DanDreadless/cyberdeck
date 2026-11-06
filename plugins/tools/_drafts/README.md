# Draft tool profiles (not loaded)

Everything in `_drafts/` is skipped by Cyberdeck (folders starting with `_` aren't loaded).

On 2026-11-04 the generated drafts were reviewed against the real tools on Kali. 18 were fixed
and moved into the category folders: cewl, hashcat, hydra, john, msfvenom, dnsenum, dnsrecon,
masscan, rustscan, snmpwalk, mysql-query (was `mysql`), sqlmap, wfuzz, enum4linux-ng,
impacket-GetNPUsers, impacket-GetUserSPNs, netexec-smb (was `netexec`) and smbclient.

## What's left, and why it isn't a profile
Cyberdeck runs a tool as a background job with **no terminal and stdin closed**. These don't
fit that model as they are:

| Profile | Why it stays here | Use instead |
|--|--|--|
| `services/ssh.yaml` | interactive shell | run `ssh` yourself; `hydra` for guessing |
| `services/ftp.yaml` | interactive client | nmap's `ftp-anon` script (service scan); `curl ftp://<ip>/ -u anonymous:` |
| `services/nc.yaml` | interactive / listener | run `nc` yourself (banner grabs are in the nmap service scan) |
| `services/socat.yaml` | interactive relay | run it yourself |
| `windows-ad/evil-winrm.yaml` | interactive shell | `netexec-smb` to check a login; `evil-winrm` yourself |
| `linux-privesc/linpeas.yaml` | runs **on the target**, not on Kali | serve it to the box (Phase 9 "serve tools" helper) |
| `linux-privesc/pspy.yaml` | runs on the target; not packaged on this Kali | same |
| `recon/arp-scan.yaml` | layer-2 LAN discovery: sees nothing over the HTB VPN | nmap |
| `recon/netdiscover.yaml` | layer-2 LAN discovery, needs root | nmap |

A one-shot, non-interactive mode of one of these can still become a profile (the way `mysql`
became `mysql-query`). Write it as `<tool>-<mode>.yaml` and then:

1. Use `../_template.yaml` (every field is explained in its comments) as the reference. Common problems:
   - an input that isn't used (`target` declared, but the command uses something else);
   - a flag written next to an option that already renders it (`-p`, `{opt.ports}`);
   - `{opt.x}` inside a longer argument (`user@{opt.host}`, `file,{opt.wordlist}`): only
     inputs and context variables can sit inside text; make it an input, or use
     `joined: true` for `--flag=value` options;
   - files the tool writes under `{out}` must be listed in `outputs:` (that creates the folder);
   - anything that prompts (passwords, "continue?") hangs or fails: pass it on the command line.
2. Keep (or tighten) its safety tag: credential guessing and cracking are `bruteforce`; shells,
   payloads, SQL injection and ticket attacks are `exploit`; service clients, SMB/LDAP
   enumeration and fast scanners are `intrusive`.
3. `cyberdeck tools check plugins/tools/_drafts/<file>` until it passes, move it into
   `plugins/tools/<category>/`, and run it once (`cyberdeck run <id>`).
