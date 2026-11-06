#!/usr/bin/env bash
# Pull the project from the Kali VM (where it is developed) into this machine's copy, so you can
# commit and push from here. Run from Git Bash on the Windows host, inside this repo:
#
#   bash scripts/sync-from-kali.sh            # copy everything over, list files that exist only here
#   bash scripts/sync-from-kali.sh --delete   # ...and delete those (they were removed on Kali)
#
# Env: KALI_HOST (default: kali-vm ssh alias), KALI_PATH (default: Code/cyberdeck under the VM home).
# Never touches .git, .env or .venv on this side. Kali is the source of truth: don't edit here.
set -euo pipefail
host="${KALI_HOST:-kali-vm}"
remote="${KALI_PATH:-Code/cyberdeck}"
delete=0
[[ "${1:-}" == "--delete" ]] && delete=1
cd "$(dirname "$0")/.."

skip_names=(.git .env .venv __pycache__ .pytest_cache .mypy_cache .ruff_cache)
tar_excludes=()
for name in "${skip_names[@]}"; do tar_excludes+=("--exclude=$name"); done
list_files='find . \( -name .git -o -name .venv -o -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .ruff_cache \) -prune -o -type f ! -name .env -print'

ssh -o BatchMode=yes "$host" "cd $remote && tar ${tar_excludes[*]} -czf - ." | tar -xzf -

remote_list="$(ssh -o BatchMode=yes "$host" "cd $remote && $list_files" | LC_ALL=C sort)"
local_list="$(eval "$list_files" | LC_ALL=C sort)"
extras="$(LC_ALL=C comm -13 <(printf '%s\n' "$remote_list") <(printf '%s\n' "$local_list") | sed '/^$/d')"

if [[ -n "$extras" ]]; then
  if [[ $delete -eq 1 ]]; then
    while IFS= read -r file; do rm -f -- "$file" && echo "deleted $file"; done <<< "$extras"
    find . -path ./.git -prune -o -type d -empty -print -delete 2>/dev/null || true
  else
    echo "Files only on this machine (removed on Kali?). Re-run with --delete to remove them:"
    printf '  %s\n' $extras
  fi
fi
echo "Synced from $host:~/$remote. Check 'git status', then commit and push from here."
