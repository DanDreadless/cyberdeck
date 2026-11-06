#!/usr/bin/env bash
# Publish to GitHub without the private files. Gitea (origin) gets everything; GitHub gets the
# same history with docs/ and CLAUDE.md removed from every commit (and added to that copy's
# .gitignore), so they never appear in GitHub's history. Run from Git Bash on the Windows host, inside this repo, after committing:
#
#   bash scripts/publish-github.sh            # update the local `github-main` branch, show it
#   bash scripts/publish-github.sh --push     # ...and push it to the `github` remote's main
#
# How: each new commit on SOURCE (default main) is copied onto `github-main` with the private
# paths taken out of its tree, keeping the author, date and message plus a "Source-Commit:"
# trailer. The next run starts after the last Source-Commit, so it is incremental and
# repeatable. Commits that only touched private paths are skipped. If GitHub has commits of
# its own (edited on the website), the script stops and says how to build on top of them. Merge commits are copied as
# plain commits (GitHub's history is linear).
#
# Env: SOURCE (default main), BRANCH (default github-main), REMOTE (default github).
set -euo pipefail

PRIVATE=(docs CLAUDE.md)
PRIVATE_IGNORE=(docs/ CLAUDE.md)   # appended to GitHub's .gitignore
source_ref="${SOURCE:-main}"
branch="${BRANCH:-github-main}"
remote="${REMOTE:-github}"
push=0
[[ "${1:-}" == "--push" ]] && push=1
cd "$(dirname "$0")/.."

git rev-parse --verify -q "$source_ref" >/dev/null || { echo "no branch $source_ref" >&2; exit 1; }

# Commits made on GitHub itself (a web edit) must be on the branch before adding to it.
if git remote get-url "$remote" >/dev/null 2>&1 && git fetch -q "$remote" main 2>/dev/null; then
  if git rev-parse -q --verify "refs/heads/$branch" >/dev/null &&
     ! git merge-base --is-ancestor FETCH_HEAD "$branch"; then
    echo "$remote/main has commits that $branch doesn't (an edit made on GitHub?):" >&2
    git log --oneline "$branch..FETCH_HEAD" >&2
    echo "Copy the change into main (on Kali) if you want to keep it, then build on top of it:" >&2
    echo "  git branch -f $branch FETCH_HEAD && bash scripts/publish-github.sh --push" >&2
    exit 1
  fi
fi

tip="$(git rev-parse -q --verify "refs/heads/$branch" || true)"
last=""
if [[ -n "$tip" ]]; then
  # The newest Source-Commit anywhere in the branch (GitHub web edits don't carry one).
  last="$(git log --format=%B "$tip" | sed -n 's/^Source-Commit: //p' | head -1)"
fi
range="$source_ref"
[[ -n "$last" ]] && range="$last..$source_ref"

index="$(mktemp)"
trap 'rm -f "$index"' EXIT
copied=0
for commit in $(git rev-list --reverse --first-parent "$range"); do
  GIT_INDEX_FILE="$index" git read-tree "$commit"
  GIT_INDEX_FILE="$index" git rm -r -q --cached --ignore-unmatch -- "${PRIVATE[@]}" >/dev/null
  # GitHub's .gitignore also lists the private paths, so a clone from GitHub ignores them too.
  # (Gitea's can't: an ignored file is never committed, and Gitea keeps them.)
  ignore_blob="$(
    { git show "$commit:.gitignore" 2>/dev/null || true
      printf '\n# --- kept on the private (Gitea) repo only; scripts/publish-github.sh ------\n'
      printf '%s\n' "${PRIVATE_IGNORE[@]}"
    } | git hash-object -w --stdin
  )"
  GIT_INDEX_FILE="$index" git update-index --add --cacheinfo "100644,$ignore_blob,.gitignore"
  tree="$(GIT_INDEX_FILE="$index" git write-tree)"
  if [[ -n "$tip" && "$tree" == "$(git rev-parse "$tip^{tree}")" ]]; then
    continue  # only private files changed
  fi
  message="$(git log -1 --format=%B "$commit")"
  parent=()
  [[ -n "$tip" ]] && parent=(-p "$tip")
  tip="$(
    GIT_AUTHOR_NAME="$(git log -1 --format=%an "$commit")" \
    GIT_AUTHOR_EMAIL="$(git log -1 --format=%ae "$commit")" \
    GIT_AUTHOR_DATE="$(git log -1 --format=%aD "$commit")" \
      git commit-tree "$tree" "${parent[@]}" -m "$message" -m "Source-Commit: $commit"
  )"
  copied=$((copied + 1))
done

if [[ -z "$tip" ]]; then
  echo "Nothing to publish yet." >&2
  exit 1
fi
git update-ref "refs/heads/$branch" "$tip"

# Safety net: refuse to push if a private path is anywhere in the branch's history.
leaked="$(git log --format= --name-only "$branch" | grep -E '^(docs/|CLAUDE\.md$)' | sort -u || true)"
if [[ -n "$leaked" ]]; then
  echo "Private files found in $branch history; not pushing:" >&2
  printf '  %s\n' $leaked >&2
  exit 1
fi

echo "$branch: $copied new commit(s), tip $(git rev-parse --short "$branch") (from $source_ref)."
git log --oneline -5 "$branch"
if [[ $push -eq 1 ]]; then
  git push "$remote" "$branch:main"
else
  echo "Check it, then: bash scripts/publish-github.sh --push"
fi
