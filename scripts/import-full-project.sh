#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

# Import full xrdp-console main + history using the owner's existing local clone.
# No new branches, backups, production actions, resets of legacy, or force push.
SOURCE_PATH="${1:-${HOME}/xrdp-console}"
DESTINATION="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$DESTINATION"

if [[ "$(git branch --show-current)" != 'main' ]]; then
  echo 'ERROR: RDP-server must be checked out on its existing main branch.' >&2
  exit 2
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'ERROR: RDP-server working tree is modified; commit/clear it first.' >&2
  exit 2
fi
if ! git -C "$SOURCE_PATH" rev-parse --verify 'refs/heads/main^{commit}' >/dev/null 2>&1; then
  echo "ERROR: No local xrdp-console main history at: $SOURCE_PATH" >&2
  exit 2
fi
if ! git remote get-url origin | grep -Eiq '(^|[:/])k1moradi/RDP-server(\.git)?$'; then
  echo 'ERROR: origin must point to k1moradi/RDP-server.' >&2
  exit 2
fi
BASE_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git ls-remote origin refs/heads/main | cut -f1)"
if [[ "$BASE_SHA" != "$REMOTE_SHA" ]]; then
  echo "ERROR: local main ($BASE_SHA) differs from origin/main ($REMOTE_SHA)." >&2
  echo 'Run git pull --ff-only and retry. Nothing has been changed.' >&2
  exit 2
fi

# Fetch from the local Git database: the former GitHub URL is deleted.
git fetch --no-tags "$SOURCE_PATH" refs/heads/main
SOURCE_SHA="$(git rev-parse FETCH_HEAD)"
if git merge-base --is-ancestor "$SOURCE_SHA" "$BASE_SHA"; then
  echo "Already imported historical main commit: $SOURCE_SHA"
  exit 0
fi
printf 'Importing historical main %s into RDP-server main %s\n' "$SOURCE_SHA" "$BASE_SHA"

# Import the complete tracked tree, not merely selected C++23 files.
git archive --format=tar "$SOURCE_SHA" | tar -xf - -C "$DESTINATION"
git add -A -- .

# Preserve the existing C++23-first standalone build, namespace, tests,
# current security fixes, project documentation, and GitHub CI. Everything
# absent from the new RDP-server snapshot remains imported into the root.
for path in \
    .gitignore .github/workflows/ci.yml \
    CMakeLists.txt README.md CODEX.md NOTICE THIRD_PARTY.md LICENSE \
    docs/ARCHITECTURE.md docs/ROADMAP.md docs/MIGRATION.md; do
  git restore --source="$BASE_SHA" --staged --worktree -- "$path"
done
while IFS= read -r -d '' path; do
  git restore --source="$BASE_SHA" --staged --worktree -- "$path"
done < <(git ls-tree -r -z --name-only "$BASE_SHA" -- src/ tests/)

# Never let the former repository's remote branch deletion automation run
# against this new repository. Its source remains in old Git history.
if git ls-files --error-unmatch .github/workflows/branch-consolidation.yml >/dev/null 2>&1; then
  git rm -f -- .github/workflows/branch-consolidation.yml
fi

# Audit: every file from historical main must be tracked in the merged tree
# (except that dangerous obsolete workflow).
expected="$(mktemp)"
actual="$(mktemp)"
trap 'rm -f "$expected" "$actual"' EXIT
git ls-tree -r --name-only "$SOURCE_SHA" | LC_ALL=C sort > "$expected"
git ls-files | LC_ALL=C sort > "$actual"
missing="$(comm -23 "$expected" "$actual" | grep -v '^\.github/workflows/branch-consolidation\.yml$' || true)"
if [[ -n "$missing" ]]; then
  printf 'ERROR: Historical files missing from merged index:\n%s\n' "$missing" >&2
  exit 3
fi

# A genuine two-parent integration commit: the tree contains historical
# files AND the modern source, and both independent histories are reachable.
# No empty 'ours' merge, no new branch, no force push.
TREE_SHA="$(git write-tree)"
COMMIT_SHA="$(printf 'migration: import complete historical project source and Git history into RDP-server\n\nImport xrdp-console main %s with all tracked files; preserve the maintained standalone C++23 build, namespace, security fixes, documentation and CI. Historical xrdp files remain for migration only, not linked into the active C++23 build.\n' "$SOURCE_SHA" | git commit-tree "$TREE_SHA" -p "$BASE_SHA" -p "$SOURCE_SHA")"
git update-ref refs/heads/main "$COMMIT_SHA" "$BASE_SHA"
git reset --hard "$COMMIT_SHA"

printf '\nIntegrated commit: %s\nOld main: %s\nTracked files: %s\n' \
  "$COMMIT_SHA" "$SOURCE_SHA" "$(git ls-files | wc -l | tr -d ' ')"
git push origin HEAD:refs/heads/main
printf '\nCOMPLETE: full historical main tree and its Git history pushed to RDP-server/main.\n'
