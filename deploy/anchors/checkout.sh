#!/usr/bin/env bash
# Puts the `audit-anchors` branch in ./anchors as a git worktree. On the first run the branch
# doesn't exist yet: it is created as an orphan (no shared history with main) holding only the
# anchors file, a README, and a vercel.json that tells Vercel not to deploy this branch.
set -euo pipefail
BRANCH="${ANCHOR_BRANCH:-audit-anchors}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if git fetch --quiet --depth 1 origin "$BRANCH" 2>/dev/null; then
  git worktree add --quiet -B "$BRANCH" anchors FETCH_HEAD
  echo "checked out $BRANCH ($(wc -l < anchors/anchors.jsonl 2>/dev/null || echo 0) anchors so far)"
else
  git worktree add --quiet --detach anchors
  cd anchors
  git checkout --quiet --orphan "$BRANCH"
  git rm -rfq .
  cp "$HERE/README.md" README.md
  mkdir -p ui && cp "$HERE/vercel.json" ui/vercel.json
  echo "created a new, empty $BRANCH branch"
fi
