#!/usr/bin/env bash
# Commits ./anchors (the audit-anchors worktree) if the anchors file changed, and pushes it.
# A plain push, never a force push: history on this branch is only ever added to.
set -euo pipefail
BRANCH="${ANCHOR_BRANCH:-audit-anchors}"
cd anchors
git add -A
if git diff --cached --quiet; then
  echo "nothing new to anchor"
  exit 0
fi
ROW="$(tail -n 1 anchors.jsonl | sed -E 's/.*"last_id":([0-9]+).*/\1/')"
git -c user.name="agentgate-anchor" -c user.email="agentgate-anchor@users.noreply.github.com" \
    commit --quiet -m "anchor: audit chain head at row ${ROW}"
git push --quiet origin "HEAD:refs/heads/${BRANCH}"
echo "pushed anchor for row ${ROW} to ${BRANCH}"
