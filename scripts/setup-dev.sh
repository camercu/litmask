#!/usr/bin/env bash
# scripts/setup-dev.sh — bootstrap the local development environment.
#
# Task 2 ships this as a near-no-op that only verifies pinned tools.
# Task 3 will extend it to install pre-commit hooks (pre-commit, pre-push,
# commit-msg) and run `npm ci` for commitlint.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "litmask: setup-dev — verifying pinned tools…"
just check-tool-versions

echo "litmask: setup-dev — done."
echo "litmask: hint: pre-commit hook installation lands in Task 3."
