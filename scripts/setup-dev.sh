#!/usr/bin/env bash
# scripts/setup-dev.sh — bootstrap the local development environment.
#
# Run from inside the Nix shell (or with all pinned tools on PATH).
set -euo pipefail

cd "$(dirname "$0")/.."

echo "litmask: setup-dev — verifying pinned tools…"
just check-tool-versions

echo "litmask: setup-dev — installing Node devDependencies for commitlint…"
npm ci --no-audit --no-fund

echo "litmask: setup-dev — installing git hooks via pre-commit…"
pre-commit install --install-hooks \
    --hook-type pre-commit \
    --hook-type pre-push \
    --hook-type commit-msg

echo "litmask: setup-dev — done."
