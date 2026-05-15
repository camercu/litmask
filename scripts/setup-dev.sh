#!/usr/bin/env bash
# scripts/setup-dev.sh — bootstrap the local development environment.
#
# Every tool used here lives in `shell.nix`; the script enters a Nix
# subshell so PATH resolves to the pinned versions regardless of
# whether the caller has already run `nix-shell`. The Nix shell is
# the single source of truth for tool versions — no fallback
# installer paths. Safe to re-run; each install step is idempotent.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v nix-shell >/dev/null 2>&1; then
    echo "litmask: setup-dev — nix-shell not on PATH" >&2
    echo "  hint: install Nix from https://nixos.org/download" >&2
    exit 1
fi

nix-shell --run '
    set -euo pipefail

    # `rustup show active-toolchain` reads rust-toolchain.toml and
    # triggers a download if the pinned channel is not installed yet.
    echo "litmask: setup-dev — ensuring Rust toolchain matches rust-toolchain.toml…"
    rustup show active-toolchain >/dev/null

    # Authoritative match against `.tool-versions`; aborts on drift
    # so a misaligned nix-shell surfaces here instead of in CI.
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
'
