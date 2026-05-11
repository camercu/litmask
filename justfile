set shell := ["bash", "-euo", "pipefail", "-c"]

warnings := "-D warnings"

default:
    @just --list

# ── Formatting ──────────────────────────────────────────────

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

# ── Linting ─────────────────────────────────────────────────

lint: fmt-check lint-clippy

lint-clippy:
    cargo clippy --all-targets --workspace -- {{warnings}}

# ── Testing ─────────────────────────────────────────────────

test:
    cargo test --workspace

# ── Building / checking ─────────────────────────────────────

build:
    cargo build --workspace --all-targets

# ── Documentation ───────────────────────────────────────────

doc:
    RUSTDOCFLAGS="{{warnings}}" cargo doc --workspace --no-deps

# ── CI ──────────────────────────────────────────────────────

ci: fmt-check lint test build doc
