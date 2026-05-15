set shell := ["bash", "-euo", "pipefail", "-c"]

warnings := "-D warnings"
stable_toolchain := "+stable"

default:
    @just --list

# ── Formatting ──────────────────────────────────────────────

fmt: fmt-rust fmt-taplo

fmt-rust:
    cargo fmt --all

# Format every TOML file in the workspace via taplo. Mirrors fmt-rust
# so a single `just fmt` keeps both Rust and TOML aligned.
fmt-taplo:
    taplo format

fmt-check:
    cargo fmt --all --check

# ── Linting ─────────────────────────────────────────────────

lint: fmt-check lint-clippy lint-typos lint-taplo lint-deny

lint-clippy:
    cargo clippy --all-targets --workspace -- {{warnings}}

lint-clippy-stable:
    cargo {{stable_toolchain}} clippy --all-targets --workspace

lint-typos:
    typos

# Check that every TOML file in the workspace is formatted by taplo.
# Runs in `just lint` and `just ci`; surfaces drift before it slips
# into a review.
lint-taplo:
    taplo format --check

lint-deny:
    cargo deny check advisories licenses bans sources

# ── Testing ─────────────────────────────────────────────────

test:
    cargo test --workspace

# Latest-stable sanity check. Skips the trybuild compile_fixtures
# harness because rustc's diagnostic text drifts between minor
# releases and the snapshots are byte-exact against the
# `.tool-versions` toolchain (1.88.0 today). The canonical-gate job
# runs everything, including the fixtures, on the pinned toolchain.
test-stable:
    cargo {{stable_toolchain}} test --workspace -- --skip compile_fixtures

# Build and run every in-repo example end-to-end. Sources LITMASK_UNLOCK_KEY
# from the build's litmask.config. Wired into `just ci` to catch example
# bitrot.
test-examples:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --example hello_world
    unlock_key=$(awk -F'"' '/^unlock_key/ {print $2}' target/debug/litmask.config)
    LITMASK_UNLOCK_KEY="$unlock_key" cargo run --example hello_world

# ── Building / checking ─────────────────────────────────────

build:
    cargo build --workspace --all-targets

# Verify the runtime crate compiles with `--no-default-features --features alloc`
# (the no_std + alloc configuration). Feature-matrix expansion lands in Task 27;
# this single combo guards against feature-gate regressions today.
check-no-default:
    cargo check -p litmask --no-default-features --features alloc

# ── Documentation ───────────────────────────────────────────

doc:
    RUSTDOCFLAGS="{{warnings}}" cargo doc --workspace --no-deps

# ── Tool versions ───────────────────────────────────────────

check-tool-versions:
    #!/usr/bin/env bash
    set -euo pipefail
    drift=0
    while read -r name version; do
        case "$name" in
            rust)          actual=$(rustc --version | awk '{print $2}') ;;
            just)          actual=$(just --version | awk '{print $2}') ;;
            cargo-deny)    actual=$(cargo-deny --version | awk '{print $2}') ;;
            cargo-nextest) actual=$(cargo nextest --version | head -1 | awk '{print $2}') ;;
            typos-cli)     actual=$(typos --version | awk '{print $2}') ;;
            taplo-cli)     actual=$(taplo --version | awk '{print $2}') ;;
            nodejs)        actual=$(node --version | sed 's/^v//') ;;
            *)             continue ;;
        esac
        if [ "$actual" != "$version" ]; then
            printf '  %-14s pinned=%s  actual=%s\n' "$name" "$version" "$actual"
            drift=1
        fi
    done < <(grep -v '^#' .tool-versions | grep -v '^$')
    # `rust-toolchain.toml` is read by rustup when devs `cd` into the
    # repo, so its `channel` must agree with `.tool-versions`' rust
    # line — otherwise local builds and CI use different toolchains.
    if [ -f rust-toolchain.toml ]; then
        rt_channel=$(grep -E '^channel\s*=' rust-toolchain.toml | head -1 | sed -E 's/^channel\s*=\s*"([^"]+)".*/\1/')
        tv_rust=$(grep -E '^rust\s' .tool-versions | awk '{print $2}')
        if [ -n "$rt_channel" ] && [ "$rt_channel" != "$tv_rust" ]; then
            printf '  %-14s .tool-versions=%s  rust-toolchain.toml=%s\n' \
                'rust (channel)' "$tv_rust" "$rt_channel"
            drift=1
        fi
    fi
    if [ "$drift" -eq 1 ]; then
        echo "tool versions have drifted from .tool-versions"
        exit 1
    else
        echo "all tool versions match .tool-versions"
    fi

# ── Setup ───────────────────────────────────────────────────

setup:
    ./scripts/setup-dev.sh

# ── Hooks ───────────────────────────────────────────────────

# Fast checks run on every git commit via pre-commit.
pre-commit: fmt-check lint-typos
    cargo check --all-targets --workspace --quiet

# Slower checks run on every git push via pre-commit. lint-deny and
# lint-typos are cheap (sub-second) and surface advisory/typo drift
# before it hits a remote runner.
pre-push:
    RUSTFLAGS="{{warnings}}" RUSTDOCFLAGS="{{warnings}}" just lint-clippy lint-typos lint-deny test doc

# ── CI ──────────────────────────────────────────────────────

ci: fmt-check lint test test-examples build check-no-default doc

# Stable-channel best-effort sanity check; runs in a continue-on-error
# CI job so toolchain regressions surface without blocking PR merge.
ci-stable: lint-clippy-stable test-stable

# ── Release ─────────────────────────────────────────────────

# Releases are driven by `release-plz` in .github/workflows/release.yml:
# every push to `main` opens or updates a "Release v{version}" PR with
# the bump + CHANGELOG.md entry; merging the PR cuts the GitHub Release
# and tag. There is no local `just release` recipe — release-plz runs
# from the action, not from the workspace. To preview a release PR
# locally, install the binary (`cargo install release-plz`) and run
# `release-plz release-pr --dry-run`.
