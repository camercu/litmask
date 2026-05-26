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

# Two passes because nextest does not yet support doc-tests upstream;
# `cargo test --doc` covers them, `nextest` covers unit + integration
# tests with parallel execution + better output.
test:
    cargo nextest run --workspace
    cargo test --workspace --doc

# Run tests with --all-features so dual-cipher (chacha + aes-gcm)
# code paths are exercised. Catches bugs like encrypt-with-one-cipher /
# decrypt-with-another when CURRENT_CIPHER resolves differently than
# the hardcoded cipher in a test helper.
test-all-features:
    cargo nextest run --workspace --all-features

# Latest-stable sanity check. Skips the trybuild compile_fixtures
# harness because rustc's diagnostic text drifts between minor
# releases and the snapshots are byte-exact against the
# `.tool-versions` toolchain (1.88.0 today). The canonical-gate job
# runs everything, including the fixtures, on the pinned toolchain.
test-stable:
    cargo {{stable_toolchain}} nextest run --workspace -E 'not test(compile_fixtures)'
    cargo {{stable_toolchain}} test --workspace --doc

# Build and run every in-repo example end-to-end. Sources
# LITMASK_UNLOCK_KEY from the build's litmask.config. Examples are
# discovered by globbing `litmask/examples/*.rs` so adding a new
# example file is the only step needed to wire it in.
test-examples:
    #!/usr/bin/env bash
    set -euo pipefail
    # Build first so the canonical `litmask.config` exists before any
    # example runs (the build script writes it).
    cargo build --workspace --examples
    unlock_key=$(awk -F'"' '/^unlock_key/ {print $2}' target/debug/litmask.config)
    found=0
    for src in litmask/examples/*.rs; do
        name=$(basename "$src" .rs)
        # `hw_id_provider` requires both the `hw-id` feature AND a
        # prior `litmask-cli bind` step (otherwise init fails with
        # `decryption_failed`, since the build's wrapper is encrypted
        # under the env-var key, not the hardware-derived one). The
        # recipe can't perform the bind step (it would mutate the
        # binary mid-run), so the example's runtime path is exercised
        # by the dedicated integration test in
        # `litmask/tests/hw_id_provider.rs` and the masking property
        # of the built binary is exercised by
        # `litmask/tests/example_scrub.rs::hw_id_provider_example_*`.
        if [ "$name" = "hw_id_provider" ]; then
            continue
        fi
        echo "litmask: test-examples — running $name"
        # Export both the canonical env-var name AND the custom name
        # `weak_mask_demo` reads (`MYAPP_SECRET_KEY`). The extra
        # binding is a no-op for every other example and avoids
        # special-casing inside the loop. The example's own scrub
        # asserts the custom name is absent from the binary, so the
        # weak_mask! hiding stays verifiable end-to-end.
        LITMASK_UNLOCK_KEY="$unlock_key" \
        MYAPP_SECRET_KEY="$unlock_key" \
            cargo run --quiet --example "$name"
        found=$((found + 1))
    done
    if [ "$found" -eq 0 ]; then
        echo "litmask: test-examples — no examples discovered under litmask/examples/" >&2
        exit 1
    fi

# ── Coverage ────────────────────────────────────────────────

coverage:
    cargo llvm-cov nextest --workspace --all-features --html

coverage-text:
    cargo llvm-cov nextest --workspace --all-features

coverage-lcov:
    cargo llvm-cov nextest --workspace --all-features --lcov --output-path target/llvm-cov/lcov.info

# ── Building / checking ─────────────────────────────────────

build:
    cargo build --workspace --all-targets

# Verify the runtime crate compiles with `--no-default-features --features alloc`
# (the no_std + alloc configuration). Feature-matrix expansion lands in Task 27;
# this single combo guards against feature-gate regressions today.
check-no-default:
    cargo check -p litmask --no-default-features --features alloc

# Cross-compile the runtime crate to a bare-metal embedded target
# (§2.10.1–§2.10.6). The `thumbv7m-none-eabi` triple has no `std`
# and no allocator, so this fails fast if any `std::` reference
# leaks into `--no-default-features --features alloc` builds.
check-no-std:
    cargo check --target thumbv7m-none-eabi -p litmask --no-default-features --features alloc

semver-check:
    cargo semver-checks check-release --workspace

# ── Documentation ───────────────────────────────────────────

# `--all-features` so every feature-gated symbol (`HardwareIdProvider`
# under `hw-id`, the `aes-gcm` cipher path, etc.) is documented and
# every intra-doc link resolves. Mirrors the
# `[package.metadata.docs.rs] all-features = true` declared in each
# member crate's Cargo.toml, so local `just doc` output matches what
# docs.rs would render.
doc:
    RUSTDOCFLAGS="{{warnings}}" cargo doc --workspace --no-deps --all-features

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
            cargo-llvm-cov) actual=$(cargo llvm-cov --version | awk '{print $2}') ;;
            cargo-semver-checks) actual=$(cargo semver-checks --version | awk '{print $2}') ;;
            nodejs)        actual=$(node --version | sed 's/^v//') ;;
            *)
                # Loud failure: a new entry in `.tool-versions` without
                # a matching case here would otherwise drift silently.
                printf '  %-14s unrecognized (add a case to check-tool-versions)\n' "$name"
                drift=1
                continue
                ;;
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

# Fast checks run on every git commit via pre-commit. Mirrors the
# fast tier of `just lint` (fmt + typos + taplo); the heavier checks
# (clippy, deny, tests) live in `just pre-push`.
pre-commit: fmt-check lint-typos lint-taplo
    cargo check --all-targets --workspace --quiet

# Slower checks run on every git push via pre-commit. Mirrors `just
# ci` so anything red in CI was already red locally; the gap that
# previously skipped lint-taplo / check-no-default / test-examples
# allowed taplo + no_std + example-bitrot regressions to land on
# main.
pre-push:
    RUSTFLAGS="{{warnings}}" RUSTDOCFLAGS="{{warnings}}" just lint test test-examples check-no-default doc

# ── CI ──────────────────────────────────────────────────────

ci: fmt-check lint test test-all-features test-examples build check-no-default check-no-std doc ci-coverage

# Best-effort coverage summary. Prints to stdout but does not fail CI
# pre-1.0 (no minimum threshold set).
ci-coverage:
    -cargo llvm-cov nextest --workspace --all-features

# Stable-channel best-effort sanity check; runs in a continue-on-error
# CI job so toolchain regressions surface without blocking PR merge.
ci-stable: lint-clippy-stable test-stable

# ── Release ─────────────────────────────────────────────────

# Invoked by .github/workflows/release.yml after a successful CI run on
# main. semantic-release reads .releaserc.json; the
# `semantic-release-cargo` plugin is configured with
# `{ publish: false, alwaysVerifyToken: false }`, so its `prepare` hook
# still runs (version bump in Cargo.toml + Cargo.lock) but the
# crates.io push is skipped. The workflow already exports
# CARGO_REGISTRY_TOKEN, so enabling crates.io publishes is a one-line
# edit: flip `publish` to `true` in .releaserc.json.
release:
    npm ci
    npx semantic-release
