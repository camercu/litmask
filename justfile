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

# ── Cleaning ───────────────────────────────────────────────

clean:
    cargo clean

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
test: test-unit test-doc

test-unit:
    cargo nextest run --workspace

test-doc:
    cargo test --workspace --doc

# Unit tests only — integration tests and examples import std-gated
# types (FileProvider, EnvVarProvider) that don't compile under
# no-default-features.
test-no-default:
    cargo nextest run -p litmask -p litmask-internal --no-default-features --features alloc --lib

test-machine-id:
    cargo nextest run -p litmask --features machine-id

# Scoped to litmask + litmask-internal: `--workspace` would unify
# features with litmask-cli (which activates both ciphers), defeating
# the single-cipher property this recipe exists to test.
test-aes-gcm:
    cargo nextest run -p litmask -p litmask-internal --no-default-features --features std,aes-gcm
    cargo test -p litmask -p litmask-internal --doc --no-default-features --features std,aes-gcm

# Run tests with --all-features so dual-cipher (chacha + aes-gcm)
# code paths are exercised. Catches bugs like encrypt-with-one-cipher /
# decrypt-with-another when CURRENT_CIPHER resolves differently than
# the hardcoded cipher in a test helper. Examples are excluded
# (`--lib --tests --bins`): the `machine_id_provider` example's
# `init!(machine_id)` only compiles under a `machine` seal (see
# `ci-coverage`).
test-all-features:
    cargo nextest run --workspace --all-features --lib --tests --bins

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
    ./scripts/test-examples.sh

# ── Coverage ────────────────────────────────────────────────

# Coverage instrumentation bakes a per-file covmap into each object.
# Deleting a source file or example orphans its covmap inside
# target/llvm-cov-target (cached binaries + incremental codegen units);
# `cargo llvm-cov clean` does NOT purge those, so the dead file lingers
# as a phantom 0%-covered row and deflates the totals. Wipe the coverage
# build dir so every report reflects only the current source set.
_cov-purge:
    rm -rf target/llvm-cov-target

coverage: _cov-purge
    cargo llvm-cov nextest --workspace --all-features

alias cov := coverage

coverage-html: _cov-purge
    cargo llvm-cov nextest --workspace --all-features --html

alias cov-html := coverage-html

coverage-lcov: _cov-purge
    cargo llvm-cov nextest --workspace --all-features --lcov --output-path target/llvm-cov/lcov.info

alias cov-lcov := coverage-lcov

# ── Building / checking ─────────────────────────────────────

build:
    cargo build --workspace --all-targets

# Generate cargo's built-in timing report for crate compilation.
# Opens target/cargo-timings/cargo-timing.html showing per-crate
# compile durations, parallelism, and the critical path.
build-timings:
    cargo build --workspace --all-targets --timings

# Verify the runtime crate compiles with `--no-default-features --features alloc`
# (the no_std + alloc configuration). `test-no-default` runs unit tests under
# the same feature set; this recipe is a faster compile-only gate.
check-no-default:
    cargo check -p litmask --no-default-features --features alloc

# Cross-compile the runtime crate to a bare-metal embedded target
# (§2.10.1–§2.10.6). The `thumbv7m-none-eabi` triple has no `std`
# and no allocator, so this fails fast if any `std::` reference
# leaks into `--no-default-features --features alloc` builds.
check-no-std:
    cargo check --target thumbv7m-none-eabi -p litmask --no-default-features --features alloc

# `cargo check` only (no linking) so no cross-linker is required.
check-cross:
    cargo check --target x86_64-pc-windows-gnu -p litmask -p litmask-internal
    cargo check --target aarch64-apple-darwin -p litmask -p litmask-internal

semver-check:
    cargo semver-checks check-release --workspace

# Nightly dependency-fingerprint scrub. Verifies the docs/DEPLOYMENT.md
# hardening recipe still strips dep / litmask source-path strings from
# `.rodata`. Nightly-only (uses unstable `-Zlocation-detail` /
# `-Zfmt-debug`), so it lives in its own CI lane, not the stable gate.
scrub-hardened:
    ./scripts/scrub-hardened.sh

# ── Documentation ───────────────────────────────────────────

# `--all-features` so every feature-gated symbol (`MachineIdProvider`
# under `machine-id`, the `aes-gcm` cipher path, etc.) is documented and
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
            cargo-fuzz) actual=$(cargo fuzz --version 2>/dev/null | awk '{print $2}') ;;
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

ci:
    #!/usr/bin/env bash
    set -euo pipefail
    just fmt-check
    just lint
    cov_log=$(mktemp)
    trap 'rm -f "$cov_log"' EXIT
    CARGO_BUILD_JOBS=$(($(nproc 2>/dev/null || sysctl -n hw.ncpu) / 2)) \
        just ci-coverage >"$cov_log" 2>&1 &
    pid_cov=$!
    just test-doc
    just test-examples
    just build
    just doc
    just test-no-default
    just check-no-default
    just test-aes-gcm
    just check-no-std
    just check-cross
    printf '\n══ ci-coverage (background) ══\n'
    if wait "$pid_cov"; then
        tail -1 "$cov_log"
    else
        cat "$cov_log"
        exit 1
    fi

ci-timed:
    #!/usr/bin/env bash
    set -euo pipefail
    time_step() {
        local step=$1
        local start=$(date +%s)
        just "$step"
        local elapsed=$(( $(date +%s) - start ))
        printf '%4ds  %s\n' "$elapsed" "$step"
    }
    ci_start=$(date +%s)
    time_step fmt-check
    time_step lint
    cov_log=$(mktemp)
    trap 'rm -f "$cov_log"' EXIT
    cov_start=$(date +%s)
    { CARGO_BUILD_JOBS=$(($(nproc 2>/dev/null || sysctl -n hw.ncpu) / 2)) \
        just ci-coverage; } >"$cov_log" 2>&1 &
    pid_cov=$!
    time_step test-doc
    time_step test-examples
    time_step build
    time_step doc
    time_step test-no-default
    time_step check-no-default
    time_step test-aes-gcm
    time_step check-no-std
    time_step check-cross
    printf '\n══ ci-coverage (background) ══\n'
    if wait "$pid_cov"; then
        tail -1 "$cov_log"
    else
        cat "$cov_log"
        exit 1
    fi
    printf '%4ds  ci-coverage\n' "$(( $(date +%s) - cov_start ))"
    ci_elapsed=$(( $(date +%s) - ci_start ))
    printf '\nTotal: %ds\n' "$ci_elapsed"

# Best-effort coverage summary. Prints to stdout but does not fail CI
# pre-1.0 (no minimum threshold set).
# Examples are excluded (`--lib --tests --bins`): the `machine_id_provider`
# example uses `init!(machine_id)`, whose build-time form↔tier cross-check
# rejects every seal but `machine`. A generic `--all-features` build seals
# `embedded` (no `LITMASK_MACHINE_ID`), so compiling the example would
# `compile_error!`. Its masking + round-trip behavior is covered by
# `tests/example_scrub.rs` and `tests/machine_tier_e2e.rs` instead.
ci-coverage:
    cargo llvm-cov nextest --workspace --all-features --lib --tests --bins

# Stable-channel best-effort sanity check; runs in a continue-on-error
# CI job so toolchain regressions surface without blocking PR merge.
ci-stable: lint-clippy-stable test-stable

# ── Fuzz ───────────────────────────────────────────────────

# Run cargo-fuzz targets (requires nightly). Default 10s per target.
fuzz duration="10":
    cd litmask && cargo +nightly fuzz run parse_format_template -- -max_total_time={{duration}}

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
