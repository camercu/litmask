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

clean: _profraw-purge
    cargo clean
    # The nested `benches/` workspace and the generated build fixtures are
    # separate workspaces, so root `cargo clean` can't reach their target
    # dirs; the fixtures themselves are generated. Remove both.
    rm -rf benches/target benches/build-fixtures

# ── Linting ─────────────────────────────────────────────────

lint: fmt-check lint-clippy lint-typos lint-taplo lint-markdown lint-actions lint-deny

lint-clippy:
    cargo clippy --all-targets --workspace -- {{warnings}}
    # Second pass under --all-features: feature-gated modules (the
    # `serde` proc-macro derives, `machine-id` paths) are not
    # compiled by the default-feature pass above, so without this they
    # escape clippy entirely. Examples are excluded (`--lib --tests
    # --bins`) for the same seal-tier reason as `test-all-features`: no
    # single env config compiles every example's `init!` form.
    cargo clippy --all-features --workspace --lib --tests --bins -- {{warnings}}

# Intentionally non-blocking: no `-D warnings`. Stable clippy gains/changes
# lints between releases, so denying here would fail the pinned-toolchain
# gate on lints we don't control. Runs in a continue-on-error CI lane.
lint-clippy-stable:
    cargo {{stable_toolchain}} clippy --all-targets --workspace

lint-typos:
    typos

# Check that every TOML file in the workspace is formatted by taplo.
# Runs in `just lint` and `just ci`; surfaces drift before it slips
# into a review.
lint-taplo:
    taplo format --check

# Lint Markdown structure (headings, lists, fenced-code languages).
# Config + globs/ignores live in `.markdownlint-cli2.yaml`; line-length
# is disabled there because it can't wrap reference tables.
lint-markdown:
    markdownlint-cli2

# Lint GitHub Actions workflows (syntax, expression typos, shell issues
# in `run:` blocks via shellcheck). Catches workflow bugs that otherwise
# only surface on a pushed CI run.
lint-actions:
    actionlint

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
# the single-cipher property this recipe exists to test. `unstable-serde`
# is folded in so the masked-name decrypt path (a cipher-specific blob)
# runs under aes-gcm; `--all-features` only ever exercises it under
# chacha, which wins feature unification (litmask-internal/src/aead.rs).
test-aes-gcm:
    cargo nextest run -p litmask -p litmask-internal --no-default-features --features std,aes-gcm,unstable-serde
    cargo test -p litmask -p litmask-internal --doc --no-default-features --features std,aes-gcm,unstable-serde

# Run tests with --all-features so dual-cipher (chacha + aes-gcm)
# code paths are exercised. Catches bugs like encrypt-with-one-cipher /
# decrypt-with-another when CURRENT_CIPHER resolves differently than
# the hardcoded cipher in a test helper.
#
# Examples are excluded (`--lib --tests --bins`) by necessity, not
# oversight: the seal tier is fixed per-build from env presence and
# `init!` forms are compile-time cross-checked against it, while the
# examples deliberately span tiers — `file_provider` / `weak_mask_demo`'s
# `init!(provider)` needs an `external` seal (LITMASK_UNLOCK_KEY set),
# `machine_id_provider`'s `init!(bind_to_machine)` needs a `machine`
# seal (LITMASK_MACHINE_ID set), and the plain examples' lazy `mask!`
# needs an `embedded` seal. No single env configuration compiles all,
# so a unified all-features example build cannot exist. Each example is
# instead built and scrubbed with tailored features + env by
# `litmask/tests/example_scrub.rs`, and run by `just test-examples`.
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

# Build and run every in-repo example end-to-end. Mints
# LITMASK_UNLOCK_KEY material with `litmask keygen` for the External-tier
# examples. Examples are discovered by globbing `litmask/examples/*.rs` so
# adding a new example file is the only step needed to wire it in.
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

# Instrumented child processes (rustc expanding the instrumented
# proc-macro, example/CLI binaries spawned by e2e tests) can lose
# LLVM_PROFILE_FILE and fall back to LLVM's default profile name,
# dropping `default_*.profraw` into their cwd (workspace root, crate
# dirs) instead of under target/. Sweep after every coverage recipe
# (and in `clean`) so the fallout never lingers in the tree.
_profraw-purge:
    find . -name '*.profraw' -not -path '*/target/*' -not -path './node_modules/*' -delete

coverage *flags: _cov-purge && _profraw-purge
    cargo llvm-cov nextest --workspace --all-features {{flags}}

alias cov := coverage

coverage-html: (coverage "--html")
alias cov-html := coverage-html

coverage-lcov: (coverage "--lcov --output-path target/llvm-cov/lcov.info")
alias cov-lcov := coverage-lcov

# ── Building / checking ─────────────────────────────────────

build:
    cargo build --workspace --all-targets

# Generate cargo's built-in timing report for crate compilation.
# Opens target/cargo-timings/cargo-timing.html showing per-crate
# compile durations, parallelism, and the critical path.
build-timings:
    cargo build --workspace --all-targets --timings

# ── Benchmarking ────────────────────────────────────────────

# Runtime benchmarks (divan) in the nested `benches/` workspace. Mints
# an unlock key, seals the fixture under the External tier with it, and
# re-supplies the same key at runtime via EnvVarProvider. Build + run
# share one env so the release-profile reseal still matches the runtime
# key. The roundtrip test runs first so a bad seal fails loudly before
# any timing number is trusted. Not part of `just ci` — run on demand.
bench:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/bench
    key="$(cargo run -q -p litmask-cli -- keygen)"
    LITMASK_UNLOCK_KEY="$key" cargo test --manifest-path benches/litmask-bench/Cargo.toml
    # Persist the divan table (no stable JSON output, so capture verbatim)
    # for `just bench-doc` to fold into docs/BENCHMARKS.md.
    LITMASK_UNLOCK_KEY="$key" cargo bench --manifest-path benches/litmask-bench/Cargo.toml \
        | tee target/bench/runtime.log

# Build-time benchmarks (hyperfine). Regenerates the masked_N / plain_N
# fixture crates, then times clean and incremental builds across
# N=10/100/1000 and the dev + release profiles, exporting JSON per
# (scenario, profile) to target/bench-build/. Clean builds include
# compiling the litmask dep tree (total adoption cost); incremental
# touches only the leaf source (isolates build.rs + proc-macro). Embedded
# tier, so no key is needed — the fixtures are only compiled, never run.
# Not part of `just ci` — run on demand. Requires hyperfine (pinned in
# .tool-versions; install via your package manager).
bench-build:
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/gen-build-fixtures.sh
    mkdir -p target/bench-build
    base=benches/build-fixtures
    for profile in dev release; do
        flag=""; [ "$profile" = release ] && flag="--release"
        # Clean: each timed run is a full from-scratch build. `--runs 3`
        # keeps the (slow, dep-recompiling) clean matrix bounded.
        hyperfine --warmup 0 --runs 3 \
            -L mode masked,plain -L n 10,100,1000 \
            --command-name "{mode}_{n}" \
            --prepare "cargo clean --manifest-path $base/{mode}_{n}/Cargo.toml" \
            --export-json "target/bench-build/clean-$profile.json" \
            "cargo build $flag --manifest-path $base/{mode}_{n}/Cargo.toml"
        # Incremental: `--setup` compiles deps once; `--prepare` touches
        # the leaf so each timed run re-expands + recompiles only it.
        hyperfine --warmup 1 --runs 5 \
            -L mode masked,plain -L n 10,100,1000 \
            --command-name "{mode}_{n}" \
            --setup "cargo build $flag --manifest-path $base/{mode}_{n}/Cargo.toml" \
            --prepare "touch $base/{mode}_{n}/src/main.rs" \
            --export-json "target/bench-build/incremental-$profile.json" \
            "cargo build $flag --manifest-path $base/{mode}_{n}/Cargo.toml"
    done
    echo "build-bench JSON written to target/bench-build/"

# Regenerate docs/BENCHMARKS.md from the latest `just bench` +
# `just bench-build` artifacts, stamping a provenance header. The doc is
# generated, never hand-edited; run the two benches first so the numbers
# are current.
bench-doc:
    ./scripts/gen-benchmarks.sh

# Verify the runtime crate compiles with `--no-default-features --features alloc`
# (the no_std + alloc configuration). `test-no-default` runs unit tests under
# the same feature set; this recipe is a faster compile-only gate.
check-no-default:
    cargo check -p litmask --no-default-features --features alloc

# Cross-compile the runtime crate to a bare-metal embedded target
# (§2.10.1–§2.10.6). The `thumbv7m-none-eabi` triple has no `std`
# and no allocator, so this fails fast if any `std::` reference
# leaks into `--no-default-features --features alloc` builds. The second
# check adds `unstable-stack`: the `mask_stack!` guard types (`MaskStr` /
# `MaskBytes` / `MaskCStr`) must stay `core`/`alloc`-only — `MaskCStr`
# borrows `core::ffi::CStr`, so it works without `std`, unlike the heap
# `mask!(c"...")`.
check-no-std:
    cargo check --target thumbv7m-none-eabi -p litmask --no-default-features --features alloc
    cargo check --target thumbv7m-none-eabi -p litmask --no-default-features --features alloc,unstable-stack

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
            markdownlint-cli2) actual=$(markdownlint-cli2 --version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/^v//') ;;
            actionlint)    actual=$(actionlint --version | head -1) ;;
            cargo-llvm-cov) actual=$(cargo llvm-cov --version | awk '{print $2}') ;;
            cargo-semver-checks) actual=$(cargo semver-checks --version | awk '{print $2}') ;;
            cargo-fuzz) actual=$(cargo fuzz --version 2>/dev/null | awk '{print $2}') ;;
            hyperfine) actual=$(hyperfine --version | awk '{print $2}') ;;
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
    # `rust-toolchain.toml` is read by rust-overlay in shell.nix to
    # build the dev toolchain, so its `channel` must agree with
    # `.tool-versions`' rust line — otherwise local builds and CI use
    # different toolchains.
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
# fast tier of `just lint` (fmt + typos + taplo + markdown); the heavier
# checks (clippy, deny, tests) live in `just pre-push`.
pre-commit: fmt-check lint-typos lint-taplo lint-markdown
    cargo check --all-targets --workspace --quiet

# Slower checks run on every git push via pre-commit. A fast subset of
# `just ci`, not a full mirror: it skips the cross/no_std/single-cipher/
# all-features lanes (test-no-default, test-aes-gcm, check-no-std,
# check-cross, all-features tests) to keep push latency down, so those can
# still go red in CI after a green push. Catches the common regressions
# (lint, default-feature tests, examples, check-no-default, doc).
pre-push:
    RUSTFLAGS="{{warnings}}" RUSTDOCFLAGS="{{warnings}}" just lint test test-examples check-no-default doc

# ── CI ──────────────────────────────────────────────────────

# Pass `timed` (see `ci-timed`) to print per-step wall-clock timings.
# The step list lives here once; `ci-timed` reuses it via dependency.
ci mode="":
    #!/usr/bin/env bash
    set -euo pipefail
    timed=""; [ "{{mode}}" = "timed" ] && timed=1
    step() {
        if [ -z "$timed" ]; then just "$1"; return; fi
        local start=$(date +%s)
        just "$1"
        printf '%4ds  %s\n' "$(( $(date +%s) - start ))" "$1"
    }
    ci_start=$(date +%s)
    step fmt-check
    step lint
    cov_log=$(mktemp)
    trap 'rm -f "$cov_log"' EXIT
    cov_start=$(date +%s)
    { CARGO_BUILD_JOBS=$(($(nproc 2>/dev/null || sysctl -n hw.ncpu) / 2)) \
        just ci-coverage; } >"$cov_log" 2>&1 &
    pid_cov=$!
    step test-doc
    step test-examples
    step build
    step doc
    step test-no-default
    step check-no-default
    step test-aes-gcm
    step check-no-std
    step check-cross
    printf '\n══ ci-coverage (background) ══\n'
    if wait "$pid_cov"; then
        tail -1 "$cov_log"
    else
        cat "$cov_log"
        exit 1
    fi
    if [ -n "$timed" ]; then
        printf '%4ds  ci-coverage\n' "$(( $(date +%s) - cov_start ))"
        printf '\nTotal: %ds\n' "$(( $(date +%s) - ci_start ))"
    fi

# `ci` with per-step wall-clock timings (foreground steps + coverage + total).
ci-timed: (ci "timed")

# Best-effort coverage summary. Prints to stdout but does not fail CI
# pre-1.0 (no minimum threshold set).
# Examples are excluded (`--lib --tests --bins`): the `machine_id_provider`
# example uses `init!(machine_id)`, whose build-time form↔tier cross-check
# rejects every seal but `machine`. A generic `--all-features` build seals
# `embedded` (no `LITMASK_MACHINE_ID`), so compiling the example would
# `compile_error!`. Its masking + round-trip behavior is covered by
# `tests/example_scrub.rs` and `tests/machine_tier_e2e.rs` instead.
ci-coverage: && _profraw-purge
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
