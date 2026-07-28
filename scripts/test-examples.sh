#!/usr/bin/env bash
set -euo pipefail
# Without nullglob an empty examples dir leaves the literal
# `litmask/examples/*.rs` as a loop item, which classifies as an example
# named `*` and dispatches a bogus `cargo run`. With it, the loop runs
# zero times and the empty-dir guard below is the thing that fires.
shopt -s nullglob
# Build first so the `litmask` CLI exists for `keygen` below.
cargo build --workspace --examples
# The External-tier examples just need *some* unlock material at build and
# run time; mint a fresh key the sanctioned way rather than scraping a
# build artifact. (Embedded examples ignore it entirely — see below.)
unlock_key=$(target/debug/litmask keygen)

# Examples are classified first and run group-by-group, NOT in directory
# order. Seal tier hinges on build-env presence, so every switch between
# an Embedded and an External example reruns `build.rs`, reseals the
# shared wrapper, and rebuilds litmask plus every dependent example.
# Directory order alternates the two (~6 transitions) and measured 15s;
# grouping cuts it to ~3 transitions and 8s. Within a group the env and
# feature set are identical, so cargo reuses everything.
# Arrays, not space-joined strings: names must never be re-split or
# glob-expanded on the way to `cargo run`. An unquoted `$list` expansion
# is subject to pathname expansion, so an example named `demo[1].rs`
# would silently dispatch as whatever `demo[1]` matched in the cwd — and
# the accounting guard below, which counts rather than compares
# identities, would still pass.
embedded=()      # keyless lazy path; factor env MUST be unset
serde_group=()   # Embedded + `unstable-serde`
stack_group=()   # Embedded + `unstable-stack`
envelope=()      # External, but sealed under a FIXED plaintext (see below)
external=()      # External, sealed under the freshly minted `unlock_key`
skipped=()
discovered=0

for src in litmask/examples/*.rs; do
    name=$(basename "$src" .rs)
    discovered=$((discovered + 1))
    case "$name" in
    # `machine_id_provider` requires the `machine-id` feature and a
    # `machine`-tier build seal (LITMASK_MACHINE_ID set), and only
    # decrypts on the host whose id matches that seal — so this
    # default-feature script can neither build nor run it. The masking
    # property of the built binary is exercised instead by
    # `litmask/tests/example_scrub.rs::machine_id_provider_example_*`,
    # and the full runtime round-trip by
    # `litmask/tests/machine_tier_e2e.rs`.
    machine_id_provider) skipped+=("$name") ;;
    # `mask_serde_demo` requires the `unstable-serde` feature
    # (EXPERIMENTAL); it is Embedded-tier like the plain examples, so
    # the same env-stripping applies — only the feature flag differs.
    mask_serde_demo) serde_group+=("$name") ;;
    # `stack_demo` requires the `unstable-stack` feature; it is
    # Embedded-tier like the plain examples, so the same env-stripping
    # applies — only the feature flag differs.
    stack_demo) stack_group+=("$name") ;;
    # `envelope_provider` embeds a *wrapped* copy of its unlock material and
    # unwraps it at runtime through a stub HSM (no env read at run time). The
    # embedded blob decrypts to a FIXED plaintext, so the build must seal
    # under that same plaintext — not the freshly-minted `keygen` value the
    # generic External group uses. Its masking property is scrubbed by
    # `tests/example_scrub.rs::envelope_provider_*`.
    envelope_provider) envelope+=("$name") ;;
    *)
        # Seal-tier hinges on env presence: setting LITMASK_UNLOCK_KEY at
        # build selects the External tier and reseals the shared wrapper.
        # So only the runtime-sourced examples (those passing a provider to
        # `init!`, i.e. `init!(SomeProvider...)`) may run with it set — the
        # build then seals under the same material the provider reads back.
        # Embedded examples MUST run with it unset: under an External reseal
        # the keyless lazy path can no longer open the wrapper, and a no-arg
        # `init!()` would fail its tier cross-check at compile time. The
        # `[A-Z]` guard matches a provider-type argument while skipping the
        # no-arg `init!()` and the `init!(bind_to_machine)` keyword form.
        # NOTE: this greps the whole source, comments included — an Embedded
        # example whose doc comment happens to show `init!(SomeProvider)`
        # would be misclassified as External. None do today; if one ever
        # does, switch to an explicit per-example allow-list. A genuine
        # form↔tier mismatch is still caught loudly by the build's
        # cross-check regardless.
        if grep -qE 'init!\([A-Z]' "$src"; then
            external+=("$name")
        else
            embedded+=("$name")
        fi
        ;;
    esac
done

found=0

# Run one group under a single build environment. `$1` is the unlock
# material ("" selects the Embedded path, which must run with both factor
# vars unset), `$2` the extra cargo features (may be empty), and the rest
# the example names. The cargo argv is assembled as an array so an empty
# feature set adds no argument and no name is ever re-split or globbed.
run_group() {
    local keyed="$1" features="$2"
    shift 2
    local name
    for name in "$@"; do
        echo "litmask: test-examples — running $name"
        found=$((found + 1))
        local cmd=(cargo run --quiet)
        [ -n "$features" ] && cmd+=(--features "$features")
        cmd+=(--example "$name")
        if [ -n "$keyed" ]; then
            # Export the canonical name AND the custom name `weak_mask_demo`
            # reads (`MYAPP_SECRET_KEY`); the extra binding is a harmless
            # superset for `file_provider`. The example's own scrub asserts
            # the custom name is absent from the binary, so the weak_mask!
            # hiding stays verifiable end-to-end. With LITMASK_UNLOCK_KEY set
            # the build reseals External, so `init!(provider)` passes its
            # form↔tier cross-check.
            LITMASK_UNLOCK_KEY="$keyed" MYAPP_SECRET_KEY="$keyed" "${cmd[@]}"
        else
            # Strip any inherited factor env so the build stays Embedded.
            env -u LITMASK_UNLOCK_KEY -u LITMASK_MACHINE_ID "${cmd[@]}"
        fi
    done
}

# `--features provider-examples` satisfies the keyed examples'
# `required-features` gate (they are skipped by the default build).
run_group "" "" ${embedded[@]+"${embedded[@]}"}
run_group "" "unstable-serde" ${serde_group[@]+"${serde_group[@]}"}
run_group "" "unstable-stack" ${stack_group[@]+"${stack_group[@]}"}
run_group "envelope-demo-unlock-material-do-not-reuse" "provider-examples" \
    ${envelope[@]+"${envelope[@]}"}
run_group "$unlock_key" "provider-examples" ${external[@]+"${external[@]}"}

if [ "$discovered" -eq 0 ]; then
    echo "litmask: test-examples — no examples discovered under litmask/examples/" >&2
    exit 1
fi
# Every discovered example must be either run or explicitly skipped. The
# classifier routes by name, so a new example that no branch claims (or a
# group left unrun by a future edit) would otherwise vanish silently —
# this script is the only place several examples are executed at all.
# Counts only: this catches a dropped or duplicated dispatch, not a
# swap of one name for another.
if [ "$((found + ${#skipped[@]}))" -ne "$discovered" ]; then
    echo "litmask: test-examples — accounted for $((found + ${#skipped[@]})) of" \
        "$discovered examples (ran $found, skipped ${#skipped[@]});" \
        "an example was discovered but never dispatched" >&2
    exit 1
fi
