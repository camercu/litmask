#!/usr/bin/env bash
set -euo pipefail
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
embedded=""      # keyless lazy path; factor env MUST be unset
serde_group=""   # Embedded + `unstable-serde`
stack_group=""   # Embedded + `unstable-stack`
envelope=""      # External, but sealed under a FIXED plaintext (see below)
external=""      # External, sealed under the freshly minted `unlock_key`
skipped=""
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
    machine_id_provider) skipped="$skipped $name" ;;
    # `mask_serde_demo` requires the `unstable-serde` feature
    # (EXPERIMENTAL); it is Embedded-tier like the plain examples, so
    # the same env-stripping applies — only the feature flag differs.
    mask_serde_demo) serde_group="$serde_group $name" ;;
    # `stack_demo` requires the `unstable-stack` feature; it is
    # Embedded-tier like the plain examples, so the same env-stripping
    # applies — only the feature flag differs.
    stack_demo) stack_group="$stack_group $name" ;;
    # `envelope_provider` embeds a *wrapped* copy of its unlock material and
    # unwraps it at runtime through a stub HSM (no env read at run time). The
    # embedded blob decrypts to a FIXED plaintext, so the build must seal
    # under that same plaintext — not the freshly-minted `keygen` value the
    # generic External group uses. Its masking property is scrubbed by
    # `tests/example_scrub.rs::envelope_provider_*`.
    envelope_provider) envelope="$envelope $name" ;;
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
            external="$external $name"
        else
            embedded="$embedded $name"
        fi
        ;;
    esac
done

found=0
run() {
    echo "litmask: test-examples — running $1"
    found=$((found + 1))
}

# Strip any inherited factor env so the build stays Embedded.
for name in $embedded; do
    run "$name"
    env -u LITMASK_UNLOCK_KEY -u LITMASK_MACHINE_ID \
        cargo run --quiet --example "$name"
done
for name in $serde_group; do
    run "$name"
    env -u LITMASK_UNLOCK_KEY -u LITMASK_MACHINE_ID \
        cargo run --quiet --features unstable-serde --example "$name"
done
for name in $stack_group; do
    run "$name"
    env -u LITMASK_UNLOCK_KEY -u LITMASK_MACHINE_ID \
        cargo run --quiet --features unstable-stack --example "$name"
done
for name in $envelope; do
    run "$name"
    LITMASK_UNLOCK_KEY="envelope-demo-unlock-material-do-not-reuse" \
        cargo run --quiet --features provider-examples --example "$name"
done
# Export the canonical name AND the custom name `weak_mask_demo` reads
# (`MYAPP_SECRET_KEY`); the extra binding is a harmless superset for
# `file_provider`. The example's own scrub asserts the custom name is
# absent from the binary, so the weak_mask! hiding stays verifiable
# end-to-end. `--features provider-examples` satisfies the examples'
# `required-features` gate (they are skipped by the default build); with
# LITMASK_UNLOCK_KEY set the build reseals External, so `init!(provider)`
# passes its form↔tier cross-check.
for name in $external; do
    run "$name"
    LITMASK_UNLOCK_KEY="$unlock_key" \
    MYAPP_SECRET_KEY="$unlock_key" \
        cargo run --quiet --features provider-examples --example "$name"
done

if [ "$found" -eq 0 ]; then
    echo "litmask: test-examples — no examples discovered under litmask/examples/" >&2
    exit 1
fi
# Every discovered example must be either run or explicitly skipped. The
# classifier routes by name, so a new example that no branch claims (or a
# group left unrun by a future edit) would otherwise vanish silently —
# this script is the only place several examples are executed at all.
skipped_count=$(printf '%s' "$skipped" | wc -w | tr -d ' ')
if [ "$((found + skipped_count))" -ne "$discovered" ]; then
    echo "litmask: test-examples — accounted for $((found + skipped_count)) of" \
        "$discovered examples (ran $found, skipped $skipped_count); an example" \
        "was discovered but never dispatched" >&2
    exit 1
fi
