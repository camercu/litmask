#!/usr/bin/env bash
set -euo pipefail
# Build first so the canonical `litmask.config` exists before any
# example runs (the build script writes it).
cargo build --workspace --examples
unlock_key=$(awk -F'"' '/^unlock_key/ {print $2}' target/debug/litmask.config)
found=0
for src in litmask/examples/*.rs; do
    name=$(basename "$src" .rs)
    # `machine_id_provider` requires the `machine-id` feature and a
    # `machine`-tier build seal (LITMASK_MACHINE_ID set), and only
    # decrypts on the host whose id matches that seal — so this
    # default-feature loop can neither build nor run it. The masking
    # property of the built binary is exercised instead by
    # `litmask/tests/example_scrub.rs::machine_id_provider_example_*`,
    # and the full runtime round-trip by
    # `litmask/tests/machine_tier_e2e.rs`.
    if [ "$name" = "machine_id_provider" ]; then
        continue
    fi
    echo "litmask: test-examples — running $name"
    # `masked_serde_demo` requires the `unstable-serde` feature
    # (EXPERIMENTAL); it is Embedded-tier like the plain examples, so
    # the same env-stripping applies — only the feature flag differs.
    if [ "$name" = "masked_serde_demo" ]; then
        env -u LITMASK_UNLOCK_KEY -u LITMASK_MACHINE_ID \
            cargo run --quiet --features unstable-serde --example "$name"
        found=$((found + 1))
        continue
    fi
    # Seal-tier hinges on env presence: setting LITMASK_UNLOCK_KEY at
    # build selects the External tier and reseals the shared wrapper.
    # So only the runtime-sourced examples (`init_with!` providers) may
    # run with it set — the build then seals under the same material
    # the provider reads back. Embedded examples MUST run with it unset:
    # under an External reseal the keyless lazy path can no longer open
    # the wrapper, and a no-arg `init!()` would fail its tier
    # cross-check at compile time.
    if grep -q 'init_with!' "$src"; then
        # Export the canonical name AND the custom name `weak_mask_demo`
        # reads (`MYAPP_SECRET_KEY`); the extra binding is a harmless
        # superset for `file_provider`. The example's own scrub asserts
        # the custom name is absent from the binary, so the weak_mask!
        # hiding stays verifiable end-to-end.
        LITMASK_UNLOCK_KEY="$unlock_key" \
        MYAPP_SECRET_KEY="$unlock_key" \
            cargo run --quiet --example "$name"
    else
        # Strip any inherited factor env so the build stays Embedded.
        env -u LITMASK_UNLOCK_KEY -u LITMASK_MACHINE_ID \
            cargo run --quiet --example "$name"
    fi
    found=$((found + 1))
done
if [ "$found" -eq 0 ]; then
    echo "litmask: test-examples — no examples discovered under litmask/examples/" >&2
    exit 1
fi
