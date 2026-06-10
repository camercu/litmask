#!/bin/sh
# Nightly dependency-fingerprint scrub for litmask CI.
#
# Regression net for the nightly hardening recipe documented in
# docs/DEPLOYMENT.md ("Removing dependency fingerprints"). The stable
# `strip = "symbols"` profile leaves `.rodata` panic-location path
# strings such as `.../blake3-1.8.5/src/lib.rs` and litmask's own
# `litmask/src/runtime.rs`; the example_scrub integration test
# allow-lists `blake3` for exactly this reason. The two nightly flags
# below blank those strings for every crate compiled in-build. This
# script proves the recipe still works, so a toolchain or dependency
# change that reintroduces the leak fails CI instead of silently
# eroding the documented guarantee.
#
# Target: the `machine_id_provider` example, the binary that carries
# the allow-listed `blake3` leak under the stable profile (it links
# `derive_machine_id_key`, the runtime BLAKE3 path).
#
# Requires a nightly toolchain (`-Zlocation-detail` / `-Zfmt-debug`
# are unstable). Run via `just scrub-hardened`.
set -eu

EXAMPLE="machine_id_provider"
BIN="target/release/examples/${EXAMPLE}"

# The example calls `init!(machine_id)`, which cross-checks its form
# against the build-sealed tier at macro-expansion time. Without a key
# channel the build seals the Embedded floor and the macro rejects the
# mismatch, so the Machine tier must be sealed by handing `emit()` a
# valid self-checking token on LITMASK_MACHINE_ID. This binary is only
# strings-scanned, never run, so the host-matching property is moot — any
# well-formed token suffices; source it through the canonical
# `show-machine-id` path. A host without a readable machine id (§1.6.5)
# cannot seal the tier, so skip cleanly rather than fail.
cargo +nightly build --release -p litmask-cli
if ! MACHINE_TOKEN="$(target/release/litmask show-machine-id 2>/dev/null)"; then
    echo "scrub-hardened: SKIP — machine id unavailable on this host" >&2
    exit 0
fi

# Both flags are nightly-only and apply to every crate compiled in
# this build (deps included). location-detail=none blanks panic
# file/line/column records; fmt-debug=none drops derive(Debug) name
# strings (e.g. StreamCipherError, MachineUidError).
RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none" \
    LITMASK_MACHINE_ID="${MACHINE_TOKEN}" \
    cargo +nightly build --release \
    -p litmask --features machine-id --example "${EXAMPLE}"

if [ ! -f "${BIN}" ]; then
    echo "scrub-hardened: build did not produce ${BIN}" >&2
    exit 1
fi

# Each pattern is a fingerprint the stable profile leaks and the
# hardening recipe must remove. `blake3` is the allow-listed leak from
# example_scrub; the litmask path tells expose the crate itself.
fail=0
for pattern in 'blake3' 'litmask/src' 'litmask-internal'; do
    hits=$(strings -n 4 "${BIN}" | grep -ic "${pattern}" || true)
    if [ "${hits}" -ne 0 ]; then
        echo "scrub-hardened: FAIL — '${pattern}' present ${hits}x in ${BIN}" >&2
        strings -n 4 "${BIN}" | grep -i "${pattern}" | sort -u | sed 's/^/  /' >&2
        fail=1
    else
        echo "scrub-hardened: OK — '${pattern}' absent"
    fi
done

exit "${fail}"
