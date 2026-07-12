#!/bin/sh
# Machine-tier platform smoke test for litmask CI (§2.13.2).
#
# Usage: platform-smoke.sh <cli> [--expect-unavailable | --expect-empty-id]
#
#   <cli>                 path to the built `litmask` CLI binary
#   --expect-unavailable  this host has no machine-uid mechanism (stock
#                         OpenBSD): assert show-machine-id exits 69 and the
#                         sealed binary's init!(machine_id) fails at runtime
#                         with EX_UNAVAILABLE (69) (§2.13.2.4), instead of
#                         treating it as a failure.
#   --expect-empty-id     this host has the mechanism but an empty
#                         machine-id (a bare systemd container, e.g.
#                         almalinux:9, where systemd-machine-id-setup has not
#                         run at boot): assert show-machine-id exits 69 and
#                         the sealed binary rejects the empty read as
#                         malformed key material, exiting EX_DATAERR (65)
#                         (§1.6.3) — distinct from the no-mechanism
#                         EX_UNAVAILABLE path above.
#
# Machine-tier keying is established at BUILD time: the example is built
# with LITMASK_MACHINE_ID set to this host's id (from `show-machine-id`),
# and init!(machine_id) re-derives the same key at runtime. There is no
# post-build bind step — the script seals and runs the prebuilt binary.
set -eu

# A unique substring of the masked Twain quote the machine_id_provider
# example prints — must match the example's literal (and the scrub
# substring in tests/example_scrub.rs).
MARKER="distort them as you please"

CLI="$1"
MODE=normal
case "${2:-}" in
    --expect-unavailable) MODE=unavailable ;;
    --expect-empty-id) MODE=empty-id ;;
    "") ;;
    *)
        echo "FAIL: unknown option: $2" >&2
        exit 2
        ;;
esac

EXE=""
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) EXE=".exe" ;;
esac
BIN="target/debug/examples/machine_id_provider${EXE}"

# §2.13.2.2 — marker must not be recoverable by strings(1). Falls back to
# grep -a on platforms without strings (Windows Git Bash).
assert_marker_absent() {
    if [ ! -f "$1" ]; then
        echo "FAIL: binary not found: $1"
        exit 1
    fi
    if command -v strings >/dev/null 2>&1; then
        if strings "$1" | grep -q "$MARKER"; then
            echo "FAIL: marker found by strings"
            exit 1
        fi
    else
        if grep -qa "$MARKER" "$1"; then
            echo "FAIL: marker found by grep"
            exit 1
        fi
    fi
    echo "  ok: marker absent in binary"
}

# Determine the build-time machine id from the canonical CLI path — the
# same value a consumer would seal against. On hosts without a stable id
# show-machine-id exits 69; seal under a placeholder so we can still build
# and exercise the runtime failure path (§2.13.2.4).
id_exit=0
MACHINE_ID="$("$CLI" show-machine-id 2>/dev/null)" || id_exit=$?

if [ "$MODE" != "normal" ]; then
    # Both a no-mechanism host (OpenBSD) and a present-but-empty host
    # (bare systemd container) report EX_UNAVAILABLE (69) here: the CLI
    # treats an empty `machine_uid` read as "no usable id" (§2.9.3). The
    # runtime paths then diverge, checked after the run below.
    if [ "$id_exit" -ne 69 ]; then
        echo "FAIL: expected show-machine-id EX_UNAVAILABLE (69), got $id_exit"
        exit 1
    fi
    echo "  ok: show-machine-id reported EX_UNAVAILABLE (69)"
    # No host id, but `emit()` requires the self-checking token form
    # (§4.1.1). Seal under a well-formed placeholder token so the build
    # still succeeds; the runtime `machine_uid::get()` on this host then
    # either fails (unavailable) or returns empty (empty-id), exercising
    # the corresponding init failure path. Value is
    # `litmask show-machine-id`'s token form for the id below
    # (raw_id ‖ "." ‖ base64url(BLAKE3(raw_id)[..5])).
    MACHINE_ID="unavailable-host-placeholder.9E6M3pc"
elif [ "$id_exit" -ne 0 ]; then
    echo "FAIL: show-machine-id failed ($id_exit) on a host expected to have a stable id"
    exit 1
fi

# Seal the example under the chosen machine id. LITMASK_MACHINE_ID is part
# of the build's rerun key, so this freshly seals the `machine` tier.
LITMASK_MACHINE_ID="$MACHINE_ID" \
    cargo build --features machine-id --example machine_id_provider
echo "  ok: machine-tier example sealed"

assert_marker_absent "$BIN"

# Run the prebuilt binary directly (never `cargo run`, which would reseal
# under a fresh build). The machine factor is re-sourced from the host.
run_exit=0
run_out="$("$BIN" 2>/dev/null)" || run_exit=$?

if [ "$MODE" != "normal" ]; then
    # A host that cannot supply a usable machine factor must fail init
    # cleanly and never leak the marker. The exact code names the cause:
    # a failed lookup is EX_UNAVAILABLE (69) (§2.13.2.4); an empty read is
    # malformed key material, EX_DATAERR (65) (§1.6.3).
    case "$MODE" in
        unavailable) want=69; why="machine-uid lookup failed" ;;
        empty-id) want=65; why="empty machine-uid rejected as malformed material" ;;
    esac
    if [ "$run_exit" -ne "$want" ]; then
        echo "FAIL: expected exit $want ($why), got $run_exit"
        exit 1
    fi
    if printf '%s' "$run_out" | grep -q "$MARKER"; then
        echo "FAIL: marker leaked despite machine binding failure"
        exit 1
    fi
    echo "PASS: machine-tier init failed cleanly (exit $want) — $why"
    exit 0
fi

# §2.13.2.3 — sealed and run on the same host: the binary opens and prints
# the marker.
if [ "$run_exit" -ne 0 ]; then
    echo "FAIL: sealed binary exited $run_exit on its own host"
    exit 1
fi
if ! printf '%s' "$run_out" | grep -q "$MARKER"; then
    echo "FAIL: sealed binary did not print the expected marker"
    exit 1
fi
echo "  ok: sealed binary output matches on its own host"

echo "PASS: smoke test complete"
