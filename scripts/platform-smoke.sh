#!/bin/sh
# Platform smoke test for litmask CI (§2.13.2).
#
# Usage: platform-smoke.sh <binary> <config> <cli> [--expect-unavailable]
#
# --expect-unavailable: expect bind to fail with EX_UNAVAILABLE (69),
#     validating the §2.13.2.4 failure path (stock OpenBSD).
set -eu

MARKER="greatly exaggerated"

BINARY="$1"
CONFIG="$2"
CLI="$3"
EXPECT_UNAVAILABLE=false
if [ "${4:-}" = "--expect-unavailable" ]; then
    EXPECT_UNAVAILABLE=true
fi

# §2.13.2.2 — marker must not be recoverable by strings(1).
# Falls back to grep -a on platforms without strings (Windows Git Bash).
assert_marker_absent() {
    if command -v strings >/dev/null 2>&1; then
        if strings "$1" | grep -q "$MARKER"; then
            echo "FAIL ($2): marker found by strings"
            exit 1
        fi
    else
        if grep -qa "$MARKER" "$1"; then
            echo "FAIL ($2): marker found by grep"
            exit 1
        fi
    fi
    echo "  ok: marker absent ($2)"
}

assert_marker_absent "$BINARY" "pre-bind"

# §2.13.2.3 / §2.13.2.4 — bind
bind_exit=0
"$CLI" bind "$BINARY" --config "$CONFIG" || bind_exit=$?

if [ "$EXPECT_UNAVAILABLE" = "true" ]; then
    if [ "$bind_exit" -ne 69 ]; then
        echo "FAIL: expected EX_UNAVAILABLE (69), got $bind_exit"
        exit 1
    fi
    echo "PASS: bind correctly returned EX_UNAVAILABLE (69)"
    exit 0
fi

if [ "$bind_exit" -ne 0 ]; then
    echo "FAIL: bind exited $bind_exit"
    exit 1
fi
echo "  ok: bind succeeded"

# Verify bound binary still decrypts correctly.
unlock_key=$(awk -F'"' '/^unlock_key/ {print $2}' "$CONFIG")
LITMASK_UNLOCK_KEY="$unlock_key" "$BINARY" | grep -q "$MARKER"
echo "  ok: bound binary output matches"

assert_marker_absent "$BINARY" "post-bind"

# §2.13.2.5 — rebind with different salt.
"$CLI" bind "$BINARY" --config "$CONFIG" --salt "cmViaW5kLXNhbHQ"
unlock_key=$(awk -F'"' '/^unlock_key/ {print $2}' "$CONFIG")
LITMASK_UNLOCK_KEY="$unlock_key" "$BINARY" | grep -q "$MARKER"
echo "  ok: rebind cycle passed"

echo "PASS: smoke test complete"
