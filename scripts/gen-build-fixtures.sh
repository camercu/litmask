#!/usr/bin/env bash
set -euo pipefail
# Generate standalone fixture crates for the build-time benchmark
# (`just bench-build`). For each call-site count N, emits a `masked_N`
# crate (N `mask!` sites + a build.rs sealing the Embedded tier) and a
# `plain_N` twin (N plain string literals, no litmask). Comparing the two
# at each N isolates litmask's build cost; the slope across N gives the
# per-call-site overhead.
#
# Embedded tier is deliberate: the fixtures are only ever *compiled* by
# the benchmark, never run, so no unlock key or `init!` is needed and the
# build takes no environment setup.
#
# Output lives under a gitignored dir; regenerated (idempotently) on every
# `just bench-build`, so the 1000-line sources are never committed.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/benches/build-fixtures"
sizes=(10 100 1000)

rm -rf "$out"

emit_main() {
    # $1 = mode (masked|plain), $2 = N, $3 = target file
    local mode="$1" n="$2" file="$3"
    {
        echo "fn main() {"
        echo "    let mut acc = 0usize;"
        local i
        for ((i = 0; i < n; i++)); do
            if [ "$mode" = masked ]; then
                echo "    acc += litmask::mask!(\"bench-build-literal-$i\").len();"
            else
                echo "    acc += \"bench-build-literal-$i\".len();"
            fi
        done
        echo "    std::hint::black_box(acc);"
        echo "}"
    } >"$file"
}

for n in "${sizes[@]}"; do
    # ── masked_N ────────────────────────────────────────────
    dir="$out/masked_$n"
    mkdir -p "$dir/src"
    # Empty `[workspace]` table detaches the fixture from the litmask
    # workspace so it builds (and `cargo clean`s) in isolation.
    cat >"$dir/Cargo.toml" <<EOF
[workspace]

[package]
name = "bench_build_masked_$n"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
litmask = { path = "../../../litmask" }

[build-dependencies]
litmask-build = { path = "../../../litmask-build" }
EOF
    echo 'fn main() { litmask_build::emit(); }' >"$dir/build.rs"
    emit_main masked "$n" "$dir/src/main.rs"

    # ── plain_N ─────────────────────────────────────────────
    dir="$out/plain_$n"
    mkdir -p "$dir/src"
    cat >"$dir/Cargo.toml" <<EOF
[workspace]

[package]
name = "bench_build_plain_$n"
version = "0.0.0"
edition = "2024"
publish = false
EOF
    emit_main plain "$n" "$dir/src/main.rs"
done

echo "generated build fixtures under $out: masked_/plain_ × ${sizes[*]}"
