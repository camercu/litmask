//! Runtime benchmarks for litmask.
//!
//! - `decrypt_masked` vs the two baselines (size-swept): steady-state
//!   cost of a `mask!`-style access. `decrypt_masked` returns the owned
//!   `String` that masking produces — AEAD open *and* its heap alloc,
//!   both real per-access costs. Two baselines bracket the comparison:
//!     - `plain_baseline` (`&'static str`, ~0): what a no-litmask user
//!       writes when they only read the literal. The gap to it is
//!       litmask's *total* overhead, allocation included.
//!     - `plain_owned` (`"…".to_string()`): the allocation a user pays
//!       anyway when they need an owned `String`. The gap from it to
//!       `decrypt_masked` isolates the *pure crypto* cost.
//! - `decrypt_masked_stack_*`: the zero-alloc `mask_stack!` path —
//!   decrypts into an inline `MaskStr<N>` with no heap allocation. The gap
//!   to `decrypt_masked` at the same size is the allocation `mask!` pays;
//!   the gap to `plain_baseline` is `mask_stack!`'s total overhead.
//! - `first_use_unlock`: the one-time cost paid on the first masked
//!   access for a wrapper — recover the `mask_key` (provider KDF + wrapper
//!   AEAD-open) and cache it. It runs the real production path cold by
//!   clearing the process-global cache before each sample. The number
//!   also includes one 16-byte blob decrypt + alloc; subtract the 16-byte
//!   `decrypt_masked` point to isolate the pure unlock.
//!
//! `init!(provider)` governor install is not benched separately: its cost
//! is the eager first-use unlock above plus a process-global cell store
//! (a few ns), so `first_use_unlock` already captures it.
//!
//! Run via `just bench` (sets `LITMASK_UNLOCK_KEY` for build + run).

use litmask::{EnvVarProvider, MaskStr, init};

fn main() {
    // One process-global governor for the whole run; the lazy path then
    // unlocks the fixture wrapper on first `mask!`.
    init!(EnvVarProvider::default()).expect("External-tier unlock");
    divan::main();
}

#[divan::bench(args = [16usize, 256, 4096])]
fn decrypt_masked(n: usize) -> String {
    match n {
        16 => litmask_bench::masked_16(),
        256 => litmask_bench::masked_256(),
        4096 => litmask_bench::masked_4096(),
        _ => unreachable!(),
    }
}

#[divan::bench(args = [16usize, 256, 4096])]
fn plain_baseline(n: usize) -> &'static str {
    match n {
        16 => litmask_bench::PLAIN_16,
        256 => litmask_bench::PLAIN_256,
        4096 => litmask_bench::PLAIN_4096,
        _ => unreachable!(),
    }
}

#[divan::bench(args = [16usize, 256, 4096])]
fn plain_owned(n: usize) -> String {
    match n {
        16 => litmask_bench::PLAIN_16.to_owned(),
        256 => litmask_bench::PLAIN_256.to_owned(),
        4096 => litmask_bench::PLAIN_4096.to_owned(),
        _ => unreachable!(),
    }
}

// Stack-backed decrypt at each size. Returning the `MaskStr<N>` lets divan
// drop it outside the timed region, matching how `decrypt_masked` excludes
// the `String` drop — so the comparison is decrypt-only on both sides. `N`
// is a compile-time const, so the sizes are three functions, not an arg
// sweep.
#[divan::bench]
fn decrypt_masked_stack_16() -> MaskStr<16> {
    litmask_bench::masked_stack_16()
}

#[divan::bench]
fn decrypt_masked_stack_256() -> MaskStr<256> {
    litmask_bench::masked_stack_256()
}

#[divan::bench]
fn decrypt_masked_stack_4096() -> MaskStr<4096> {
    litmask_bench::masked_stack_4096()
}

// `sample_size = 1` is load-bearing: divan runs the input generator
// `sample_size` times *before* the timed loop, so only at size 1 is each
// timed call actually cold. The generator (untimed) clears the cache; the
// timed closure then pays the full first-use unlock through the real path.
#[divan::bench(sample_size = 1, sample_count = 1000)]
fn first_use_unlock(bencher: divan::Bencher) {
    bencher
        .with_inputs(litmask::test_util::reset_mask_key_cache)
        .bench_values(|()| litmask_bench::masked_16());
}
