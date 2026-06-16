//! Runtime benchmarks for litmask.
//!
//! - `decrypt_masked` vs `plain_baseline` (size-swept): steady-state cost
//!   of a `mask!`-style access. `decrypt_masked` returns the owned
//!   `String` that masking produces — AEAD open *and* its heap alloc,
//!   both real per-access costs — against the `&'static str` a no-litmask
//!   user would write (zero). The gap is the true cost of adopting
//!   litmask, allocation included.
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

use litmask::{EnvVarProvider, init};

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
        _ => litmask_bench::masked_4096(),
    }
}

#[divan::bench(args = [16usize, 256, 4096])]
fn plain_baseline(n: usize) -> &'static str {
    match n {
        16 => litmask_bench::PLAIN_16,
        256 => litmask_bench::PLAIN_256,
        _ => litmask_bench::PLAIN_4096,
    }
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
