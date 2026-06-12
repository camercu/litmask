//! Init-after-lazy fail-fast e2e fixture. Sealed at the Embedded floor
//! and deliberately calls `mask!()` BEFORE `init!()`: the first `mask!()`
//! lazily initializes the runtime, so the late `init!()` arrives after
//! the fact. On Embedded the lazy key equals the `init!()` key, so the
//! bug is functionally invisible today — but it bites the moment the
//! consumer reseals at a higher tier. A debug build must therefore
//! diverge at the late `init!()` with an init-ordering diagnostic
//! instead of silently returning `Ok(())`.

use litmask::{init, mask};

fn main() {
    // Lazy init fires here — legal on an Embedded seal.
    println!("{}", mask!("init-after-lazy-pre-canary-4c8d1f"));
    // Too late: the mask key was already lazily installed. Debug builds
    // must panic here naming the ordering bug.
    init!().unwrap();
    println!("init-after-lazy-post-canary-9b2e7a");
}
