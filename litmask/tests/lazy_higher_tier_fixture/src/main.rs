//! Higher-tier lazy-init refusal e2e fixture. Sealed at the `external`
//! tier (built with `LITMASK_UNLOCK_KEY` set) but deliberately calls
//! `mask!()` with NO `init!(...)` first. The first `mask!()` therefore
//! hits the lazy-init path, which must refuse to silently derive the
//! Embedded key on a higher-tier build and instead diverge with an
//! init-ordering diagnostic.

use litmask::mask;

fn main() {
    // No `init!(...)` ran — under an `external`-sealed build the lazy
    // Embedded path must refuse rather than derive the wrong key.
    println!("{}", mask!("lazy-higher-tier-canary-7d1e4b"));
}
