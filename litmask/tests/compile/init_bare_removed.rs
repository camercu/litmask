//! Bare `init!()` was removed (ADR-0001): the keyless Embedded tier
//! self-initializes on the first `mask!()`, so the no-argument form no
//! longer exists. The grammar check rejects it before any tier read, so
//! this fails regardless of the leaked `LITMASK_SEAL_TIER`.

use litmask::init;

fn main() {
    let _ = init!();
}
