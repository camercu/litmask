//! §2.3.1.4: each skipped literal under `#[mask_all]` emits a
//! ghost-deprecation warning identifying the reason. Pinning the
//! warning under `#[deny(deprecated)]` turns it into a compile
//! error so trybuild can snapshot the message text — that locks
//! the §2.3.1.4 wording against accidental drift.

#![deny(deprecated)]

use litmask::mask_all;

#[mask_all]
mod fixture {
    pub fn classify(x: &str) -> u32 {
        match x {
            "alpha" => 1,
            _ => 0,
        }
    }
}

fn main() {
    let _ = fixture::classify("alpha");
}
