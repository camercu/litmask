//! `#[mask_all(strict)]` upgrades the pattern-position skip warning
//! to a hard compile error (§2.3.3.1). The fixture must fail to
//! compile and the error text must identify the skip reason by its tag
//! (pinned by the paired `.stderr` snapshot).

use litmask::mask_all;

#[mask_all(strict)]
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
