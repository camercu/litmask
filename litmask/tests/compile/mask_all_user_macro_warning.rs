//! A literal string argument to an unrecognized (user-defined)
//! macro inside `#[mask_all]` is left unmasked and emits a "skipped
//! literal: unrecognized_macro" deprecation warning.
//! `#![deny(deprecated)]` upgrades the warning to a hard error so
//! trybuild snapshots the exact text — locks the reason tag against
//! drift.

#![deny(deprecated)]

use litmask::mask_all;

macro_rules! my_user_macro {
    ($s:literal) => {
        $s
    };
}

#[mask_all]
mod fixture {
    pub fn fixture() -> &'static str {
        my_user_macro!("user-defined-literal")
    }
}

fn main() {
    let _ = fixture::fixture();
}
