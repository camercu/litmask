//! A string literal in a `const` initializer must produce a
//! "skipped literal: const_initializer" deprecation warning.
//! `#![deny(deprecated)]` makes that warning a hard error so
//! trybuild can snapshot the exact text — locks the reason tag
//! against drift.

#![deny(deprecated)]

use litmask::mask_all;

#[mask_all]
mod fixture {
    pub const SLUG: &str = "compile-time-only";
}

fn main() {
    let _ = fixture::SLUG;
}
