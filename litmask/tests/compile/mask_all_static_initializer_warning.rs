//! §2.3.1.4: a string literal in a `static` initializer must produce
//! a "skipped literal: static_initializer" deprecation warning.
//! `#![deny(deprecated)]` makes that warning a hard error so
//! trybuild can snapshot the exact text — locks the reason tag
//! against drift.

#![deny(deprecated)]

use litmask::mask_all;

#[mask_all]
mod fixture {
    pub static GREETING: &str = "hello-static";
}

fn main() {
    let _ = fixture::GREETING;
}
