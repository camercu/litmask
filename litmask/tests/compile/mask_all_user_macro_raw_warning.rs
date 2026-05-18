//! Raw string literal arguments to user-defined macros emit the same
//! `unrecognized_macro` warning as quoted forms. Pre-fix,
//! `count_string_literal_tokens` matched literal prefixes via
//! `starts_with('"')` / `b"` / `c"`, so `r"..."`, `br"..."`, `cr"..."`
//! slipped through unwarned.

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
        my_user_macro!(r"raw-user-literal")
    }
}

fn main() {
    let _ = fixture::fixture();
}
