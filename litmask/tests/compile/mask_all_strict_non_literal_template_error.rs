//! `#[mask_all(strict)]` upgrades the §2.3.2.2 non-literal-template
//! format warning to a hard compile error (§2.3.3.1). `concat!(...)`
//! is a macro expansion, not a `LitStr` at the syn-parse layer, so
//! the walker cannot mask the template bytes — strict mode must
//! fail loudly rather than silently emit the original `format!` call.

use litmask::mask_all;

#[mask_all(strict)]
mod fixture {
    pub fn fixture(n: u32) -> String {
        format!(concat!("x=", "{}"), n)
    }
}

fn main() {
    let _ = fixture::fixture(1);
}
