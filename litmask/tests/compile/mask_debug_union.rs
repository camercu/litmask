//! `MaskDebug` must reject unions loudly — the plain `Debug` derive
//! rejects them too, and silently degrading to cleartext names would
//! defeat the opt-in masking.

use litmask::MaskDebug;

#[derive(MaskDebug)]
union RawHandle {
    fd: i32,
    token: u32,
}

fn main() {}
