//! `MaskSerialize` must reject unions loudly — the plain serde derive
//! rejects them too, and silently degrading to cleartext names would
//! defeat the opt-in masking.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
union RawHandle {
    fd: i32,
    token: u32,
}

fn main() {}
