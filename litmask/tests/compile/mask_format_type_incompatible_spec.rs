//! Per-placeholder `format_args!` checks reject specs that cannot
//! apply to the supplied argument type. Hex (`{:x}`) requires
//! `LowerHex`, which `&str` does not implement — the failure
//! originates inside our generated check, locking the contract
//! that we do per-placeholder type validation.

use litmask::mask_format;

fn main() {
    let _ = mask_format!("{:x}", "not a number");
}
