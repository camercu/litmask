//! Per-placeholder `write_fmt` / `format_args!` rejects specs that
//! cannot apply to the supplied argument type. Hex (`{:x}`) requires
//! `LowerHex`, which `&str` does not implement — the failure
//! originates inside the generated per-placeholder write, locking
//! the contract that we do per-placeholder type validation.

use litmask::mask_format;

fn main() {
    let _ = mask_format!("{:x}", "not a number");
}
