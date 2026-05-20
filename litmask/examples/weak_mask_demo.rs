//! `weak_mask!` vs `mask!` — when to use each.
//!
//! `weak_mask!` is anti-`strings(1)` only: the obfuscated bytes AND
//! the XOR key both live in the same binary, so a disassembler
//! recovers the plaintext trivially. Use it ONLY for the bootstrap
//! window before `init!()` runs (env var names, default file paths
//! — strings that must be readable before the AEAD key cell is
//! populated). Real secrets always use `mask!`.
//!
//! Both calls below run end-to-end; both fixture phrases are
//! absent from the compiled `.rodata` so the strings/grep recipe
//! in `hello_world.rs` reports nothing.

use litmask::{mask, weak_mask};

fn main() {
    // Weak: appropriate for non-secret config strings that need to
    // be readable before `init!()`. Recoverable by Level-2
    // (disassembler) attackers.
    println!(
        "weak={}",
        weak_mask!("yellow-velvet-tortoise-9c4f1a — fixture")
    );

    // Strong: appropriate for actual secrets. AEAD-encrypted; the
    // mask_key is itself encrypted under the unlock_key supplied by
    // a runtime `KeyProvider`.
    println!("strong={}", mask!("emerald-puma-c2d8f4 — strong fixture"));
}
