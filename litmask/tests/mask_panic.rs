//! Integration tests for the masked panic family: `mask_panic!`,
//! `mask_todo!`, `mask_unimplemented!`, `mask_unreachable!`.
//!
//! Each is a thin wrapper around `mask_format!` that forwards the
//! decrypted string to the corresponding `core` panic macro. The
//! stdlib macro's own boilerplate prefix (e.g. `todo!`'s "not yet
//! implemented: ") stays in cleartext — it is ubiquitous stdlib text,
//! not a user secret. These tests verify the decrypted message reaches
//! the panic payload with that prefix intact, and that the bare,
//! template-less forms forward to the unprefixed stdlib default.
//!
//! Format-string correctness is locked by `mask_format.rs`; here we
//! assert the panic payload via `catch_unwind` (see `common::assert_panic_msg`).

mod common;

use common::assert_panic_msg;
use litmask::{mask_panic, mask_todo, mask_unimplemented, mask_unreachable};

// ── mask_panic! ─────────────────────────────────────────────────

#[test]
fn mask_panic_static_message_has_no_prefix() {
    let msg = assert_panic_msg(|| mask_panic!("detonation-sequence-omega"));
    assert_eq!(msg, "detonation-sequence-omega");
}

#[test]
fn mask_panic_format_args() {
    let msg = assert_panic_msg(|| mask_panic!("code {}", 7));
    assert_eq!(msg, "code 7");
}

#[test]
fn mask_panic_bare_forwards_to_default() {
    let msg = assert_panic_msg(|| mask_panic!());
    assert_eq!(msg, "explicit panic");
}

// ── mask_todo! ──────────────────────────────────────────────────

#[test]
fn mask_todo_message_keeps_stdlib_prefix() {
    let msg = assert_panic_msg(|| mask_todo!("wire-up-the-thing"));
    assert_eq!(msg, "not yet implemented: wire-up-the-thing");
}

#[test]
fn mask_todo_bare_forwards_to_default() {
    let msg = assert_panic_msg(|| mask_todo!());
    assert_eq!(msg, "not yet implemented");
}

// ── mask_unimplemented! ─────────────────────────────────────────

#[test]
fn mask_unimplemented_message_keeps_stdlib_prefix() {
    let msg = assert_panic_msg(|| mask_unimplemented!("variant-not-handled"));
    assert_eq!(msg, "not implemented: variant-not-handled");
}

#[test]
fn mask_unimplemented_bare_forwards_to_default() {
    let msg = assert_panic_msg(|| mask_unimplemented!());
    assert_eq!(msg, "not implemented");
}

// ── mask_unreachable! ───────────────────────────────────────────

#[test]
fn mask_unreachable_message_keeps_stdlib_prefix() {
    let msg = assert_panic_msg(|| mask_unreachable!("parser-invariant-broken"));
    assert_eq!(
        msg,
        "internal error: entered unreachable code: parser-invariant-broken"
    );
}

#[test]
fn mask_unreachable_bare_forwards_to_default() {
    let msg = assert_panic_msg(|| mask_unreachable!());
    assert_eq!(msg, "internal error: entered unreachable code");
}
