//! Transparent-masking spike (ADR-0001): two **masking crates** —
//! each built with its own **mask key** and **wrapper** — must decrypt
//! their own blobs independently in one process. The former single
//! set-once mask-key cell made the first wrapper win and the second
//! panic; the per-wrapper **mask-key cache** lets them coexist.
//!
//! The test builds two Embedded wrappers + blobs purely in memory
//! (mirroring `litmask_build::emit()`), then drives the runtime decrypt
//! entry point `__decrypt` directly — no `mask!()`, no `OUT_DIR`.

#![cfg(feature = "std")]

use litmask_internal::test_util::{build_blob, build_embedded_wrapper};
use litmask_internal::{KEY_LEN, NONCE_LEN};

#[test]
fn two_masking_crates_decrypt_independently() {
    // Two independent masking crates: distinct seeds → distinct wrapper
    // nonces → distinct mask keys + wrappers.
    let mask_key_a = [0x11u8; KEY_LEN];
    let mask_key_b = [0x22u8; KEY_LEN];
    let wrapper_a = build_embedded_wrapper(&mask_key_a, &[0xAAu8; KEY_LEN]);
    let wrapper_b = build_embedded_wrapper(&mask_key_b, &[0xBBu8; KEY_LEN]);
    let blob_a = build_blob(&mask_key_a, &[1u8; NONCE_LEN], b"alpha-secret-quux");
    let blob_b = build_blob(&mask_key_b, &[2u8; NONCE_LEN], b"bravo-secret-zzyx");

    // Same process, same global cache. The per-wrapper cache derives and
    // caches each crate's mask key under its own wrapper nonce; the old
    // single cell would cache crate A's key and fail crate B's AEAD tag.
    let a = litmask::__internal::__decrypt(&blob_a, &wrapper_a, "embedded");
    let b = litmask::__internal::__decrypt(&blob_b, &wrapper_b, "embedded");

    assert_eq!(a, b"alpha-secret-quux");
    assert_eq!(b, b"bravo-secret-zzyx");

    // Re-decrypting through the cached entries stays correct (and crate
    // A's key is unaffected by crate B having been cached after it).
    let a_again = litmask::__internal::__decrypt(&blob_a, &wrapper_a, "embedded");
    assert_eq!(a_again, b"alpha-secret-quux");
}
