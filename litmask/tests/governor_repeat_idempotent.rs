//! Governed masking (ADR-0001 UC3), idempotency contract: installing the
//! governor twice is a no-op — the first governor wins and stays, so a
//! second `__govern_external` (even with a wrong key) returns Ok without
//! re-deriving or replacing it.
//!
//! Its own test binary because the governor is process-global
//! install-once: co-locating this with `governed_masking.rs` in one
//! process would make the two tests fight over a single install and turn
//! the outcome order-dependent. A separate integration file gets a fresh
//! process, so this test installs the governor itself and then re-installs.

#![cfg(feature = "std")]

use litmask::__internal::{__decrypt, __govern_external};
use litmask::{KeyError, KeyProvider, UnlockKey};
use litmask_internal::test_util::{build_blob, build_wrapper};
use litmask_internal::{KEY_LEN, NONCE_LEN, base64url};

/// Governing provider that hands back one fixed unlock key for every
/// wrapper — the uniform-seal External case.
struct FixedKey([u8; KEY_LEN]);

impl KeyProvider for FixedKey {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        UnlockKey::from_base64url(&base64url::encode(&self.0))
    }
}

#[test]
fn repeat_govern_is_idempotent() {
    let unlock = [0x5Au8; KEY_LEN];
    let host_mask = [0x11u8; KEY_LEN];
    let lib_mask = [0x22u8; KEY_LEN];
    let host_wrapper = build_wrapper(&unlock, &host_mask, &[0xA0u8; KEY_LEN]);
    let lib_wrapper = build_wrapper(&unlock, &lib_mask, &[0xB0u8; KEY_LEN]);
    let lib_blob = build_blob(&lib_mask, &[7u8; NONCE_LEN], b"transitive-secret");

    // Install the governor with the correct key.
    __govern_external(FixedKey(unlock), &host_wrapper).expect("install governor");

    // A second install with a deliberately wrong key must be a no-op: it
    // returns Ok and leaves the first governor in place, so the transitive
    // wrapper still unlocks through the original (correct) key.
    __govern_external(FixedKey([0xFFu8; KEY_LEN]), &host_wrapper).expect("repeat govern is Ok");
    assert_eq!(
        __decrypt(&lib_blob, &lib_wrapper, "external"),
        b"transitive-secret"
    );
}
