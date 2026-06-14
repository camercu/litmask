//! Governed masking (ADR-0001 UC3): a host installs one **governing
//! provider** and the lazy path unlocks every masking crate's wrapper
//! through it — even wrappers the host never names — provided all were
//! sealed under the same unlock key (**uniform seal**).
//!
//! Built purely in memory (mirroring `litmask_build::emit()` for the
//! External tier), driving the runtime seams directly — no `mask!()`, no
//! `OUT_DIR`. The process-global governor is install-once, so this file
//! holds a single installed governor.

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
fn governor_unlocks_a_second_crates_wrapper() {
    // Uniform seal: both crates sealed under the same external unlock key,
    // each with its own mask key + wrapper nonce.
    let unlock = [0x5Au8; KEY_LEN];
    let host_mask = [0x11u8; KEY_LEN];
    let lib_mask = [0x22u8; KEY_LEN];
    let host_wrapper = build_wrapper(&unlock, &host_mask, &[0xA0u8; KEY_LEN]);
    let lib_wrapper = build_wrapper(&unlock, &lib_mask, &[0xB0u8; KEY_LEN]);
    let lib_blob = build_blob(&lib_mask, &[7u8; NONCE_LEN], b"transitive-secret");

    // Host governs the graph with one provider, naming only its own wrapper.
    __govern_external(FixedKey(unlock), &host_wrapper).expect("install governor");

    // The transitive crate's wrapper — never named by the host — unlocks
    // lazily through the governing provider.
    assert_eq!(
        __decrypt(&lib_blob, &lib_wrapper, "external"),
        b"transitive-secret"
    );
}
