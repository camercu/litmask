//! In-memory wrapper/blob builders mirroring `litmask_build::emit()`,
//! shared across crates for tests.
//!
//! These let a test assemble the exact wire shapes (`wrapper`, per-string
//! `blob`) the build script would emit, but purely in memory — no
//! `OUT_DIR`, no `build.rs`. Exposed under the `test-util` feature so
//! downstream test targets (the transparent- and governed-masking
//! integration tests) can drive the runtime decrypt path against wrappers
//! they construct directly, rather than only the ones a real build
//! produced.
//!
//! Building these requires a selected cipher (`CURRENT_CIPHER`); enable
//! `test-util` alongside a cipher feature.

// Test helpers: the `.expect()`s fire only if the AEAD primitive fails on
// fixed-size, well-formed inputs — impossible in practice, and a panic is
// the right outcome in a test build anyway. No per-fn `# Panics` doc.
#![allow(clippy::missing_panics_doc)]

use crate::{
    CURRENT_CIPHER, EMBEDDED_UNLOCK_DERIVATION_CONTEXT, FormatVersion, KEY_LEN, NONCE_LEN,
    WRAPPER_BODY_LEN, WRAPPER_LEN, WRAPPER_PLAINTEXT_LEN, aead_encrypt, assemble_wrapper,
    derive_embedded_unlock_key, nonce_for_wrapper,
};

/// Seal a wrapper for `mask_key` under an explicit `unlock_key`: `nonce
/// || AEAD(version || mask_key)`, with the nonce derived from `seed`. The
/// shape `emit()` writes for the External/Machine tiers and every
/// `init!` seam reopens.
#[must_use]
pub fn build_wrapper(
    unlock_key: &[u8; KEY_LEN],
    mask_key: &[u8; KEY_LEN],
    seed: &[u8; KEY_LEN],
) -> [u8; WRAPPER_LEN] {
    let nonce = nonce_for_wrapper(seed);
    let mut plaintext = [0u8; WRAPPER_PLAINTEXT_LEN];
    plaintext[0] = FormatVersion::CURRENT.to_byte();
    plaintext[1..].copy_from_slice(mask_key);
    let body = aead_encrypt(CURRENT_CIPHER, unlock_key, &nonce, &plaintext).expect("seal wrapper");
    let body: &[u8; WRAPPER_BODY_LEN] = body
        .as_slice()
        .try_into()
        .expect("AEAD output of WRAPPER_PLAINTEXT_LEN plaintext is WRAPPER_BODY_LEN bytes");
    assemble_wrapper(&nonce, body)
}

/// Seal an Embedded-tier wrapper for `mask_key`: same shape as
/// [`build_wrapper`], but the keyless unlock key is derived from the
/// wrapper's own nonce (the tier `emit()` selects when no key channel is
/// present, and `EmbeddedProvider` reopens).
#[must_use]
pub fn build_embedded_wrapper(mask_key: &[u8; KEY_LEN], seed: &[u8; KEY_LEN]) -> [u8; WRAPPER_LEN] {
    let nonce = nonce_for_wrapper(seed);
    let unlock_key = derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &nonce);
    build_wrapper(&unlock_key, mask_key, seed)
}

/// Seal a per-string blob (`nonce || AEAD(plaintext)`) under `mask_key`,
/// the shape every `mask!()` expansion embeds.
#[must_use]
pub fn build_blob(
    mask_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> alloc::vec::Vec<u8> {
    let body = aead_encrypt(CURRENT_CIPHER, mask_key, nonce, plaintext).expect("seal blob");
    let mut blob = alloc::vec::Vec::with_capacity(NONCE_LEN + body.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&body);
    blob
}
