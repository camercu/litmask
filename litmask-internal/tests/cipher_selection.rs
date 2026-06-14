//! Cipher selection (§1.5.1, §2.7.1) — the feature-gated default for
//! the runtime crate is ChaCha20-Poly1305; `--features aes-gcm`
//! (alongside `--no-default-features`) flips to AES-256-GCM.
//!
//! These tests live at the `litmask-internal` boundary so they pin
//! the wire format invariants without going through the runtime
//! crate's macro layer.

#[cfg(any(feature = "chacha20-poly1305", feature = "aes-gcm"))]
#[allow(unused_imports)]
use litmask_internal::CURRENT_CIPHER;
#[allow(unused_imports)]
use litmask_internal::{CipherId, FormatVersion, KEY_LEN, NONCE_LEN, aead_decrypt, aead_encrypt};

#[test]
fn format_version_v1_byte_is_0x01() {
    // The wrapper's version byte is on the wire and load-bearing: the
    // runtime validates it after decrypting the wrapper, and every future
    // cross-version migration keys off it. A discriminant swap on
    // `FormatVersion::V1` would break wire compatibility silently; the
    // unit test in lib.rs covers it inside the crate, this one covers it
    // across the public boundary so a renamed-or-deleted re-export also
    // surfaces here.
    assert_eq!(FormatVersion::V1.to_byte(), 0x01);
    assert_eq!(FormatVersion::CURRENT.to_byte(), 0x01);
}

#[test]
#[cfg(all(feature = "chacha20-poly1305", not(feature = "aes-gcm")))]
fn current_cipher_default_is_chacha20_poly1305() {
    assert_eq!(CURRENT_CIPHER, CipherId::ChaCha20Poly1305);
}

#[test]
#[cfg(all(feature = "aes-gcm", not(feature = "chacha20-poly1305")))]
fn current_cipher_aes_gcm_selects_aes256gcm() {
    assert_eq!(CURRENT_CIPHER, CipherId::Aes256Gcm);
}

#[test]
#[cfg_attr(not(feature = "aes-gcm"), ignore = "requires aes-gcm feature")]
fn aes_gcm_aead_round_trips() {
    let key = [0x11u8; KEY_LEN];
    let nonce = [0x22u8; NONCE_LEN];
    let plaintext = b"AES-256-GCM round-trip fixture";
    let ciphertext = aead_encrypt(CipherId::Aes256Gcm, &key, &nonce, plaintext).expect("encrypt");
    let recovered = aead_decrypt(CipherId::Aes256Gcm, &key, &nonce, &ciphertext).expect("decrypt");
    assert_eq!(recovered, plaintext);
}

#[test]
#[cfg_attr(not(feature = "aes-gcm"), ignore = "requires aes-gcm feature")]
fn aes_gcm_rejects_wrong_key() {
    let key = [0x11u8; KEY_LEN];
    let nonce = [0x22u8; NONCE_LEN];
    let ciphertext = aead_encrypt(CipherId::Aes256Gcm, &key, &nonce, b"x").expect("encrypt");
    let wrong = [0x33u8; KEY_LEN];
    assert!(aead_decrypt(CipherId::Aes256Gcm, &wrong, &nonce, &ciphertext).is_err());
}

#[test]
#[cfg_attr(
    not(all(feature = "chacha20-poly1305", feature = "aes-gcm")),
    ignore = "requires both cipher features"
)]
fn both_aead_helpers_round_trip_when_both_ciphers_compiled() {
    // When both backends are compiled in (feature unification, or
    // `--all-features`), the dispatch must handle either CipherId. The
    // cipher is fixed per build and never appears on the wire — this
    // only pins that both arms work when both are present.
    let key = [0x55u8; KEY_LEN];
    let nonce = [0x66u8; NONCE_LEN];
    let plaintext = b"dual-cipher build";
    let chacha = aead_encrypt(CipherId::ChaCha20Poly1305, &key, &nonce, plaintext).unwrap();
    let aes = aead_encrypt(CipherId::Aes256Gcm, &key, &nonce, plaintext).unwrap();
    assert_ne!(
        chacha, aes,
        "different ciphers must produce different output"
    );
    assert_eq!(
        aead_decrypt(CipherId::ChaCha20Poly1305, &key, &nonce, &chacha).unwrap(),
        plaintext,
    );
    assert_eq!(
        aead_decrypt(CipherId::Aes256Gcm, &key, &nonce, &aes).unwrap(),
        plaintext,
    );
}
