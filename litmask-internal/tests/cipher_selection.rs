//! Cipher selection (§1.5.1, §2.7.1) — the feature-gated default for
//! the runtime crate is ChaCha20-Poly1305; `--features aes-gcm`
//! (alongside `--no-default-features`) flips to AES-256-GCM.
//!
//! These tests live at the `litmask-internal` boundary so they pin
//! the wire format invariants without going through the runtime
//! crate's macro layer.

#[allow(unused_imports)]
use litmask_internal::{
    CURRENT_CIPHER, CipherId, FormatVersion, KEY_LEN, NONCE_LEN, aead_decrypt, aead_encrypt,
};

#[test]
fn format_version_v1_byte_is_0x01() {
    // The wrapper's version byte is load-bearing for every reader
    // (the runtime crate's wrapper-cipher check, litmask-cli's
    // dispatcher, every future cross-version migration). A discriminant
    // swap on `FormatVersion::V1` would break wire compatibility silently;
    // the unit test in lib.rs covers it inside the crate, this one
    // covers it across the public boundary so a renamed-or-deleted
    // re-export also surfaces here.
    assert_eq!(FormatVersion::V1.to_byte(), 0x01);
    assert_eq!(FormatVersion::CURRENT.to_byte(), 0x01);
}

#[test]
#[cfg_attr(
    not(all(feature = "chacha20-poly1305", not(feature = "aes-gcm"))),
    ignore = "only meaningful in chacha20-poly1305-only builds"
)]
fn current_cipher_default_is_chacha20_poly1305() {
    assert_eq!(CURRENT_CIPHER, CipherId::ChaCha20Poly1305);
    assert_eq!(CURRENT_CIPHER.to_byte(), 0x01);
}

#[test]
#[cfg_attr(
    not(all(feature = "aes-gcm", not(feature = "chacha20-poly1305"))),
    ignore = "only meaningful in aes-gcm-only builds"
)]
fn current_cipher_aes_gcm_byte_is_0x02() {
    assert_eq!(CURRENT_CIPHER, CipherId::Aes256Gcm);
    assert_eq!(CURRENT_CIPHER.to_byte(), 0x02);
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
    ignore = "requires both cipher features (dual-cipher CLI build)"
)]
fn both_ciphers_compile_simultaneously_for_cli_dispatch() {
    // litmask-cli enables both ciphers and dispatches at runtime
    // based on the wrapper's cipher-id byte. Pin that the helpers
    // accept either CipherId without re-compilation AND that the
    // on-the-wire discriminants stay locked. The single-cipher
    // tests above each cover one direction (0x01 OR 0x02); a
    // swap of the discriminants would pass both of those but
    // break the CLI's dispatch — this dual-feature test is the
    // only place that catches it.
    assert_eq!(CipherId::ChaCha20Poly1305.to_byte(), 0x01);
    assert_eq!(CipherId::Aes256Gcm.to_byte(), 0x02);

    let key = [0x55u8; KEY_LEN];
    let nonce = [0x66u8; NONCE_LEN];
    let plaintext = b"dual-cipher CLI mode";
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
