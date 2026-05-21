//! Cipher selection (§1.5.1, §2.7.1) — the feature-gated default for
//! the runtime crate is ChaCha20-Poly1305; `--features aes-gcm`
//! (alongside `--no-default-features`) flips to AES-256-GCM.
//!
//! These tests live at the `litmask-internal` boundary so they pin
//! the wire format invariants without going through the runtime
//! crate's macro layer.

// Different feature combinations exercise different subsets of
// imports; the `cfg(test_)` blocks below gate accordingly. Without
// this allow, building under e.g. `--features chacha20-poly1305`
// alone would warn about `KEY_LEN` / `aead_*` being unused.
#![allow(unused_imports)]

use litmask_internal::{CURRENT_CIPHER, CipherId, KEY_LEN, NONCE_LEN, aead_decrypt, aead_encrypt};

#[test]
#[cfg(all(feature = "chacha20-poly1305", not(feature = "aes-gcm")))]
fn current_cipher_default_is_chacha20_poly1305() {
    assert_eq!(CURRENT_CIPHER, CipherId::ChaCha20Poly1305);
    assert_eq!(CURRENT_CIPHER.to_byte(), 0x01);
}

#[test]
#[cfg(all(feature = "aes-gcm", not(feature = "chacha20-poly1305")))]
fn current_cipher_aes_gcm_byte_is_0x02() {
    assert_eq!(CURRENT_CIPHER, CipherId::Aes256Gcm);
    assert_eq!(CURRENT_CIPHER.to_byte(), 0x02);
}

#[test]
#[cfg(feature = "aes-gcm")]
fn aes_gcm_aead_round_trips() {
    let key = [0x11u8; KEY_LEN];
    let nonce = [0x22u8; NONCE_LEN];
    let plaintext = b"AES-256-GCM round-trip fixture";
    let ciphertext = aead_encrypt(CipherId::Aes256Gcm, &key, &nonce, plaintext).expect("encrypt");
    let recovered = aead_decrypt(CipherId::Aes256Gcm, &key, &nonce, &ciphertext).expect("decrypt");
    assert_eq!(recovered, plaintext);
}

#[test]
#[cfg(feature = "aes-gcm")]
fn aes_gcm_rejects_wrong_key() {
    let key = [0x11u8; KEY_LEN];
    let nonce = [0x22u8; NONCE_LEN];
    let ciphertext = aead_encrypt(CipherId::Aes256Gcm, &key, &nonce, b"x").expect("encrypt");
    let wrong = [0x33u8; KEY_LEN];
    assert!(aead_decrypt(CipherId::Aes256Gcm, &wrong, &nonce, &ciphertext).is_err());
}

#[test]
#[cfg(all(feature = "chacha20-poly1305", feature = "aes-gcm"))]
fn both_ciphers_compile_simultaneously_for_cli_dispatch() {
    // litmask-cli enables both ciphers and dispatches at runtime
    // based on the wrapper's cipher-id byte. Pin that the helpers
    // accept either CipherId without re-compilation.
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
