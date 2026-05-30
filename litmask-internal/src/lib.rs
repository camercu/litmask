//! Shared crypto primitives, wire-format constants, and pure helpers
//! for the litmask binary format.
//!
//! Internal crate. Not part of the public litmask API. Versioned in
//! lockstep with `litmask`; do not depend on this crate directly. The
//! `litmask`, `litmask-build`, and `litmask-macros` crates all depend
//! on this one for a single canonical definition of the wire format,
//! AEAD primitives, nonce derivation, and key derivation.
//!
//! All functions here are pure (no I/O, no global state) and
//! `no_std`-compatible.

#![no_std]

extern crate alloc;

// At least one cipher must be enabled — otherwise the AEAD helpers
// would have nothing to dispatch to. Catching this at the crate
// level produces a single readable error instead of a forest of
// missing-symbol errors downstream.
#[cfg(not(any(
    feature = "chacha20-poly1305",
    feature = "aes-gcm",
    feature = "all-ciphers",
)))]
compile_error!(
    "litmask-internal requires at least one cipher feature: \
     enable `chacha20-poly1305` (default), `aes-gcm`, or `all-ciphers`."
);

mod aead;
#[cfg(any(feature = "chacha20-poly1305", feature = "aes-gcm"))]
pub use self::aead::CURRENT_CIPHER;
pub use self::aead::{AeadError, aead_decrypt, aead_encrypt};

mod kdf;
pub use kdf::{HW_ID_DERIVATION_CONTEXT, WEAK_XOR_KEY_LEN, derive_hw_key, derive_weak_xor_key};

mod nonce;
pub use nonce::{nonce_for_call_site, nonce_for_wrapper};

mod wire;
pub use wire::{
    CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305, CIPHER_OFFSET, CipherId, FORMAT_V1,
    FormatVersion, HEADER_LEN, KEY_LEN, NONCE_LEN, NONCE_OFFSET, ParsedWrapper, TAG_LEN,
    UnknownCipherId, UnknownFormatVersion, VERSION_OFFSET, WRAPPER_BODY_LEN, WRAPPER_LEN,
    WrapperParseError, assemble_wrapper, parse_wrapper, wrapper_nonce,
};

pub mod base64url;
pub mod decrypt;
pub mod format_parser;
pub mod scan;

/// XOR every byte of `input` against the cyclically-repeated `key`,
/// returning the result as a new `Vec`.
///
/// The operation is its own inverse: applying it twice with the same
/// key recovers the original input. Used by the `weak_mask!` macro to
/// obfuscate string literals against the per-build wrapper bytes so
/// litmask-supplied static strings do not contribute a fixed byte
/// signature to user binaries.
///
/// # Panics
///
/// Panics if `key.is_empty()` while `input` is non-empty.
#[must_use]
pub fn xor_cycle(input: &[u8], key: &[u8]) -> alloc::vec::Vec<u8> {
    if input.is_empty() {
        return alloc::vec::Vec::new();
    }
    assert!(!key.is_empty(), "key must be non-empty");
    input
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect()
}

/// Render the data fields of a `litmask.config` TOML file.
///
/// Returns the `unlock_key`, `locator`, and `length` fields as a TOML
/// fragment (no header comments). Callers prepend their own header.
/// Shared by `litmask-build` (build-time) and `litmask-cli bind`
/// (post-build rebind) so the field layout cannot drift between the
/// two producers.
#[must_use]
pub fn render_config_fields(
    unlock_key: &[u8; KEY_LEN],
    locator: &[u8; NONCE_LEN],
) -> alloc::string::String {
    alloc::format!(
        "unlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
        base64url::encode(unlock_key),
        base64url::encode(locator),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_cycle_empty_input_is_noop() {
        let key = [0xAAu8; 8];
        assert!(xor_cycle(&[], &key).is_empty());
    }

    #[test]
    fn xor_cycle_self_inverse_with_matching_lengths() {
        let plaintext = b"hello world";
        let key = b"0123456789ab";
        let encoded = xor_cycle(plaintext, key);
        let decoded = xor_cycle(&encoded, key);
        assert_eq!(decoded.as_slice(), plaintext);
    }

    #[test]
    fn xor_cycle_handles_key_shorter_than_input() {
        let plaintext = b"abcdef";
        let key = b"\xff\x55";
        let out = xor_cycle(plaintext, key);
        assert_eq!(
            out.as_slice(),
            &[
                b'a' ^ 0xff,
                b'b' ^ 0x55,
                b'c' ^ 0xff,
                b'd' ^ 0x55,
                b'e' ^ 0xff,
                b'f' ^ 0x55,
            ]
        );
    }

    #[test]
    fn xor_cycle_handles_key_longer_than_input() {
        let plaintext = b"hi";
        let key = b"\x01\x02\x03\x04\x05";
        let out = xor_cycle(plaintext, key);
        assert_eq!(out.as_slice(), &[b'h' ^ 0x01, b'i' ^ 0x02]);
    }

    #[test]
    #[should_panic(expected = "key must be non-empty")]
    fn xor_cycle_panics_on_empty_key_with_nonempty_input() {
        let _ = xor_cycle(b"x", &[]);
    }

    #[test]
    fn render_config_fields_contains_all_required_toml_keys() {
        let body = render_config_fields(&[0u8; KEY_LEN], &[0u8; NONCE_LEN]);
        assert!(body.contains("unlock_key = "));
        assert!(body.contains("locator = "));
        assert!(body.contains(&alloc::format!("length = {WRAPPER_LEN}")));
    }

    #[test]
    fn render_config_fields_round_trips_base64url_values() {
        let unlock_key = [0xAAu8; KEY_LEN];
        let locator = [0xBBu8; NONCE_LEN];
        let body = render_config_fields(&unlock_key, &locator);
        let expected_key_b64 = base64url::encode(&unlock_key);
        let expected_loc_b64 = base64url::encode(&locator);
        assert!(body.contains(&expected_key_b64));
        assert!(body.contains(&expected_loc_b64));
    }

    proptest::proptest! {
        #[test]
        fn proptest_xor_cycle_self_inverse(
            input in proptest::collection::vec(proptest::num::u8::ANY, 0..=512),
            key in proptest::collection::vec(proptest::num::u8::ANY, 1..=64),
        ) {
            let encoded = xor_cycle(&input, &key);
            let decoded = xor_cycle(&encoded, &key);
            proptest::prop_assert_eq!(decoded, input);
        }
    }
}
