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

mod config;
pub use config::render_config_fields;

mod weak;
pub use weak::xor_cycle;
