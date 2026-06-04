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
pub use kdf::{
    EMBEDDED_UNLOCK_DERIVATION_CONTEXT, MACHINE_ID_DERIVATION_CONTEXT, WEAK_XOR_KEY_LEN,
    derive_embedded_unlock_key, derive_machine_id_key, derive_weak_xor_key,
};

mod nonce;
pub use nonce::{nonce_for_call_site, nonce_for_wrapper};

mod wire;
pub use wire::{
    CipherId, FormatVersion, KEY_LEN, NONCE_LEN, NONCE_OFFSET, ParsedWrapper, TAG_LEN,
    UnknownFormatVersion, WRAPPER_BODY_LEN, WRAPPER_LEN, WRAPPER_PLAINTEXT_LEN, assemble_wrapper,
    parse_wrapper,
};
// `wrapper_nonce` has no out-of-crate callers (consumers derive the
// wrapper nonce via `nonce_for_wrapper`); keep it crate-private.
pub(crate) use wire::wrapper_nonce;

// Deliberately kept a namespaced `pub mod` rather than flattened like
// the helpers below: its public verbs are the generic `encode` /
// `decode`, which read clearly only when module-qualified
// (`base64url::encode`).
pub mod base64url;

mod decrypt;
pub use decrypt::DecryptError;
#[cfg(any(feature = "chacha20-poly1305", feature = "aes-gcm"))]
pub use decrypt::{decrypt_blob, decrypt_wrapper};

mod format_parser;
pub use format_parser::{
    ParsedPlaceholder, TemplateParseError, TemplateRef, is_token_char, parse_mask_format_template,
};

mod weak;
pub use weak::xor_cycle;
