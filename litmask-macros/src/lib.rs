//! Internal proc-macro crate for `litmask`.
//!
//! Users add `litmask` as a dependency, never this crate directly. The
//! public `litmask` crate re-exports the macros here via `pub use`.
//!
//! See `docs/SPECIFICATION.md` Amendments 4 and 5 for the rationale.
//!
//! Task 5 scope: string literals only via [`mask!`]. Byte literals and
//! C-string literals are added in Task 6. Compile-error and position
//! rejection cases land in Task 7. Spec §1.5.2 mandates per-call-site
//! nonces keyed on (file, line, column); stable Rust's `proc_macro::Span`
//! does not expose those accessors as of 1.88, so the walking skeleton
//! derives nonces from (crate name, monotonic counter, literal value)
//! instead. Spec deviation noted in Task 36's acceptance criteria
//! commentary; tightening lands when stable Span APIs ship.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, generic_array::GenericArray},
};
use proc_macro::TokenStream;
use quote::quote;
use syn::{LitStr, parse_macro_input};

// Canonical layout constants live in `litmask-internal-format`.
use litmask_internal_format::{KEY_LEN, NONCE_LEN, NONCE_TAG_CALL_SITE};

static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Mask a string literal at compile time; expand to a runtime
/// decryption call returning `String`.
///
/// Walking-skeleton scope: `mask!("text literal")` only. Subsequent
/// tasks add byte / C-string literal support (Task 6) and the
/// invalid-input compile-error pipeline (Task 7).
///
/// # Panics
///
/// Panics during macro expansion (not at the user's runtime) if:
///
/// - `OUT_DIR` is unset (the caller's crate is missing a `build.rs`
///   that invokes `litmask_build::emit()`).
/// - `litmask_key.bin` or `litmask_seed.bin` cannot be read from
///   `OUT_DIR`, or have the wrong length.
/// - ChaCha20-Poly1305 encryption fails for the literal value
///   (cryptographically extraordinary; never observed in practice).
#[proc_macro]
pub fn mask(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let value = lit.value();

    let out_dir = std::env::var_os("OUT_DIR")
        .expect("litmask: OUT_DIR not set; did you add a build.rs running litmask_build::emit()?");
    let out_dir = PathBuf::from(out_dir);

    let mask_key = load_fixed::<KEY_LEN>(&out_dir.join("litmask_key.bin"), "litmask_key.bin");
    let seed = load_fixed::<KEY_LEN>(&out_dir.join("litmask_seed.bin"), "litmask_seed.bin");

    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let idx = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = derive_nonce(&seed, &crate_name, idx, value.as_bytes());

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&mask_key));
    let ciphertext_and_tag = cipher
        .encrypt(Nonce::from_slice(&nonce), value.as_bytes())
        .expect("ChaCha20-Poly1305 encryption failed at mask! expansion");

    let mut blob: Vec<u8> = Vec::with_capacity(NONCE_LEN + ciphertext_and_tag.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext_and_tag);

    let blob_lit = byte_array_token(&blob);
    let blob_len = blob.len();

    let expanded = quote! {
        {
            const __LITMASK_BLOB: &[u8; #blob_len] = &#blob_lit;
            ::litmask::__internal::__decrypt_str(
                __LITMASK_BLOB,
                ::litmask::__wrapper_bytes!(),
            )
        }
    };

    expanded.into()
}

fn load_fixed<const N: usize>(path: &std::path::Path, friendly: &str) -> [u8; N] {
    let bytes = fs::read(path).unwrap_or_else(|e| {
        panic!(
            "litmask: failed to read {friendly} from OUT_DIR ({}): {e}; did your build.rs run litmask_build::emit()?",
            path.display(),
        )
    });
    bytes.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "litmask: {friendly} expected {N} bytes, found {}",
            bytes.len()
        )
    })
}

fn derive_nonce(
    seed: &[u8; KEY_LEN],
    crate_name: &str,
    idx: u64,
    literal: &[u8],
) -> [u8; NONCE_LEN] {
    // Walking-skeleton deviation: spec §1.5.2 keys per-call-site
    // nonces on (file, line, column), but stable `proc_macro::Span`
    // does not expose those accessors. We share the same BLAKE3
    // domain separator as the canonical algorithm
    // (`NONCE_TAG_CALL_SITE` in format.rs) so the cipher state stays
    // identifiable; only the keyed message changes.
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(NONCE_TAG_CALL_SITE);
    hasher.update(crate_name.as_bytes());
    hasher.update(b":");
    hasher.update(&idx.to_le_bytes());
    hasher.update(b":");
    hasher.update(literal);
    let digest = hasher.finalize();
    digest.as_bytes()[..NONCE_LEN]
        .try_into()
        .expect("blake3 output ≥12 bytes")
}

fn byte_array_token(bytes: &[u8]) -> proc_macro2::TokenStream {
    let elems = bytes.iter().map(|b| quote! { #b });
    quote! { [ #(#elems),* ] }
}
