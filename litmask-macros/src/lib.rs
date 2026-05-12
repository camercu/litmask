//! Internal proc-macro crate for `litmask`.
//!
//! Users add `litmask` as a dependency, never this crate directly. The
//! public `litmask` crate re-exports the macros here.

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
use litmask_internal_format::{KEY_LEN, NONCE_LEN, NONCE_TAG_CALL_SITE, WRAPPER_LEN, xor_cycle};

/// Monotonic counter that distinguishes consecutive `mask!()` calls
/// within a single proc-macro process. Combined with the build seed
/// and the literal value, it produces a unique nonce per call site.
///
/// The canonical algorithm keys per-call-site nonces on (file, line,
/// column), but stable Rust's `proc_macro::Span` does not expose
/// file/line/column accessors. The counter-based form preserves
/// uniqueness (the property that actually matters for AEAD security)
/// at the cost of cross-build determinism. Reproducible builds and
/// fully spec-canonical nonces wait on stable Span accessors or an
/// opt-in to `procmacro2_semver_exempt`.
static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Mask a string literal at compile time; expand to a runtime
/// decryption call returning `String`.
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
    // Shares the same BLAKE3 domain separator as the canonical
    // (file, line, column)-keyed algorithm in
    // `litmask_internal_format::nonce_for_call_site`; only the keyed
    // message differs.
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
        .expect("BLAKE3 output is at least NONCE_LEN bytes")
}

fn byte_array_token(bytes: &[u8]) -> proc_macro2::TokenStream {
    let elems = bytes.iter().map(|b| quote! { #b });
    quote! { [ #(#elems),* ] }
}

/// Obfuscate a string literal at compile time using XOR against the
/// per-build encrypted-`mask_key` wrapper bytes. Expand to code that
/// decodes back to `&'static str` on first runtime access and caches
/// the result for the program's lifetime.
///
/// `weak_mask!()` is weaker than [`mask!`]: there is no AEAD
/// authentication, and both ciphertext and key material live in the
/// same compiled binary, so a Level-2 attacker (disassembler + manual
/// decode) can recover the plaintext. Use `weak_mask!()` only for
/// non-secret strings that need anti-`strings(1)` protection and
/// cannot wait for `init!()` to run (env-var names, default file
/// paths, etc.). Real secrets always go through [`mask!`].
///
/// # Panics
///
/// Panics at proc-macro expansion time if `OUT_DIR` is unset or
/// `litmask_wrapper.bin` cannot be read; these indicate a missing
/// `build.rs` invoking `litmask_build::emit()`.
#[proc_macro]
pub fn weak_mask(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let value = lit.value();

    let out_dir = std::env::var_os("OUT_DIR")
        .expect("litmask: OUT_DIR not set; did you add a build.rs running litmask_build::emit()?");
    let out_dir = PathBuf::from(out_dir);

    // The wrapper is per-build random ciphertext; using it as the XOR
    // key removes any fixed litmask byte signature from the encoded
    // output.
    let wrapper =
        load_fixed::<WRAPPER_LEN>(&out_dir.join("litmask_wrapper.bin"), "litmask_wrapper.bin");

    let plaintext = value.as_bytes();
    let mut encoded = vec![0u8; plaintext.len()];
    if !plaintext.is_empty() {
        xor_cycle(plaintext, &wrapper, &mut encoded);
    }

    let encoded_lit = byte_array_token(&encoded);
    let encoded_len = encoded.len();

    let expanded = quote! {
        {
            const __WEAK_OBF: &[u8; #encoded_len] = &#encoded_lit;
            static __WEAK_CACHE: ::std::sync::OnceLock<::std::string::String> =
                ::std::sync::OnceLock::new();
            __WEAK_CACHE
                .get_or_init(|| {
                    // `core::hint::black_box` prevents LLVM from
                    // constant-folding the XOR loop into a precomputed
                    // string literal in `.rodata`. Both inputs are
                    // const-known at compile time (`__WEAK_OBF` and the
                    // `include_bytes!`-loaded wrapper), so without
                    // black_box the optimizer materializes the decoded
                    // plaintext directly.
                    let wrapper: &[u8] = ::core::hint::black_box(
                        &::litmask::__wrapper_bytes!()[..]
                    );
                    let obf: &[u8] = ::core::hint::black_box(&__WEAK_OBF[..]);
                    let mut decoded = ::std::vec![0u8; #encoded_len];
                    if !obf.is_empty() {
                        ::litmask::__internal::__xor_cycle(obf, wrapper, &mut decoded);
                    }
                    ::std::string::String::from_utf8(decoded)
                        .expect("weak_mask! input was valid UTF-8")
                })
                .as_str()
        }
    };

    expanded.into()
}
