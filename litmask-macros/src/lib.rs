//! Internal proc-macro crate for `litmask`.
//!
//! Users add `litmask` as a dependency, never this crate directly. The
//! public `litmask` crate re-exports the macros here.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use proc_macro::TokenStream;
use quote::quote;
use syn::{LitStr, parse_macro_input};

use litmask_internal::{
    CipherId, KEY_LEN, NONCE_LEN, NONCE_TAG_CALL_SITE, WRAPPER_LEN, aead_encrypt, xor_cycle,
};

/// Monotonic counter combined with the build seed to produce a unique
/// AEAD nonce per `mask!()` call. One counter per rustc process —
/// resets per crate compile, which is the correctness scope (each
/// crate that uses `mask!` has its own `mask_key`, so nonce uniqueness
/// only needs to hold within a single crate's expansion).
///
/// The spec-canonical derivation keys on (file, line, column), but
/// stable Rust's `proc_macro::Span` does not expose those accessors;
/// the counter preserves per-call-site uniqueness at the cost of
/// order-stability.
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

    let mask_key = load_out_dir_artifact::<KEY_LEN>("litmask_key.bin");
    let seed = load_out_dir_artifact::<KEY_LEN>("litmask_seed.bin");

    let idx = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = derive_nonce(&seed, idx);

    let ciphertext_and_tag = aead_encrypt(
        CipherId::ChaCha20Poly1305,
        &mask_key,
        &nonce,
        value.as_bytes(),
    )
    .expect("AEAD encryption failed at mask! expansion");

    let blob: Vec<u8> = [nonce.as_slice(), &ciphertext_and_tag].concat();
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

/// Load a fixed-size build artifact from the caller crate's `OUT_DIR`.
/// Cached per `name` for the lifetime of the proc-macro process — the
/// same file is read at most once per crate compile, regardless of how
/// many `mask!()` / `weak_mask!()` invocations the crate contains.
///
/// Panics at proc-macro expansion time with a diagnostic message if
/// `OUT_DIR` is unset, the file is missing or unreadable, or its
/// length differs from `N` — each of which indicates a missing or
/// out-of-date `litmask_build::emit()` invocation in the caller's
/// `build.rs`.
fn load_out_dir_artifact<const N: usize>(name: &'static str) -> [u8; N] {
    static CACHE: OnceLock<Mutex<HashMap<&'static str, Vec<u8>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().expect("artifact cache mutex poisoned");
    let bytes = map.entry(name).or_insert_with(|| read_out_dir_file(name));
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("litmask: {name} expected {N} bytes, found {}", bytes.len()))
}

fn read_out_dir_file(name: &str) -> Vec<u8> {
    let out_dir = std::env::var_os("OUT_DIR")
        .expect("litmask: OUT_DIR not set; did you add a build.rs running litmask_build::emit()?");
    let path = PathBuf::from(out_dir).join(name);
    fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "litmask: failed to read {name} from OUT_DIR ({}): {e}; did your build.rs run litmask_build::emit()?",
            path.display(),
        )
    })
}

/// Derive the 12-byte AEAD nonce embedded at the head of every blob.
///
/// Keys the BLAKE3 hash on the build seed and tags the message with
/// [`NONCE_TAG_CALL_SITE`] so the call-site nonce space is disjoint
/// from the wrapper nonce space at the same seed.
///
/// The counter alone is sufficient for AEAD nonce uniqueness within a
/// crate compile: `mask_key` is per-crate (each consumer crate has its
/// own `build.rs`/`OUT_DIR`), so the `(key, nonce)` pair only needs to
/// stay unique inside one rustc invocation, and `CALL_COUNTER` is
/// fresh per rustc process. The seed-keyed hash is kept solely so
/// nonces don't appear as `0, 1, 2, …` little-endian patterns in the
/// compiled binary.
fn derive_nonce(seed: &[u8; KEY_LEN], idx: u64) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(NONCE_TAG_CALL_SITE);
    hasher.update(&idx.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    out
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

    // The wrapper is per-build random ciphertext; using it as the XOR
    // key removes any fixed litmask byte signature from the encoded
    // output.
    let wrapper = load_out_dir_artifact::<WRAPPER_LEN>("litmask_wrapper.bin");

    let plaintext = value.as_bytes();
    let encoded = xor_cycle(plaintext, &wrapper);

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
                    let decoded = ::litmask::__internal::__xor_cycle(obf, wrapper);
                    ::std::string::String::from_utf8(decoded)
                        .expect("weak_mask! input was valid UTF-8")
                })
                .as_str()
        }
    };

    expanded.into()
}
