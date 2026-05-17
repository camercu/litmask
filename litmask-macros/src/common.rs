//! Helpers shared across the `mask`, `weak_mask`, `maskfmt`, and
//! `unmasked` macros: `OUT_DIR` artifact loading + byte-array token
//! emission. Each per-macro module owns its own input grammar and
//! expansion logic; this module owns the small set of utilities that
//! cross those seams.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use proc_macro2::TokenStream;
use quote::quote;
use zeroize::Zeroizing;

/// Process-lifetime cache of `OUT_DIR` artifact contents keyed by file
/// name. `Zeroizing<Vec<u8>>` keeps the type-level signal that the
/// cached buffers carry secret material (`litmask_key.bin`,
/// `litmask_seed.bin`); statics don't run `Drop`, but the wrap covers
/// any code path that evicts an entry.
type ArtifactCache = Mutex<HashMap<&'static str, Zeroizing<Vec<u8>>>>;

/// Load a fixed-size build artifact from the caller crate's `OUT_DIR`.
/// Cached per `name` for the lifetime of the proc-macro process — the
/// same file is read at most once per crate compile, regardless of how
/// many `mask!()` / `weak_mask!()` invocations the crate contains.
///
/// Two of the cached files carry secret key material
/// (`litmask_key.bin`, `litmask_seed.bin`); wrapping each cached `Vec`
/// in `Zeroizing` ensures the underlying heap buffer is wiped on drop.
/// Rust statics never run their `Drop`, so this is defense-in-depth
/// rather than active wipe — it covers any future code path that
/// evicts entries from the cache, and signals the security
/// expectation at the type level.
///
/// Panics at proc-macro expansion time with a diagnostic message if
/// `OUT_DIR` is unset, the file is missing or unreadable, or its
/// length differs from `N` — each of which indicates a missing or
/// out-of-date `litmask_build::emit()` invocation in the caller's
/// `build.rs`.
pub(crate) fn load_out_dir_artifact<const N: usize>(name: &'static str) -> [u8; N] {
    static CACHE: OnceLock<ArtifactCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().expect("artifact cache mutex poisoned");
    let bytes = map.entry(name).or_insert_with(|| read_out_dir_file(name));
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("litmask: {name} expected {N} bytes, found {}", bytes.len()))
}

fn read_out_dir_file(name: &str) -> Zeroizing<Vec<u8>> {
    let out_dir = std::env::var_os("OUT_DIR")
        .expect("litmask: OUT_DIR not set; did you add a build.rs running litmask_build::emit()?");
    let path = PathBuf::from(out_dir).join(name);
    let bytes = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "litmask: failed to read {name} from OUT_DIR ({}): {e}; did your build.rs run litmask_build::emit()?",
            path.display(),
        )
    });
    Zeroizing::new(bytes)
}

/// Emit a byte slice as a `[u8; N]` array literal token. Used by the
/// `mask!` and `weak_mask!` expansions to inline the encrypted /
/// obfuscated bytes as a `const` array in the caller's code.
pub(crate) fn byte_array_token(bytes: &[u8]) -> TokenStream {
    quote! { [ #(#bytes),* ] }
}
