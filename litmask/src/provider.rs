//! [`KeyProvider`] trait + built-in providers.
//!
//! The trait is intentionally minimal — no `deployment_hint()` or
//! similar method that would embed English-language plaintext in user
//! binaries.

use crate::error::KeyError;
use crate::key::UnlockKey;
#[cfg(feature = "std")]
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "std")]
use crate::internal::KEY_LEN;

/// A source of `unlock_key` for the layered key strategy.
///
/// The `&self` receiver permits stateful providers (cached lookups,
/// network clients). Implementations must be `Send + Sync` so providers
/// can be passed to [`crate::init_with!`] in multithreaded contexts.
pub trait KeyProvider: Send + Sync {
    /// Retrieve the `unlock_key` used to decrypt the embedded
    /// `mask_key` wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] when the underlying source is unavailable
    /// or returns malformed data.
    fn unlock_key(&self) -> Result<UnlockKey, KeyError>;
}

// Object-safety check enforced at compile time.
const _: fn() = || {
    fn _assert_object_safe(_: &dyn KeyProvider) {}
};

/// Reads `unlock_key` from a configurable environment variable.
#[cfg(feature = "std")]
pub struct EnvVarProvider {
    name: &'static str,
}

#[cfg(feature = "std")]
impl EnvVarProvider {
    /// Construct a provider reading the named environment variable.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Expose the configured variable name so error messages and
    /// operational tooling can surface it without hardcoding.
    #[must_use]
    pub const fn var_name(&self) -> &'static str {
        self.name
    }
}

#[cfg(feature = "std")]
impl Default for EnvVarProvider {
    /// Reads from `LITMASK_UNLOCK_KEY`. The variable name itself is
    /// obfuscated against the per-build wrapper bytes via the public
    /// [`crate::weak_mask!`] macro, so the literal does not appear in
    /// `.rodata` of user binaries.
    fn default() -> Self {
        Self::new(crate::weak_mask!("LITMASK_UNLOCK_KEY"))
    }
}

#[cfg(feature = "std")]
impl KeyProvider for EnvVarProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        parse_env_value(read_env_value(self.name))
    }
}

/// Read the named environment variable and wrap its value so the
/// underlying heap buffer wipes on drop. The variable holds the
/// base64url-encoded unlock key in plaintext form; without the
/// [`Zeroizing`] wrapper the buffer would linger after parsing.
#[cfg(feature = "std")]
fn read_env_value(name: &str) -> Option<Zeroizing<alloc::string::String>> {
    std::env::var(name).ok().map(Zeroizing::new)
}

/// Pure parser for an environment-variable value: maps the optional
/// owned string to the canonical [`KeyError`] surface. `None`
/// represents "env var unset" and produces [`KeyError::NotFound`];
/// `Some(value)` is delegated to [`UnlockKey::from_base64url`].
///
/// Takes ownership of a [`Zeroizing<String>`] so the plaintext base64
/// buffer is wiped when this function returns, regardless of which
/// branch executed.
///
/// Extracted as a free fn so tests cover the error-mapping paths
/// without mutating process-wide environment state (the workspace lint
/// `forbid(unsafe_code)` blocks the `unsafe { std::env::set_var(...) }`
/// pattern that env-mutation tests would otherwise require).
#[cfg(feature = "std")]
fn parse_env_value(value: Option<Zeroizing<alloc::string::String>>) -> Result<UnlockKey, KeyError> {
    match value {
        None => Err(KeyError::NotFound),
        Some(s) => UnlockKey::from_base64url(s.as_str()),
    }
}

/// Wire-format expected by [`FileProvider`].
///
/// Adding a future encoding is a non-breaking change for downstream
/// exhaustive matches via `#[non_exhaustive]`.
#[cfg(feature = "std")]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEncoding {
    /// RFC 4648 §5 url-safe base64 without padding. ASCII whitespace
    /// (including a trailing newline) is tolerated; bytes outside the
    /// alphabet surface as [`KeyError::InvalidFormat`]. This is the
    /// default — `FileProvider::new(path)` uses it.
    Base64Url,
    /// Exactly 32 raw bytes. Convenient when sourcing the key from a
    /// secret-management system that already exposes it as a binary
    /// blob (HSM-backed file, vault-rendered template, etc.).
    Raw,
}

/// Reads `unlock_key` from a filesystem path.
///
/// `FileProvider::new(path)` decodes the contents as base64url
/// (§2.5.3.1). [`FileProvider::with_encoding`] swaps the encoding
/// (§2.5.3.2). Errors map per §2.5.3.3:
///
/// | Condition | Error |
/// |---|---|
/// | Path does not exist | [`KeyError::NotFound`] |
/// | Path exists but is unreadable by this process | [`KeyError::Permission`] |
/// | Contents do not parse, or wrong length | [`KeyError::InvalidFormat`] |
///
/// The in-memory copy of the file bytes is wiped immediately after
/// the 32-byte key is extracted (§2.5.3.4) via a `Zeroizing` wrapper
/// around the read buffer. The wipe is verified in unit tests via a
/// `Counted<T>` newtype that bumps an `AtomicUsize` from its
/// `Zeroize` impl.
///
/// # TOCTOU caveat
///
/// `FileProvider` reads the file directly on every `unlock_key()`
/// call; there is no separate permission probe. A file replaced
/// between two reads — or between read and any downstream
/// authorization decision — is not protected against. Production
/// deployments should rely on filesystem-level access control
/// (directory permissions, OS-level ACLs, dedicated secret-mount
/// points like Kubernetes' projected volumes) rather than this
/// provider alone for trust.
#[cfg(feature = "std")]
pub struct FileProvider {
    path: std::path::PathBuf,
    encoding: KeyEncoding,
}

#[cfg(feature = "std")]
impl FileProvider {
    /// Construct a `FileProvider` reading `path` as base64url.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self::with_encoding(path, KeyEncoding::Base64Url)
    }

    /// Construct a `FileProvider` reading `path` with the chosen
    /// encoding.
    pub fn with_encoding(path: impl Into<std::path::PathBuf>, encoding: KeyEncoding) -> Self {
        Self {
            path: path.into(),
            encoding,
        }
    }
}

#[cfg(feature = "std")]
impl KeyProvider for FileProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        // Wrap the file bytes in Zeroizing so the heap buffer wipes
        // when this function returns. The pure helper takes the
        // buffer by value so a future refactor that retained a
        // borrow would break the contract loudly (the Counted<T>
        // unit test asserts the buffer's drop runs).
        let buffer = Zeroizing::new(read_file_bytes(&self.path)?);
        extract_key_from_buffer(buffer, self.encoding)
    }
}

/// Read a path into memory, mapping `io::Error` to the canonical
/// [`KeyError`] surface for [`FileProvider`]. The mapping is
/// exhaustive against the documented behavior in §2.5.3.3: missing →
/// `NotFound`, anything that prevents the read attempt from
/// completing → `Permission`. Genuine I/O failures (transient disk
/// errors, etc.) are rare enough that bucketing them under
/// `Permission` for v0 is acceptable; the `KeyError::Provider`
/// variant (Task 16) is the canonical home for a richer error
/// surface in v1.
#[cfg(feature = "std")]
fn read_file_bytes(path: &std::path::Path) -> Result<alloc::vec::Vec<u8>, KeyError> {
    use std::io::ErrorKind;
    std::fs::read(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => KeyError::NotFound,
        _ => KeyError::Permission,
    })
}

/// Decode a file-buffer payload into an [`UnlockKey`] under the
/// configured [`KeyEncoding`]. Takes the buffer by value so its
/// `Drop` (zeroizing wrapper) runs at function return — the
/// generic bound on `Zeroize` is load-bearing: it pins the buffer
/// to a wrapper that wipes on drop, so a caller cannot accidentally
/// hand in a plain `Vec<u8>` that lingers in the allocator.
///
/// `Base64Url` mode trims leading and trailing ASCII whitespace
/// (including a trailing newline) — editors save key files with
/// trailing newlines by default and a hard-failure mode would
/// produce a frustrating diagnostic at deployment time. `Raw`
/// mode requires exactly [`KEY_LEN`] bytes; one byte off → [`KeyError::InvalidFormat`].
// `buffer` is intentionally taken by value: the function's contract
// is that the buffer's `Drop` (which a Zeroizing wrapper hooks into
// `Zeroize::zeroize`) runs at function return. Switching to `&Z`
// would silently break the zeroize guarantee — the `Counted<T>` unit
// test pins this exact contract.
#[cfg(feature = "std")]
#[allow(clippy::needless_pass_by_value)]
fn extract_key_from_buffer<Z>(buffer: Z, encoding: KeyEncoding) -> Result<UnlockKey, KeyError>
where
    Z: AsRef<[u8]> + Zeroize,
{
    let bytes = buffer.as_ref();
    match encoding {
        KeyEncoding::Base64Url => {
            let text = core::str::from_utf8(bytes).map_err(|_| KeyError::InvalidFormat)?;
            UnlockKey::from_base64url(text.trim_matches(char::is_whitespace))
        }
        KeyEncoding::Raw => {
            let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| KeyError::InvalidFormat)?;
            Ok(UnlockKey::from_raw(arr))
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use zeroize::Zeroizing;

    const VALID_BASE64URL_32B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn default_reads_litmask_unlock_key() {
        let p = EnvVarProvider::default();
        assert_eq!(p.var_name(), "LITMASK_UNLOCK_KEY");
    }

    #[test]
    fn read_env_value_returns_zeroizing_string_so_buffer_wipes_on_drop() {
        // Type-asserts the env-read boundary returns a wiped-on-drop
        // wrapper rather than a plain String.
        let _: Option<Zeroizing<String>> = read_env_value("LITMASK_DEFINITELY_NOT_SET_XYZ_42");
    }

    #[test]
    fn parse_env_value_unset_yields_not_found() {
        assert!(matches!(parse_env_value(None), Err(KeyError::NotFound)));
    }

    #[test]
    fn parse_env_value_bad_base64_yields_invalid_format() {
        let err = parse_env_value(Some(z("not valid base64!"))).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_wrong_length_yields_invalid_format() {
        // 32-char base64url decodes to 24 bytes, not 32.
        let err = parse_env_value(Some(z("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_padded_yields_invalid_format() {
        let err =
            parse_env_value(Some(z("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_valid_32_byte_key_succeeds() {
        let key = parse_env_value(Some(z(VALID_BASE64URL_32B))).expect("valid 32-byte key");
        assert_eq!(key.as_bytes(), &[0u8; crate::internal::KEY_LEN]);
    }

    #[test]
    fn key_provider_is_object_safe() {
        let _: alloc::boxed::Box<dyn KeyProvider> =
            alloc::boxed::Box::new(EnvVarProvider::default());
    }

    // ── FileProvider ──────────────────────────────────────────

    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Newtype that bumps a caller-supplied `AtomicUsize` from its
    /// `Zeroize` impl. The `Drop` impl calls `zeroize`, mirroring the
    /// `Zeroizing<Vec<u8>>` wrapper used by the production code path,
    /// so the test can assert the wipe ran without reading dropped
    /// memory (which would be UB). Without this seam a future
    /// refactor that retained a borrow of the file buffer — and
    /// thereby prevented its drop — would silently bypass the
    /// zeroize guarantee.
    ///
    /// The counter is borrowed (`&'static AtomicUsize`) rather than a
    /// module-level static so each test owns its own counter and the
    /// shared cargo-test thread pool cannot interleave increments
    /// across tests.
    struct Counted {
        bytes: alloc::vec::Vec<u8>,
        counter: &'static AtomicUsize,
    }

    impl Counted {
        fn new(bytes: alloc::vec::Vec<u8>, counter: &'static AtomicUsize) -> Self {
            Self { bytes, counter }
        }
    }

    impl AsRef<[u8]> for Counted {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Zeroize for Counted {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            self.zeroize();
        }
    }

    #[test]
    fn extract_key_from_buffer_zeroizes_input_exactly_once() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let buf = Counted::new(VALID_BASE64URL_32B.as_bytes().to_vec(), &COUNTER);
        let key = extract_key_from_buffer(buf, KeyEncoding::Base64Url).expect("32-byte key");
        // Exactly one zeroize: the helper consumes the buffer and
        // its Drop fires at function return. Two zeroizes would
        // mean an accidental clone-and-zeroize round-trip; zero
        // means the buffer was leaked past the function.
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
        assert_eq!(key.as_bytes(), &[0u8; crate::internal::KEY_LEN]);
    }

    #[test]
    fn extract_key_from_buffer_base64url_trims_surrounding_whitespace() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let mut payload = alloc::string::String::from(VALID_BASE64URL_32B);
        payload.push('\n');
        let buf = Counted::new(payload.into_bytes(), &COUNTER);
        let _ = extract_key_from_buffer(buf, KeyEncoding::Base64Url).expect("trailing-\\n is ok");
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn extract_key_from_buffer_raw_accepts_exact_32_bytes() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let buf = Counted::new(alloc::vec![0xCDu8; crate::internal::KEY_LEN], &COUNTER);
        let key = extract_key_from_buffer(buf, KeyEncoding::Raw).expect("raw key");
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
        assert_eq!(
            key.as_bytes(),
            &[0xCDu8; crate::internal::KEY_LEN],
            "raw bytes round-trip verbatim",
        );
    }

    #[test]
    fn extract_key_from_buffer_raw_rejects_wrong_length() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let buf = Counted::new(alloc::vec![0u8; crate::internal::KEY_LEN - 1], &COUNTER);
        assert!(matches!(
            extract_key_from_buffer(buf, KeyEncoding::Raw),
            Err(KeyError::InvalidFormat),
        ));
    }

    #[test]
    fn extract_key_from_buffer_base64url_rejects_non_utf8() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        // A non-UTF-8 byte cannot be a valid base64url codepoint;
        // strict failure beats silently truncating to the UTF-8
        // prefix and pretending the rest is padding.
        let buf = Counted::new(alloc::vec![0xFFu8; 4], &COUNTER);
        assert!(matches!(
            extract_key_from_buffer(buf, KeyEncoding::Base64Url),
            Err(KeyError::InvalidFormat),
        ));
    }

    #[test]
    fn read_file_bytes_maps_missing_path_to_not_found() {
        let mut path = std::env::temp_dir();
        path.push("litmask-fileprovider-definitely-not-existing-xyz-42");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(read_file_bytes(&path), Err(KeyError::NotFound),));
    }

    #[test]
    fn key_encoding_default_for_new_is_base64url() {
        // `new(path)` is documented (§2.5.3.1) as the default-base64url
        // constructor; locked here so a future refactor that flips the
        // default surfaces as a test failure rather than silent
        // breakage of every FileProvider deployment.
        let provider = FileProvider::new("/dev/null");
        assert_eq!(provider.encoding, KeyEncoding::Base64Url);
    }
}
