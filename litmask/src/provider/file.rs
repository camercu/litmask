//! [`FileProvider`] + [`KeyEncoding`]: reads `unlock_key` from a
//! filesystem path.

use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyError;
use crate::internal::KEY_LEN;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// Wire-format expected by [`FileProvider`].
///
/// Adding a future encoding is a non-breaking change for downstream
/// exhaustive matches via `#[non_exhaustive]`.
///
/// # Examples
///
/// ```
/// use litmask::KeyEncoding;
///
/// let enc = KeyEncoding::Base64Url;
/// assert_eq!(enc, KeyEncoding::Base64Url);
/// ```
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
/// # Examples
///
/// ```no_run
/// # fn main() -> Result<(), litmask::InitError> {
/// let provider = litmask::FileProvider::new("/run/secrets/litmask_key");
/// litmask::init_with!(provider)?;
/// # Ok(())
/// # }
/// ```
///
/// `FileProvider::new(path)` decodes the contents as base64url.
/// [`FileProvider::with_encoding`] swaps the encoding. Errors map:
///
/// | Condition | Error |
/// |---|---|
/// | Path does not exist | [`KeyError::NotFound`] |
/// | Path exists but is unreadable by this process | [`KeyError::Permission`] |
/// | Contents do not parse, or wrong length | [`KeyError::InvalidFormat`] |
///
/// The in-memory copy of the file bytes is wiped immediately after
/// the 32-byte key is extracted via a `Zeroizing` wrapper
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
#[derive(Debug)]
pub struct FileProvider {
    path: std::path::PathBuf,
    encoding: KeyEncoding,
}

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
/// exhaustive against the documented behavior: missing →
/// `NotFound`, anything that prevents the read attempt from
/// completing → `Permission`. Genuine I/O failures (transient disk
/// errors, etc.) are rare enough that bucketing them under
/// `Permission` for v0 is acceptable; the `KeyError::Provider`
/// variant is the canonical home for a richer error surface in v1.
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

#[cfg(test)]
mod tests {
    use super::super::test_util::Counted;
    use super::*;
    use crate::key::VALID_BASE64URL_32B;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn extract_key_from_buffer_zeroizes_input_exactly_once() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let buf = Counted::new(VALID_BASE64URL_32B.as_bytes().to_vec(), &COUNTER);
        let key = extract_key_from_buffer(buf, KeyEncoding::Base64Url).expect("32-byte key");
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
        assert_eq!(key.as_bytes(), &[0u8; KEY_LEN]);
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
        let buf = Counted::new(alloc::vec![0xCDu8; KEY_LEN], &COUNTER);
        let key = extract_key_from_buffer(buf, KeyEncoding::Raw).expect("raw key");
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
        assert_eq!(
            key.as_bytes(),
            &[0xCDu8; KEY_LEN],
            "raw bytes round-trip verbatim",
        );
    }

    #[test]
    fn extract_key_from_buffer_raw_rejects_wrong_length() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let buf = Counted::new(alloc::vec![0u8; KEY_LEN - 1], &COUNTER);
        assert!(matches!(
            extract_key_from_buffer(buf, KeyEncoding::Raw),
            Err(KeyError::InvalidFormat),
        ));
    }

    #[test]
    fn extract_key_from_buffer_base64url_rejects_non_utf8() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
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
    fn debug_shows_path_and_encoding() {
        let p = FileProvider::new("/run/secrets/key");
        let dbg = alloc::format!("{p:?}");
        assert!(dbg.contains("/run/secrets/key"), "Debug must show the path");
        assert!(dbg.contains("Base64Url"), "Debug must show the encoding");
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
