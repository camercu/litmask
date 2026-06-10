//! [`FileProvider`]: reads `unlock_key` material from a filesystem path.

use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyError;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// Reads `unlock_key` material from a filesystem path.
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
/// The file contents are treated as raw external material of any
/// length and normalized into the `unlock_key` via [`UnlockKey::derive`]
/// — no encoding or length constraint. A single trailing newline is
/// stripped so a key file saved by an editor and an env var carrying
/// the same secret derive the identical key. Errors map:
///
/// | Condition | Error |
/// |---|---|
/// | Path does not exist | [`KeyError::NotFound`] |
/// | Path exists but is unreadable by this process | [`KeyError::Permission`] |
///
/// File contents never fail to parse: any bytes are valid material, so
/// there is no `InvalidFormat` surface here.
///
/// The in-memory copy of the file bytes is wiped immediately after the
/// key is derived, via a `Zeroizing` wrapper around the read buffer.
/// The wipe is verified in unit tests via a `Counted<T>` newtype that
/// bumps an `AtomicUsize` from its `Zeroize` impl.
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
}

impl FileProvider {
    /// Construct a `FileProvider` reading `path`.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
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
        Ok(derive_key_from_buffer(buffer))
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

/// Normalize a file-buffer payload into an [`UnlockKey`] via the
/// external-material KDF. Takes the buffer by value so its `Drop`
/// (zeroizing wrapper) runs at function return — the generic bound on
/// `Zeroize` is load-bearing: it pins the buffer to a wrapper that
/// wipes on drop, so a caller cannot accidentally hand in a plain
/// `Vec<u8>` that lingers in the allocator.
///
/// A single trailing newline is stripped during derivation (editors
/// append one when saving) so the file and env channels agree on one
/// secret; the trim lives inside [`UnlockKey::derive`]. Any bytes are
/// valid material — derivation is infallible.
#[allow(clippy::needless_pass_by_value)]
fn derive_key_from_buffer<Z>(buffer: Z) -> UnlockKey
where
    Z: AsRef<[u8]> + Zeroize,
{
    UnlockKey::derive(buffer.as_ref())
}

#[cfg(test)]
mod tests {
    use super::super::test_util::Counted;
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn derive_key_from_buffer_derives_and_zeroizes_input_exactly_once() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let buf = Counted::new(b"operator material".to_vec(), &COUNTER);
        let key = derive_key_from_buffer(buf);
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
        assert_eq!(key, UnlockKey::derive(b"operator material"));
    }

    #[test]
    fn derive_key_from_buffer_strips_one_trailing_newline() {
        static BARE: AtomicUsize = AtomicUsize::new(0);
        static NEWLINED: AtomicUsize = AtomicUsize::new(0);
        let bare = derive_key_from_buffer(Counted::new(b"secret".to_vec(), &BARE));
        let newlined = derive_key_from_buffer(Counted::new(b"secret\n".to_vec(), &NEWLINED));
        // A key file with the editor-appended newline derives the same
        // key as the bare secret — the file and env channels agree.
        assert_eq!(bare, newlined);
    }

    #[test]
    fn derive_key_from_buffer_accepts_arbitrary_length() {
        static SHORT: AtomicUsize = AtomicUsize::new(0);
        static LONG: AtomicUsize = AtomicUsize::new(0);
        // No length constraint: the KDF normalizes any-length material.
        let short = derive_key_from_buffer(Counted::new(alloc::vec![0x01u8; 1], &SHORT));
        let long = derive_key_from_buffer(Counted::new(alloc::vec![0x01u8; 4096], &LONG));
        assert_ne!(short, long);
    }

    #[test]
    fn read_file_bytes_maps_missing_path_to_not_found() {
        let mut path = std::env::temp_dir();
        path.push("litmask-fileprovider-definitely-not-existing-xyz-42");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(read_file_bytes(&path), Err(KeyError::NotFound),));
    }

    #[test]
    fn debug_shows_path() {
        let p = FileProvider::new("/run/secrets/key");
        let dbg = alloc::format!("{p:?}");
        assert!(dbg.contains("/run/secrets/key"), "Debug must show the path");
    }
}
