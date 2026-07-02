//! [`FileProvider`]: reads `unlock_key` material from a filesystem path.

use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyError;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// Reads `unlock_key` material from a filesystem path.
///
/// # Examples
///
/// ```ignore
/// let provider = litmask::FileProvider::new("/run/secrets/litmask_key");
/// litmask::init!(provider)?;
/// ```
///
/// The snippet is `ignore`d rather than compiled: `init!(provider)` is
/// the External form and only compiles against an externally-sealed
/// build, whereas litmask's own doctests build at the Embedded tier.
///
/// The file contents are treated as raw external material and
/// normalized into the `unlock_key` via [`UnlockKey::derive`] — no
/// encoding step, no upper length constraint. A single trailing newline
/// is stripped so a key file saved by an editor and an env var carrying
/// the same secret derive the identical key. Errors map:
///
/// | Condition | Error |
/// |---|---|
/// | Path does not exist | [`KeyError::NotFound`] |
/// | Path exists but is unreadable by this process | [`KeyError::Permission`] |
/// | Contents are empty after the newline trim | [`KeyError::InvalidFormat`] |
///
/// The empty case is always a misconfiguration (a touched-but-never-
/// populated key file): `emit()` refuses to seal empty material
/// (§1.6.3), so no valid seal can match it. Any other byte sequence is
/// valid material.
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
        derive_key_from_buffer(buffer)
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
/// secret; the trim lives inside [`UnlockKey::derive`]. Material that
/// trims to zero bytes is rejected as [`KeyError::InvalidFormat`] (see
/// the type-level table); any other bytes are valid material.
#[allow(clippy::needless_pass_by_value)]
fn derive_key_from_buffer<Z>(buffer: Z) -> Result<UnlockKey, KeyError>
where
    Z: AsRef<[u8]> + Zeroize,
{
    super::derive_nonempty_material(buffer.as_ref())
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
        let key = derive_key_from_buffer(buf).expect("non-empty material derives");
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
        assert_eq!(key, UnlockKey::derive(b"operator material"));
    }

    #[test]
    fn derive_key_from_buffer_strips_one_trailing_newline() {
        static BARE: AtomicUsize = AtomicUsize::new(0);
        static NEWLINED: AtomicUsize = AtomicUsize::new(0);
        let bare =
            derive_key_from_buffer(Counted::new(b"secret".to_vec(), &BARE)).expect("derives");
        let newlined =
            derive_key_from_buffer(Counted::new(b"secret\n".to_vec(), &NEWLINED)).expect("derives");
        // A key file with the editor-appended newline derives the same
        // key as the bare secret — the file and env channels agree.
        assert_eq!(bare, newlined);
    }

    #[test]
    fn derive_key_from_buffer_accepts_arbitrary_length() {
        static SHORT: AtomicUsize = AtomicUsize::new(0);
        static LONG: AtomicUsize = AtomicUsize::new(0);
        // No upper length constraint: the KDF normalizes any-length
        // non-empty material.
        let short =
            derive_key_from_buffer(Counted::new(alloc::vec![0x01u8; 1], &SHORT)).expect("derives");
        let long = derive_key_from_buffer(Counted::new(alloc::vec![0x01u8; 4096], &LONG))
            .expect("derives");
        assert_ne!(short, long);
    }

    /// An empty key file (touched but never populated) can never open
    /// any valid seal — build-side `emit()` refuses to seal empty
    /// material (§1.6.3). Reject it as `InvalidFormat`, and still wipe
    /// the buffer exactly once on the error path.
    #[test]
    fn derive_key_from_buffer_rejects_empty_material_and_still_zeroizes() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let result = derive_key_from_buffer(Counted::new(alloc::vec::Vec::new(), &COUNTER));
        assert!(matches!(result, Err(KeyError::InvalidFormat)));
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
    }

    /// A file holding only the editor-appended newline is empty material.
    #[test]
    fn derive_key_from_buffer_rejects_newline_only_material() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let result = derive_key_from_buffer(Counted::new(b"\n".to_vec(), &COUNTER));
        assert!(matches!(result, Err(KeyError::InvalidFormat)));
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
