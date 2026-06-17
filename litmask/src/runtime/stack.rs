//! Stack-backed masked outputs (the `mask_stack!` family).
//!
//! Each guard owns its decrypted plaintext inline in a `Zeroizing<[u8; N]>`
//! — no heap allocation — and wipes it on drop. `N` is the exact plaintext
//! length, stamped as a `const` by the `mask_stack!` expansion from the
//! literal it sealed (so the blob's `nonce || ciphertext || tag` framing
//! gives `N = blob.len() - NONCE_LEN - TAG_LEN`).
//!
//! Unlike the heap `mask!` outputs (`String` / `Vec` / `CString`), these
//! never touch the allocator at all — their distinguishing property. This
//! is *not* a stronger wipe than the heap path: a `mask!` literal's length
//! is fixed at compile time, so its buffer is a single exact-size
//! allocation that `Zeroizing<mask!(...)>` overwrites just as completely.
//! The point is keeping the plaintext off the heap entirely.
//!
//! `unsafe` is forbidden workspace-wide, so the `&str` view is produced by
//! a *checked* conversion on every deref. The bytes are valid by
//! construction (the macro sealed valid UTF-8 and the AEAD tag rejects
//! tampering first), so the error arm routes to the same `diagnostics`
//! no-fingerprint panic the heap path uses and is unreachable in practice.

use core::ops::Deref;

use zeroize::Zeroizing;

use crate::internal::{WRAPPER_LEN, decrypt_blob_into};

/// A stack-resident masked UTF-8 string — the output of
/// `mask_stack!("...")`. Derefs to [`str`]; the inline `[u8; N]` buffer is
/// overwritten when the value drops.
pub struct MaskStr<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> Deref for MaskStr<N> {
    type Target = str;

    fn deref(&self) -> &str {
        match core::str::from_utf8(self.0.as_ref()) {
            Ok(s) => s,
            Err(_) => crate::diagnostics::blob_utf8_failure(),
        }
    }
}

/// A stack-resident masked byte string — the output of
/// `mask_stack!(b"...")`. Derefs to `[u8]`; the inline `[u8; N]` buffer is
/// overwritten when the value drops.
pub struct MaskBytes<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> Deref for MaskBytes<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// `mask_stack!("...")` seam: unlock the wrapper's `mask_key` through the
/// governing / lazy path (identical to [`crate::__internal::__decrypt`]),
/// then decrypt `blob` straight into a stack `[u8; N]`, allocating nothing.
///
/// # Panics
///
/// Same policy as the heap seams: bare `panic!()` in release, actionable
/// [`crate::diagnostics`] text in debug, on AEAD failure or a lazy
/// first-`mask_stack!()` against a higher-tier seal.
#[doc(hidden)]
#[must_use]
pub fn __decrypt_stack_str<const N: usize>(
    blob: &[u8],
    wrapper: &[u8; WRAPPER_LEN],
    tier: &str,
) -> MaskStr<N> {
    MaskStr(decrypt_into::<N>(blob, wrapper, tier, 0))
}

/// `mask_stack!(b"...")` seam. Same governed unlock + in-place decrypt as
/// [`__decrypt_stack_str`]; no UTF-8 validation, since the output is raw
/// bytes.
///
/// # Panics
///
/// Same policy as [`__decrypt_stack_str`].
#[doc(hidden)]
#[must_use]
pub fn __decrypt_stack_bytes<const N: usize>(
    blob: &[u8],
    wrapper: &[u8; WRAPPER_LEN],
    tier: &str,
) -> MaskBytes<N> {
    MaskBytes(decrypt_into::<N>(blob, wrapper, tier, 0))
}

/// A stack-resident masked C string — the output of `mask_stack!(c"...")`.
/// Derefs to [`core::ffi::CStr`]; the inline `[u8; N]` buffer holds the
/// `N - 1` payload bytes plus the trailing NUL terminator the blob omits,
/// and is overwritten when the value drops.
///
/// Unlike heap `mask!(c"...")` (which yields a `CString` and so needs
/// `alloc`), this borrows `core::ffi::CStr` from its own inline buffer, so
/// the C-string form needs no allocator at the call site. The crate still
/// links `alloc` today, so this is not yet a fully heapless build.
pub struct MaskCStr<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> Deref for MaskCStr<N> {
    type Target = core::ffi::CStr;

    fn deref(&self) -> &core::ffi::CStr {
        match core::ffi::CStr::from_bytes_with_nul(self.0.as_ref()) {
            Ok(c) => c,
            Err(_) => crate::diagnostics::blob_cstr_failure(),
        }
    }
}

/// `mask_stack!(c"...")` seam. The blob holds the `N - 1` payload bytes
/// (the NUL terminator is stripped before sealing, like heap
/// `mask!(c"...")`); `trailer = 1` leaves the final buffer byte as the `0`
/// terminator a `&CStr` borrow needs.
///
/// # Panics
///
/// Same policy as [`__decrypt_stack_str`].
#[doc(hidden)]
#[must_use]
pub fn __decrypt_stack_cstr<const N: usize>(
    blob: &[u8],
    wrapper: &[u8; WRAPPER_LEN],
    tier: &str,
) -> MaskCStr<N> {
    MaskCStr(decrypt_into::<N>(blob, wrapper, tier, 1))
}

/// Shared body for every stack seam: fetch the `mask_key` (governor or the
/// lazy Embedded floor, exactly like [`crate::__internal::__decrypt`]) and
/// decrypt into the front `N - trailer` bytes of a fresh zeroizing
/// `[u8; N]`. `trailer` is `1` for the NUL-terminated C-string buffer and
/// `0` otherwise; the trailing bytes stay zero. Any failure routes to the
/// bare / `diagnostics` panic the heap path uses, so no litmask-identifying
/// text reaches a release binary.
///
/// `decrypt_blob_into` rejects a payload-length mismatch, so a macro vs.
/// runtime disagreement on `trailer` surfaces here as a decrypt failure
/// rather than silent truncation.
fn decrypt_into<const N: usize>(
    blob: &[u8],
    wrapper: &[u8; WRAPPER_LEN],
    tier: &str,
    trailer: usize,
) -> Zeroizing<[u8; N]> {
    let mask_key = super::mask_key_or_lazy_init(wrapper, tier);
    let mut buf = Zeroizing::new([0u8; N]);
    match decrypt_blob_into(mask_key.as_bytes(), blob, &mut buf[..N - trailer]) {
        Ok(()) => buf,
        Err(_) => crate::diagnostics::blob_failure(),
    }
}
