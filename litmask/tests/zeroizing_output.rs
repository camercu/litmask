//! §2.15.1.1–.2: a consumer can opt a masked output into zeroize-on-drop
//! by wrapping it in the re-exported `litmask::Zeroizing`, without the
//! `mask!` return type changing. These exercise the consumer pattern
//! end-to-end (Embedded tier self-initializes on first `mask!`).

use litmask::{Zeroizing, mask};

#[test]
fn zeroizing_wraps_masked_string_round_trip() {
    let secret = Zeroizing::new(mask!("super-secret-token"));
    // Derefs to `str`, so read sites that took `&str` keep working.
    assert_eq!(secret.as_str(), "super-secret-token");
}

#[test]
fn zeroizing_wraps_masked_bytes_round_trip() {
    let secret = Zeroizing::new(mask!(b"raw-secret-bytes"));
    assert_eq!(secret.as_slice(), b"raw-secret-bytes");
}

#[test]
fn plain_mask_still_returns_string() {
    // §2.15.1.1: the default return type is unchanged — a bare `mask!`
    // still binds to `String`, opting in is the consumer's choice.
    let plain: String = mask!("not-wrapped");
    assert_eq!(plain, "not-wrapped");
}
