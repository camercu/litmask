//! Reversible XOR obfuscation backing the `weak_mask!` macro.

use alloc::vec::Vec;

/// XOR every byte of `input` against the cyclically-repeated `key`,
/// returning the result as a new `Vec`.
///
/// The operation is its own inverse: applying it twice with the same
/// key recovers the original input. Used by the `weak_mask!` macro to
/// obfuscate string literals against the per-build wrapper bytes so
/// litmask-supplied static strings do not contribute a fixed byte
/// signature to user binaries.
///
/// # Panics
///
/// Panics if `key.is_empty()` while `input` is non-empty.
#[must_use]
pub fn xor_cycle(input: &[u8], key: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    assert!(!key.is_empty(), "key must be non-empty");
    input
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_cycle_empty_input_is_noop() {
        let key = [0xAAu8; 8];
        assert!(xor_cycle(&[], &key).is_empty());
    }

    #[test]
    fn xor_cycle_self_inverse_with_matching_lengths() {
        let plaintext = b"hello world";
        let key = b"0123456789ab";
        let encoded = xor_cycle(plaintext, key);
        let decoded = xor_cycle(&encoded, key);
        assert_eq!(decoded.as_slice(), plaintext);
    }

    #[test]
    fn xor_cycle_handles_key_shorter_than_input() {
        let plaintext = b"abcdef";
        let key = b"\xff\x55";
        let out = xor_cycle(plaintext, key);
        assert_eq!(
            out.as_slice(),
            &[
                b'a' ^ 0xff,
                b'b' ^ 0x55,
                b'c' ^ 0xff,
                b'd' ^ 0x55,
                b'e' ^ 0xff,
                b'f' ^ 0x55,
            ]
        );
    }

    #[test]
    fn xor_cycle_handles_key_longer_than_input() {
        let plaintext = b"hi";
        let key = b"\x01\x02\x03\x04\x05";
        let out = xor_cycle(plaintext, key);
        assert_eq!(out.as_slice(), &[b'h' ^ 0x01, b'i' ^ 0x02]);
    }

    #[test]
    #[should_panic(expected = "key must be non-empty")]
    fn xor_cycle_panics_on_empty_key_with_nonempty_input() {
        let _ = xor_cycle(b"x", &[]);
    }

    proptest::proptest! {
        #[test]
        fn proptest_xor_cycle_self_inverse(
            input in proptest::collection::vec(proptest::num::u8::ANY, 0..=512),
            key in proptest::collection::vec(proptest::num::u8::ANY, 1..=64),
        ) {
            let encoded = xor_cycle(&input, &key);
            let decoded = xor_cycle(&encoded, &key);
            proptest::prop_assert_eq!(decoded, input);
        }
    }
}
