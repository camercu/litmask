//! Self-checking machine-id token codec (§2.9.3).
//!
//! `litmask show-machine-id` prints the host machine id with an
//! appended check group so an operator copying it through a
//! human channel (chat, email, a ticket) can have the value validated
//! before it is sealed into a build. The check group rides **in-band**
//! in the copied token — stdout, not stderr — because the copy channel
//! carries only what the operator selected, and a separate stream would
//! be dropped.
//!
//! The token is `raw_id ‖ "." ‖ check`, where `check` is the
//! base64url encoding of the first [`CHECK_LEN`] bytes of
//! `BLAKE3(raw_id)`. The raw machine id never contains `.` (it is hex
//! and/or hyphen-delimited UUID text), and the base64url alphabet never
//! emits `.`, so the separator is unambiguous: the token splits at its
//! single `.`.
//!
//! Both the CLI (which emits the token) and `litmask-build::emit` (which
//! decodes `LITMASK_MACHINE_ID` back to the raw id before deriving the
//! machine key) call through here, so a token minted on the target host
//! decodes to exactly the bytes the runtime `MachineIdProvider`
//! recomputes via `machine_uid::get()`. A mistyped token is rejected at
//! build time rather than surfacing as an opaque runtime init failure.

use alloc::string::String;

use crate::base64url;

/// Number of leading `BLAKE3(raw_id)` bytes used as the check group.
/// Five bytes (40 bits) make an accidental single-character corruption
/// pass the check with probability `2^-40` — far below any realistic
/// copy/paste error rate — while keeping the appended group short (7
/// base64url characters).
pub const CHECK_LEN: usize = 5;

/// Separator between the raw id and its check group. Chosen because it
/// appears in neither machine-id text (hex / hyphenated UUID) nor the
/// base64url alphabet, so [`decode_machine_id_token`] can split on it
/// unambiguously.
const SEPARATOR: char = '.';

/// Errors from [`decode_machine_id_token`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineTokenError {
    /// No separator was found — the input is not a self-checking token.
    Malformed,
    /// The check group does not match the id it accompanies: the token
    /// was corrupted in transit (or never was a valid token).
    CheckMismatch,
}

impl core::fmt::Display for MachineTokenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("not a self-checking machine-id token (no check group)"),
            Self::CheckMismatch => {
                f.write_str("machine-id token check group mismatch (corrupted in transit?)")
            }
        }
    }
}

impl core::error::Error for MachineTokenError {}

/// Compute the base64url check group for `raw_id`.
fn check_group(raw_id: &str) -> String {
    let digest = blake3::hash(raw_id.as_bytes());
    base64url::encode(&digest.as_bytes()[..CHECK_LEN])
}

/// Encode a raw machine id as its self-checking token (§2.9.3).
#[must_use]
pub fn encode_machine_id_token(raw_id: &str) -> String {
    let mut token = String::with_capacity(raw_id.len() + 1 + (CHECK_LEN * 4 / 3 + 1));
    token.push_str(raw_id);
    token.push(SEPARATOR);
    token.push_str(&check_group(raw_id));
    token
}

/// Decode a self-checking token back to its raw machine id, validating
/// the check group.
///
/// # Errors
///
/// - [`MachineTokenError::Malformed`] if `token` has no separator.
/// - [`MachineTokenError::CheckMismatch`] if the check group does not
///   match the accompanying id (corruption in transit).
pub fn decode_machine_id_token(token: &str) -> Result<&str, MachineTokenError> {
    let (raw_id, check) = token
        .rsplit_once(SEPARATOR)
        .ok_or(MachineTokenError::Malformed)?;
    if check_group(raw_id) == check {
        Ok(raw_id)
    } else {
        Err(MachineTokenError::CheckMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_raw_id() {
        let raw = "ABCDEF01-2345-6789-ABCD-EF0123456789";
        let token = encode_machine_id_token(raw);
        assert_eq!(decode_machine_id_token(&token), Ok(raw));
    }

    #[test]
    fn token_carries_the_raw_id_as_a_prefix() {
        let raw = "deadbeefdeadbeefdeadbeefdeadbeef";
        let token = encode_machine_id_token(raw);
        assert!(token.starts_with(raw));
        assert_eq!(token.as_bytes()[raw.len()], b'.');
    }

    #[test]
    fn rejects_input_without_a_separator() {
        assert_eq!(
            decode_machine_id_token("no-check-group-here"),
            Err(MachineTokenError::Malformed)
        );
    }

    /// The whole point of the check group: any single-character
    /// corruption — in the id half OR the check half — must be caught.
    #[test]
    fn detects_single_character_corruption_anywhere() {
        let raw = "ABCDEF01-2345-6789-ABCD-EF0123456789";
        let token = encode_machine_id_token(raw);
        let bytes = token.as_bytes();
        for i in 0..bytes.len() {
            let mut corrupted = bytes.to_vec();
            // Flip to a definitely-different ASCII char that keeps the
            // string UTF-8 and within the token's character classes.
            corrupted[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
            let corrupted = String::from_utf8(corrupted).expect("ascii stays utf-8");
            if corrupted == token {
                continue;
            }
            assert_ne!(
                decode_machine_id_token(&corrupted),
                Ok(raw),
                "corruption at byte {i} ({corrupted:?}) slipped past the check group"
            );
        }
    }

    #[test]
    fn a_valid_token_for_a_different_id_decodes_to_that_other_id() {
        // A well-formed token captured on another host decodes cleanly —
        // it is simply the *wrong* host, detected later by the key
        // derivation, not by the check group.
        let other = encode_machine_id_token("not-this-hosts-machine-id-0000");
        assert_eq!(
            decode_machine_id_token(&other),
            Ok("not-this-hosts-machine-id-0000")
        );
    }
}
