//! Shared `litmask.config` parsing for the CLI subcommands.
//!
//! Both `inspect` and `bind` read the same TOML file:
//!
//! ```toml
//! unlock_key = "<base64url>"
//! locator    = "<base64url>"
//! length     = 62
//! ```
//!
//! `inspect` needs only `locator`; `bind` needs `unlock_key` and
//! `locator`. The two subcommands historically each carried their
//! own copy of the parse logic plus their own malformed-input
//! error category. Consolidating here gives one canonical parse
//! function and one typed error surface — drift between the two
//! subcommands' TOML expectations cannot happen.

use litmask_internal::{KEY_LEN, NONCE_LEN, base64url};
use zeroize::Zeroizing;

/// Decoded `litmask.config` payload. `unlock_key` is wrapped in
/// `Zeroizing` so the heap copy wipes on drop — callers that
/// extract the bytes into their own buffer (e.g. `bind` copies into
/// a `[u8; KEY_LEN]` array) take responsibility for further
/// lifecycle.
#[derive(Debug)]
pub(crate) struct LitmaskConfig {
    pub(crate) unlock_key: [u8; KEY_LEN],
    pub(crate) locator: [u8; NONCE_LEN],
}

/// Failure shapes for [`parse`]. The granularity matches what each
/// subcommand can act on: callers map `Malformed` to their
/// stdout/exit-code surface (`ConfigMalformed` outcome for `bind`,
/// `EX_USAGE` stderr for `inspect`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// TOML body did not parse as a document, or lacked one of the
    /// required fields, or the base64url payload did not decode to
    /// the expected length.
    Malformed,
}

/// Parse `litmask.config` text into the canonical typed shape.
///
/// `inspect` needs only `locator`; calling [`parse_locator_only`]
/// avoids decoding `unlock_key` (and skipping the Zeroizing wrap
/// for a field the caller doesn't use).
pub(crate) fn parse(config_text: &str) -> Result<LitmaskConfig, ParseError> {
    let table: toml::Table = config_text.parse().map_err(|_| ParseError::Malformed)?;
    let unlock_key = decode_unlock_key(&table)?;
    let locator = decode_locator(&table)?;
    Ok(LitmaskConfig {
        unlock_key,
        locator,
    })
}

/// Decode just the `locator` field. Used by `inspect`, which never
/// touches `unlock_key` — skipping the `unlock_key` parse path avoids
/// decoding the secret to its raw 32-byte form. (The base64url-encoded
/// secret still transits the `toml::Table` we parse above; eliminating
/// the secret from `inspect`'s address space entirely would require a
/// scanner that drops `unlock_key` before the TOML body lands in
/// memory, which §2.9.2 doesn't ask for.)
pub(crate) fn parse_locator_only(config_text: &str) -> Result<[u8; NONCE_LEN], ParseError> {
    let table: toml::Table = config_text.parse().map_err(|_| ParseError::Malformed)?;
    decode_locator(&table)
}

fn decode_unlock_key(table: &toml::Table) -> Result<[u8; KEY_LEN], ParseError> {
    let text = table
        .get("unlock_key")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::Malformed)?;
    let bytes = Zeroizing::new(base64url::decode(text).map_err(|_| ParseError::Malformed)?);
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ParseError::Malformed)
}

fn decode_locator(table: &toml::Table) -> Result<[u8; NONCE_LEN], ParseError> {
    let text = table
        .get("locator")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::Malformed)?;
    let bytes = base64url::decode(text).map_err(|_| ParseError::Malformed)?;
    bytes.try_into().map_err(|_| ParseError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 zero bytes
    const VALID_LOCATOR_B64: &str = "AAAAAAAAAAAAAAAA"; // 12 zero bytes

    fn valid_config() -> String {
        format!(
            "# fixture\nunlock_key = \"{VALID_KEY_B64}\"\nlocator = \"{VALID_LOCATOR_B64}\"\nlength = 62\n",
        )
    }

    #[test]
    fn parse_accepts_well_formed_config() {
        let cfg = parse(&valid_config()).expect("well-formed config parses");
        assert_eq!(cfg.unlock_key, [0u8; KEY_LEN]);
        assert_eq!(cfg.locator, [0u8; NONCE_LEN]);
    }

    #[test]
    fn parse_accepts_leading_comment_block() {
        // `# litmask.config` headers from litmask-build come with a
        // multi-line comment; the document parser must skip past them.
        let body = format!(
            "# litmask.config — fixture\n# SECRET: do not commit.\nunlock_key = \"{VALID_KEY_B64}\"\nlocator = \"{VALID_LOCATOR_B64}\"\n",
        );
        assert!(parse(&body).is_ok());
    }

    #[test]
    fn parse_rejects_missing_unlock_key() {
        let body = format!("locator = \"{VALID_LOCATOR_B64}\"\n");
        assert!(matches!(parse(&body), Err(ParseError::Malformed)));
    }

    #[test]
    fn parse_rejects_missing_locator() {
        let body = format!("unlock_key = \"{VALID_KEY_B64}\"\n");
        assert!(matches!(parse(&body), Err(ParseError::Malformed)));
    }

    #[test]
    fn parse_rejects_non_string_unlock_key() {
        let body = format!("unlock_key = 42\nlocator = \"{VALID_LOCATOR_B64}\"\n");
        assert!(matches!(parse(&body), Err(ParseError::Malformed)));
    }

    #[test]
    fn parse_rejects_invalid_base64url_unlock_key() {
        let body =
            format!("unlock_key = \"not valid base64!!!\"\nlocator = \"{VALID_LOCATOR_B64}\"\n",);
        assert!(matches!(parse(&body), Err(ParseError::Malformed)));
    }

    #[test]
    fn parse_rejects_wrong_length_locator() {
        // 16 raw bytes = 22 base64url chars; not the required 12.
        let too_long = base64url::encode(&[0u8; 16]);
        let body = format!("unlock_key = \"{VALID_KEY_B64}\"\nlocator = \"{too_long}\"\n");
        assert!(matches!(parse(&body), Err(ParseError::Malformed)));
    }

    #[test]
    fn parse_rejects_wrong_length_unlock_key() {
        let too_short = base64url::encode(&[0u8; 24]);
        let body = format!("unlock_key = \"{too_short}\"\nlocator = \"{VALID_LOCATOR_B64}\"\n");
        assert!(matches!(parse(&body), Err(ParseError::Malformed)));
    }

    #[test]
    fn parse_rejects_non_toml_garbage() {
        assert!(matches!(
            parse("this is not toml at all"),
            Err(ParseError::Malformed)
        ));
    }

    #[test]
    fn parse_locator_only_succeeds_without_unlock_key() {
        let body = format!("locator = \"{VALID_LOCATOR_B64}\"\nlength = 62\n");
        assert_eq!(parse_locator_only(&body).unwrap(), [0u8; NONCE_LEN]);
    }

    #[test]
    fn parse_locator_only_still_rejects_missing_locator() {
        let body = format!("unlock_key = \"{VALID_KEY_B64}\"\n");
        assert_eq!(parse_locator_only(&body), Err(ParseError::Malformed));
    }
}
