//! `#[serde(default)]` / `#[serde(default = "path")]` support in
//! `MaskDeserialize` (`serde`), including the interaction with
//! `skip_deserializing`. Compared against a plain-serde twin so the
//! accepted inputs and filled values match byte-for-byte (§E.2.6).

#![cfg(feature = "serde")]

mod common;

use litmask::{MaskDeserialize, MaskSerialize};

fn default_port() -> u16 {
    8443
}

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
struct MaskedDefaults {
    host: String,
    #[serde(default)]
    retries: u8,
    #[serde(default = "default_port")]
    port: u16,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct PlainDefaults {
    host: String,
    #[serde(default)]
    retries: u8,
    #[serde(default = "default_port")]
    port: u16,
}

#[test]
fn missing_fields_use_defaults_like_plain_derive() {
    // Only `host` present: `retries` -> Default (0), `port` -> path (8443).
    let input = r#"{"host":"h"}"#;
    let masked: MaskedDefaults = serde_json::from_str(input).expect("masked de");
    let plain: PlainDefaults = serde_json::from_str(input).expect("plain de");
    assert_eq!(masked.host, plain.host);
    assert_eq!(masked.retries, plain.retries);
    assert_eq!(masked.port, plain.port);
    assert_eq!(masked.retries, 0);
    assert_eq!(masked.port, 8443);
}

#[test]
fn present_fields_override_defaults() {
    let input = r#"{"host":"h","retries":5,"port":1234}"#;
    let masked: MaskedDefaults = serde_json::from_str(input).expect("masked de");
    assert_eq!(
        masked,
        MaskedDefaults {
            host: "h".to_string(),
            retries: 5,
            port: 1234,
        },
    );
}

#[test]
fn default_missing_via_seq() {
    // Positional (seq) input shorter than the struct: trailing
    // defaulted fields fill in rather than erroring on length.
    let masked: MaskedDefaults = serde_json::from_str(r#"["h"]"#).expect("masked seq de");
    let plain: PlainDefaults = serde_json::from_str(r#"["h"]"#).expect("plain seq de");
    assert_eq!(masked.host, plain.host);
    assert_eq!(masked.retries, plain.retries);
    assert_eq!(masked.port, plain.port);
}

// skip_deserializing + default = "path": the skipped field takes the
// path's value, not Default.
#[derive(MaskDeserialize, PartialEq, Debug)]
struct MaskedSkipDefault {
    kept: u8,
    #[serde(skip_deserializing, default = "default_port")]
    port: u16,
}

#[derive(serde::Deserialize, PartialEq, Debug)]
struct PlainSkipDefault {
    kept: u8,
    #[serde(skip_deserializing, default = "default_port")]
    port: u16,
}

#[test]
fn skip_deserializing_uses_default_path() {
    let input = r#"{"kept":3,"port":999}"#;
    let masked: MaskedSkipDefault = serde_json::from_str(input).expect("masked de");
    let plain: PlainSkipDefault = serde_json::from_str(input).expect("plain de");
    assert_eq!(masked.kept, plain.kept);
    assert_eq!(masked.port, plain.port);
    // `port` is skip_deserializing, so the wire value 999 is ignored and
    // the default path supplies 8443.
    assert_eq!(masked.port, 8443);
}
