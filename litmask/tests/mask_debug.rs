//! Integration tests for `#[derive(MaskDebug)]`.
//!
//! Output-identity contract: a type deriving `MaskDebug` must produce
//! byte-identical `{:?}` and `{:#?}` output to the same shape deriving
//! plain `Debug` — masking names changes the binary's `.rodata`, never
//! the formatted output.

mod common;

use litmask::MaskDebug;

#[derive(MaskDebug)]
struct MaskedConfig {
    license_server_url: String,
    activation_count: u32,
}

/// Plain-derive twin with the *same* type name, so the formatted
/// output (which includes the type name) can be compared verbatim.
mod plain {
    #[derive(Debug)]
    pub struct MaskedConfig {
        pub license_server_url: String,
        pub activation_count: u32,
    }
}

#[test]
fn mask_debug_named_struct_matches_plain_derive() {
    common::init_once();
    let masked = MaskedConfig {
        license_server_url: "https://license.example.com".to_string(),
        activation_count: 7,
    };
    let plain = plain::MaskedConfig {
        license_server_url: "https://license.example.com".to_string(),
        activation_count: 7,
    };
    assert_eq!(format!("{masked:?}"), format!("{plain:?}"));
    assert_eq!(format!("{masked:#?}"), format!("{plain:#?}"));
    assert_eq!(
        format!("{masked:?}"),
        r#"MaskedConfig { license_server_url: "https://license.example.com", activation_count: 7 }"#,
    );
}
