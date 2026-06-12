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

#[derive(MaskDebug)]
struct MaskedPair(String, u32);

#[derive(MaskDebug)]
struct MaskedMarker;

#[derive(MaskDebug)]
enum MaskedMode {
    Idle,
    Probing(String, u8),
    Active { since_epoch: u64 },
}

/// Plain-derive twins with the *same* type names, so the formatted
/// output (which includes the type name) can be compared verbatim.
mod plain {
    #[derive(Debug)]
    pub struct MaskedConfig {
        pub license_server_url: String,
        pub activation_count: u32,
    }

    #[derive(Debug)]
    pub struct MaskedPair(pub String, pub u32);

    #[derive(Debug)]
    pub struct MaskedMarker;

    #[derive(Debug)]
    pub enum MaskedMode {
        Idle,
        Probing(String, u8),
        Active { since_epoch: u64 },
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

#[test]
fn mask_debug_tuple_struct_matches_plain_derive() {
    common::init_once();
    let masked = MaskedPair("beacon".to_string(), 3);
    let plain = plain::MaskedPair("beacon".to_string(), 3);
    assert_eq!(format!("{masked:?}"), format!("{plain:?}"));
    assert_eq!(format!("{masked:#?}"), format!("{plain:#?}"));
    assert_eq!(format!("{masked:?}"), r#"MaskedPair("beacon", 3)"#);
}

#[test]
fn mask_debug_unit_struct_matches_plain_derive() {
    common::init_once();
    assert_eq!(
        format!("{:?}", MaskedMarker),
        format!("{:?}", plain::MaskedMarker)
    );
    assert_eq!(
        format!("{:#?}", MaskedMarker),
        format!("{:#?}", plain::MaskedMarker)
    );
    assert_eq!(format!("{:?}", MaskedMarker), "MaskedMarker");
}

#[test]
fn mask_debug_enum_variants_match_plain_derive() {
    common::init_once();
    let cases = [
        (MaskedMode::Idle, plain::MaskedMode::Idle),
        (
            MaskedMode::Probing("ping".to_string(), 2),
            plain::MaskedMode::Probing("ping".to_string(), 2),
        ),
        (
            MaskedMode::Active { since_epoch: 99 },
            plain::MaskedMode::Active { since_epoch: 99 },
        ),
    ];
    for (masked, plain) in &cases {
        assert_eq!(format!("{masked:?}"), format!("{plain:?}"));
        assert_eq!(format!("{masked:#?}"), format!("{plain:#?}"));
    }
    assert_eq!(
        format!("{:?}", MaskedMode::Active { since_epoch: 99 }),
        "Active { since_epoch: 99 }"
    );
}
