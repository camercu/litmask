//! Integration tests for `#[derive(MaskDebug)]`.
//!
//! Output-identity contract: a type deriving `MaskDebug` must produce
//! byte-identical `{:?}` and `{:#?}` output to the same shape deriving
//! plain `Debug` — masking names changes the binary's `.rodata`, never
//! the formatted output.

// Fixture fields are read only through the generated Debug impls,
// and rustc deliberately ignores `#[automatically_derived]` Debug
// impls in dead-code analysis — plain `derive(Debug)` fixtures would
// warn identically.
#![allow(dead_code)]

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

#[derive(MaskDebug)]
struct MaskedEnvelope<'a, T> {
    sequence_marker_zzyzx: u64,
    borrowed_label_qwxz: &'a str,
    payload: T,
}

#[derive(MaskDebug)]
struct MaskedRawIdent {
    r#type: String,
}

#[derive(MaskDebug)]
enum MaskedRawVariant {
    r#Loop,
}

#[derive(MaskDebug)]
struct MaskedEmpty {}

/// Uninhabited: only needs to compile — there is no value to format.
#[derive(MaskDebug)]
enum MaskedNever {}

#[derive(MaskDebug)]
enum MaskedCarrier<T> {
    Holding(T),
    Tagged { cargo_label_xyzzy: T },
}

/// Field names chosen to collide with the generated locals — the
/// expansion must stay hygienic under adversarial user idents.
#[derive(MaskDebug)]
enum MaskedShadow {
    Clash { __f: u8, __builder: u8 },
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

    #[derive(Debug)]
    pub struct MaskedEnvelope<'a, T> {
        pub sequence_marker_zzyzx: u64,
        pub borrowed_label_qwxz: &'a str,
        pub payload: T,
    }

    #[derive(Debug)]
    pub struct MaskedRawIdent {
        pub r#type: String,
    }

    #[derive(Debug)]
    pub enum MaskedRawVariant {
        r#Loop,
    }

    #[derive(Debug)]
    pub struct MaskedEmpty {}

    #[derive(Debug)]
    pub enum MaskedCarrier<T> {
        Holding(T),
        Tagged { cargo_label_xyzzy: T },
    }

    #[derive(Debug)]
    pub enum MaskedShadow {
        Clash { __f: u8, __builder: u8 },
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
        format!("{MaskedMarker:?}"),
        format!("{:?}", plain::MaskedMarker)
    );
    assert_eq!(
        format!("{MaskedMarker:#?}"),
        format!("{:#?}", plain::MaskedMarker)
    );
    assert_eq!(format!("{MaskedMarker:?}"), "MaskedMarker");
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

#[test]
fn mask_debug_generic_struct_matches_plain_derive() {
    common::init_once();
    let masked = MaskedEnvelope {
        sequence_marker_zzyzx: 42,
        borrowed_label_qwxz: "tag",
        payload: vec!["a", "b"],
    };
    let plain = plain::MaskedEnvelope {
        sequence_marker_zzyzx: 42,
        borrowed_label_qwxz: "tag",
        payload: vec!["a", "b"],
    };
    assert_eq!(format!("{masked:?}"), format!("{plain:?}"));
    assert_eq!(format!("{masked:#?}"), format!("{plain:#?}"));
}

#[test]
fn mask_debug_raw_idents_unraw_like_plain_derive() {
    common::init_once();
    let masked = MaskedRawIdent {
        r#type: "beacon".to_string(),
    };
    let plain = plain::MaskedRawIdent {
        r#type: "beacon".to_string(),
    };
    assert_eq!(format!("{masked:?}"), format!("{plain:?}"));
    assert_eq!(
        format!("{masked:?}"),
        r#"MaskedRawIdent { type: "beacon" }"#
    );
    assert_eq!(
        format!("{:?}", MaskedRawVariant::r#Loop),
        format!("{:?}", plain::MaskedRawVariant::r#Loop),
    );
    assert_eq!(format!("{:?}", MaskedRawVariant::r#Loop), "Loop");
}

#[test]
fn mask_debug_empty_struct_matches_plain_derive() {
    common::init_once();
    assert_eq!(
        format!("{:?}", MaskedEmpty {}),
        format!("{:?}", plain::MaskedEmpty {})
    );
}

#[test]
fn mask_debug_shadowing_field_names_match_plain_derive() {
    common::init_once();
    let masked = MaskedShadow::Clash {
        __f: 1,
        __builder: 2,
    };
    let plain = plain::MaskedShadow::Clash {
        __f: 1,
        __builder: 2,
    };
    assert_eq!(format!("{masked:?}"), format!("{plain:?}"));
    assert_eq!(format!("{masked:#?}"), format!("{plain:#?}"));
}

#[test]
fn mask_debug_generic_enum_matches_plain_derive() {
    common::init_once();
    assert_eq!(
        format!("{:?}", MaskedCarrier::Holding(vec![1u8, 2])),
        format!("{:?}", plain::MaskedCarrier::Holding(vec![1u8, 2])),
    );
    assert_eq!(
        format!(
            "{:#?}",
            MaskedCarrier::Tagged {
                cargo_label_xyzzy: "x"
            }
        ),
        format!(
            "{:#?}",
            plain::MaskedCarrier::Tagged {
                cargo_label_xyzzy: "x"
            }
        ),
    );
}
