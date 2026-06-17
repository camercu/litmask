//! `#[serde(rename_all = ...)]` support in `MaskSerialize` /
//! `MaskDeserialize` (`serde`). Each masked type is compared
//! against a structurally-identical plain-serde twin to pin the case
//! conventions byte-for-byte (§E.2.1/§E.2.6).

#![cfg(feature = "serde")]

mod common;

use litmask::{MaskDeserialize, MaskSerialize};

// One struct per case convention would be verbose; this macro stamps a
// masked twin + plain twin sharing field names, then asserts identical
// JSON and a clean round-trip.
macro_rules! rename_all_case {
    ($test:ident, $rule:literal, $expected:literal) => {
        #[test]
        fn $test() {
            #[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
            #[serde(rename_all = $rule)]
            struct Masked {
                first_field: u8,
                second_field: u8,
            }

            #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
            #[serde(rename_all = $rule)]
            struct Plain {
                first_field: u8,
                second_field: u8,
            }

            let masked = Masked {
                first_field: 1,
                second_field: 2,
            };
            let plain = Plain {
                first_field: 1,
                second_field: 2,
            };
            let json = serde_json::to_string(&masked).expect("serialize");
            assert_eq!(
                json,
                serde_json::to_string(&plain).expect("plain serialize")
            );
            assert!(json.contains($expected), "json {json} lacks {}", $expected);
            let back: Masked = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, masked);
        }
    };
}

rename_all_case!(rename_all_lowercase, "lowercase", "\"first_field\":1");
rename_all_case!(rename_all_uppercase, "UPPERCASE", "\"FIRST_FIELD\":1");
rename_all_case!(rename_all_pascal, "PascalCase", "\"FirstField\":1");
rename_all_case!(rename_all_camel, "camelCase", "\"firstField\":1");
rename_all_case!(rename_all_snake, "snake_case", "\"first_field\":1");
rename_all_case!(
    rename_all_screaming_snake,
    "SCREAMING_SNAKE_CASE",
    "\"FIRST_FIELD\":1"
);
rename_all_case!(rename_all_kebab, "kebab-case", "\"first-field\":1");
rename_all_case!(
    rename_all_screaming_kebab,
    "SCREAMING-KEBAB-CASE",
    "\"FIRST-FIELD\":1"
);

#[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MaskedEnum {
    DormantBeacon,
    // Variant-level `rename_all` applies to this variant's fields,
    // while the container rule applies to the variant names.
    #[serde(rename_all = "camelCase")]
    ActiveRelay {
        relay_endpoint: String,
    },
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PlainEnum {
    DormantBeacon,
    #[serde(rename_all = "camelCase")]
    ActiveRelay {
        relay_endpoint: String,
    },
}

#[test]
fn rename_all_on_enum_variants_and_variant_fields() {
    for (masked, plain) in [
        (MaskedEnum::DormantBeacon, PlainEnum::DormantBeacon),
        (
            MaskedEnum::ActiveRelay {
                relay_endpoint: "r".to_string(),
            },
            PlainEnum::ActiveRelay {
                relay_endpoint: "r".to_string(),
            },
        ),
    ] {
        let json = serde_json::to_string(&masked).expect("serialize");
        assert_eq!(
            json,
            serde_json::to_string(&plain).expect("plain serialize")
        );
        let back: MaskedEnum = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, masked);
    }
}

#[test]
fn rename_all_split_serialize_deserialize() {
    #[derive(MaskSerialize, MaskDeserialize, PartialEq, Debug)]
    #[serde(rename_all(serialize = "kebab-case", deserialize = "PascalCase"))]
    struct Masked {
        first_field: u8,
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    #[serde(rename_all(serialize = "kebab-case", deserialize = "PascalCase"))]
    struct Plain {
        first_field: u8,
    }

    let masked = Masked { first_field: 5 };
    let json = serde_json::to_string(&masked).expect("serialize");
    assert_eq!(
        json,
        serde_json::to_string(&Plain { first_field: 5 }).expect("plain")
    );
    assert_eq!(json, r#"{"first-field":5}"#);
    // Deserialize side uses PascalCase.
    let back: Masked = serde_json::from_str(r#"{"FirstField":9}"#).expect("deserialize");
    assert_eq!(back, Masked { first_field: 9 });
}
