//! Integration tests for `#[mask_all]`'s derive-swapping
//! (`unstable-serde`): a plain `#[derive(Serialize)]` /
//! `#[derive(Deserialize)]` / `#[derive(Debug)]` on a type inside a
//! `#[mask_all]` module is rewritten to litmask's masking derives, so
//! the round-trip and `Debug` output stay byte-identical to the plain
//! derives while the names are AEAD-masked in the binary (binary
//! absence is pinned by the `strings` scrub in `example_scrub.rs`).

#![cfg(feature = "unstable-serde")]

mod common;

use litmask::mask_all;

#[mask_all]
mod swapped {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    pub struct Config {
        pub license_server_url: String,
        pub activation_count: u32,
    }
}

#[test]
fn mask_all_swaps_serde_derives_round_trip() {
    let config = swapped::Config {
        license_server_url: "https://license.example.com".to_string(),
        activation_count: 7,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    assert_eq!(
        json,
        r#"{"license_server_url":"https://license.example.com","activation_count":7}"#,
    );
    let back: swapped::Config = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, config);
}

#[test]
fn mask_all_swaps_debug_derive_output_identical() {
    let config = swapped::Config {
        license_server_url: "https://license.example.com".to_string(),
        activation_count: 7,
    };
    assert_eq!(
        format!("{config:?}"),
        r#"Config { license_server_url: "https://license.example.com", activation_count: 7 }"#,
    );
}

#[mask_all]
mod swapped_enum {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    pub enum Tier {
        Embedded,
        Machine(u32),
        External { region: String },
    }
}

#[test]
fn mask_all_swaps_derives_on_enum_round_trip() {
    for value in [
        swapped_enum::Tier::Embedded,
        swapped_enum::Tier::Machine(9),
        swapped_enum::Tier::External {
            region: "eu".to_string(),
        },
    ] {
        let json = serde_json::to_string(&value).expect("serialize");
        let back: swapped_enum::Tier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, value);
    }
}

#[mask_all]
mod opted_out {
    // `#[unmasked_derive]` keeps the plain derives — the type still
    // serializes and Debug-prints, proving the opt-out compiles and
    // the marker is consumed by `#[mask_all]`.
    #[litmask::unmasked_derive]
    #[derive(serde::Serialize, Debug, PartialEq)]
    pub struct PlainConfig {
        pub field_one: u8,
    }
}

#[test]
fn mask_all_opt_out_keeps_plain_derives_working() {
    let plain = opted_out::PlainConfig { field_one: 5 };
    assert_eq!(
        serde_json::to_string(&plain).expect("serialize"),
        r#"{"field_one":5}"#,
    );
    assert_eq!(format!("{plain:?}"), "PlainConfig { field_one: 5 }");
}
