//! End-to-end exercise of the **External tier**.
//!
//! A standalone fixture crate (`tests/external_fixture/`) runs
//! `litmask_build::emit()` in its own `build.rs` and calls the External
//! `init!(<provider>)` form. Building it with `LITMASK_UNLOCK_KEY` set
//! seals the `external` tier: the build derives `unlock_key =
//! KDF("litmask-unlock-v1", material)` and wraps `mask_key` under it.
//!
//! The fixture lives in its own one-crate workspace (note the empty
//! `[workspace]` table in its manifest) so building it with
//! `LITMASK_UNLOCK_KEY` present does NOT reseal the litmask crate's own
//! embedded build in this workspace's shared target dir.
//!
//! The test builds the fixture ONCE with material `X`, then runs it
//! TWICE — the runtime material only affects the running process, never
//! the sealed binary:
//!
//! - run with `X` → `EnvVarProvider` re-derives the same `unlock_key`,
//!   unwraps `mask_key`, and `mask!` round-trips the canary plaintext.
//! - run with `Y` → a different `unlock_key`, the AEAD tag check on the
//!   wrapper fails, `init!` returns `Err`, and the canary never prints.

mod common;

/// External-factor material the fixture is SEALED with at build time and
/// the material a successful runtime must re-supply. Arbitrary length /
/// bytes — `UnlockKey::derive` normalizes it.
const SEALED_MATERIAL: &str = "operator-supplied external unlock material v1";

/// Material that does NOT match the seal — re-derives a different
/// `unlock_key`, so the wrapper's AEAD tag check must reject it.
const WRONG_MATERIAL: &str = "an entirely different operator secret";

#[test]
fn external_tier_round_trips_with_matching_material_and_fails_with_wrong_material() {
    let bin = common::build_sealed_fixture(SEALED_MATERIAL);

    let (ok, stdout) = common::run_fixture(&bin, SEALED_MATERIAL);
    assert!(
        ok,
        "fixture should exit cleanly when given the sealed material"
    );
    assert!(
        stdout.contains(common::CANARY),
        "matching material must decrypt the canary; stdout was {stdout:?}"
    );

    let (ok, stdout) = common::run_fixture(&bin, WRONG_MATERIAL);
    assert!(
        !ok,
        "fixture must fail to initialize under non-matching material"
    );
    assert!(
        !stdout.contains(common::CANARY),
        "wrong material must never reveal the canary; stdout was {stdout:?}"
    );
}
