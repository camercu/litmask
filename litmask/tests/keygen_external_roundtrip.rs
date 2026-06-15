//! `litmask keygen` produces a usable `LITMASK_UNLOCK_KEY` (§2.9.2).
//!
//! `keygen` is a pure stdout generator: 32 random bytes, base64url. The
//! external tier derives its `unlock_key` from *arbitrary* material via
//! `KDF("litmask-unlock-v1", material)`, so a keygen value is consumable
//! as-is. This test proves the pipe `litmask keygen | <consumer>` end to
//! end: mint a key, seal the external fixture under it, and confirm the
//! same key opens the binary (and a different key does not).
//!
//! The fixture is the same one `external_tier_e2e` uses; cargo runs test
//! binaries sequentially, so the shared fixture target dir is not raced.

use std::process::Command;

mod common;

/// Mint a key by running the real CLI: `litmask keygen`. Returns the
/// trimmed stdout — exactly what a `litmask keygen | …` pipe delivers.
fn keygen() -> String {
    let out = Command::new(common::cargo())
        .args(["run", "--quiet", "-p", "litmask-cli", "--", "keygen"])
        .current_dir(common::workspace_root())
        .output()
        .expect("invoke `cargo run -p litmask-cli -- keygen`");
    assert!(out.status.success(), "keygen exited non-zero");
    assert!(out.stderr.is_empty(), "keygen must write nothing to stderr");
    String::from_utf8(out.stdout)
        .expect("keygen stdout is UTF-8")
        .trim_end()
        .to_owned()
}

#[test]
fn keygen_output_is_a_usable_external_unlock_key() {
    let key = keygen();
    // A keygen value is 32 bytes base64url (43 unpadded chars).
    assert_eq!(key.len(), 43, "keygen output should be 43 base64url chars");
    assert_eq!(
        litmask_internal::base64url::decode(&key)
            .expect("keygen output decodes")
            .len(),
        32,
        "keygen output must decode to 32 bytes",
    );

    let bin = common::build_sealed_fixture(&key);

    let (ok, stdout) = common::run_fixture(&bin, &key);
    assert!(ok, "the minted key must open the binary it sealed");
    assert!(
        stdout.contains(common::CANARY),
        "keygen key must decrypt the canary; stdout was {stdout:?}"
    );

    // A different key re-derives a different unlock_key → AEAD rejects it.
    let other = keygen();
    assert_ne!(key, other, "two keygen calls must differ");
    let (ok, stdout) = common::run_fixture(&bin, &other);
    assert!(!ok, "a different key must not open the binary");
    assert!(
        !stdout.contains(common::CANARY),
        "a wrong key must never reveal the canary; stdout was {stdout:?}"
    );
}
