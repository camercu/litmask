//! Regression net: every example binary is scanned with `strings` for
//! a curated list of forbidden substrings. Any case-insensitive match
//! fails the test, catching the kind of identifier or
//! operational-tooling-vocabulary leak that would weaken the library's
//! "no litmask-identifying plaintext in compiled user binaries"
//! property.
//!
//! The scrub builds examples under the strip-symbols release profile
//! (the recommended deployment configuration). Debug builds always
//! contain crate / type name strings via DWARF; testing them against
//! the dirty-word list would be a guaranteed false-positive that
//! provides no signal.
//!
//! The forbidden list lives in `tests/common/mod.rs`. Add an entry
//! when a new identifiable term enters the codebase. The list is not a
//! proof of leak-freedom; high-entropy-fixture strings checks (see
//! `mask_round_trip.rs`) provide the positive security signal.

mod common;

use common::Profile;

/// Examples cleared for the case-insensitive library-identifier scrub
/// under the plain default-features `build_example`. Add new names here
/// when new examples land under `litmask/examples/`.
///
/// Examples absent from this loop need a build the default-features,
/// Embedded-sealed `build_example` cannot produce, so each has a
/// dedicated test that builds with the right features/seal:
///
/// - `file_provider` / `weak_mask_demo`: pass a runtime `KeyProvider`
///   to `init!` (the External form), so they carry
///   `required-features = ["provider-examples"]` and only compile
///   against an externally-sealed build. Their dedicated tests build
///   with that feature and `LITMASK_UNLOCK_KEY` set (which reseals
///   External). `file_provider` also references the published
///   `LITMASK_UNLOCK_KEY_FILE` literal, so it is fixture-scrubbed only;
///   `weak_mask_demo` `weak_mask!()`s its custom env-var name and so
///   still runs the full identifier scrub.
/// - `machine_id_provider`: gated behind `--features machine-id` (see
///   [`machine_id_provider_example_masked_fixtures_absent_from_binary`]).
///   The BLAKE3 context literal `"machine-v1"` is hidden by
///   `weak_mask!()` in `MachineIdProvider`, so it doesn't leak —
///   but the `blake3` crate embeds its own name in internal symbol
///   strings (e.g. `blake3_*` function names) that we can't filter
///   away. The `machine_id` scrub allow-lists `blake3` specifically.
/// - `mask_serde_demo`: gated behind `--features serde`.
const EXAMPLES: &[&str] = &[
    "hello_world",
    "byte_cstr_demo",
    "include_str_demo",
    "mask_format_demo",
    "mask_macros_demo",
    "mask_all_demo",
    "mask_debug_demo",
    "mask_print_e2e",
];

const EXCEPTIONS: &[&str] = &[
    "file_provider",
    "weak_mask_demo",
    "machine_id_provider",
    "mask_serde_demo",
    // `required-features = ["unstable-stack"]`; scrubbed by
    // `stack_demo_fixtures_and_identifiers_absent_from_binary`.
    "stack_demo",
];

/// Arbitrary `LITMASK_UNLOCK_KEY` value for building the provider
/// examples: its presence at build time selects the External seal tier
/// so `init!(provider)` passes its form↔tier cross-check. The value is
/// never used to decrypt — these scrubs inspect bytes and never run the
/// binary — so any non-empty string works.
const SCRUB_EXTERNAL_KEY: &str = "litmask-scrub-external-placeholder-key";

#[test]
fn no_forbidden_substrings_in_any_example_binary() {
    for name in EXAMPLES {
        common::build_example(name, Profile::Release);
        let path = common::example_path(name, Profile::Release);
        assert!(path.exists(), "example binary missing: {}", path.display());
        common::assert_no_dirty_words(&path);
    }
}

/// `weak_mask_demo` exercises BOTH masking layers: `weak_mask!`
/// hides the custom env-var name that the bootstrap `EnvVarProvider`
/// reads, and `mask!` hides the AEAD-encrypted payload. Both probes
/// must be absent from the compiled binary — `MYAPP_SECRET_KEY` is
/// the env-var name a passive `strings` scan would otherwise reveal
/// as a lookup target; `the real secret was the friends` is the secret payload.
#[test]
fn weak_mask_demo_env_var_name_and_payload_absent_from_binary() {
    // `init!(provider)` compiles only against an External seal, so build
    // with the `provider-examples` feature and `LITMASK_UNLOCK_KEY` set.
    common::build_example_with_features_and_env(
        "weak_mask_demo",
        Profile::Release,
        &["provider-examples"],
        &[("LITMASK_UNLOCK_KEY", SCRUB_EXTERNAL_KEY)],
    );
    let path = common::example_path("weak_mask_demo", Profile::Release);
    assert!(path.exists(), "example binary missing: {}", path.display());
    // weak_mask!()'d env-var name — visible to `strings(1)` would
    // tell an attacker exactly where the unlock key lives.
    common::assert_substring_absent(&path, "MYAPP_SECRET_KEY");
    // mask!()'d payload — the AEAD layer must hide it even though
    // it's a fixture, since this example doubles as the load-bearing
    // demo of the `weak_mask! → init!(provider) → mask!` pattern.
    common::assert_substring_absent(&path, "the real secret was the friends");
    // weak_mask_demo masks its custom env-var name, so unlike the other
    // provider example it still clears the full identifier scrub.
    common::assert_no_dirty_words(&path);
}

/// `mask!(b"...")` and `mask!(c"...")` must keep their fixture bytes
/// out of the compiled binary — all three literal kinds go through
/// AEAD encryption at expansion time. Each fixture is a lexically
/// unusual phrase to keep the absence assertion precise.
#[test]
fn byte_and_cstr_fixtures_absent_from_binary() {
    common::build_example("byte_cstr_demo", Profile::Release);
    let path = common::example_path("byte_cstr_demo", Profile::Release);
    common::assert_substring_absent(&path, "the-cake-is-a-lie");
    common::assert_substring_absent(&path, "this-cstring-is-in-witness-protection");
}

/// `mask!(include_str!(...))` must mask the file contents at
/// proc-macro time so the plaintext from the fixture file is absent
/// from the compiled binary.
#[test]
fn include_str_fixture_absent_from_binary() {
    common::build_example("include_str_demo", Profile::Release);
    let path = common::example_path("include_str_demo", Profile::Release);
    common::assert_substring_absent(&path, "Non-Official Cover (NOC) List");
}

/// `mask_format!` must mask the literal fragments between placeholders
/// so the template text never appears in plaintext. Each fragment
/// phrase is lexically unusual to make the absence assertion
/// precise.
#[test]
fn mask_format_fragments_absent_from_binary() {
    common::build_example("mask_format_demo", Profile::Release);
    let path = common::example_path("mask_format_demo", Profile::Release);
    common::assert_substring_absent(&path, "drained $");
    common::assert_substring_absent(&path, "blame the raccoons");
    common::assert_substring_absent(&path, "this-name-is-a-secret");
    common::assert_substring_absent(&path, "captured-and-hidden");
    common::assert_substring_absent(&path, "width-on-a-need-to-know-basis");
}

/// Every bare string / byte string / C string literal rewritten by
/// `#[mask_all]` must be absent from the compiled binary. Fixtures
/// in `mask_all_demo` are unique-enough phrases that the absence
/// assertion is precise.
#[test]
fn mask_all_literals_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "now-you-see-me-now-you-dont");
    common::assert_substring_absent(&path, "these-bytes-saw-too-much");
    common::assert_substring_absent(&path, "this-cstring-took-it-to-the-grave");
}

/// `include_str!` and `concat!` invocations inside a `#[mask_all]`
/// module must be wrapped in `mask!()` so their resulting strings
/// are absent from binary plaintext. The included-file content
/// (`this-file-self-destructs-at-compile-time`) lives only in the fixture
/// file at compile time and would otherwise land in `.rodata`; the
/// concatenated literal (`decrypt-me-if-you-can`) is assembled
/// by the `concat!` builtin and would similarly be a single
/// `.rodata` string.
#[test]
fn mask_all_include_str_and_concat_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "this-file-self-destructs-at-compile-time");
    common::assert_substring_absent(&path, "decrypt-me-if-you-can");
}

/// `format!(template, args...)` inside `#[mask_all]` is rewritten
/// to `mask_format!(template, args...)` when `template` is a string
/// literal. The literal-fragment text must be absent from binary
/// plaintext.
#[test]
fn mask_all_format_template_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "this-fragment-survived-the-build");
}

/// Output macros (`println!` etc.) with a literal template inside
/// `#[mask_all]` are wrapped so the formatted result flows through
/// `mask_format!` first; the template fragment must be absent from
/// binary plaintext.
#[test]
fn mask_all_println_template_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "this-line-is-off-the-record");
}

/// `panic!` with a literal message inside `#[mask_all]` is wrapped
/// analogously to the output macros — the message text gets masked
/// while the panic still fires at runtime. The fixture phrase must
/// be absent from the binary plaintext.
#[test]
fn mask_all_panic_message_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "oops-the-secret-fell-out");
}

/// `write!`/`writeln!` with a literal template inside `#[mask_all]`
/// are wrapped via `mask_format!` so the literal text is masked while
/// the writer side-effect is preserved.
#[test]
fn mask_all_write_template_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "scribbled-in-the-margins");
}

/// Qualified macro paths (`std::format!`, `core::dbg!`, etc.) are
/// recognized by their last path segment, so `std::format!("...")`
/// gets the same rewrite as bare `format!("...")` and its template
/// is masked.
#[test]
fn mask_all_qualified_path_template_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "path-qualified-and-classified");
}

/// `assert!` / `assert_eq!` / `assert_ne!` with a custom message
/// argument: the message text is masked while the assertion still
/// fires. The `debug_assert!` family is intentionally NOT scrubbed
/// here — its body is dead-code-eliminated in release builds via
/// `cfg!(debug_assertions)`, so absence of the literal is a property
/// of LLVM DCE rather than litmask's masking.
#[test]
fn mask_all_assert_with_message_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "this-better-be-true-or-else");
    common::assert_substring_absent(&path, "twins-separated-at-birth");
    common::assert_substring_absent(&path, "as-different-as-night-and-day");
}

/// Remaining `Output` family (`eprintln!`, `print!`, `eprint!`)
/// shares the println rewrite path; each template literal must be
/// absent from binary plaintext.
#[test]
fn mask_all_eprintln_print_eprint_templates_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "whispered-to-stderr");
    common::assert_substring_absent(&path, "printed-in-invisible-ink");
    common::assert_substring_absent(&path, "muttered-under-my-breath");
}

/// Remaining panic family (`todo!`, `unimplemented!`, `unreachable!`)
/// shares the panic rewrite path; each message literal must be
/// absent from binary plaintext.
#[test]
fn mask_all_todo_unimplemented_unreachable_messages_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "build-the-secret-lair-later");
    common::assert_substring_absent(&path, "teleporter-not-invented-yet");
    common::assert_substring_absent(&path, "the-butler-definitely-did-it");
}

/// `include_bytes!(...)` inside `#[mask_all]` is rewritten to
/// `mask_include_bytes!`, so the file bytes (a unique UTF-8
/// phrase) must be absent from the binary plaintext.
#[test]
fn mask_all_include_bytes_absent_from_binary() {
    common::build_example("mask_all_demo", Profile::Release);
    let path = common::example_path("mask_all_demo", Profile::Release);
    common::assert_substring_absent(&path, "raw-bytes-on-the-lam");
}

/// Direct-call invocations of the six dedicated `mask_*!` macros
/// (not via `#[mask_all]`) MUST mask their plaintext as completely
/// as the rewrite path. `mask_macros_demo` exercises each macro at
/// its canonical form; this test pins absence for the three macros
/// with reliably-distinct fixture phrases. `mask_env!` /
/// `mask_option_env!` aren't asserted (env-dependent values);
/// `mask_file!`'s output is unobservable here because
/// `core::panic::Location::caller()` independently embeds the same
/// path string at every panic site.
#[test]
fn mask_macros_demo_direct_calls_absent_from_binary() {
    common::build_example("mask_macros_demo", Profile::Release);
    let path = common::example_path("mask_macros_demo", Profile::Release);
    // mask_include_str! — file contents.
    common::assert_substring_absent(&path, "Non-Official Cover (NOC) List");
    // mask_include_bytes! — file bytes.
    common::assert_substring_absent(&path, "raw-bytes-on-the-lam");
    // mask_concat! — concatenated string, including the integer /
    // float / bool / char stringifications which must all share
    // the same masked blob.
    common::assert_substring_absent(&path, "42-is-the-answer");
}

/// Placeholder names (named args, implicit captures, dynamic-width
/// refs) MUST NOT appear in the compiled binary. The fixtures below
/// are unique tokens used as placeholder names in `mask_format_demo`;
/// their absence locks the proc-macro's positional rewriting.
#[test]
fn mask_format_placeholder_names_absent_from_binary() {
    common::build_example("mask_format_demo", Profile::Release);
    let path = common::example_path("mask_format_demo", Profile::Release);
    // Named arg.
    common::assert_substring_absent(&path, "nobody_will_ever_guess_this");
    // Implicit-capture local name.
    common::assert_substring_absent(&path, "the_secret_ingredient");
    // Dynamic-width ref.
    common::assert_substring_absent(&path, "eyes_only_field_width");
}

/// `hello_world` and `file_provider` each mask a different public-domain
/// quip — the canonical "first example" payloads the docs invite users
/// to verify via `strings | grep`. Without this test, a `mask!`
/// regression in either would silently leak the quote and only the
/// identifier scrub would fire — and only if the regression also leaked
/// a library identifier. Each probe is a lexically-unusual substring of
/// its example's quote, unique enough that dependency text can't
/// false-positive.
#[test]
fn quote_fixtures_absent_from_canonical_examples() {
    // `hello_world` builds under the default Embedded seal; `file_provider`
    // passes a `FileProvider` to `init!` (External form), so it needs the
    // `provider-examples` feature and `LITMASK_UNLOCK_KEY` set to seal
    // External.
    common::build_example("hello_world", Profile::Release);
    common::build_example_with_features_and_env(
        "file_provider",
        Profile::Release,
        &["provider-examples"],
        &[("LITMASK_UNLOCK_KEY", SCRUB_EXTERNAL_KEY)],
    );
    for (name, probe) in [
        ("hello_world", "if two of them are dead"),
        ("file_provider", "except temptation"),
    ] {
        let path = common::example_path(name, Profile::Release);
        assert!(path.exists(), "example binary missing: {}", path.display());
        common::assert_substring_absent(&path, probe);
    }
}

/// `machine_id_provider` is gated behind `--features machine-id` (per its
/// `required-features` in `Cargo.toml`), so the workspace's default
/// `cargo build --workspace --examples` skips it cleanly and the
/// `test-examples` shell recipe never runs it (the host id recomputed at
/// runtime won't match the placeholder id this scrub builds under, so
/// `init!(bind_to_machine)` would fail with `decryption_failed`).
/// The masking property is testable without ever executing the
/// example: build with the feature and scrub the binary.
///
/// `init!(bind_to_machine)` only compiles against a `machine`-tier seal, which
/// the build script emits only when `LITMASK_MACHINE_ID` is set — so the
/// build must pass an id via the env channel. The id is sourced through
/// the canonical `litmask show-machine-id` CLI (the same path the docs
/// prescribe), falling back to a placeholder on hosts with no machine id.
/// The value is arbitrary here because the scrub inspects bytes, never
/// runs the binary — so the scrub coverage holds on every host.
///
/// The test shells out to `cargo build --features machine-id` directly
/// rather than gating on `#[cfg(feature = "machine-id")]` — the test
/// binary itself doesn't need the feature enabled to invoke cargo
/// with it. That keeps the scrub running under the standard
/// `cargo test --workspace` invocation that CI uses.
///
/// Both scrubs apply: the masked quote fixture must be absent (proves
/// `mask!` worked), and the identifier scrub runs with `"blake3"`
/// allow-listed. The `blake3` allow is the one unavoidable leak:
/// the `blake3` crate embeds its own name in internal symbol
/// strings (`blake3_*` function names) regardless of how the
/// downstream code uses it. Both BLAKE3 context literals
/// (`"litmask-machine-id-v1"` and `"litmask-machine-id-salt-v1"`) are
/// hidden by `weak_mask!()` in `MachineIdProvider::unlock_key`, so they
/// do NOT need allow-list entries — that's a load-bearing property of the
/// `weak_mask!()` calls.
#[test]
fn machine_id_provider_example_masked_fixtures_absent_from_binary() {
    // `machine_id_via_cli` already returns the self-checking token form
    // `emit()` requires; on hosts without a machine id, fall back to a
    // well-formed token over a placeholder id so the build still seals.
    let machine_id = common::machine_id_via_cli().unwrap_or_else(|| {
        litmask_internal::encode_machine_id_token("litmask-scrub-placeholder-machine-id")
    });
    common::build_example_with_features_and_env(
        "machine_id_provider",
        Profile::Release,
        &["machine-id"],
        &[("LITMASK_MACHINE_ID", &machine_id)],
    );
    let path = common::example_path("machine_id_provider", Profile::Release);
    assert!(
        path.exists(),
        "machine_id_provider binary missing after build (did `cargo build --features machine-id --example machine_id_provider` succeed?): {}",
        path.display(),
    );
    common::assert_substring_absent(&path, "distort them as you please");
    // Both context literals MUST be absent: the runtime `weak_mask!()`
    // calls are the only thing standing between them and a
    // `strings(1)`-visible appearance. If a future refactor drops a
    // `weak_mask!()` wrapper, one of these assertions fires.
    common::assert_substring_absent(&path, "litmask-machine-id-v1");
    common::assert_substring_absent(&path, "litmask-machine-id-salt-v1");
    common::assert_no_dirty_words_except(&path, &["blake3"]);
}

/// `mask_debug_demo` derives `MaskDebug`: the struct name, field
/// names, and enum variant names must be absent from the compiled
/// binary — plain `#[derive(Debug)]` would embed each as a cleartext
/// `&'static str` in `.rodata` reachable by `strings(1)`. The
/// `mask!`-ed field values are scrubbed too, same as every other
/// example.
#[test]
fn mask_debug_demo_names_and_fixtures_absent_from_binary() {
    common::build_example("mask_debug_demo", Profile::Release);
    let path = common::example_path("mask_debug_demo", Profile::Release);
    common::assert_fixtures_scrubbed(
        "mask_debug_demo",
        &path,
        &[
            // Struct name — passed to `debug_struct` by the plain derive.
            "CovertBeaconManifest",
            // Field names — passed to `.field` by the plain derive.
            "rendezvous_url_quux",
            "activation_token_xyzzy",
            // Enum variant names — one per match arm in the plain derive.
            "DormantUntilDawn",
            "ExfilWindowOpen",
            "jitter_millis_zzyzx",
            // `mask!`-ed field value.
            "beacon.fabrikam-exfil.example",
        ],
    );
}

/// `mask_serde_demo` derives `MaskSerialize` + `MaskDeserialize`
/// (`serde` feature): the struct name and every field
/// name must be absent from the compiled binary — the plain serde
/// derives would embed each as a cleartext `&'static str` reachable by
/// `strings(1)` (serialize: `serialize_field` names; deserialize:
/// `FIELDS` arrays, field-matching arms, `missing field` diagnostics).
/// The `mask!`-ed field values are scrubbed too, same as
/// every other example. The example sits in `EXCEPTIONS` because its
/// `required-features = ["serde"]` makes the default-features
/// `EXAMPLES` loop unable to build it; this test shells out with the
/// feature enabled, mirroring the `machine_id_provider` pattern, so the
/// scrub runs under the standard default-features `cargo test`.
#[test]
fn mask_serde_demo_names_and_fixtures_absent_from_binary() {
    common::build_example_with_features("mask_serde_demo", Profile::Release, &["serde"]);
    let path = common::example_path("mask_serde_demo", Profile::Release);
    assert!(
        path.exists(),
        "mask_serde_demo binary missing after build: {}",
        path.display(),
    );
    common::assert_fixtures_scrubbed(
        "mask_serde_demo",
        &path,
        &[
            // Type names — passed to `serialize_struct` /
            // `*_variant` / `debug_struct` by the plain derives.
            "ClandestineTelemetryManifest",
            "UplinkChannelState",
            // Field names — passed to `serialize_field` / `.field`.
            "covert_endpoint_quux",
            "activation_token_xyzzy",
            "heartbeat_jitter_millis",
            "uplink_channel_state",
            "relay_handle_quux",
            // `#[serde(rename)]` wire name and `#[serde(alias)]` — the
            // masked-attr surface must be absent from the binary too.
            "renamed_marker_qwxz",
            "alt_endpoint_zzyx",
            // Enum variant names — the externally-tagged key in
            // self-describing formats.
            "DormantUntilDawnZzyzx",
            "ActiveRelayWindow",
            // `mask!`-ed field values.
            "beacon.fabrikam-exfil.example",
            "correct-horse-battery-staple",
            "relay-handle-7-zzyzx",
        ],
    );
    common::assert_no_dirty_words(&path);
}

/// `stack_demo` exercises `mask_stack!` for all three literal kinds
/// (`MaskStr` / `MaskBytes` / `MaskCStr`). Each fixture must be absent
/// from the release binary — the stack guards decrypt at runtime, so the
/// plaintext is never in `.rodata`. Sits in `EXCEPTIONS` because its
/// `required-features = ["unstable-stack"]` makes the default-features `EXAMPLES`
/// loop unable to build it; the functional round-trip (running the binary
/// and checking decrypted output) lives in `tests/mask_stack.rs`.
#[test]
fn stack_demo_fixtures_and_identifiers_absent_from_binary() {
    common::build_example_with_features("stack_demo", Profile::Release, &["unstable-stack"]);
    let path = common::example_path("stack_demo", Profile::Release);
    assert!(
        path.exists(),
        "stack_demo binary missing after build: {}",
        path.display(),
    );
    common::assert_substring_absent(&path, "treasure under the bird bath");
    common::assert_substring_absent(&path, "other car is a submarine");
    common::assert_substring_absent(&path, "landing was filmed in my garage");
    common::assert_no_dirty_words(&path);
}

/// Every `.rs` file under `litmask/examples/` must appear in either
/// [`EXAMPLES`] or [`EXCEPTIONS`]. Catches the "added a new example
/// but forgot to add scrub coverage" failure mode.
#[test]
fn all_examples_accounted_for_in_scrub_tests() {
    let examples_dir = common::workspace_root().join("litmask/examples");
    let mut on_disk: Vec<String> = std::fs::read_dir(&examples_dir)
        .expect("read examples dir")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().to_str()?.to_string();
            name.strip_suffix(".rs").map(String::from)
        })
        .collect();
    on_disk.sort();

    let mut accounted: Vec<String> = EXAMPLES
        .iter()
        .chain(EXCEPTIONS.iter())
        .map(|s| (*s).to_string())
        .collect();
    accounted.sort();

    assert_eq!(
        on_disk, accounted,
        "examples/ directory and EXAMPLES + EXCEPTIONS are out of sync"
    );
}
