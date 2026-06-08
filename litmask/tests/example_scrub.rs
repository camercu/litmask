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

/// Examples cleared for the case-insensitive library-identifier
/// scrub. Add new names here when new examples land under
/// `litmask/examples/`.
///
/// Three examples are intentionally absent because they reference
/// the canonical published env-var name (`LITMASK_UNLOCK_KEY` /
/// `LITMASK_UNLOCK_KEY_FILE`) as a plain string literal — by design,
/// for pedagogical clarity — and that literal contains the
/// `unlock_key` and `litmask` forbidden substrings. Real-world
/// deployments would `weak_mask!()` the env-var name (see
/// `weak_mask_demo`); the identifier-scrub absence is testable
/// there, while these examples are covered by fixture-absence
/// checks only:
///
/// - `file_provider`: demonstrates `FileProvider`; reads
///   `LITMASK_UNLOCK_KEY_FILE` to find the key file.
/// - `machine_id_provider`: gated behind `--features machine-id` (see
///   [`machine_id_provider_example_masked_fixtures_absent_from_binary`]).
///   The BLAKE3 context literal `"machine-v1"` is hidden by
///   `weak_mask!()` in `MachineIdProvider`, so it doesn't leak —
///   but the `blake3` crate embeds its own name in internal symbol
///   strings (e.g. `blake3_*` function names) that we can't filter
///   away. The `machine_id` scrub allow-lists `blake3` specifically.
const EXAMPLES: &[&str] = &[
    "hello_world",
    "weak_mask_demo",
    "byte_cstr_demo",
    "include_str_demo",
    "mask_format_demo",
    "mask_macros_demo",
    "mask_all_demo",
    "mask_print_e2e",
];

const EXCEPTIONS: &[&str] = &["file_provider", "machine_id_provider"];

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
    common::build_example("weak_mask_demo", Profile::Release);
    let path = common::example_path("weak_mask_demo", Profile::Release);
    // weak_mask!()'d env-var name — visible to `strings(1)` would
    // tell an attacker exactly where the unlock key lives.
    common::assert_substring_absent(&path, "MYAPP_SECRET_KEY");
    // mask!()'d payload — the AEAD layer must hide it even though
    // it's a fixture, since this example doubles as the load-bearing
    // demo of the `weak_mask! → init_with! → mask!` pattern.
    common::assert_substring_absent(&path, "the real secret was the friends");
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

/// `hello_world` and `file_provider` both mask the same Twain quote
/// — that's the canonical "first example" payload the docs invite
/// users to verify via `strings | grep`. Without this test, a
/// `mask!` regression in either would silently leak the quote and
/// only the identifier scrub would fire — and only if the regression
/// also leaked a library identifier. Probe on `"The reports of my
/// death"` rather than `"greatly exaggerated"` because the latter is
/// common enough English that dependency text could plausibly
/// contain it; the former is unique to the Twain quote.
#[test]
fn twain_fixture_absent_from_canonical_examples() {
    for name in ["hello_world", "file_provider"] {
        common::build_example(name, Profile::Release);
        let path = common::example_path(name, Profile::Release);
        common::assert_substring_absent(&path, "The reports of my death");
    }
}

/// `machine_id_provider` is gated behind `--features machine-id` (per its
/// `required-features` in `Cargo.toml`), so the workspace's default
/// `cargo build --workspace --examples` skips it cleanly and the
/// `test-examples` shell recipe never runs it (the host id recomputed at
/// runtime won't match the placeholder id this scrub builds under, so
/// `init!(machine_id)` would fail with `decryption_failed`).
/// The masking property is testable without ever executing the
/// example: build with the feature and scrub the binary.
///
/// `init!(machine_id)` only compiles against a `machine`-tier seal, which
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
/// Both scrubs apply: the Twain fixture must be absent (proves
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
    let machine_id = common::machine_id_via_cli()
        .unwrap_or_else(|| "litmask-scrub-placeholder-machine-id".to_string());
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
    common::assert_substring_absent(&path, "The reports of my death");
    // Both context literals MUST be absent: the runtime `weak_mask!()`
    // calls are the only thing standing between them and a
    // `strings(1)`-visible appearance. If a future refactor drops a
    // `weak_mask!()` wrapper, one of these assertions fires.
    common::assert_substring_absent(&path, "litmask-machine-id-v1");
    common::assert_substring_absent(&path, "litmask-machine-id-salt-v1");
    common::assert_no_dirty_words_except(&path, &["blake3"]);
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
