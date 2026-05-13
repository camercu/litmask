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

/// Every example binary the workspace ships. Add new names here when
/// new examples land under `litmask/examples/`.
const EXAMPLES: &[&str] = &["hello_world", "weak_mask_demo"];

#[test]
fn no_forbidden_substrings_in_any_example_binary() {
    for name in EXAMPLES {
        common::build_example(name, Profile::Release);
        let path = common::example_path(name, Profile::Release);
        assert!(path.exists(), "example binary missing: {}", path.display());
        common::assert_no_dirty_words(&path);
    }
}

/// `weak_mask!` must obfuscate user-supplied literals so the plaintext
/// is absent from the compiled binary. The fixture is deliberately a
/// lexically unusual phrase so a false-positive against std /
/// dependency strings is implausible.
#[test]
fn weak_mask_fixture_absent_from_binary() {
    common::build_example("weak_mask_demo", Profile::Release);
    let path = common::example_path("weak_mask_demo", Profile::Release);
    common::assert_substring_absent(&path, "yellow-velvet-tortoise-9c4f1a");
}
