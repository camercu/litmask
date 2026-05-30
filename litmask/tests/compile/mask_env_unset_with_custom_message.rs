//! When the named env var is unset, `mask_env!` emits the optional
//! second-arg custom message verbatim — no `mask_env!` prefix —
//! exactly as stdlib `env!("NAME", "msg")` does (spec §2.1.6.3).

use litmask::mask_env;

fn main() {
    let _: String = mask_env!(
        "LITMASK_TRYBUILD_DEFINITELY_UNSET_X9Z42",
        "custom: please run with FOO set"
    );
}
