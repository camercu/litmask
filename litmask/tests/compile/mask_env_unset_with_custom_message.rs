//! When the named env var is unset, `mask_env!` consults the
//! optional second-arg custom message (mirroring stdlib `env!`).
//! The custom message appears in place of the default
//! "is not set" tail.

use litmask::mask_env;

fn main() {
    let _: String = mask_env!(
        "LITMASK_TRYBUILD_DEFINITELY_UNSET_X9Z42",
        "custom: please run with FOO set"
    );
}
