//! `mask_env!` fails to compile when the env var is unset, per
//! spec §2.1.6.3. The name is a made-up unique sentinel that's
//! reliably unset in any reasonable build environment.

use litmask::mask_env;

fn main() {
    let _: String = mask_env!("LITMASK_TRYBUILD_DEFINITELY_UNSET_X9Z42");
}
