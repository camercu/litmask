//! Machine-tier end-to-end example: seal the build's `unlock_key` to the
//! host machine id so the binary decrypts only on the machine it was
//! built for.
//!
//! The machine factor is supplied at BUILD time via `LITMASK_MACHINE_ID`
//! and re-sourced at RUNTIME by `init!(bind_to_machine)`, which recomputes the
//! host id locally via `machine_uid::get()`. For the two to match, build
//! with `LITMASK_MACHINE_ID` set to this host's id (the CLI prints it):
//!
//! ```sh
//! LITMASK_MACHINE_ID="$(cargo run -q -p litmask-cli -- show-machine-id)" \
//!     cargo build --release --features machine-id --example machine_id_provider
//!
//! # Run the prebuilt binary directly on the SAME host — no env var,
//! # no key file: the machine id is recomputed at startup.
//! ./target/release/examples/machine_id_provider
//! # prints the decrypted Twain quote
//! ```
//!
//! Run the prebuilt binary directly, never `cargo run`: a release
//! `cargo run` reruns `build.rs` and reseals the wrapper, desyncing it
//! from the host id captured above (see `hello_world.rs`).
//!
//! Moving the binary to a different host makes `init!(bind_to_machine)` fail
//! with `decryption_failed`: the runtime recomputes a different machine
//! id, derives a different `unlock_key`, and the wrapper's AEAD tag check
//! rejects it.

use std::process::ExitCode;

use litmask::{init, mask};

fn main() -> ExitCode {
    // Surface the sysexits-aligned code instead of the `?`/`Termination`
    // default of 1, so a machine-id lookup failure (no `/etc/machine-id`,
    // stock OpenBSD) exits EX_UNAVAILABLE (69) and a wrong-host seal exits
    // EX_DATAERR (65) — the contract a deployment script keys on.
    if let Err(e) = init!(bind_to_machine) {
        eprintln!("init!(bind_to_machine) failed: {e}");
        // sysexits codes are 0..=78; the fallback is unreachable.
        return ExitCode::from(u8::try_from(e.sysexit_code()).unwrap_or(70));
    }
    println!(
        "{}",
        mask!("Get your facts first, then you can distort them as you please. — Mark Twain"),
    );
    ExitCode::SUCCESS
}
