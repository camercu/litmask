//! `weak_mask!` real-world use case: hide a custom env-var name so
//! `strings(1)` doesn't reveal where the unlock key lives, then use
//! `init_with!` to bootstrap AEAD-strength masking on top.
//!
//! Why `weak_mask!` instead of `mask!` for the env-var name: the name
//! has to be readable BEFORE `init!()` runs (it tells the provider
//! where to look), and `mask!` needs the AEAD mask key cell to
//! already be populated. `weak_mask!` only needs the per-build
//! wrapper bytes, which are statically present from the start of
//! `main()`.
//!
//! `weak_mask!` is anti-`strings(1)` ONLY: both the obfuscated bytes
//! and the XOR key live in the same binary, so a disassembler-equipped
//! attacker recovers the plaintext trivially. The trade-off is right
//! for non-secret metadata (env var names, default file paths) — not
//! for actual secrets, which always go through `mask!`.
//!
//! Verify masking via the strings/grep recipe in `hello_world.rs`.
//! Two probes confirm both layers: `MYAPP_SECRET_KEY` (the env-var
//! name, hidden by `weak_mask!`) and `emerald-puma-c2d8f4` (the
//! payload, hidden by `mask!`).

use litmask::{EnvVarProvider, init_with, mask, weak_mask};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // weak_mask!() the env-var name so an attacker scanning the
    // binary for env-lookup targets doesn't get a free pointer at
    // where the unlock key lives.
    let env_var_name: &'static str = weak_mask!("MYAPP_SECRET_KEY");
    init_with!(EnvVarProvider::new(env_var_name))?;

    // Actual sensitive content — masked with the AEAD-strength
    // macro because it's a real secret, not just lookup metadata.
    println!(
        "payload={}",
        mask!("emerald-puma-c2d8f4 — secret payload, AEAD-encrypted")
    );
    Ok(())
}
