# litmask examples

A map of the runnable examples, grouped by **seal tier**. The tier is a
build-time property (chosen by which key material is present when the
example is compiled), and each example binary demonstrates exactly one
tier — which is why they live in separate files rather than one.

`just test-examples` (`scripts/test-examples.sh`) builds and runs every
example below with the correct per-tier env and features; treat that
script as the source of truth for how each is invoked.

## Embedded tier (default)

No key material; `mask!()` self-initializes on first use. Build/run with
no `LITMASK_UNLOCK_KEY` / `LITMASK_MACHINE_ID` in the environment (their
presence would seal a different tier).

```sh
cargo run --example hello_world
```

| Example | Shows |
|---|---|
| `hello_world` | Minimal end-to-end: mask a string at compile time, decrypt at runtime. |
| `mask_macros_demo` | Canonical direct-call form of every `mask_*!` macro — which input each takes and type each returns. |
| `byte_cstr_demo` | `mask!(b"...")` → `Vec<u8>` and `mask!(c"...")` → `CString`, for embedded keys / non-UTF-8 / FFI. |
| `include_str_demo` | `mask_include_str!("path")` masks a file's contents read at compile time. |
| `mask_format_demo` | `mask_format!` — masked `format!`; literal fragments are encrypted, placeholder names never land in the binary. |
| `mask_debug_demo` | Mask `Debug` type, field, and variant names at compile time; decrypt during formatting. |
| `mask_all_demo` | `#[mask_all]` rewrites every bare string-shaped literal in a module to `mask!(literal)`. |
| `mask_print_e2e` / `mask_eprint_e2e` | Fixtures for the `mask_print!`/`mask_eprint!` stdout/stderr capture tests. |

## Embedded tier, experimental features

Embedded, but each needs its (semver-exempt) feature flag.

```sh
cargo run --features unstable-serde --example mask_serde_demo
cargo run --features unstable-stack --example stack_demo
```

| Example | Feature | Shows |
|---|---|---|
| `mask_serde_demo` | `unstable-serde` | Mask serde field and struct names at compile time; decrypt on first use. |
| `stack_demo` | `unstable-stack` | `mask_stack!` decrypts a literal into a stack-resident, zero-alloc guard that wipes on drop. |

## External tier (`provider-examples`)

The `unlock_key` is sourced at runtime through a provider passed to
`init!(...)`, and must also be present at build time (its presence seals
the External tier). Mint one with the CLI:

```sh
LITMASK_UNLOCK_KEY=$(cargo run -q -p litmask-cli -- keygen) \
  cargo run --features provider-examples --example file_provider
```

| Example | Shows |
|---|---|
| `file_provider` | Source the `unlock_key` from a filesystem path instead of an env var. |
| `custom_provider` | Hand-implement `KeyProvider` for your own secrets backend (vault/HSM/KMS) via the typed edge (`UnlockMaterial::new` + `UnlockKey::derive`). Runnable form of the `docs/DEPLOYMENT.md` snippet. |
| `weak_mask_demo` | `weak_mask!` hides a custom env-var name from `strings(1)`, then bootstraps AEAD-strength masking via `init!(provider)`. (Reads `MYAPP_SECRET_KEY`.) |

## Machine tier (`machine-id`)

Sealed to the host machine id at build time, so the binary decrypts only
on the machine it was built for. This one can't be built or run by the
default loop; its masking and round-trip are covered by
`tests/example_scrub.rs` and `tests/machine_tier_e2e.rs`.

| Example | Shows |
|---|---|
| `machine_id_provider` | Seal the build's `unlock_key` to the host machine id via `init!(bind_to_machine)`. |
