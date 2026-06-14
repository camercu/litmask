---
status: accepted (implemented)
---

# Masking-crate unlock governance: libraries lazy-unlock, host governs

## Context

litmask must serve three usage patterns (see `CONTEXT.md` → Usage patterns):
**self-masking** (a host binary masks its own strings — works today),
**transparent masking** (a host links several **masking libraries**, each
unaware-transitive), and **governed masking** (the host supplies one
**unlock key** for the whole dependency graph). Two runtime facts block
the latter two: the **mask key** lives in a single set-once process-global
cell (`runtime/mod.rs`), so a second masking crate's blobs fail the AEAD
tag; and the lazy unlock path hardcodes `EmbeddedProvider`, so a host
cannot override a transitive library's unlock. (The external **unlock key**
is material-only — `BLAKE3::derive_key("litmask-unlock-v1", material)`, no
per-build salt — so one external key _can_ open every wrapper sealed under
it, which is what makes governed masking feasible.)

## Decision

1. **Masking libraries rely on lazy unlock only — they never call
   `init!()`.** A library just `mask!()`s; unlocking is the host's concern.
2. Replace the single set-once mask-key cell with a **mask-key cache**
   keyed by **wrapper**, so each masking crate self-unlocks independently
   (transparent masking).
3. `init!(provider)` / `init!(bind_to_machine)` install a process-global
   **governing provider** that the lazy path consults for _every_ wrapper
   before falling back to the per-crate keyless `EmbeddedProvider`.
   Governed masking additionally requires a **uniform seal** (one
   `LITMASK_UNLOCK_KEY` in the build environment, reaching every crate's
   `emit()`).
4. **Drop bare `init!()`.** The Embedded tier is keyless and self-derived,
   so it has no early-failure mode worth catching eagerly; lazy init
   already covers it. Surviving forms all _govern_. New verb triad:
   **seal** (build) · **bind** (machine) · **govern** (host installs the
   provider).

## Considered options

- _Keep bare `init!()` + the single mask-key cell._ Rejected: two masking
  crates in one binary collide, blocking transparent and governed masking.
- _Per-crate runtime configuration (each library exposes its own init)._
  Rejected: forces the host to know and wire every transitive masking
  dependency, defeating transparency.

## Consequences

- **Breaking** (removing bare `init!()`, changing `init!` semantics from
  "decrypt my wrapper" to "install the governing provider"); pre-1.0 → MINOR.
- **Ordering:** governed masking requires the host install the governing
  provider before any transitive `mask!()` fires; a library that masks in a
  `static`/constructor can defeat that and must fail loud.
- **Build coupling:** a uniform seal means the host's build environment
  dictates every dependency's **seal tier** (Embedded → External). The
  binary owner, not the library author, governs deployment security.
- **Security gradient:** transparent masking leaves every dependency at the
  keyless Embedded floor (`strings(1)`-resistance only); governed masking
  uniformly upgrades the whole graph to a real unlock key.

## Implementation status

Implemented. The single set-once mask-key cell is now a per-wrapper
**mask-key cache** (`runtime/mask_key_store.rs`); `init!(...)` installs a
process-global **governing provider** (`runtime/governor.rs`) that the lazy
path consults for every wrapper when one is installed (its key opens any
tier), falling back to the keyless Embedded floor otherwise; and bare
`init!()` is removed — the Embedded
tier self-initializes on the first `mask!()`. Uniform-seal handling is
inherent: a crate's seal tier comes from the shared build environment, so a
dependency graph is uniformly Embedded, External, or Machine, and the
governor's key matches every wrapper it opens.
