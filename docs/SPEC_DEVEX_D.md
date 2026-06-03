# litmask Developer-Experience — Specification (Variant D: B Minus the Baked Debug Key — ELIMINATED)

> **Status:** eliminated. Truncated to a design+rationale summary on
> 2026-06-02; full text recoverable from git history (commit `8b9b916` that
> added the DevEx variant set).

## Design (what this variant was)

D adopted **B's foundation verbatim** — operator-owned `unlock_key`, derived
locator, opaque wrapper, reseal-default deployment, no-argv secret channels, the
four-outcome `verify` — and made exactly two changes, both of which **removed**
machinery:

- **Deleted `K_dev`** (B's baked per-crate debug constant) and the entire
  self-decrypting-debug-binary hazard class it spawned. Zero-*per-run* wiring was
  replaced with a one-time **developer-environment key** read through a standard
  §8 channel — the portable baseline being a gitignored keyfile
  (`FileProvider` / `Emit::key_file()`), with `direnv`/`just`/env optional. The
  dev build sealed under the key the compiled-in provider resolves on the dev
  host, so the dev loop ran the **real** provider for every family (fixing B
  §3.7's "green run ≠ wired" caveat universally) and a debug binary was **inert
  without the key**, exactly like release.
- **Adopted C's single `init!` provider site** (removing `init_with!`) — the one
  C ergonomic that costs **no wire format** — while dropping C's decl_blob,
  `derive`-verb consolidation, per-customer-seed model, and workflow guard.

D owned two honest costs: the always-present dev key could seal a *local* release
build (contained by a normative clean-env release rule, §3.6), and the dev key
was a real secret needing §8 hygiene (unlike non-secret `K_dev`).

## Why eliminated

D's two ideas are both inherited by every later variant (`_E`/`_F`/`_G`), and its
distinguishing contribution — the dev-key-channel answer to zero-wiring — was
**superseded twice**:

- **`_E`'s pass-through dev** removed the need for any dev key at all, then
- **`_G`'s nonce-derived Tier-0 default** beat both: debug seals with zero wiring,
  no dev key, no plaintext-in-debug, and no ambient-key footgun — resolving the
  exact dev-loop tension D and E each half-solved.

D's one residual virtue — "the dev loop exercises the real provider" — is
**recovered by `_G` §3.2 path (a)** (wire the real provider in dev for full
dev↔prod parity), now offered as an option *alongside* the zero-wiring Tier-0
fallback rather than as the only path. Nothing unique to D survives.

What lived on, lived on elsewhere:

- **`K_dev` removal** and its deletion cascade (no self-decrypting binary, no
  per-crate derivation, no scrub-MUST for a constant, no PROFILE-fused seal gate)
  → carried by `_E`/`_F`/`_G`.
- **Single `init!` site / `init_with!` removed / `build.rs` bytes-only** →
  `_E` §4bis, `_F` §3, `_G`.
- **Real-provider-in-dev parity** → `_G` §3.2 path (a).
- **Refusal of C's machinery** (decl_blob, `derive`, per-customer seed, workflow
  guard) → upheld by `_E`/`_F`/`_G`.
