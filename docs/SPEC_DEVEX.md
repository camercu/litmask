# litmask Developer-Experience — Specification (base — ELIMINATED)

> **Status:** eliminated. Truncated to a design+rationale summary on
> 2026-06-02; full text recoverable from git history (commit that added the
> DevEx variant set). The friction analysis this draft introduced is
> preserved in `docs/SPEC_DEVEX_REVIEW_CONTEXT.md`.

## Design (what this variant was)

The original DevEx spec. Walked a real consumer (Alice shipping "Cryptio" as a
unique build per customer) through the loop and surfaced seven friction points
plus one security leak (**F1–F7, S1**). Its fixes kept the existing crypto
topology and bolted tooling onto it:

- **Build-generated `unlock_key`** — litmask mints the sealing key per build;
  the operator never owns it.
- **Baked debug `K_dev`** (§1.7) — a debug-only auto-key path so the dev loop
  decrypts without ceremony.
- **Build-identity ledger** (§7) — records build provenance.
- **Key-extractor CLI** (§2.1) plus an `awk`-on-`litmask.config` ritual to pull
  key material back out.
- **Secret `litmask.config` file** as the config channel.
- **`inspect --check-decrypt`** (§1.1) to catch the locator-only false-pass.

## Why eliminated

The whole inversion chain (A → B → …) rejected its central premise:
build-generated key ownership and the secret config file. Every downstream
variant starts from operator-owned keys and a no-config-file design, so nothing
unique here survives as-is.

What lived on, lived on elsewhere:

- The **friction catalogue (F1–F7, S1)** — the genuinely durable contribution —
  is carried by `docs/SPEC_DEVEX_REVIEW_CONTEXT.md` (friction-to-impl anchor
  map).
- The **build-generated-key idea** is reborn, scoped down, as **Variant G's
  Tier-0 baked default** (`bare init!()` = build-baked `unlock_key`, the
  obfstr+AEAD floor) — no longer the only option, just the zero-config floor.
