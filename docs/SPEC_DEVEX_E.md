# litmask Developer-Experience — Specification (Variant E: Pass-Through Dev + Honest Topology — ELIMINATED)

> **Status:** eliminated. Truncated to a design+rationale summary on
> 2026-06-02; full text recoverable from git history (commit `8b9b916` that
> added the DevEx variant set).

## Design (what this variant was)

E adopted **D's foundation** — operator-owned `unlock_key`, derived locator,
opaque wrapper, reseal-default deployment, single `init!` site, no-argv secret
channels — and made three changes, two net deletions and one doc-first reframe:

- **Pass-through dev (the headline).** E did **not seal in the dev loop at all**:
  debug builds compiled literals in the clear and `init!` was a no-op. This
  deleted D's developer-key channel, its secret-hygiene burden, and its
  ambient-key footgun, on top of D's already-removed `K_dev`. The dev loop needed
  no key, no file, no setup — strictly less than D.
- **Demoted `MachineIdProvider`** from core machinery to one provider among
  several, and **cut the `verify` ceremony** — the four-outcome exit-code
  namespace and the `--deny` lock-out — down to a single decrypt-success question
  on YAGNI grounds. It re-added one thing the chain cut too early: a **minimal
  AEAD provider-descriptor blob (E.6)** so `verify`/`reseal` catch a
  provider/seal *identity* mismatch offline.
- **Topology-first, honest crypto framing.** Made the deployment-topology
  decision tree the first page of the docs: server-side = real protection;
  distributed = obfuscation; key custody (not cipher strength) is the boundary.

## Why eliminated

E's durable contributions all survive in `_F`/`_G`, while its two
distinguishing moves were each rejected by a later variant:

- Its **machine-id demotion** was **reverted by `_F`** (which re-centered
  machine-id as the distributed default while keeping E's machine-id *honesty*) —
  a rejected branch.
- Its unique surviving idea — **pass-through dev** — was **explicitly dropped by
  `_G`** as inferior. Pass-through's plaintext-in-debug was E's own self-described
  *sharpest residual* (§8.2): an accidentally-shipped debug build leaks plaintext
  outright, defeating the very static-analysis threat litmask exists to counter.
  `_G`'s nonce-derived Tier-0 makes debug **seal** with zero wiring, so the dev
  loop carries no plaintext and pass-through loses its reason to exist.

What lived on, lived on elsewhere:

- **Topology-first, honest docs** (server-side protection vs distributed
  obfuscation; crypto-strength-is-not-the-boundary) → `_F` §1, `_G`.
- **`verify` cut to decrypt-success** (four-code namespace + `--deny` deferred
  under YAGNI) → `_F`, `_G`.
- **Minimal AEAD provider-descriptor blob (E.6)** → `_F` §3.4 (extended to the
  full `multi` factor set), `_G`.
- **Single `init!` site / pass-through type-identity guards** → folded into
  `_F`/`_G` (with pass-through itself dropped by `_G`).
- **Machine-id *honesty*** (lateral-theft mitigation, not local-attacker defense)
  → kept by `_F` §1.4 even as the demotion was reverted.
