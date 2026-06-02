# litmask Developer-Experience — Specification (Variant C: Declarative + Layered — ELIMINATED)

> **Status:** eliminated. Truncated to a design+rationale summary on
> 2026-06-02; full text recoverable from git history (commit that added the
> DevEx variant set).

## Design (what this variant was)

C adopts **Variant B's foundation verbatim** (operator-owned `unlock_key`,
derived locator, opaque wrapper, reseal-default deployment, `K_dev`
zero-wiring, no-argv secret channels) and piles maximal machinery on top:

- **`decl_blob`** — an AEAD-sealed provider *declaration*, sealed under
  `mask_key` so it survives reseal. The build records which key provider the
  binary expects.
- **Two-layer crate split** — separates the masking core from the
  provider/declaration layer.
- **Consolidated `derive` verb** — one CLI verb subsuming the key-derivation
  steps.
- **Per-customer seed** = `KDF(master_seed, customer-id)` — built-in
  per-customer key separation.
- **Debug-never-ship workflow guard** — a gate preventing debug artifacts from
  shipping.

## Why eliminated

C is the maximal-machinery end of the spectrum, and **Variant D and everything
after it decisively reject that direction** — D is explicitly "B − K_dev" with
*less* machinery, not more. The declarative/layered apparatus (crate split,
`derive` verb, per-customer seed, workflow guard) was judged unnecessary
surface (YAGNI).

Only one idea survives, in minimal form: **`decl_blob` lives on as Variant E's
§6 AEAD provider-*descriptor* blob** — a stripped-down record of the expected
provider, without C's surrounding layering.
