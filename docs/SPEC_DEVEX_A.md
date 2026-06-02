# litmask Developer-Experience — Specification (Variant A: Operator-Owned Key — ELIMINATED)

> **Status:** eliminated. Truncated to a design+rationale summary on
> 2026-06-02; full text recoverable from git history (commit that added the
> DevEx variant set).

## Design (what this variant was)

The first inversion of the base spec. A flips **key ownership**: `unlock_key`
stops being build-generated and becomes an **operator-supplied input** at both
build time and run time. The operator owns and provisions the sealing key; the
build no longer mints it.

A was a minimal inversion — it kept the rest of the base topology rather than
rethinking it:

- Retained the config file, demoted from secret to non-secret
  (`litmask-meta.toml`).
- Retained the baked debug `K_dev` path for the dev loop.

## Why eliminated

A's one real idea — operator-owned key inversion — is **fully absorbed by
Variant B**, which "starts from A's inversion and goes further": B keeps
operator-owned `unlock_key` and then also drops the config file (derived
locator instead), opaque-ifies the wrapper, and zero-wires `K_dev`. Everything
A contributes survives in B, and B supersedes the parts A left half-done. A
holds no unique surviving design idea, so it is cut in favour of B.
