//! Helpers shared across the `mask`, `weak_mask`, `mask_format`, and
//! `unmasked` macros. Each per-macro module owns its own input grammar
//! and expansion logic; this module owns the small set of utilities that
//! cross those seams, split by concern:
//!
//! - [`diagnostics`] — the §1.9.6 `FailTag` / `compile_error` surface.
//! - [`parse`] — string-literal parsing and path-argument reading.
//! - [`path`] — call-site path resolution and canonicalization.
//! - [`artifact`] — `OUT_DIR` build-artifact loading.
//! - [`codegen`] — the AEAD-mask token emitters.
//!
//! Re-exported flat below so callers keep importing `crate::common::*`
//! regardless of which concern an item lives in.

mod artifact;
mod codegen;
mod diagnostics;
mod parse;
mod path;

pub(crate) use artifact::load_out_dir_artifact;
// `mask_name` is reachable only through the serde derives' identifier
// codegen; gate its re-export so a non-serde build doesn't flag it unused.
pub(crate) use codegen::{byte_string_literal, mask_bytes, mask_cstr, mask_ident, mask_str};
#[cfg(feature = "unstable-serde")]
pub(crate) use codegen::{mask_name, masked_static_name};
#[cfg(feature = "stack")]
pub(crate) use codegen::{mask_stack_bytes, mask_stack_str};
pub(crate) use diagnostics::{FailTag, compile_error, env_failure};
pub(crate) use parse::{StringLiteral, parse_string_literal, read_lit_str_path, require_lit_str};
pub(crate) use path::{canonicalize_file_path, include_relative_path, manifest_dir};
