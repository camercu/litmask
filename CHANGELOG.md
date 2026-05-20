## [0.5.0](https://github.com/camercu/litmask/compare/v0.4.0...v0.5.0) (2026-05-20)

### ⚠ BREAKING CHANGES

* **macros:** pre-1.0. The mask_env! custom-message form
(mask_env!("X", "my message")) now emits 'mask_env! unset: my message'
rather than the bare custom message. Downstream consumers that
matched the exact prior wording must update. The macro-name prefix
and the closed-set tag are §1.9.6-mandated as of Amendment 2026-05-20.
* **spec:** pre-1.0 spec change. Implementations that previously
matched on the §1.9.6 exact substrings should switch to matching the
macro-name + tag pattern. The current implementation's strings already
conform; no user-visible behavior change ships with this commit.
* **macros:** public macro mask_fmt! is renamed to mask_format!.
Downstream callers must search-and-replace mask_fmt! -> mask_format!.
The error-message substring 'mask_fmt!' is also renamed; users
matching the prior text must update their checks.
* **macros:** for any out-of-tree user of `mask!(include_str!(...))`
or `mask!(concat!(...))`. Documented in Task 13A's breaking-change
list. 168/168 tests pass after the migration; clippy + fmt green.

* **macros:** remove mask!(include_str/concat) shim from mask.rs ([fcc4fdf](https://github.com/camercu/litmask/commit/fcc4fdf1c14a89c4f37ae4f452a7643ffd19cd50))
* **macros:** rename mask_fmt! to mask_format! ([1c11144](https://github.com/camercu/litmask/commit/1c11144236cf05b401343db745fa5bc4c196b9e3))
* **macros:** route every compile error through common::compile_error ([d68213e](https://github.com/camercu/litmask/commit/d68213ef66bf9b1bf85129570028606d73ff8789))
* **spec:** relax §1.9.6 to macro-name + closed tag set ([3875af9](https://github.com/camercu/litmask/commit/3875af937eae1bbe439ab86b687da4f7bcf6a2de))

### Features

* add debug_assert! at type-uncovered invariant points ([c4309af](https://github.com/camercu/litmask/commit/c4309afa081e36d8505e9f2da97ad94f7b6274d7))
* **internal:** const-assert wire-format layout invariants ([a13eee8](https://github.com/camercu/litmask/commit/a13eee8bcd259ef804b3c2febefc2df075d669e0))
* **macros:** add mask_concat! macro ([57941b1](https://github.com/camercu/litmask/commit/57941b10e537e745451e4f51aa4b766ad07fa64a))
* **macros:** add mask_env! macro ([0132eed](https://github.com/camercu/litmask/commit/0132eed5b62f7aba4380a6eba815b3a9bdcfca88))
* **macros:** add mask_file! macro ([2b818c9](https://github.com/camercu/litmask/commit/2b818c9462c35570f9d9a72b1e1edee8003b18f4))
* **macros:** add mask_include_bytes! macro ([feb0aa8](https://github.com/camercu/litmask/commit/feb0aa80eeedff3acf239549307282b5fa50f7a8))
* **macros:** add mask_include_str! macro with trybuild + round-trip tests ([39ae545](https://github.com/camercu/litmask/commit/39ae5456328524361fb7622ef59d4e15112b77fa))
* **macros:** add mask_option_env! macro ([cc23226](https://github.com/camercu/litmask/commit/cc23226c50a2d20d5d6b7f4dcdf6ee8fb19bc82a))
* **macros:** canonicalize Span::file() against CARGO_MANIFEST_DIR ([7eb044f](https://github.com/camercu/litmask/commit/7eb044f481a4b12bfa2435d6bd3e254484e019c7))
* **macros:** expand mask_all macro coverage + harden walker internals ([a98a87f](https://github.com/camercu/litmask/commit/a98a87f56a57269bb0a32079e5645391952d86e3))
* **macros:** full macro substitution table + qualified paths ([cd22315](https://github.com/camercu/litmask/commit/cd22315067a7e411e501323700e12ef5f099e418))
* **macros:** mask_all rewrites format!(literal, ...) to maskfmt! ([2cef42d](https://github.com/camercu/litmask/commit/2cef42d9a2427deec05494e8fada5b8954208642))
* **macros:** mask_all rewrites panic-family macros ([4dcfa0c](https://github.com/camercu/litmask/commit/4dcfa0cc97dbcb1634549c1f45ae4bf7e77419f3))
* **macros:** mask_all rewrites println-family output macros ([8c52b3d](https://github.com/camercu/litmask/commit/8c52b3de63cadde431bdbde9a1e6cc140f23a7c8))
* **macros:** mask_all rewrites stdlib forms to dedicated mask_*! macros ([1be1cf0](https://github.com/camercu/litmask/commit/1be1cf0989256ff336997c8bd4dc180fed206f4b))
* **macros:** mask_all warns on user-defined macro literal args ([edeef57](https://github.com/camercu/litmask/commit/edeef57e392b31550e80c103cc8bf509874b00b8))
* **macros:** mask_all wraps include_str! and concat! in mask! ([06c6200](https://github.com/camercu/litmask/commit/06c6200e04865451e5ff46857e1f021edb83163a))
* **macros:** mask_concat! accepts every stdlib literal kind ([70f5aa1](https://github.com/camercu/litmask/commit/70f5aa190243591b20cca15a781d2cf8d9f860ab))
* **macros:** mask_env! accepts stdlib env!'s optional 2nd arg + NotUnicode ([cee9195](https://github.com/camercu/litmask/commit/cee91957744af8ef18fbca023699237bf4bca3dd)), closes [#11](https://github.com/camercu/litmask/issues/11)

### Bug Fixes

* **internal:** zeroize wrapper-decrypt intermediate plaintext ([e9dbc42](https://github.com/camercu/litmask/commit/e9dbc4241ecca473d1de7e8684eb217bc8777368))
* **macros:** reject invalid maskfmt placeholder names with typed error ([779f2fb](https://github.com/camercu/litmask/commit/779f2fb8fdee0abd84a3ac4df5d1fe9ac4fba535))
* **macros:** scope mask_all skip anchors per nested module ([860b396](https://github.com/camercu/litmask/commit/860b3966b4b24981b8ba7ce2978fa5c330527a21))
* **macros:** use macro@ disambiguator for mask_all rustdoc links ([09785e5](https://github.com/camercu/litmask/commit/09785e5cfb0a5ed027418a585aec2ad284936de4))

## [0.4.0](https://github.com/camercu/litmask/compare/v0.3.0...v0.4.0) (2026-05-17)

### Features

* **macros:** clearer error when mask_all is applied to non-module ([e6f77f6](https://github.com/camercu/litmask/commit/e6f77f622e2d10c9dd8b2ded71c68681766a8d50))
* **macros:** mask_all ghost-deprecation warnings per skip ([542420a](https://github.com/camercu/litmask/commit/542420afe712c488a6d0c2466f273ef37b6f5980)), closes [#5](https://github.com/camercu/litmask/issues/5)
* **macros:** mask_all skip rules — patterns + const/static ([8d946e7](https://github.com/camercu/litmask/commit/8d946e78a87eb940a705f53dd4c80addd2be5bcc))
* **macros:** mask_all walking skeleton ([fa19eed](https://github.com/camercu/litmask/commit/fa19eed6046049c233b1adf6a14e0a05b8a5ad33)), closes [#1](https://github.com/camercu/litmask/issues/1) [#4](https://github.com/camercu/litmask/issues/4) [#6](https://github.com/camercu/litmask/issues/6)

### Performance Improvements

* **macros:** drop two allocations in mask_all hot paths ([e8ed24c](https://github.com/camercu/litmask/commit/e8ed24c656da0f501633d9bc500dd5e7bb5d404b))

## [0.3.0](https://github.com/camercu/litmask/compare/v0.2.0...v0.3.0) (2026-05-17)

### Features

* **macros:** maskfmt! named args, implicit captures, dynamic width/precision ([1d24851](https://github.com/camercu/litmask/commit/1d248516220e7918e1b9063fac8a142b3a453e24))

### Bug Fixes

* **macros:** reject duplicate named args in maskfmt! ([9dac5dc](https://github.com/camercu/litmask/commit/9dac5dcde640e727c85bd301d8c97a8bc3a08e65))

### Performance Improvements

* **macros:** cache build_placeholder_emission + hoist out_ident ([0426acc](https://github.com/camercu/litmask/commit/0426acc395e40bd3d3dd6703e3eb10404206eb8a))
* **macros:** use bitmap for maskfmt unused-positional check ([2c9fdfa](https://github.com/camercu/litmask/commit/2c9fdfa336228a0e9cc48a3d2ee8e48aba5e3184))
* **test:** memoize build_example per (name, profile) ([23a5557](https://github.com/camercu/litmask/commit/23a5557b77f1108f7f12119e33bf0d4498a4b30e))

## [0.2.0](https://github.com/camercu/litmask/compare/v0.1.2...v0.2.0) (2026-05-17)


### Features

* **error:** add InitError::Decryption variant ([57130af](https://github.com/camercu/litmask/commit/57130af22d44c1ba2645a623aac385300d8be6c4))
* **internal:** mark FormatVersion + CipherId as non_exhaustive ([8e6639d](https://github.com/camercu/litmask/commit/8e6639d6a7cd5e48d0aaf2627317793e0063e572))
* **macros:** add maskfmt! for masked format-string templates ([1377a63](https://github.com/camercu/litmask/commit/1377a6382ea4f2293c44e4418e1ff19b30da0484))
* **macros:** add unmasked! identity macro ([7d84f7e](https://github.com/camercu/litmask/commit/7d84f7e89eb069fd54e0b9b16c9dee30cd3b9694))
* **macros:** clearer no_std error for mask!(c"...") ([ed3d65a](https://github.com/camercu/litmask/commit/ed3d65a43ec0c9c37e083920b152fc1a6827b77b))
* **macros:** mask! input grammar — invalid rejection + include_str!/concat! whitelist ([12bb8b8](https://github.com/camercu/litmask/commit/12bb8b8d328a37b83eab826f209aad993d48d3cf))
* **macros:** support b"..." and c"..." literals in mask! ([156a632](https://github.com/camercu/litmask/commit/156a63255acd42f3dfc31b7f89c698217f981c84))
* **runtime:** route wrapper AEAD failure to InitError::Decryption ([c4a2a12](https://github.com/camercu/litmask/commit/c4a2a127d991b26487acb32cf4749b87795a0c45))


### Bug Fixes

* **build:** honor LITMASK_RNG_SEED + profile-aware seed sourcing ([a6bbbfe](https://github.com/camercu/litmask/commit/a6bbbfe654c13f88ead4578e4ae022e60d76e298))
* **runtime:** gate decrypt_wrapper_or_panic on std feature ([206fdb7](https://github.com/camercu/litmask/commit/206fdb7e33e2af7e3a68afd739fb1b080a85f609))
* **tests:** correct misspelling of vermilion fixture marker ([88270cd](https://github.com/camercu/litmask/commit/88270cdae0f61cc35587c022afc3580c8e0e3730))


### Reverts

* **ci:** restore semantic-release-cargo in place of release-plz ([d4a5eb7](https://github.com/camercu/litmask/commit/d4a5eb79781ad90ff05d53e5b5f7c80111c1d605))

## [0.1.2](https://github.com/camercu/litmask/compare/v0.1.1...v0.1.2) (2026-05-13)


### Bug Fixes

* **ci:** disable @semantic-release/github issue/PR comment hooks ([a6653c2](https://github.com/camercu/litmask/commit/a6653c235dd559178fff208caf322c8bdb1e7fe5))

## [0.1.1](https://github.com/camercu/litmask/compare/v0.1.0...v0.1.1) (2026-05-13)


### Bug Fixes

* **ci:** centralize inter-crate deps in [workspace.dependencies] ([f803e0a](https://github.com/camercu/litmask/commit/f803e0a928f21d247de8c63902a3b92ce716c908))
