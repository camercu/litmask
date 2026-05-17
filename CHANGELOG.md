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
