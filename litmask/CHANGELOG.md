# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/camercu/litmask/releases/tag/v0.1.2) - 2026-05-16

### Bug Fixes

- *(runtime)* gate decrypt_wrapper_or_panic on std feature
- *(tests)* rename fixture marker vermillion → vermilion

### Features

- *(macros)* add maskfmt! for masked format-string templates
- *(macros)* add unmasked! identity macro
- *(runtime)* route wrapper AEAD failure to InitError::Decryption
- *(error)* add InitError::Decryption variant
- *(macros)* mask! input grammar — invalid rejection + include_str!/concat! whitelist
- *(macros)* clearer no_std error for mask!(c"...")
- *(macros)* support b"..." and c"..." literals in mask!
- *(security)* wipe transient parse buffers
- *(weak_mask)* public macro for bootstrap-string obfuscation
- walking skeleton — mask!("text") round-trip end-to-end
