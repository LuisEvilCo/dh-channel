# Changelog

All notable changes to this crate. Versions follow semver; `0.x` means the
API may still change between minor versions.

## 0.1.1 - 2026-10-12

- The published package no longer includes the test suite and CI files
  (`exclude` in `Cargo.toml`): 16 files, about 100 KiB, down from 20 files
  and 160 KiB. Nothing a consumer compiles changed.
- This changelog.

## 0.1.0 - 2026-10-12

- First release: `crypto` (Ed25519 to X25519 key agreement, `crypto_box`
  envelopes), `envelope`, `keys`, `key_manager`, `replay`, the reqwest
  `client` and the axum `receiver`. Edition 2024, `rust-version` 1.85.
