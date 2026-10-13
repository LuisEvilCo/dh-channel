# Changelog

All notable changes to this crate. Versions follow semver; `0.x` means the
API may still change between minor versions.

## 0.2.0 - 2026-10-13

- `compute_shared_secret` refuses a peer key whose X25519 output is all zero
  (RFC 7748 section 6.1) with the new `DhError::LowOrderPublicKey`. libsodium
  already rejected such points during Ed25519 conversion; the crate now checks
  on its own as well, because sodiumoxide's `precompute` discards libsodium's
  failure and would hand back an all-zero key.
- `DhError` is `#[non_exhaustive]` so future variants are not breaking.
  Matching on it exhaustively needs a wildcard arm, hence the minor bump.
- Tests: the nine low-order, zero and non-canonical Ed25519 points libsodium
  blocklists are asserted rejected; the X25519 function is checked against
  the RFC 7748 section 5.2 and 6.1 test vectors.
- Docs, README and tests use placeholder service ids (`foo`, `bar`, `baz`)
  instead of the names of the services the crate was extracted from.

## 0.1.1 - 2026-10-12

- The published package no longer includes the test suite and CI files
  (`exclude` in `Cargo.toml`): 16 files, about 100 KiB, down from 20 files
  and 160 KiB. Nothing a consumer compiles changed.
- This changelog.

## 0.1.0 - 2026-10-12

- First release: `crypto` (Ed25519 to X25519 key agreement, `crypto_box`
  envelopes), `envelope`, `keys`, `key_manager`, `replay`, the reqwest
  `client` and the axum `receiver`. Edition 2024, `rust-version` 1.85.
