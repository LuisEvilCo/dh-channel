# Changelog

All notable changes to this crate. Versions follow semver; `0.x` means the
API may still change between minor versions.

## 0.3.0 - 2026-11-10

- A service can publish other public keys in its `/keys` document, each
  under a name next to `ed25519`: `public_keys_reply_with` builds the body,
  `PublishedKey` (`publicKey` plus an optional `algorithm`) is one entry,
  and `PublicKeys::key(name)` reads it from a fetched document. The channel
  still uses only `ed25519`. The name `ed25519` cannot be taken and an
  entry with an empty key is not published. The 503 body is unchanged.
- Reading is tolerant: entries next to `ed25519` that are not a published
  key are ignored instead of failing the document, so a peer on a newer
  version never breaks one on this version. Documents from 0.2 peers read
  as before, and 0.2 peers read documents with extra entries (serde ignores
  unknown fields there).
- `KeyManager::refresh_key` fetches a peer's document again and replaces
  the cached copy. The cached shared key is dropped only if the peer's
  Ed25519 key changed; a failed fetch changes nothing.
- Breaking, hence the minor bump: `PublicKeys` has a new public field,
  `other`. Code that builds it with a struct literal or matches it
  exhaustively needs the field; `PublicKeys::new` is unchanged.

## 0.2.1 - 2026-11-04

- New feature `client-rustls`: the sender and the default key fetcher built on
  reqwest with rustls instead of the native TLS backend, for services shipped
  in images without OpenSSL. `client` is unchanged (reqwest default TLS);
  enable one or the other. reqwest is now pulled with `default-features =
  false` so the chosen feature decides the backend.

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
