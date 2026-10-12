# dh-channel

Sealed inter-service channel for Rust services: static Diffie-Hellman over
Ed25519 identities, libsodium `crypto_box` envelopes, an axum receiver and a
reqwest client.

Its TypeScript counterpart for NestJS services is `@tendril-llc/nest-dh-channel`.
Both carry a fixture produced by the other, so the wire format cannot drift.

## How it works

- Every service holds a long-lived Ed25519 keypair and publishes the public
  half at `GET /keys`.
- Two services derive the same shared key from their own private key and the
  other's public key: `crypto_box_beforenm` after converting both keys to
  X25519. Keys are fetched lazily and cached in memory, no expiry.
- A sealed request is `POST { "sealed": "<hex>" }` with the header
  `X-Service-Id: <sender>`. The header only picks the key to try; opening the
  envelope is the authentication.
- The plaintext is JSON with `ts` (unix ms) and `requestId` plus the payload.
  The receiver rejects a `ts` more than 60 s from its clock and a `requestId`
  it has seen in the last 60 s.
- The response is sealed the same way and echoes `requestId`.

Wire format, byte for byte:

```text
shared   = crypto_box_beforenm(ed25519_pk_to_curve25519(peer_pk), ed25519_sk_to_curve25519(own_sk))
envelope = hex( nonce[24] || crypto_box_easy_afternm(plaintext, nonce, shared) )
```

## Install

```toml
[dependencies]
dh-channel = "0.1"
```

Features: `client` (reqwest sender) and `axum` (receiver), both on by default.
A service that only receives can use `default-features = false, features = ["axum"]`.

## Publish your keys

```rust
use axum::{routing::get, Json, Router};
use axum::http::StatusCode;
use dh_channel::public_keys_reply;

async fn keys() -> (StatusCode, Json<serde_json::Value>) {
    let (status, body) = public_keys_reply(&config.ed25519_public_key_hex, &config.ed25519_private_key_hex);
    (StatusCode::from_u16(status).unwrap(), Json(body))
}

let app = Router::new().route("/keys", get(keys));
```

The body is `{ "status": "success", "data": { "ed25519": { "publicKey": "<hex>" } } }`,
or a 503 with `{ "status": "error", "data": "<message>" }` when either half of the
pair is missing.

## Register peers

```rust
use dh_channel::{KeyManager, Peer};
use std::sync::Arc;

let keys = Arc::new(KeyManager::new(vec![
    Peer::new("auth", &config.auth_url),          // scheme optional, /keys appended
    Peer::new("contacts", &config.contacts_url),
]));
```

`KeyManager::with_fetcher` takes any `KeyFetcher` for tests or other transports.

## Send sealed requests

```rust
use dh_channel::{DhClient, SealedPayload, new_request_id, now_millis};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct LoginRequest { ts: i64, #[serde(rename = "requestId")] request_id: String, email: String }
impl SealedPayload for LoginRequest { fn request_id(&self) -> &str { &self.request_id } }

#[derive(Deserialize)]
struct LoginResponse { #[serde(rename = "requestId")] request_id: String, #[serde(rename = "authToken")] auth_token: String }
impl SealedPayload for LoginResponse { fn request_id(&self) -> &str { &self.request_id } }

let client = DhClient::new("auth", config.ed25519_private_key_hex.clone(), keys.clone());
let response: LoginResponse = client
    .post("edge", &format!("{}/auth/v2/internal/login-token", config.edge_url), &LoginRequest {
        ts: now_millis(),
        request_id: new_request_id(),
        email,
    })
    .await?;
```

Failures are `std::io::Error` with a kind the caller can map to a status:

| Kind | When |
|---|---|
| `NotFound` | unregistered peer, or the peer answered 404 |
| `InvalidData` | missing or malformed key; response not an envelope, wrong shape, or another `requestId` |
| `PermissionDenied` | 401 or 403, or a response that does not open under the shared key |
| `InvalidInput` | 400 or 422 |
| `Other` | transport failure, or any other non-2xx |

## Receive sealed requests (axum)

```rust
use axum::{middleware, routing::post, Router};
use dh_channel::{dh_auth, seal_response, DhContext, DhPayload, DhReceiver, InMemoryReplayStore};
use std::sync::Arc;

let receiver = Arc::new(
    DhReceiver::new(config.ed25519_private_key_hex.clone(), keys.clone(), Arc::new(InMemoryReplayStore::new()))
        .allow(["auth"]), // optional: only these senders
);

let app = Router::new().route(
    "/v2/internal/login-token",
    post(login_token).route_layer(middleware::from_fn_with_state(receiver, dh_auth)),
);

async fn login_token(ctx: DhContext, DhPayload(body): DhPayload<LoginBody>) -> axum::response::Response {
    // ...
    seal_response(&ctx, &serde_json::json!({ "authToken": token }))
}
```

`dh_auth` answers plain JSON `{ "statusCode", "message" }` on rejection: 401 for an
unknown sender, an envelope that does not open, a stale `ts`, a bad or replayed
`requestId`; 400 for a body that is not `{ sealed }`; 403 for a sender outside the
allow list; 503 when the shared key or the replay store is unavailable.
`DhPayload<T>` answers 422 when the plaintext does not fit `T`.

### Replay store

`InMemoryReplayStore` is for tests and single-instance deployments. With more
than one task, implement `ReplayStore` over your Redis client with
`SET dh:req:{service_id}:{request_id} 1 NX EX 60` and return whether the key was
set. The crate ships no Redis client so it does not pin a version on consumers.

## Development

```text
cargo fmt
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
```

`tests/crypto_test.rs` includes an envelope produced by `libsodium-wrappers`.

## Releases

Releases are made from GitHub Actions on a `v*` tag, through crates.io trusted
publishing (no stored token). The workflow checks that the tag matches
`Cargo.toml`, then runs fmt, clippy and tests before `cargo publish`.

```text
# bump version in Cargo.toml, commit
git tag v0.2.0
git push --follow-tags
```

The very first version is published by hand (`cargo publish`), after which the
repository and workflow are registered under the crate's Trusted Publishing
settings on crates.io.

## License

MIT
