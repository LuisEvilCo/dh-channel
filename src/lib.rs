//! Sealed inter-service channel.
//!
//! Every service holds a long-lived Ed25519 keypair and publishes the public
//! half at `GET /keys`. Two services derive the same shared key from their own
//! private key and the peer's public key (libsodium `crypto_box_beforenm` after
//! converting both keys to X25519), then exchange sealed envelopes:
//!
//! ```text
//! shared   = crypto_box_beforenm(ed25519_pk_to_curve25519(peer_pk), ed25519_sk_to_curve25519(own_sk))
//! envelope = hex( nonce[24] || crypto_box_easy_afternm(plaintext, nonce, shared) )
//! ```
//!
//! A sealed request is `POST { "sealed": "<hex>" }` with the header
//! `X-Service-Id: <sender>`. The header only picks the key to try; opening the
//! envelope is the authentication. The plaintext is JSON carrying `ts` (unix
//! milliseconds) and `requestId` plus the payload; receivers reject a `ts`
//! further than 60 s from their clock and a `requestId` seen within the last
//! 60 s. The response is sealed the same way and echoes the `requestId`.
//!
//! The crate has four layers:
//!
//! - [`crypto`]: key agreement and envelope primitives. Nothing here panics on
//!   bad input.
//! - [`keys`] and [`key_manager`]: the `/keys` document, and a cache of peer
//!   public keys and derived shared keys.
//! - [`client`] (feature `client`): [`client::DhClient`] sends sealed requests
//!   and opens sealed responses.
//! - [`receiver`] (feature `axum`): the [`receiver::dh_auth`] middleware, the
//!   [`receiver::DhPayload`] extractor and [`receiver::seal_response`].
//!
//! A TypeScript counterpart for NestJS services exists; both carry a fixture
//! produced by the other so the wire format cannot drift.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod envelope;
pub mod key_manager;
pub mod keys;
pub mod replay;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "axum")]
pub mod receiver;

pub use crypto::{DhError, compute_shared_secret, open_message, seal_message};
pub use envelope::{
    FRESHNESS_WINDOW_MS, SERVICE_ID_HEADER, SealedEnvelope, SealedPayload, new_request_id,
    now_millis, open_payload, seal_payload,
};
pub use key_manager::{KeyFetcher, KeyManager, Peer};
pub use keys::{KeyPair, KeysError, PublicKeys, public_keys_reply};
pub use replay::{InMemoryReplayStore, ReplayStore};

#[cfg(feature = "client")]
pub use client::{DhClient, post_sealed};

#[cfg(feature = "axum")]
pub use receiver::{DhContext, DhPayload, DhReceiver, DhSender, dh_auth, seal_response};

/// The libsodium precomputed shared key type, re-exported so callers do not
/// need a direct dependency on `sodiumoxide`.
pub use sodiumoxide::crypto::box_::PrecomputedKey;
