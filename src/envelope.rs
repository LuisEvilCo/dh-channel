//! The sealed envelope and the fields every sealed payload carries.
//!
//! A sealed request or response is `{ "sealed": "<hex>" }`. The plaintext is
//! JSON with `ts` (unix milliseconds) and `requestId` plus the payload. The
//! receiver rejects a `ts` further than [`FRESHNESS_WINDOW_MS`] from its clock
//! and a `requestId` it has already accepted; the response echoes the
//! `requestId` so the sender can bind it to the request.

use crate::crypto::{open_message, seal_message};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::PrecomputedKey;
use std::io::{Error, ErrorKind};
use std::time::{SystemTime, UNIX_EPOCH};

/// Header naming the sender of a sealed request, as written on the wire.
pub const SERVICE_ID_HEADER: &str = "X-Service-Id";

/// How far a payload's `ts` may be from the receiver's clock, in milliseconds.
pub const FRESHNESS_WINDOW_MS: i64 = 60_000;

/// The only thing visible on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// `hex(nonce[24] || ciphertext)`.
    pub sealed: String,
}

/// Fields every sealed payload carries, request and response alike.
///
/// Implement it on request and response types so [`crate::client::DhClient`]
/// can check that a response echoes the request it answers.
pub trait SealedPayload {
    /// The `requestId` field.
    fn request_id(&self) -> &str;
}

/// Unix time in milliseconds for the `ts` field.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A random 128-bit request id, hex encoded. Uses libsodium's CSPRNG so no
/// extra dependency is needed.
pub fn new_request_id() -> String {
    let _ = sodiumoxide::init();
    hex::encode(sodiumoxide::randombytes::randombytes(16))
}

/// True when `ts` is within [`FRESHNESS_WINDOW_MS`] of `now`.
pub fn is_fresh(ts: i64, now: i64) -> bool {
    (now - ts).abs() <= FRESHNESS_WINDOW_MS
}

/// True when `request_id` looks like one of ours: 16 to 64 hex characters or
/// dashes, which also admits UUIDs.
pub fn is_valid_request_id(request_id: &str) -> bool {
    let len = request_id.len();
    (16..=64).contains(&len)
        && request_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Seals `payload` as JSON into an envelope.
pub fn seal_payload<T: Serialize>(
    shared_key: &PrecomputedKey,
    payload: &T,
) -> Result<SealedEnvelope, Error> {
    let plaintext = serde_json::to_string(payload).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("sealed payload is not serializable: {e}"),
        )
    })?;
    Ok(SealedEnvelope {
        sealed: seal_message(shared_key, &plaintext),
    })
}

/// Opens an envelope and parses the plaintext as `T`.
///
/// A failed MAC check comes back as [`ErrorKind::PermissionDenied`], every
/// other problem as [`ErrorKind::InvalidData`].
pub fn open_payload<T: DeserializeOwned>(
    shared_key: &PrecomputedKey,
    envelope: &SealedEnvelope,
) -> Result<T, Error> {
    let plaintext = open_message(shared_key, &envelope.sealed)?;
    serde_json::from_str(&plaintext).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("sealed payload has unexpected shape: {e}"),
        )
    })
}
