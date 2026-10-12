//! The `/keys` document a service publishes, and the pair it holds.
//!
//! Every service answers `GET /keys` with its Ed25519 public key in the
//! `{ "status": "success", "data": { "ed25519": { "publicKey": "<hex>" } } }`
//! envelope. [`public_keys_reply`] builds that body, or the 503 error body
//! when either half of the pair is missing, with the same messages the
//! NestJS services use.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use std::io::{Error, ErrorKind};

/// The public half of a service identity, as served at `/keys`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PublicKeys {
    /// The Ed25519 public key.
    pub ed25519: Ed25519PublicKey,
}

/// Hex-encoded Ed25519 public key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    /// 32 bytes, hex.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

impl PublicKeys {
    /// Wraps a hex public key.
    pub fn new(public_key_hex: impl Into<String>) -> Self {
        PublicKeys {
            ed25519: Ed25519PublicKey {
                public_key: public_key_hex.into(),
            },
        }
    }

    /// Reads a `/keys` body, enveloped as `{ status, data }` or bare.
    pub fn from_response(value: Value) -> Result<PublicKeys, Error> {
        let inner = match value {
            Value::Object(mut map) if map.contains_key("status") && map.contains_key("data") => {
                map.remove("data").unwrap_or(Value::Null)
            }
            other => other,
        };
        let keys: PublicKeys = serde_json::from_value(inner).map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("keys response has unexpected shape: {e}"),
            )
        })?;
        if keys.ed25519.public_key.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "keys response has an empty ed25519.publicKey",
            ));
        }
        Ok(keys)
    }
}

/// Why a service cannot publish its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysError {
    /// The configured public key is empty.
    MissingPublicKey,
    /// The configured private key is empty. Without it the public half is
    /// useless to peers, since no shared key can be derived on this side.
    MissingPrivateKey,
}

impl fmt::Display for KeysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeysError::MissingPublicKey => {
                write!(f, "Public key authorization service is not available")
            }
            KeysError::MissingPrivateKey => write!(f, "Key authorization service is not available"),
        }
    }
}

impl std::error::Error for KeysError {}

impl From<KeysError> for Error {
    fn from(err: KeysError) -> Self {
        Error::new(ErrorKind::BrokenPipe, err.to_string())
    }
}

/// This service's Ed25519 pair, both halves hex encoded and trimmed.
#[derive(Clone)]
pub struct KeyPair {
    /// 32 bytes, hex.
    pub public_key_hex: String,
    /// 64 bytes, hex (libsodium seed || public key layout).
    pub private_key_hex: String,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key_hex", &self.public_key_hex)
            .field("private_key_hex", &"<redacted>")
            .finish()
    }
}

impl KeyPair {
    /// Validates that both halves are present. Values are trimmed.
    pub fn new(
        public_key_hex: impl AsRef<str>,
        private_key_hex: impl AsRef<str>,
    ) -> Result<KeyPair, KeysError> {
        let public_key_hex = public_key_hex.as_ref().trim().to_string();
        let private_key_hex = private_key_hex.as_ref().trim().to_string();
        if public_key_hex.is_empty() {
            return Err(KeysError::MissingPublicKey);
        }
        if private_key_hex.is_empty() {
            return Err(KeysError::MissingPrivateKey);
        }
        Ok(KeyPair {
            public_key_hex,
            private_key_hex,
        })
    }

    /// The public half, as served at `/keys`.
    pub fn public_keys(&self) -> PublicKeys {
        PublicKeys::new(self.public_key_hex.clone())
    }
}

/// Builds the `GET /keys` reply: `(200, success body)` or `(503, error body)`.
///
/// Replaces the `checkService` copies in each service. The error messages
/// match the NestJS helper so every service answers the same way.
pub fn public_keys_reply(public_key_hex: &str, private_key_hex: &str) -> (u16, Value) {
    match KeyPair::new(public_key_hex, private_key_hex) {
        Ok(pair) => (
            200,
            json!({ "status": "success", "data": pair.public_keys() }),
        ),
        Err(err) => (503, json!({ "status": "error", "data": err.to_string() })),
    }
}
