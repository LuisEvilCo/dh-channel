//! The `/keys` document a service publishes, and the pair it holds.
//!
//! Every service answers `GET /keys` with its Ed25519 public key in the
//! `{ "status": "success", "data": { "ed25519": { "publicKey": "<hex>" } } }`
//! envelope. [`public_keys_reply`] builds that body, or the 503 error body
//! when either half of the pair is missing, with the same messages on every
//! service.
//!
//! A service may publish other public keys in the same document, each under
//! a name of its choosing next to `ed25519`:
//! `"data": { "ed25519": { .. }, "foo": { "algorithm": "RS256", "publicKey": ".." } }`.
//! [`public_keys_reply_with`] builds that body and [`PublicKeys::key`] reads
//! an entry on the other side. The channel itself only ever uses `ed25519`;
//! a peer that does not know a name ignores it.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Error, ErrorKind};

/// The name of the channel's own key in the `/keys` document. No other
/// published key may take it.
pub const ED25519_KEY_NAME: &str = "ed25519";

/// The public half of a service identity, as served at `/keys`, plus any
/// other public keys the service publishes there.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PublicKeys {
    /// The Ed25519 public key.
    pub ed25519: Ed25519PublicKey,
    /// Other public keys, by the name they are published under. Empty for a
    /// service that publishes only its identity. Entries of the document
    /// that are not `{ publicKey, algorithm? }` are left out when reading.
    #[serde(
        flatten,
        default,
        deserialize_with = "published_keys_only",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub other: BTreeMap<String, PublishedKey>,
}

/// A public key published next to the Ed25519 identity: a signature
/// verification key, for example. Never a secret: everything here is served
/// to anyone who asks.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    /// What the key is for, in the publisher's words: `RS256`, `EdDSA`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// The key, in whatever text encoding the publisher documents.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

impl PublishedKey {
    /// A key with no stated algorithm. The value is trimmed.
    pub fn new(public_key: impl AsRef<str>) -> Self {
        PublishedKey {
            algorithm: None,
            public_key: public_key.as_ref().trim().to_string(),
        }
    }

    /// A key and the algorithm it belongs to. Both are trimmed.
    pub fn with_algorithm(algorithm: impl AsRef<str>, public_key: impl AsRef<str>) -> Self {
        PublishedKey {
            algorithm: Some(algorithm.as_ref().trim().to_string()),
            public_key: public_key.as_ref().trim().to_string(),
        }
    }
}

/// Reads the entries next to `ed25519` that are published keys with a
/// non-empty `publicKey`, and leaves out everything else, so a field this
/// version does not know never makes a peer's document unreadable.
fn published_keys_only<'de, D>(deserializer: D) -> Result<BTreeMap<String, PublishedKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let entries = BTreeMap::<String, Value>::deserialize(deserializer)?;
    Ok(entries
        .into_iter()
        .filter(|(name, _)| name != ED25519_KEY_NAME)
        .filter_map(|(name, value)| {
            serde_json::from_value::<PublishedKey>(value)
                .ok()
                .filter(|key| !key.public_key.trim().is_empty())
                .map(|key| (name, key))
        })
        .collect())
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
            other: BTreeMap::new(),
        }
    }

    /// Adds another public key under `name`. Two cases add nothing: the
    /// name `ed25519`, which belongs to the identity, and a key whose value
    /// is empty, so a service whose optional key is not configured publishes
    /// no entry for it instead of an empty one.
    pub fn with_key(mut self, name: impl Into<String>, key: PublishedKey) -> Self {
        let name = name.into();
        if name != ED25519_KEY_NAME && !name.trim().is_empty() && !key.public_key.is_empty() {
            self.other.insert(name, key);
        }
        self
    }

    /// The key published under `name`, if the service publishes one.
    pub fn key(&self, name: &str) -> Option<&PublishedKey> {
        self.other.get(name)
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
/// The error messages are fixed so every service answers the same way.
pub fn public_keys_reply(public_key_hex: &str, private_key_hex: &str) -> (u16, Value) {
    public_keys_reply_with(
        public_key_hex,
        private_key_hex,
        std::iter::empty::<(String, PublishedKey)>(),
    )
}

/// Like [`public_keys_reply`], also publishing `other` public keys by name
/// next to `ed25519` (see [`PublicKeys::with_key`] for the two cases that
/// are left out).
///
/// Pass public keys only: the body is served to anyone. The 503 body is the
/// same as [`public_keys_reply`]'s and carries none of them.
pub fn public_keys_reply_with<I, N>(
    public_key_hex: &str,
    private_key_hex: &str,
    other: I,
) -> (u16, Value)
where
    I: IntoIterator<Item = (N, PublishedKey)>,
    N: Into<String>,
{
    match KeyPair::new(public_key_hex, private_key_hex) {
        Ok(pair) => {
            let keys = other
                .into_iter()
                .fold(pair.public_keys(), |keys, (name, key)| {
                    keys.with_key(name, key)
                });
            (200, json!({ "status": "success", "data": keys }))
        }
        Err(err) => (503, json!({ "status": "error", "data": err.to_string() })),
    }
}
