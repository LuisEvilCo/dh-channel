//! Static Diffie-Hellman sealed channel primitives.
//!
//! Each service holds a long-lived Ed25519 keypair and publishes the public
//! half at `/keys`. Both sides convert their Ed25519 keys to X25519 and derive
//! the same 32-byte shared key with libsodium's `crypto_box_beforenm`
//! ([`box_::precompute`]). Messages are then sealed with
//! `crypto_box_easy_afternm` and travel as `hex(nonce[24] || ciphertext)`.
//!
//! The Node counterparts are `crypto_sign_ed25519_{pk,sk}_to_curve25519`,
//! `crypto_box_beforenm`, `crypto_box_easy_afternm` and
//! `crypto_box_open_easy_afternm` from `libsodium-wrappers`. Raw
//! `crypto_scalarmult` does NOT produce the same key.
//!
//! Nothing in this module panics on bad input. Every failure surfaces as a
//! [`DhError`] so a malformed key or ciphertext on a request path becomes an
//! HTTP error instead of a crashed worker.

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::PrecomputedKey;
use sodiumoxide::crypto::sign::ed25519;
use std::fmt;
use std::io::{Error, ErrorKind};

/// Size in bytes of the nonce prefix in the sealed envelope.
pub const NONCE_BYTES: usize = box_::NONCEBYTES;
/// Size in bytes of the Poly1305 authentication tag appended by libsodium.
pub const MAC_BYTES: usize = box_::MACBYTES;

/// Errors produced by the sealed channel primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhError {
    /// A hex string could not be decoded. Names the offending input.
    InvalidHex(&'static str),
    /// A decoded key did not have the length libsodium expects. Names the key.
    InvalidKeyLength(&'static str),
    /// Ed25519 to X25519 conversion was rejected by libsodium. Names the key.
    KeyConversion(&'static str),
    /// The envelope is shorter than nonce + MAC, so it cannot contain a message.
    CiphertextTooShort,
    /// Authentication failed: wrong shared key or tampered ciphertext.
    DecryptionFailed,
    /// The decrypted bytes are not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for DhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhError::InvalidHex(what) => write!(f, "{what} is not valid hex"),
            DhError::InvalidKeyLength(what) => write!(f, "{what} has an invalid length"),
            DhError::KeyConversion(what) => {
                write!(f, "{what} could not be converted from ed25519 to x25519")
            }
            DhError::CiphertextTooShort => write!(f, "sealed message is too short"),
            DhError::DecryptionFailed => write!(f, "sealed message failed to open"),
            DhError::InvalidUtf8 => write!(f, "opened message is not valid utf-8"),
        }
    }
}

impl std::error::Error for DhError {}

impl From<DhError> for Error {
    fn from(err: DhError) -> Self {
        let kind = match err {
            DhError::DecryptionFailed => ErrorKind::PermissionDenied,
            _ => ErrorKind::InvalidData,
        };
        Error::new(kind, err.to_string())
    }
}

/// Derives the shared key between this service and a peer.
///
/// # Arguments
///
/// * `own_private_key_hex` - This service's Ed25519 secret key, hex encoded
///   (64 bytes, the libsodium seed || public key layout).
/// * `peer_public_key_hex` - The peer's Ed25519 public key, hex encoded (32 bytes).
///
/// Both inputs are trimmed before decoding because `/keys` endpoints have been
/// observed to return keys with trailing whitespace.
///
/// # Returns
///
/// The precomputed X25519 shared key, identical on both sides.
pub fn compute_shared_secret(
    own_private_key_hex: &str,
    peer_public_key_hex: &str,
) -> Result<PrecomputedKey, DhError> {
    let own_sk_bytes =
        hex::decode(own_private_key_hex.trim()).map_err(|_| DhError::InvalidHex("private key"))?;
    let own_sign_sk = ed25519::SecretKey::from_slice(&own_sk_bytes)
        .ok_or(DhError::InvalidKeyLength("private key"))?;
    let own_kx_sk = ed25519::to_curve25519_sk(&own_sign_sk)
        .map_err(|_| DhError::KeyConversion("private key"))?;
    let own_kx_sk =
        box_::SecretKey::from_slice(&own_kx_sk.0).ok_or(DhError::KeyConversion("private key"))?;

    let peer_pk_bytes =
        hex::decode(peer_public_key_hex.trim()).map_err(|_| DhError::InvalidHex("public key"))?;
    let peer_sign_pk = ed25519::PublicKey::from_slice(&peer_pk_bytes)
        .ok_or(DhError::InvalidKeyLength("public key"))?;
    let peer_kx_pk = ed25519::to_curve25519_pk(&peer_sign_pk)
        .map_err(|_| DhError::KeyConversion("public key"))?;
    let peer_kx_pk =
        box_::PublicKey::from_slice(&peer_kx_pk.0).ok_or(DhError::KeyConversion("public key"))?;

    Ok(box_::precompute(&peer_kx_pk, &own_kx_sk))
}

/// Seals a plaintext message for the peer.
///
/// # Arguments
///
/// * `shared_key` - The key from [`compute_shared_secret`].
/// * `message` - Plaintext to seal.
///
/// # Returns
///
/// `hex(nonce[24] || ciphertext)`. A fresh random nonce is generated per call,
/// so sealing the same message twice yields different envelopes. This function
/// cannot fail.
pub fn seal_message(shared_key: &PrecomputedKey, message: &str) -> String {
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal_precomputed(message.as_bytes(), &nonce, shared_key);

    let mut packet: Vec<u8> = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    packet.extend_from_slice(nonce.as_ref());
    packet.extend_from_slice(&ciphertext);

    hex::encode(packet)
}

/// Opens an envelope produced by [`seal_message`] (or its Node counterpart).
///
/// # Arguments
///
/// * `shared_key` - The key from [`compute_shared_secret`].
/// * `cipher_text_hex` - `hex(nonce[24] || ciphertext)`.
///
/// # Returns
///
/// The plaintext as a UTF-8 string, or a [`DhError`] describing why the
/// envelope could not be opened. A failed MAC check (wrong key or tampering)
/// is reported as [`DhError::DecryptionFailed`].
pub fn open_message(shared_key: &PrecomputedKey, cipher_text_hex: &str) -> Result<String, DhError> {
    let bytes =
        hex::decode(cipher_text_hex.trim()).map_err(|_| DhError::InvalidHex("sealed message"))?;

    if bytes.len() < NONCE_BYTES + MAC_BYTES {
        return Err(DhError::CiphertextTooShort);
    }

    let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_BYTES);
    let nonce = box_::Nonce::from_slice(nonce_bytes).ok_or(DhError::CiphertextTooShort)?;

    let plaintext = box_::open_precomputed(ciphertext, &nonce, shared_key)
        .map_err(|_| DhError::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|_| DhError::InvalidUtf8)
}

/// Generates a fresh Ed25519 keypair as `(public_key_hex, private_key_hex)`.
///
/// Convenience for tests and for minting a service identity; production
/// services read their pair from configuration.
pub fn generate_keypair_hex() -> (String, String) {
    // init is idempotent and only fails if libsodium cannot initialise, in
    // which case nothing in this crate can work anyway.
    let _ = sodiumoxide::init();
    let (pk, sk) = ed25519::gen_keypair();
    (hex::encode(pk.as_ref()), hex::encode(sk.as_ref()))
}
