//! The `/keys` document and the pair behind it.

use dh_channel::keys::{KeyPair, KeysError, PublicKeys, public_keys_reply};
use serde_json::json;
use std::io::ErrorKind;

#[test]
fn public_keys_serialize_in_the_shared_shape() {
    let keys = PublicKeys::new("abcd");
    assert_eq!(
        serde_json::to_value(&keys).unwrap(),
        json!({ "ed25519": { "publicKey": "abcd" } })
    );
}

#[test]
fn from_response_accepts_the_envelope_and_the_bare_shape() {
    let enveloped = json!({ "status": "success", "data": { "ed25519": { "publicKey": "abcd" } } });
    let bare = json!({ "ed25519": { "publicKey": "abcd" } });
    assert_eq!(
        PublicKeys::from_response(enveloped).unwrap(),
        PublicKeys::new("abcd")
    );
    assert_eq!(
        PublicKeys::from_response(bare).unwrap(),
        PublicKeys::new("abcd")
    );
}

#[test]
fn from_response_rejects_missing_or_empty_keys() {
    for body in [
        json!({ "status": "success", "data": {} }),
        json!({ "ed25519": {} }),
        json!({ "ed25519": { "publicKey": "  " } }),
        json!("text"),
        json!(null),
    ] {
        let err = PublicKeys::from_response(body).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }
}

#[test]
fn key_pair_trims_and_requires_both_halves() {
    let pair = KeyPair::new(" pub \n", "\tpriv ").unwrap();
    assert_eq!(pair.public_key_hex, "pub");
    assert_eq!(pair.private_key_hex, "priv");
    assert_eq!(pair.public_keys(), PublicKeys::new("pub"));

    assert_eq!(
        KeyPair::new("", "priv").unwrap_err(),
        KeysError::MissingPublicKey
    );
    assert_eq!(
        KeyPair::new("pub", " ").unwrap_err(),
        KeysError::MissingPrivateKey
    );
}

#[test]
fn key_pair_debug_redacts_the_private_half() {
    let pair = KeyPair::new("pub", "super-secret").unwrap();
    let debug = format!("{pair:?}");
    assert!(debug.contains("pub"));
    assert!(!debug.contains("super-secret"));
}

#[test]
fn reply_is_200_with_the_public_key() {
    let (status, body) = public_keys_reply("abcd", "ef01");
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({ "status": "success", "data": { "ed25519": { "publicKey": "abcd" } } })
    );
    assert!(!body.to_string().contains("ef01"));
}

#[test]
fn reply_is_503_with_the_shared_messages_when_a_half_is_missing() {
    let (status, body) = public_keys_reply("", "ef01");
    assert_eq!(status, 503);
    assert_eq!(
        body,
        json!({ "status": "error", "data": "Public key authorization service is not available" })
    );

    let (status, body) = public_keys_reply("abcd", "");
    assert_eq!(status, 503);
    assert_eq!(
        body,
        json!({ "status": "error", "data": "Key authorization service is not available" })
    );
}

#[test]
fn keys_error_converts_to_io_error() {
    let err: std::io::Error = KeysError::MissingPrivateKey.into();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    assert_eq!(
        err.to_string(),
        "Key authorization service is not available"
    );
    fn takes_error(_: &dyn std::error::Error) {}
    takes_error(&KeysError::MissingPublicKey);
}
