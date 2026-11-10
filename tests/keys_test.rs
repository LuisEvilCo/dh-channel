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

mod published_keys {
    use super::*;
    use dh_channel::keys::{ED25519_KEY_NAME, PublishedKey, public_keys_reply_with};

    #[test]
    fn a_service_without_other_keys_serializes_as_before() {
        // 0.2 peers and the TypeScript library must see the same document.
        assert_eq!(
            serde_json::to_value(PublicKeys::new("abcd")).unwrap(),
            json!({ "ed25519": { "publicKey": "abcd" } })
        );
        let (_, body) = public_keys_reply("pub", "priv");
        assert_eq!(
            body,
            json!({ "status": "success", "data": { "ed25519": { "publicKey": "pub" } } })
        );
    }

    #[test]
    fn other_keys_sit_next_to_ed25519_under_their_names() {
        let (status, body) = public_keys_reply_with(
            "pub",
            "priv",
            [
                ("foo", PublishedKey::with_algorithm("RS256", " rsa-key \n")),
                ("bar", PublishedKey::new("plain-key")),
            ],
        );

        assert_eq!(status, 200);
        assert_eq!(
            body,
            json!({
                "status": "success",
                "data": {
                    "ed25519": { "publicKey": "pub" },
                    "foo": { "algorithm": "RS256", "publicKey": "rsa-key" },
                    "bar": { "publicKey": "plain-key" }
                }
            })
        );
    }

    #[test]
    fn the_identity_cannot_be_replaced_and_empty_keys_are_not_published() {
        let (_, body) = public_keys_reply_with(
            "pub",
            "priv",
            [
                (ED25519_KEY_NAME, PublishedKey::new("impostor")),
                ("unset", PublishedKey::with_algorithm("RS256", "   ")),
                ("  ", PublishedKey::new("nameless")),
            ],
        );

        assert_eq!(
            body,
            json!({ "status": "success", "data": { "ed25519": { "publicKey": "pub" } } })
        );
    }

    #[test]
    fn the_error_body_carries_no_other_key() {
        for (public, private) in [("", "priv"), ("pub", "")] {
            let (status, body) =
                public_keys_reply_with(public, private, [("foo", PublishedKey::new("rsa-key"))]);
            assert_eq!(status, 503);
            assert_eq!(body["status"], "error");
            assert!(!body.to_string().contains("rsa-key"));
        }
    }

    #[test]
    fn the_private_half_never_reaches_the_document() {
        let (_, body) = public_keys_reply_with(
            "pub",
            "PRIVATE-HALF",
            [("foo", PublishedKey::with_algorithm("RS256", "rsa-key"))],
        );
        assert!(!body.to_string().contains("PRIVATE-HALF"));
    }

    #[test]
    fn a_reader_finds_a_published_key_by_name() {
        let keys = PublicKeys::from_response(json!({
            "status": "success",
            "data": {
                "ed25519": { "publicKey": "abcd" },
                "foo": { "algorithm": "RS256", "publicKey": "rsa-key" },
                "bar": { "publicKey": "plain-key" }
            }
        }))
        .unwrap();

        assert_eq!(keys.ed25519.public_key, "abcd");
        assert_eq!(
            keys.key("foo"),
            Some(&PublishedKey::with_algorithm("RS256", "rsa-key"))
        );
        assert_eq!(keys.key("bar"), Some(&PublishedKey::new("plain-key")));
        assert_eq!(keys.key("baz"), None);
        // the identity is not listed among the others
        assert_eq!(keys.key(ED25519_KEY_NAME), None);
    }

    #[test]
    fn a_reader_ignores_entries_that_are_not_published_keys() {
        // A newer peer may add anything; none of it may make the document
        // unreadable or show up as a key.
        let keys = PublicKeys::from_response(json!({
            "ed25519": { "publicKey": "abcd" },
            "version": 3,
            "note": "text",
            "list": ["a"],
            "empty": { "publicKey": "  " },
            "shapeless": { "algorithm": "RS256" },
            "nothing": null,
            "wrongType": { "publicKey": 42 },
            "  ": { "publicKey": "nameless" },
            "good": { "publicKey": " kept ", "algorithm": 7, "extra": true },
            "named": { "publicKey": "also-kept", "algorithm": " RS256 " }
        }))
        .unwrap();

        // The same document and the same answer as the TypeScript library's
        // `readPublishedKeys` test.
        assert_eq!(keys.ed25519.public_key, "abcd");
        assert_eq!(keys.other.keys().collect::<Vec<_>>(), ["good", "named"]);
        assert_eq!(keys.key("good"), Some(&PublishedKey::new("kept")));
        assert_eq!(
            keys.key("named"),
            Some(&PublishedKey::with_algorithm("RS256", "also-kept"))
        );
    }

    #[test]
    fn a_document_survives_a_round_trip() {
        let keys = PublicKeys::new("abcd")
            .with_key("foo", PublishedKey::with_algorithm("RS256", "rsa-key"));

        let body = json!({ "status": "success", "data": keys });

        assert_eq!(PublicKeys::from_response(body).unwrap(), keys);
    }

    #[test]
    fn other_keys_do_not_excuse_a_missing_identity() {
        let err = PublicKeys::from_response(json!({
            "foo": { "algorithm": "RS256", "publicKey": "rsa-key" }
        }))
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }
}
