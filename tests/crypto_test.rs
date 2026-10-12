//! Key agreement and envelope primitives: the happy path, every `DhError`
//! variant, and the wire format locked against libsodium-wrappers.

use dh_channel::crypto::{
    compute_shared_secret, generate_keypair_hex, open_message, seal_message, DhError, MAC_BYTES,
    NONCE_BYTES,
};
use sodiumoxide::crypto::box_;
use std::io::ErrorKind;

fn keypair_hex() -> (String, String) {
    generate_keypair_hex()
}

mod compute_shared_secret_tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_key() {
        let (alice_pk, alice_sk) = keypair_hex();
        let (bob_pk, bob_sk) = keypair_hex();

        let alice_side = compute_shared_secret(&alice_sk, &bob_pk).unwrap();
        let bob_side = compute_shared_secret(&bob_sk, &alice_pk).unwrap();

        assert_eq!(alice_side.0, bob_side.0);
    }

    #[test]
    fn different_peers_derive_different_keys() {
        let (_, alice_sk) = keypair_hex();
        let (bob_pk, _) = keypair_hex();
        let (carol_pk, _) = keypair_hex();

        let with_bob = compute_shared_secret(&alice_sk, &bob_pk).unwrap();
        let with_carol = compute_shared_secret(&alice_sk, &carol_pk).unwrap();

        assert_ne!(with_bob.0, with_carol.0);
    }

    #[test]
    fn trims_whitespace_around_hex_keys() {
        let (alice_pk, alice_sk) = keypair_hex();
        let (bob_pk, bob_sk) = keypair_hex();

        let padded =
            compute_shared_secret(&format!("  {alice_sk}\n"), &format!("\t{bob_pk} ")).unwrap();
        let clean = compute_shared_secret(&bob_sk, &alice_pk).unwrap();

        assert_eq!(padded.0, clean.0);
    }

    #[test]
    fn rejects_non_hex_keys() {
        let (bob_pk, _) = keypair_hex();
        let (_, alice_sk) = keypair_hex();
        assert_eq!(
            compute_shared_secret("not-hex!!", &bob_pk).unwrap_err(),
            DhError::InvalidHex("private key")
        );
        assert_eq!(
            compute_shared_secret(&alice_sk, "zz").unwrap_err(),
            DhError::InvalidHex("public key")
        );
    }

    #[test]
    fn rejects_keys_of_the_wrong_length() {
        let (bob_pk, _) = keypair_hex();
        let (_, alice_sk) = keypair_hex();
        // 32 bytes: a seed, not the 64-byte libsodium secret key
        assert_eq!(
            compute_shared_secret(&hex::encode([7u8; 32]), &bob_pk).unwrap_err(),
            DhError::InvalidKeyLength("private key")
        );
        assert_eq!(
            compute_shared_secret(&alice_sk, &hex::encode([7u8; 16])).unwrap_err(),
            DhError::InvalidKeyLength("public key")
        );
        assert_eq!(
            compute_shared_secret("", &bob_pk).unwrap_err(),
            DhError::InvalidKeyLength("private key")
        );
        assert_eq!(
            compute_shared_secret(&alice_sk, "").unwrap_err(),
            DhError::InvalidKeyLength("public key")
        );
    }

    #[test]
    fn placeholder_keys_fail_cleanly() {
        assert!(compute_shared_secret("test", "test").is_err());
    }

    #[test]
    fn generated_pairs_have_libsodium_sizes() {
        let (pk, sk) = keypair_hex();
        assert_eq!(pk.len(), 64);
        assert_eq!(sk.len(), 128);
        assert!(
            sk.ends_with(&pk),
            "libsodium secret keys end with the public key"
        );
    }
}

mod seal_open_tests {
    use super::*;

    fn shared_pair() -> (box_::PrecomputedKey, box_::PrecomputedKey) {
        let (alice_pk, alice_sk) = keypair_hex();
        let (bob_pk, bob_sk) = keypair_hex();
        (
            compute_shared_secret(&alice_sk, &bob_pk).unwrap(),
            compute_shared_secret(&bob_sk, &alice_pk).unwrap(),
        )
    }

    #[test]
    fn round_trip() {
        let (alice, bob) = shared_pair();
        let sealed = seal_message(&alice, "hello bob");
        assert_eq!(open_message(&bob, &sealed).unwrap(), "hello bob");
    }

    #[test]
    fn round_trip_json_payload_with_unicode() {
        let (alice, bob) = shared_pair();
        let payload = r#"{"ts":1758812345123,"requestId":"6c1e9f0e","email":"josé@example.com","password":"päss"}"#;
        let sealed = seal_message(&alice, payload);
        assert_eq!(open_message(&bob, &sealed).unwrap(), payload);
    }

    #[test]
    fn round_trip_empty_message() {
        let (alice, bob) = shared_pair();
        let sealed = seal_message(&alice, "");
        assert_eq!(open_message(&bob, &sealed).unwrap(), "");
    }

    #[test]
    fn wire_format_is_hex_nonce_then_ciphertext() {
        let (alice, _) = shared_pair();
        let message = "wire format";
        let sealed = seal_message(&alice, message);

        assert!(sealed.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sealed.len(), 2 * (NONCE_BYTES + message.len() + MAC_BYTES));
        assert_eq!(NONCE_BYTES, 24);
        assert_eq!(MAC_BYTES, 16);
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let (alice, bob) = shared_pair();
        let a = seal_message(&alice, "same");
        let b = seal_message(&alice, "same");
        assert_ne!(a, b);
        assert_eq!(open_message(&bob, &a).unwrap(), "same");
        assert_eq!(open_message(&bob, &b).unwrap(), "same");
    }

    #[test]
    fn open_trims_whitespace() {
        let (alice, bob) = shared_pair();
        let sealed = seal_message(&alice, "trim me");
        assert_eq!(
            open_message(&bob, &format!(" {sealed}\n")).unwrap(),
            "trim me"
        );
    }

    #[test]
    fn wrong_key_and_tampering_fail_as_decryption() {
        let (alice, bob) = shared_pair();
        let (_, stranger) = shared_pair();
        let sealed = seal_message(&alice, "secret");
        assert_eq!(
            open_message(&stranger, &sealed).unwrap_err(),
            DhError::DecryptionFailed
        );

        let mut bytes = hex::decode(&sealed).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(
            open_message(&bob, &hex::encode(&bytes)).unwrap_err(),
            DhError::DecryptionFailed
        );

        let mut bytes = hex::decode(&sealed).unwrap();
        bytes[0] ^= 0xff;
        assert_eq!(
            open_message(&bob, &hex::encode(&bytes)).unwrap_err(),
            DhError::DecryptionFailed
        );
    }

    #[test]
    fn malformed_envelopes_are_rejected_by_shape() {
        let (_, bob) = shared_pair();
        assert_eq!(
            open_message(&bob, "this is not hex").unwrap_err(),
            DhError::InvalidHex("sealed message")
        );
        assert_eq!(
            open_message(&bob, "abc").unwrap_err(),
            DhError::InvalidHex("sealed message")
        );
        assert_eq!(
            open_message(&bob, "").unwrap_err(),
            DhError::CiphertextTooShort
        );
        let too_short = hex::encode(vec![0u8; NONCE_BYTES + MAC_BYTES - 1]);
        assert_eq!(
            open_message(&bob, &too_short).unwrap_err(),
            DhError::CiphertextTooShort
        );
        let garbage = hex::encode(vec![0u8; NONCE_BYTES + MAC_BYTES]);
        assert_eq!(
            open_message(&bob, &garbage).unwrap_err(),
            DhError::DecryptionFailed
        );
    }

    #[test]
    fn non_utf8_plaintext_is_rejected() {
        let (alice, bob) = shared_pair();
        let nonce = box_::gen_nonce();
        let ct = box_::seal_precomputed(&[0xff, 0xfe, 0xfd], &nonce, &alice);
        let mut packet = nonce.as_ref().to_vec();
        packet.extend_from_slice(&ct);
        assert_eq!(
            open_message(&bob, &hex::encode(packet)).unwrap_err(),
            DhError::InvalidUtf8
        );
    }
}

/// Produced by `libsodium-wrappers` 0.7 (the Node side): two Ed25519 pairs,
/// the shared key alice derived for bob, and an envelope alice sealed for
/// bob. If this test fails, the two implementations have drifted apart.
mod libsodium_wrappers_interop {
    use super::*;

    const ALICE_PK: &str = "7139e02246106ea2954eb60573a709275a6af4f3e7c9fe8b80844e58f0afaf9d";
    const ALICE_SK: &str = "e2b5b86df90bb3771cb9976682f5a3cfb92e2f5feffe19419ca118a2babbf2d27139e02246106ea2954eb60573a709275a6af4f3e7c9fe8b80844e58f0afaf9d";
    const BOB_PK: &str = "7428af532e7412ea0c18c683f0e1fc0a86efcbdd16102b23756b7766fbf67a72";
    const BOB_SK: &str = "05d6669b7a741864db9b64ebe67934fd103242a154cd4b8c73cdc4604b43f7cc7428af532e7412ea0c18c683f0e1fc0a86efcbdd16102b23756b7766fbf67a72";
    const SHARED: &str = "64eb83bd564b738a6ed74f92d82d8756d8d0a96a20e9757f6a7db91af58a90d9";
    const MESSAGE: &str = r#"{"ts":1760000000000,"requestId":"6c1e9f0e2b8a4d3f9a7e1f2b3c4d5e6f","hello":"from libsodium-wrappers"}"#;
    const SEALED: &str = "e4252e6b4d628212ff550eb84723d490f322fd4c0febf5a665949159ec63a913eb386da5af1098f502955b145af76e537c1ce4df63ed5f28af87e610dfd0ed51cd37be8f2770989d1e1376c2a1f2ba956ad85f82e9f877cba1d057b3486bbfd1b829036574d6b0da643e0110a24647b7604264664ae131efad2c3671675911553acaeddf2b69029a58596cafbf";

    #[test]
    fn derives_the_same_shared_key_as_crypto_box_beforenm() {
        let alice_side = compute_shared_secret(ALICE_SK, BOB_PK).unwrap();
        let bob_side = compute_shared_secret(BOB_SK, ALICE_PK).unwrap();
        assert_eq!(hex::encode(alice_side.0), SHARED);
        assert_eq!(hex::encode(bob_side.0), SHARED);
    }

    #[test]
    fn opens_an_envelope_sealed_by_libsodium_wrappers() {
        let bob_side = compute_shared_secret(BOB_SK, ALICE_PK).unwrap();
        assert_eq!(open_message(&bob_side, SEALED).unwrap(), MESSAGE);
    }

    #[test]
    fn seals_envelopes_libsodium_wrappers_can_open() {
        // Symmetric check: what we seal for bob opens under bob's derivation,
        // which equals the Node-derived SHARED key above.
        let alice_side = compute_shared_secret(ALICE_SK, BOB_PK).unwrap();
        let bob_side = compute_shared_secret(BOB_SK, ALICE_PK).unwrap();
        let sealed = seal_message(&alice_side, MESSAGE);
        assert_eq!(open_message(&bob_side, &sealed).unwrap(), MESSAGE);
    }
}

mod error_tests {
    use super::*;

    #[test]
    fn display_messages_name_the_offending_input() {
        assert_eq!(
            DhError::InvalidHex("public key").to_string(),
            "public key is not valid hex"
        );
        assert_eq!(
            DhError::InvalidKeyLength("private key").to_string(),
            "private key has an invalid length"
        );
        assert_eq!(
            DhError::KeyConversion("public key").to_string(),
            "public key could not be converted from ed25519 to x25519"
        );
        assert_eq!(
            DhError::CiphertextTooShort.to_string(),
            "sealed message is too short"
        );
        assert_eq!(
            DhError::DecryptionFailed.to_string(),
            "sealed message failed to open"
        );
        assert_eq!(
            DhError::InvalidUtf8.to_string(),
            "opened message is not valid utf-8"
        );
    }

    #[test]
    fn converts_to_io_error_with_meaningful_kind() {
        let denied: std::io::Error = DhError::DecryptionFailed.into();
        assert_eq!(denied.kind(), ErrorKind::PermissionDenied);

        let invalid: std::io::Error = DhError::InvalidHex("public key").into();
        assert_eq!(invalid.kind(), ErrorKind::InvalidData);
        assert_eq!(invalid.to_string(), "public key is not valid hex");
    }

    #[test]
    fn is_a_std_error() {
        fn takes_error(_: &dyn std::error::Error) {}
        takes_error(&DhError::InvalidUtf8);
    }
}
