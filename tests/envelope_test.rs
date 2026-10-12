//! Envelope helpers: sealing and opening typed payloads, ids and freshness.

use dh_channel::crypto::{compute_shared_secret, generate_keypair_hex};
use dh_channel::envelope::{
    is_fresh, is_valid_request_id, new_request_id, now_millis, open_payload, seal_payload,
    SealedEnvelope, SealedPayload, FRESHNESS_WINDOW_MS, SERVICE_ID_HEADER,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::ErrorKind;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Ping {
    ts: i64,
    #[serde(rename = "requestId")]
    request_id: String,
    message: String,
}

impl SealedPayload for Ping {
    fn request_id(&self) -> &str {
        &self.request_id
    }
}

fn shared() -> (
    sodiumoxide::crypto::box_::PrecomputedKey,
    sodiumoxide::crypto::box_::PrecomputedKey,
) {
    let (a_pk, a_sk) = generate_keypair_hex();
    let (b_pk, b_sk) = generate_keypair_hex();
    (
        compute_shared_secret(&a_sk, &b_pk).unwrap(),
        compute_shared_secret(&b_sk, &a_pk).unwrap(),
    )
}

#[test]
fn seal_and_open_a_typed_payload() {
    let (alice, bob) = shared();
    let ping = Ping {
        ts: now_millis(),
        request_id: new_request_id(),
        message: "hello".into(),
    };

    let envelope = seal_payload(&alice, &ping).unwrap();
    assert!(envelope.sealed.chars().all(|c| c.is_ascii_hexdigit()));

    let opened: Ping = open_payload(&bob, &envelope).unwrap();
    assert_eq!(opened, ping);
    assert_eq!(opened.request_id(), ping.request_id);
}

#[test]
fn envelope_serializes_as_sealed_only() {
    let envelope = SealedEnvelope {
        sealed: "abcd".into(),
    };
    assert_eq!(
        serde_json::to_string(&envelope).unwrap(),
        r#"{"sealed":"abcd"}"#
    );
    let parsed: SealedEnvelope = serde_json::from_str(r#"{"sealed":"abcd","extra":1}"#).unwrap();
    assert_eq!(parsed, envelope);
}

#[test]
fn open_with_the_wrong_key_is_permission_denied() {
    let (alice, _) = shared();
    let (_, stranger) = shared();
    let envelope = seal_payload(&alice, &serde_json::json!({ "a": 1 })).unwrap();
    let err = open_payload::<serde_json::Value>(&stranger, &envelope).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn open_with_the_wrong_shape_is_invalid_data() {
    let (alice, bob) = shared();
    let envelope = seal_payload(&alice, &serde_json::json!({ "not": "a ping" })).unwrap();
    let err = open_payload::<Ping>(&bob, &envelope).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("unexpected shape"));
}

#[test]
fn open_a_malformed_envelope_is_invalid_data() {
    let (_, bob) = shared();
    let err = open_payload::<Ping>(
        &bob,
        &SealedEnvelope {
            sealed: "zz".into(),
        },
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[test]
fn request_ids_are_128_random_bits_in_hex() {
    let mut seen = HashSet::new();
    for _ in 0..100 {
        let id = new_request_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(is_valid_request_id(&id));
        seen.insert(id);
    }
    assert_eq!(seen.len(), 100);
}

#[test]
fn request_id_validation_admits_uuids_and_rejects_junk() {
    assert!(is_valid_request_id("6c1e9f0e2b8a4d3f9a7e1f2b3c4d5e6f"));
    assert!(is_valid_request_id("123e4567-e89b-12d3-a456-426614174000"));
    assert!(!is_valid_request_id("short"));
    assert!(!is_valid_request_id(&"f".repeat(65)));
    assert!(!is_valid_request_id("6c1e9f0e2b8a4d3f9a7e1f2b3c4d5e6g"));
    assert!(!is_valid_request_id(""));
}

#[test]
fn now_millis_is_unix_time() {
    let now = now_millis();
    // After 2020-01-01 and before 2100-01-01.
    assert!(now > 1_577_836_800_000);
    assert!(now < 4_102_444_800_000);
}

#[test]
fn freshness_window_is_symmetric() {
    let now = 1_760_000_000_000;
    assert!(is_fresh(now, now));
    assert!(is_fresh(now - FRESHNESS_WINDOW_MS, now));
    assert!(is_fresh(now + FRESHNESS_WINDOW_MS, now));
    assert!(!is_fresh(now - FRESHNESS_WINDOW_MS - 1, now));
    assert!(!is_fresh(now + FRESHNESS_WINDOW_MS + 1, now));
    assert_eq!(FRESHNESS_WINDOW_MS, 60_000);
}

#[test]
fn header_name_matches_the_wire() {
    assert_eq!(SERVICE_ID_HEADER, "X-Service-Id");
}
