//! `DhClient` against a wiremock peer that behaves like the receiver: it
//! opens the sealed request with the key derived from its own private key
//! and the sender's public key, checks the fields, and answers with a sealed
//! response.

use dh_channel::client::{DhClient, post_sealed};
use dh_channel::crypto::{compute_shared_secret, generate_keypair_hex};
use dh_channel::envelope::{
    SERVICE_ID_HEADER, SealedEnvelope, SealedPayload, new_request_id, now_millis, open_payload,
    seal_payload,
};
use dh_channel::key_manager::{KeyManager, Peer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sodiumoxide::crypto::box_::PrecomputedKey;
use std::io::ErrorKind;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const ROUTE: &str = "/internal/login-token";

#[derive(Serialize, Deserialize)]
struct LoginRequest {
    ts: i64,
    #[serde(rename = "requestId")]
    request_id: String,
    email: String,
    password: String,
}

impl SealedPayload for LoginRequest {
    fn request_id(&self) -> &str {
        &self.request_id
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct LoginResponse {
    ts: i64,
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "authToken")]
    auth_token: String,
}

impl SealedPayload for LoginResponse {
    fn request_id(&self) -> &str {
        &self.request_id
    }
}

fn login() -> LoginRequest {
    LoginRequest {
        ts: now_millis(),
        request_id: new_request_id(),
        email: "user@example.com".into(),
        password: "pw".into(),
    }
}

/// How the fake peer answers once it has opened the request.
#[derive(Clone, Copy)]
enum Behaviour {
    Ok,
    WrongRequestId,
    WrongKey,
    NotAnEnvelope,
    NotAnObject,
    Status(u16),
}

struct FakePeer {
    shared: PrecomputedKey,
    behaviour: Behaviour,
}

impl Respond for FakePeer {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let sender = request
            .headers
            .get(SERVICE_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if sender != "foo" {
            return ResponseTemplate::new(401)
                .set_body_json(json!({ "statusCode": 401, "message": "Unknown service" }));
        }
        let content_type = request
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.starts_with("application/json") {
            return ResponseTemplate::new(400)
                .set_body_json(json!({ "statusCode": 400, "message": "not json" }));
        }
        let envelope: SealedEnvelope = match request.body_json() {
            Ok(e) => e,
            Err(_) => return ResponseTemplate::new(400),
        };
        let opened: LoginRequest = match open_payload(&self.shared, &envelope) {
            Ok(p) => p,
            Err(_) => return ResponseTemplate::new(401),
        };
        if opened.email != "user@example.com" || opened.password != "pw" {
            return ResponseTemplate::new(422);
        }

        if let Behaviour::Status(code) = self.behaviour {
            return ResponseTemplate::new(code)
                .set_body_json(json!({ "statusCode": code, "message": "x".repeat(500) }));
        }

        let request_id = match self.behaviour {
            Behaviour::WrongRequestId => "f".repeat(32),
            _ => opened.request_id.clone(),
        };
        let reply = LoginResponse {
            ts: now_millis(),
            request_id,
            auth_token: "bar.jwt".into(),
        };
        match self.behaviour {
            Behaviour::NotAnEnvelope => {
                ResponseTemplate::new(200).set_body_json(json!({ "authToken": "leaked" }))
            }
            Behaviour::NotAnObject => ResponseTemplate::new(200)
                .set_body_json(seal_payload(&self.shared, &json!([1, 2])).unwrap()),
            Behaviour::WrongKey => {
                let (a_pk, _) = generate_keypair_hex();
                let (_, b_sk) = generate_keypair_hex();
                let other = compute_shared_secret(&b_sk, &a_pk).unwrap();
                ResponseTemplate::new(200).set_body_json(seal_payload(&other, &reply).unwrap())
            }
            _ => ResponseTemplate::new(200)
                .set_body_json(seal_payload(&self.shared, &reply).unwrap()),
        }
    }
}

/// A foo keypair (the sender), a bar keypair (the receiver), a mock
/// bar serving `/keys`, and the client wired to it.
struct Fixture {
    server: MockServer,
    client: DhClient,
    bar_shared: PrecomputedKey,
    foo_shared: PrecomputedKey,
}

impl Fixture {
    async fn new() -> Self {
        let (bar_pk, bar_sk) = generate_keypair_hex();
        let (foo_pk, foo_sk) = generate_keypair_hex();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success",
                "data": { "ed25519": { "publicKey": format!("{bar_pk}\n") } }
            })))
            .mount(&server)
            .await;

        let keys = Arc::new(KeyManager::new(vec![Peer::new("bar", server.uri())]));
        let client = DhClient::new("foo", foo_sk.clone(), keys);
        Fixture {
            bar_shared: compute_shared_secret(&bar_sk, &foo_pk).unwrap(),
            foo_shared: compute_shared_secret(&foo_sk, &bar_pk).unwrap(),
            server,
            client,
        }
    }

    async fn bar_behaves(&self, behaviour: Behaviour) {
        Mock::given(method("POST"))
            .and(path(ROUTE))
            .respond_with(FakePeer {
                shared: self.bar_shared.clone(),
                behaviour,
            })
            .mount(&self.server)
            .await;
    }

    fn url(&self) -> String {
        format!("{}{}", self.server.uri(), ROUTE)
    }

    async fn post(&self) -> Result<LoginResponse, std::io::Error> {
        self.client.post("bar", &self.url(), &login()).await
    }
}

#[tokio::test]
async fn opens_the_sealed_response_and_checks_the_echoed_request_id() {
    let fx = Fixture::new().await;
    fx.bar_behaves(Behaviour::Ok).await;

    let request = login();
    let response: LoginResponse = fx.client.post("bar", &fx.url(), &request).await.unwrap();

    assert_eq!(response.auth_token, "bar.jwt");
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(fx.client.own_id(), "foo");
    assert!(fx.client.keys().is_known_peer("bar"));
    assert!(format!("{:?}", fx.client).contains("foo"));
}

#[tokio::test]
async fn fetches_the_peer_key_once_across_calls() {
    let fx = Fixture::new().await;
    fx.bar_behaves(Behaviour::Ok).await;
    fx.post().await.unwrap();
    fx.post().await.unwrap();

    let key_fetches = fx
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/keys")
        .count();
    assert_eq!(key_fetches, 1);
}

#[tokio::test]
async fn a_response_with_another_request_id_is_invalid_data() {
    let fx = Fixture::new().await;
    fx.bar_behaves(Behaviour::WrongRequestId).await;
    let err = fx.post().await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("requestId"));
}

#[tokio::test]
async fn a_response_under_another_key_is_permission_denied() {
    let fx = Fixture::new().await;
    fx.bar_behaves(Behaviour::WrongKey).await;
    let err = fx.post().await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn a_body_that_is_not_an_envelope_is_invalid_data() {
    let fx = Fixture::new().await;
    fx.bar_behaves(Behaviour::NotAnEnvelope).await;
    let err = fx.post().await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("not a sealed envelope"));
}

#[tokio::test]
async fn a_plaintext_of_the_wrong_shape_is_invalid_data() {
    let fx = Fixture::new().await;
    fx.bar_behaves(Behaviour::NotAnObject).await;
    let err = fx.post().await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[tokio::test]
async fn upstream_statuses_map_to_error_kinds() {
    for (status, kind) in [
        (401, ErrorKind::PermissionDenied),
        (403, ErrorKind::PermissionDenied),
        (404, ErrorKind::NotFound),
        (400, ErrorKind::InvalidInput),
        (422, ErrorKind::InvalidInput),
        (500, ErrorKind::Other),
        (502, ErrorKind::Other),
    ] {
        let fx = Fixture::new().await;
        fx.bar_behaves(Behaviour::Status(status)).await;
        let err = fx.post().await.unwrap_err();
        assert_eq!(err.kind(), kind, "status {status}");
        let message = err.to_string();
        assert!(message.contains(&status.to_string()), "{message}");
        // The body snippet is capped at 200 characters.
        assert!(message.len() < 400, "{}", message.len());
    }
}

#[tokio::test]
async fn transport_failures_are_other() {
    let fx = Fixture::new().await;
    let err = fx
        .client
        .post::<_, LoginResponse>("bar", "http://127.0.0.1:1/nowhere", &login())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Other);
    assert!(err.to_string().contains("failed"));
}

#[tokio::test]
async fn an_unknown_peer_fails_before_sending() {
    let fx = Fixture::new().await;
    let err = fx
        .client
        .post::<_, LoginResponse>("mallory", &fx.url(), &login())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert!(fx.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_missing_own_key_fails_before_sending() {
    let fx = Fixture::new().await;
    let client = DhClient::with_http("foo", " ", fx.client.keys().clone(), reqwest::Client::new());
    let err = client
        .post::<_, LoginResponse>("bar", &fx.url(), &login())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[tokio::test]
async fn post_sealed_sends_the_sender_header_and_json() {
    let fx = Fixture::new().await;
    fx.bar_behaves(Behaviour::Ok).await;

    let request = login();
    let response: LoginResponse = post_sealed(
        &reqwest::Client::new(),
        &fx.url(),
        "foo",
        &fx.foo_shared,
        &request,
    )
    .await
    .unwrap();
    assert_eq!(response.request_id, request.request_id);

    // The fake peer rejects any other sender id with 401.
    let err = post_sealed::<_, LoginResponse>(
        &reqwest::Client::new(),
        &fx.url(),
        "baz",
        &fx.foo_shared,
        &request,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn post_sealed_rejects_an_invalid_sender_id() {
    let fx = Fixture::new().await;
    let err = post_sealed::<_, LoginResponse>(
        &reqwest::Client::new(),
        &fx.url(),
        "bad\nid",
        &fx.foo_shared,
        &login(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}
