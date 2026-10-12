//! The axum receiver: `dh_auth` middleware, extractors and `seal_response`,
//! driven through a router with tower's `oneshot`.

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::response::Response;
use axum::routing::post;
use dh_channel::crypto::{compute_shared_secret, generate_keypair_hex};
use dh_channel::envelope::{
    SERVICE_ID_HEADER, SealedEnvelope, new_request_id, now_millis, open_payload, seal_payload,
};
use dh_channel::key_manager::{FetchFuture, KeyFetcher, KeyManager, Peer};
use dh_channel::keys::PublicKeys;
use dh_channel::receiver::{DhContext, DhPayload, DhReceiver, DhSender, dh_auth, seal_response};
use dh_channel::replay::{InMemoryReplayStore, ReplayStore};
use serde::Deserialize;
use serde_json::{Value, json};
use sodiumoxide::crypto::box_::PrecomputedKey;
use std::io::Error;
use std::sync::Arc;
use tower::ServiceExt;

const ROUTE: &str = "/v2/internal/login-token";

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

async fn login_token(
    ctx: DhContext,
    DhSender(sender): DhSender,
    DhPayload(body): DhPayload<LoginBody>,
) -> Response {
    assert_eq!(sender, ctx.service_id);
    seal_response(
        &ctx,
        &json!({
            "authToken": format!("jwt-for-{}", body.email),
            "passwordLength": body.password.len(),
            "sender": sender,
        }),
    )
}

async fn context_only(ctx: DhContext) -> Response {
    seal_response(&ctx, &json!({ "payload": ctx.payload }))
}

async fn without_middleware(ctx: DhContext) -> Response {
    seal_response(&ctx, &json!({}))
}

async fn bad_body(ctx: DhContext) -> Response {
    seal_response(&ctx, &json!([1, 2, 3]))
}

/// A fetcher serving fixed keys per peer id.
struct StaticKeys(Vec<(String, String)>);

impl KeyFetcher for StaticKeys {
    fn fetch(&self, peer: &Peer) -> FetchFuture {
        let found = self
            .0
            .iter()
            .find(|(id, _)| id == &peer.id)
            .map(|(_, pk)| pk.clone());
        Box::pin(async move {
            found
                .map(PublicKeys::new)
                .ok_or_else(|| Error::other("no key"))
        })
    }
}

struct FailingReplay;

#[async_trait]
impl ReplayStore for FailingReplay {
    async fn claim(&self, _service_id: &str, _request_id: &str) -> Result<bool, Error> {
        Err(Error::other("redis down"))
    }
}

/// Edge is the receiver; auth and contacts are registered senders.
struct Fixture {
    receiver: DhReceiver,
    /// auth's view of the shared key with edge.
    auth_shared: PrecomputedKey,
    /// contacts' view of the shared key with edge.
    contacts_shared: PrecomputedKey,
    edge_sk: String,
    keys: Arc<KeyManager>,
}

impl Fixture {
    fn new() -> Self {
        let (edge_pk, edge_sk) = generate_keypair_hex();
        let (auth_pk, auth_sk) = generate_keypair_hex();
        let (contacts_pk, contacts_sk) = generate_keypair_hex();
        let keys = Arc::new(KeyManager::with_fetcher(
            vec![
                Peer::new("auth", "auth.internal"),
                Peer::new("contacts", "contacts.internal"),
            ],
            Box::new(StaticKeys(vec![
                ("auth".into(), auth_pk),
                ("contacts".into(), contacts_pk),
            ])),
        ));
        Fixture {
            receiver: DhReceiver::new(
                edge_sk.clone(),
                keys.clone(),
                Arc::new(InMemoryReplayStore::new()),
            ),
            auth_shared: compute_shared_secret(&auth_sk, &edge_pk).unwrap(),
            contacts_shared: compute_shared_secret(&contacts_sk, &edge_pk).unwrap(),
            edge_sk,
            keys,
        }
    }

    fn app(self) -> Router {
        Self::app_with(self.receiver)
    }

    fn app_with(receiver: DhReceiver) -> Router {
        let receiver = Arc::new(receiver);
        Router::new()
            .route(
                ROUTE,
                post(login_token).route_layer(from_fn_with_state(receiver.clone(), dh_auth)),
            )
            .route(
                "/context",
                post(context_only).route_layer(from_fn_with_state(receiver.clone(), dh_auth)),
            )
            .route(
                "/bad-body",
                post(bad_body).route_layer(from_fn_with_state(receiver, dh_auth)),
            )
            .route("/unguarded", post(without_middleware))
    }
}

fn payload() -> Value {
    json!({
        "ts": now_millis(),
        "requestId": new_request_id(),
        "email": "user@example.com",
        "password": "hunter2",
    })
}

fn sealed_request(
    route: &str,
    sender: &str,
    key: &PrecomputedKey,
    plaintext: &Value,
) -> Request<Body> {
    let envelope = seal_payload(key, plaintext).unwrap();
    Request::builder()
        .method("POST")
        .uri(route)
        .header("content-type", "application/json")
        .header(SERVICE_ID_HEADER, sender)
        .body(Body::from(serde_json::to_vec(&envelope).unwrap()))
        .unwrap()
}

fn raw_request(route: &str, sender: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(route)
        .header("content-type", "application/json");
    if let Some(sender) = sender {
        builder = builder.header(SERVICE_ID_HEADER, sender);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn expect_rejection(app: Router, request: Request<Body>, status: StatusCode, message: &str) {
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), status, "{message}");
    let body = body_json(response).await;
    assert_eq!(body["statusCode"], status.as_u16());
    assert_eq!(body["message"], message);
}

#[tokio::test]
async fn accepts_a_fresh_request_and_seals_the_reply_with_the_echoed_id() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    let plaintext = payload();
    let app = fx.app();

    let response = app
        .oneshot(sealed_request(ROUTE, "auth", &auth_shared, &plaintext))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let envelope: SealedEnvelope = serde_json::from_value(body_json(response).await).unwrap();
    let opened: Value = open_payload(&auth_shared, &envelope).unwrap();
    assert_eq!(opened["authToken"], "jwt-for-user@example.com");
    assert_eq!(opened["passwordLength"], 7);
    assert_eq!(opened["sender"], "auth");
    assert_eq!(opened["requestId"], plaintext["requestId"]);
    assert!(opened["ts"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn any_registered_peer_may_call_without_an_allow_list() {
    let fx = Fixture::new();
    let contacts_shared = fx.contacts_shared.clone();
    let plaintext = payload();
    let response = fx
        .app()
        .oneshot(sealed_request(
            "/context",
            "contacts",
            &contacts_shared,
            &plaintext,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let envelope: SealedEnvelope = serde_json::from_value(body_json(response).await).unwrap();
    let opened: Value = open_payload(&contacts_shared, &envelope).unwrap();
    assert_eq!(opened["payload"]["email"], "user@example.com");
}

#[tokio::test]
async fn an_allow_list_turns_other_peers_away_with_403() {
    let fx = Fixture::new();
    let contacts_shared = fx.contacts_shared.clone();
    let auth_shared = fx.auth_shared.clone();
    let receiver = DhReceiver::new(
        fx.edge_sk.clone(),
        fx.keys.clone(),
        Arc::new(InMemoryReplayStore::new()),
    )
    .allow(["auth"]);
    let app = Fixture::app_with(receiver);

    expect_rejection(
        app.clone(),
        sealed_request(ROUTE, "contacts", &contacts_shared, &payload()),
        StatusCode::FORBIDDEN,
        "contacts may not call this route",
    )
    .await;

    let ok = app
        .oneshot(sealed_request(ROUTE, "auth", &auth_shared, &payload()))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn rejects_a_missing_or_unknown_sender() {
    let fx = Fixture::new();
    let app = fx.app();
    expect_rejection(
        app.clone(),
        raw_request(ROUTE, None, r#"{"sealed":"abcd"}"#),
        StatusCode::UNAUTHORIZED,
        "Unknown service",
    )
    .await;
    expect_rejection(
        app.clone(),
        raw_request(ROUTE, Some("mallory"), r#"{"sealed":"abcd"}"#),
        StatusCode::UNAUTHORIZED,
        "Unknown service",
    )
    .await;
    expect_rejection(
        app,
        raw_request(ROUTE, Some("  "), r#"{"sealed":"abcd"}"#),
        StatusCode::UNAUTHORIZED,
        "Unknown service",
    )
    .await;
}

#[tokio::test]
async fn rejects_bodies_that_are_not_an_envelope() {
    let fx = Fixture::new();
    let app = fx.app();
    for body in [
        "not json",
        r#"{"email":"x"}"#,
        r#"{"sealed":""}"#,
        r#"{"sealed":"zz"}"#,
    ] {
        expect_rejection(
            app.clone(),
            raw_request(ROUTE, Some("auth"), body),
            StatusCode::BAD_REQUEST,
            "Body must be { sealed: <hex> }",
        )
        .await;
    }
}

#[tokio::test]
async fn rejects_an_envelope_under_another_key() {
    let fx = Fixture::new();
    // contacts' key, but claiming to be auth
    let contacts_shared = fx.contacts_shared.clone();
    expect_rejection(
        fx.app(),
        sealed_request(ROUTE, "auth", &contacts_shared, &payload()),
        StatusCode::UNAUTHORIZED,
        "Sealed message could not be opened",
    )
    .await;
}

#[tokio::test]
async fn rejects_plaintext_that_is_not_an_object_or_lacks_ts() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    let app = fx.app();
    expect_rejection(
        app.clone(),
        sealed_request(ROUTE, "auth", &auth_shared, &json!([1])),
        StatusCode::UNAUTHORIZED,
        "Sealed payload is not an object",
    )
    .await;
    expect_rejection(
        app.clone(),
        sealed_request(
            ROUTE,
            "auth",
            &auth_shared,
            &json!({ "requestId": new_request_id() }),
        ),
        StatusCode::UNAUTHORIZED,
        "Sealed payload is missing ts",
    )
    .await;
    expect_rejection(
        app,
        sealed_request(
            ROUTE,
            "auth",
            &auth_shared,
            &json!({ "ts": "soon", "requestId": new_request_id() }),
        ),
        StatusCode::UNAUTHORIZED,
        "Sealed payload is missing ts",
    )
    .await;
}

#[tokio::test]
async fn rejects_stale_and_future_timestamps() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    let app = fx.app();
    for ts in [now_millis() - 61_000, now_millis() + 61_000] {
        let mut plaintext = payload();
        plaintext["ts"] = json!(ts);
        expect_rejection(
            app.clone(),
            sealed_request(ROUTE, "auth", &auth_shared, &plaintext),
            StatusCode::UNAUTHORIZED,
            "Sealed payload is stale",
        )
        .await;
    }
}

#[tokio::test]
async fn rejects_invalid_request_ids() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    let app = fx.app();
    for id in [
        json!("short"),
        json!(42),
        json!(null),
        json!("6c1e9f0e2b8a4d3f9a7e1f2b3c4d5e6g"),
    ] {
        let mut plaintext = payload();
        plaintext["requestId"] = id;
        expect_rejection(
            app.clone(),
            sealed_request(ROUTE, "auth", &auth_shared, &plaintext),
            StatusCode::UNAUTHORIZED,
            "Sealed payload has an invalid requestId",
        )
        .await;
    }
}

#[tokio::test]
async fn rejects_a_replayed_request_id() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    let app = fx.app();
    let plaintext = payload();

    let first = app
        .clone()
        .oneshot(sealed_request(ROUTE, "auth", &auth_shared, &plaintext))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // A fresh envelope (new nonce) with the same requestId is still a replay.
    expect_rejection(
        app,
        sealed_request(ROUTE, "auth", &auth_shared, &plaintext),
        StatusCode::UNAUTHORIZED,
        "Sealed payload was already used",
    )
    .await;
}

#[tokio::test]
async fn answers_503_when_the_replay_store_is_down() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    let receiver = DhReceiver::new(fx.edge_sk.clone(), fx.keys.clone(), Arc::new(FailingReplay));
    expect_rejection(
        Fixture::app_with(receiver),
        sealed_request(ROUTE, "auth", &auth_shared, &payload()),
        StatusCode::SERVICE_UNAVAILABLE,
        "Replay store is not available",
    )
    .await;
}

#[tokio::test]
async fn answers_503_when_the_shared_key_cannot_be_derived() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    // No private key configured on this side.
    let receiver = DhReceiver::new(" ", fx.keys.clone(), Arc::new(InMemoryReplayStore::new()));
    expect_rejection(
        Fixture::app_with(receiver),
        sealed_request(ROUTE, "auth", &auth_shared, &payload()),
        StatusCode::SERVICE_UNAVAILABLE,
        "Key authorization service is not available",
    )
    .await;
}

#[tokio::test]
async fn payload_extractor_answers_422_when_the_plaintext_does_not_fit() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    let mut plaintext = payload();
    plaintext.as_object_mut().unwrap().remove("password");
    let response = fx
        .app()
        .oneshot(sealed_request(ROUTE, "auth", &auth_shared, &plaintext))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(response).await;
    assert!(body["message"].as_str().unwrap().contains("password"));
}

#[tokio::test]
async fn context_without_the_middleware_is_a_server_error() {
    let fx = Fixture::new();
    expect_rejection(
        fx.app(),
        raw_request("/unguarded", Some("auth"), "{}"),
        StatusCode::INTERNAL_SERVER_ERROR,
        "DhContext requires the dh_auth middleware on this route",
    )
    .await;
}

#[tokio::test]
async fn seal_response_refuses_a_non_object_body() {
    let fx = Fixture::new();
    let auth_shared = fx.auth_shared.clone();
    expect_rejection(
        fx.app(),
        sealed_request("/bad-body", "auth", &auth_shared, &payload()),
        StatusCode::INTERNAL_SERVER_ERROR,
        "sealed response body must be a JSON object",
    )
    .await;
}

#[tokio::test]
async fn debug_output_hides_keys() {
    let fx = Fixture::new();
    let debug = format!("{:?}", fx.receiver);
    assert!(debug.contains("DhReceiver"));
    assert!(!debug.contains(&fx.edge_sk));
}
