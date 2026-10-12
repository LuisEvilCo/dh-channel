//! Receiving sealed requests with axum.
//!
//! [`dh_auth`] is a middleware for `axum::middleware::from_fn_with_state`. On
//! a route it guards:
//!
//! 1. `X-Service-Id` names the sender; it only selects which shared key to try.
//! 2. The body must be `{ "sealed": "<hex>" }`.
//! 3. The envelope must open under the key derived from the sender's public
//!    key and this service's private key. That is the authentication.
//! 4. `ts` must be within 60 s of this clock.
//! 5. `requestId` must not have been seen before (replay store).
//! 6. If the receiver carries an allow list, the sender must be on it.
//!
//! On success a [`DhContext`] is attached to the request so handlers can take
//! [`DhPayload`] or [`DhSender`] as extractors and answer with
//! [`seal_response`]. Rejections are plain JSON `{ statusCode, message }`
//! bodies, as the NestJS guard produces.
//!
//! ```ignore
//! let receiver = Arc::new(DhReceiver::new(private_key_hex, keys, replay).allow(["auth"]));
//! let app = Router::new().route(
//!     "/v2/internal/login-token",
//!     post(login_token).route_layer(middleware::from_fn_with_state(receiver, dh_auth)),
//! );
//!
//! async fn login_token(ctx: DhContext, DhPayload(body): DhPayload<LoginRequest>) -> Response {
//!     // ...
//!     seal_response(&ctx, &json!({ "authToken": token }))
//! }
//! ```

use crate::envelope::{
    SERVICE_ID_HEADER, SealedEnvelope, is_fresh, is_valid_request_id, now_millis, open_payload,
    seal_payload,
};
use crate::key_manager::KeyManager;
use crate::replay::ReplayStore;
use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sodiumoxide::crypto::box_::PrecomputedKey;
use std::collections::HashSet;
use std::io::ErrorKind;
use std::sync::Arc;

/// Largest sealed body accepted, in bytes. Sealed payloads are small JSON.
pub const MAX_SEALED_BODY_BYTES: usize = 1024 * 1024;

/// What the receiver needs: this service's private key, the peer registry
/// and the replay store, plus an optional allow list of sender ids.
pub struct DhReceiver {
    own_private_key_hex: String,
    keys: Arc<KeyManager>,
    replay: Arc<dyn ReplayStore>,
    allow: Option<HashSet<String>>,
}

impl std::fmt::Debug for DhReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhReceiver")
            .field("keys", &self.keys)
            .field("allow", &self.allow)
            .finish_non_exhaustive()
    }
}

impl DhReceiver {
    /// A receiver that accepts any registered peer.
    pub fn new(
        own_private_key_hex: impl Into<String>,
        keys: Arc<KeyManager>,
        replay: Arc<dyn ReplayStore>,
    ) -> Self {
        DhReceiver {
            own_private_key_hex: own_private_key_hex.into(),
            keys,
            replay,
            allow: None,
        }
    }

    /// Restricts the guarded routes to the listed sender ids. Without it any
    /// registered peer that can open the channel may call them.
    pub fn allow<I, S>(mut self, senders: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow = Some(senders.into_iter().map(Into::into).collect());
        self
    }
}

/// What [`dh_auth`] attaches to an accepted request.
#[derive(Clone)]
pub struct DhContext {
    /// The sender's id, from `X-Service-Id`.
    pub service_id: String,
    /// The request's `requestId`, echoed by [`seal_response`].
    pub request_id: String,
    /// The shared key the envelope opened under.
    pub shared_key: PrecomputedKey,
    /// The opened plaintext, a JSON object including `ts` and `requestId`.
    pub payload: Value,
}

impl std::fmt::Debug for DhContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhContext")
            .field("service_id", &self.service_id)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

fn reject(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({ "statusCode": status.as_u16(), "message": message })),
    )
        .into_response()
}

/// The middleware. Use with `axum::middleware::from_fn_with_state(Arc<DhReceiver>, dh_auth)`.
pub async fn dh_auth(
    State(receiver): State<Arc<DhReceiver>>,
    request: Request,
    next: Next,
) -> Response {
    let route = format!("{} {}", request.method(), request.uri().path());

    let service_id = request
        .headers()
        .get(SERVICE_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let Some(service_id) = service_id.filter(|id| receiver.keys.is_known_peer(id)) else {
        tracing::warn!(route, "rejected sealed request: unknown X-Service-Id");
        return reject(StatusCode::UNAUTHORIZED, "Unknown service");
    };

    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, MAX_SEALED_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return reject(StatusCode::BAD_REQUEST, "Body must be { sealed: <hex> }"),
    };
    let envelope: SealedEnvelope = match serde_json::from_slice(&bytes) {
        Ok(envelope) => envelope,
        Err(_) => return reject(StatusCode::BAD_REQUEST, "Body must be { sealed: <hex> }"),
    };
    if envelope.sealed.is_empty() || !envelope.sealed.chars().all(|c| c.is_ascii_hexdigit()) {
        return reject(StatusCode::BAD_REQUEST, "Body must be { sealed: <hex> }");
    }

    let shared_key = match receiver
        .keys
        .get_shared_secret(&service_id, &receiver.own_private_key_hex)
        .await
    {
        Ok(key) => key,
        Err(err) => {
            tracing::error!(route, sender = %service_id, error = %err, "cannot derive shared key");
            return reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "Key authorization service is not available",
            );
        }
    };

    let payload: Value = match open_payload(&shared_key, &envelope) {
        Ok(value) => value,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            tracing::warn!(route, sender = %service_id, "rejected sealed request: envelope did not open");
            return reject(
                StatusCode::UNAUTHORIZED,
                "Sealed message could not be opened",
            );
        }
        Err(err) => {
            tracing::warn!(route, sender = %service_id, error = %err, "rejected sealed request: bad plaintext");
            return reject(
                StatusCode::UNAUTHORIZED,
                "Sealed message could not be opened",
            );
        }
    };

    let Some(object) = payload.as_object() else {
        return reject(StatusCode::UNAUTHORIZED, "Sealed payload is not an object");
    };

    let Some(ts) = object.get("ts").and_then(Value::as_i64) else {
        return reject(StatusCode::UNAUTHORIZED, "Sealed payload is missing ts");
    };
    let now = now_millis();
    if !is_fresh(ts, now) {
        tracing::warn!(route, sender = %service_id, skew_ms = (now - ts).abs(), "rejected stale sealed request");
        return reject(StatusCode::UNAUTHORIZED, "Sealed payload is stale");
    }

    let request_id = match object.get("requestId").and_then(Value::as_str) {
        Some(id) if is_valid_request_id(id) => id.to_string(),
        _ => {
            return reject(
                StatusCode::UNAUTHORIZED,
                "Sealed payload has an invalid requestId",
            );
        }
    };

    if let Some(allow) = &receiver.allow {
        if !allow.contains(&service_id) {
            tracing::warn!(route, sender = %service_id, "rejected sealed request: sender not allowed");
            return reject(
                StatusCode::FORBIDDEN,
                &format!("{service_id} may not call this route"),
            );
        }
    }

    match receiver.replay.claim(&service_id, &request_id).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(route, sender = %service_id, request_id, "rejected replayed sealed request");
            return reject(StatusCode::UNAUTHORIZED, "Sealed payload was already used");
        }
        Err(err) => {
            tracing::error!(route, error = %err, "replay store unavailable");
            return reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "Replay store is not available",
            );
        }
    }

    let mut parts = parts;
    parts.extensions.insert(DhContext {
        service_id,
        request_id,
        shared_key,
        payload,
    });

    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

impl<S: Send + Sync> FromRequestParts<S> for DhContext {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<DhContext>().cloned().ok_or_else(|| {
            reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DhContext requires the dh_auth middleware on this route",
            )
        })
    }
}

/// Extracts the opened payload of a sealed request as `T`. Answers 422 when
/// the plaintext does not fit `T`, the way a validation pipe would.
pub struct DhPayload<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for DhPayload<T> {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ctx = DhContext::from_request_parts(parts, state).await?;
        serde_json::from_value(ctx.payload)
            .map(DhPayload)
            .map_err(|e| reject(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()))
    }
}

/// Extracts the sender id of a sealed request.
pub struct DhSender(pub String);

impl<S: Send + Sync> FromRequestParts<S> for DhSender {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        DhContext::from_request_parts(parts, state)
            .await
            .map(|ctx| DhSender(ctx.service_id))
    }
}

/// Seals a handler's reply with the request's shared key. The plaintext is
/// `body` plus `ts` and the echoed `requestId`, so the sender can bind the
/// response to its request. `body` must serialize to a JSON object.
pub fn seal_response<T: Serialize>(ctx: &DhContext, body: &T) -> Response {
    let mut value = match serde_json::to_value(body) {
        Ok(Value::Object(map)) => map,
        Ok(_) => {
            return reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sealed response body must be a JSON object",
            );
        }
        Err(e) => return reject(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    value.insert("ts".into(), json!(now_millis()));
    value.insert("requestId".into(), json!(ctx.request_id));

    match seal_payload(&ctx.shared_key, &Value::Object(value)) {
        Ok(envelope) => Json(envelope).into_response(),
        Err(e) => reject(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}
