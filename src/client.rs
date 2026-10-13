//! Sending sealed requests.
//!
//! [`DhClient`] resolves the shared key for a peer through the
//! [`KeyManager`], seals the request, POSTs `{ "sealed": "<hex>" }` with
//! `X-Service-Id: <own id>`, opens the sealed response and checks that it
//! echoes the request's `requestId`. [`post_sealed`] is the lower-level
//! function for callers that already hold the shared key.

use crate::envelope::{
    SERVICE_ID_HEADER, SealedEnvelope, SealedPayload, open_payload, seal_payload,
};
use crate::key_manager::KeyManager;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sodiumoxide::crypto::box_::PrecomputedKey;
use std::io::{Error, ErrorKind};
use std::sync::Arc;

fn headers(own_id: &str) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        SERVICE_ID_HEADER,
        HeaderValue::from_str(own_id).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "own service id is not a valid header value",
            )
        })?,
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    Ok(headers)
}

/// Maps a non-success upstream status to an `io::Error` kind so callers can
/// turn it into the right HTTP status without parsing strings:
/// `PermissionDenied` for 401 and 403, `NotFound` for 404, `InvalidInput`
/// for 400 and 422, `Other` for everything else.
fn status_to_error(peer: &str, status: StatusCode, body: &str) -> Error {
    let kind = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ErrorKind::PermissionDenied,
        StatusCode::NOT_FOUND => ErrorKind::NotFound,
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => ErrorKind::InvalidInput,
        _ => ErrorKind::Other,
    };
    // Upstream error bodies are unsealed framework exceptions; keep them short.
    let snippet: String = body.chars().take(200).collect();
    Error::new(
        kind,
        format!("{peer} responded {}: {snippet}", status.as_u16()),
    )
}

/// POSTs a sealed request and opens the sealed response.
///
/// # Arguments
///
/// * `client` - The reqwest client to send with.
/// * `url` - Full URL of the receiver's endpoint.
/// * `own_id` - This service's id, sent as `X-Service-Id`.
/// * `shared_key` - Shared key for that receiver.
/// * `request` - Payload to seal. Must carry a `requestId`.
///
/// # Returns
///
/// The opened response payload. Fails with `PermissionDenied` when the
/// receiver rejected the request (401 / 403) or when the response would not
/// open, `InvalidData` when the response was malformed or its `requestId`
/// did not match the request, `NotFound` and `InvalidInput` for 404 and
/// 400 / 422, and `Other` for transport failures and other statuses.
pub async fn post_sealed<Req, Resp>(
    client: &reqwest::Client,
    url: &str,
    own_id: &str,
    shared_key: &PrecomputedKey,
    request: &Req,
) -> Result<Resp, Error>
where
    Req: Serialize + SealedPayload,
    Resp: DeserializeOwned + SealedPayload,
{
    let envelope = seal_payload(shared_key, request)?;
    let peer_label = url;

    let response = client
        .post(url)
        .headers(headers(own_id)?)
        .json(&envelope)
        .send()
        .await
        .map_err(|e| Error::other(format!("sealed request to {url} failed: {e}")))?;

    let status = response.status();
    let body = response.text().await.map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("could not read upstream body: {e}"),
        )
    })?;

    if !status.is_success() {
        return Err(status_to_error(peer_label, status, &body));
    }

    let response_envelope: SealedEnvelope = serde_json::from_str(&body).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("upstream response is not a sealed envelope: {e}"),
        )
    })?;

    let opened: Resp = open_payload(shared_key, &response_envelope)?;

    if opened.request_id() != request.request_id() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "upstream response requestId does not match the request",
        ));
    }

    Ok(opened)
}

/// Sends sealed requests to registered peers.
#[derive(Clone)]
pub struct DhClient {
    own_id: String,
    own_private_key_hex: String,
    keys: Arc<KeyManager>,
    http: reqwest::Client,
}

impl std::fmt::Debug for DhClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhClient")
            .field("own_id", &self.own_id)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl DhClient {
    /// A client that identifies as `own_id` and seals with `own_private_key_hex`.
    pub fn new(
        own_id: impl Into<String>,
        own_private_key_hex: impl Into<String>,
        keys: Arc<KeyManager>,
    ) -> Self {
        Self::with_http(own_id, own_private_key_hex, keys, reqwest::Client::new())
    }

    /// Like [`DhClient::new`] with a configured reqwest client.
    pub fn with_http(
        own_id: impl Into<String>,
        own_private_key_hex: impl Into<String>,
        keys: Arc<KeyManager>,
        http: reqwest::Client,
    ) -> Self {
        DhClient {
            own_id: own_id.into(),
            own_private_key_hex: own_private_key_hex.into(),
            keys,
            http,
        }
    }

    /// This service's id as peers see it.
    pub fn own_id(&self) -> &str {
        &self.own_id
    }

    /// The key manager, for callers that need the shared key directly.
    pub fn keys(&self) -> &Arc<KeyManager> {
        &self.keys
    }

    /// Seals `request`, POSTs it to `url` as `peer_id`'s sealed route, opens
    /// the response and checks the echoed `requestId`.
    ///
    /// Key problems surface first: `NotFound` for an unregistered peer,
    /// `InvalidData` for a missing or malformed key, the fetcher's error when
    /// the peer's `/keys` cannot be read. After that the errors are those of
    /// [`post_sealed`].
    pub async fn post<Req, Resp>(
        &self,
        peer_id: &str,
        url: &str,
        request: &Req,
    ) -> Result<Resp, Error>
    where
        Req: Serialize + SealedPayload,
        Resp: DeserializeOwned + SealedPayload,
    {
        let shared_key = self
            .keys
            .get_shared_secret(peer_id, &self.own_private_key_hex)
            .await?;
        post_sealed(&self.http, url, &self.own_id, &shared_key, request)
            .await
            .map_err(|err| {
                tracing::warn!(peer = peer_id, url, error = %err, "sealed request failed");
                err
            })
    }
}
