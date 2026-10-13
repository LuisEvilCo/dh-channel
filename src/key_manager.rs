//! Peer registry plus an in-memory cache of peer public keys and derived
//! shared keys.
//!
//! Keys are fetched lazily on the first request from (or to) a peer and held
//! in RAM with no expiry, cleared on process restart. Only replay ids need a
//! shared store (see [`crate::replay`]).

use crate::crypto::compute_shared_secret;
use crate::keys::PublicKeys;
use sodiumoxide::crypto::box_::PrecomputedKey;
use std::collections::HashMap;
use std::future::Future;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use tokio::sync::Mutex;

/// A service this one accepts sealed requests from and can send them to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The id the peer sends in `X-Service-Id`, and the id it expects when
    /// this service calls it: `foo`, `bar`, `baz`.
    pub id: String,
    /// Full URL of the peer's public key endpoint.
    pub keys_url: String,
}

impl Peer {
    /// Registers a peer by base URL. A missing scheme means `https`, trailing
    /// slashes are dropped and `/keys` is appended.
    pub fn new(id: impl Into<String>, base_url: impl AsRef<str>) -> Peer {
        Peer::with_keys_path(id, base_url, "/keys")
    }

    /// Like [`Peer::new`] with a custom keys path.
    pub fn with_keys_path(
        id: impl Into<String>,
        base_url: impl AsRef<str>,
        keys_path: &str,
    ) -> Peer {
        let base = base_url.as_ref().trim();
        let with_scheme = if has_scheme(base) {
            base.to_string()
        } else {
            format!("https://{base}")
        };
        let path = if keys_path.starts_with('/') {
            keys_path.to_string()
        } else {
            format!("/{keys_path}")
        };
        Peer {
            id: id.into(),
            keys_url: format!("{}{}", with_scheme.trim_end_matches('/'), path),
        }
    }

    /// Registers a peer by the full URL of its keys endpoint.
    pub fn with_keys_url(id: impl Into<String>, keys_url: impl Into<String>) -> Peer {
        Peer {
            id: id.into(),
            keys_url: keys_url.into(),
        }
    }
}

fn has_scheme(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    !rest.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// The future a [`KeyFetcher`] returns.
pub type FetchFuture = Pin<Box<dyn Future<Output = Result<PublicKeys, Error>> + Send>>;

/// Fetches a peer's public key. The default is an HTTP GET of
/// [`Peer::keys_url`] (feature `client`); tests inject their own.
pub trait KeyFetcher: Send + Sync {
    /// Fetches the peer's `/keys` document.
    fn fetch(&self, peer: &Peer) -> FetchFuture;
}

impl<F> KeyFetcher for F
where
    F: Fn(&Peer) -> FetchFuture + Send + Sync,
{
    fn fetch(&self, peer: &Peer) -> FetchFuture {
        self(peer)
    }
}

/// Fetches `/keys` over HTTP with reqwest. Peers answer either
/// `{ status, data: { ed25519 } }` or bare `{ ed25519 }`.
#[cfg(feature = "client")]
#[derive(Clone, Default)]
pub struct HttpKeyFetcher {
    client: reqwest::Client,
}

#[cfg(feature = "client")]
impl HttpKeyFetcher {
    /// Uses the given reqwest client (timeouts, proxies and so on come with it).
    pub fn new(client: reqwest::Client) -> Self {
        HttpKeyFetcher { client }
    }
}

#[cfg(feature = "client")]
impl KeyFetcher for HttpKeyFetcher {
    fn fetch(&self, peer: &Peer) -> FetchFuture {
        let client = self.client.clone();
        let url = peer.keys_url.clone();
        let id = peer.id.clone();
        Box::pin(async move {
            let response = client
                .get(&url)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| Error::other(format!("could not fetch {id} public key: {e}")))?;
            let status = response.status();
            if !status.is_success() {
                return Err(Error::other(format!(
                    "{id} keys endpoint responded {}",
                    status.as_u16()
                )));
            }
            let value: serde_json::Value = response.json().await.map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("{id} keys response is not JSON: {e}"),
                )
            })?;
            PublicKeys::from_response(value)
        })
    }
}

/// Peer registry and key cache.
pub struct KeyManager {
    peers: HashMap<String, Peer>,
    keys_cache: Mutex<HashMap<String, PublicKeys>>,
    secrets_cache: Mutex<HashMap<String, PrecomputedKey>>,
    fetcher: Box<dyn KeyFetcher>,
}

impl std::fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyManager")
            .field("peers", &self.peers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl KeyManager {
    /// A manager that fetches keys over HTTP.
    #[cfg(feature = "client")]
    pub fn new(peers: Vec<Peer>) -> Self {
        Self::with_fetcher(peers, Box::new(HttpKeyFetcher::default()))
    }

    /// A manager with a custom fetcher (tests, or a non-HTTP transport).
    pub fn with_fetcher(peers: Vec<Peer>, fetcher: Box<dyn KeyFetcher>) -> Self {
        let peers = peers
            .into_iter()
            .map(|p| (p.id.clone(), p))
            .collect::<HashMap<_, _>>();
        KeyManager {
            peers,
            keys_cache: Mutex::new(HashMap::new()),
            secrets_cache: Mutex::new(HashMap::new()),
            fetcher,
        }
    }

    /// Registered peer ids, in no particular order.
    pub fn peer_ids(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }

    /// Whether `peer_id` is registered.
    pub fn is_known_peer(&self, peer_id: &str) -> bool {
        self.peers.contains_key(peer_id)
    }

    /// The registered peer, if any.
    pub fn peer(&self, peer_id: &str) -> Option<&Peer> {
        self.peers.get(peer_id)
    }

    /// Drops the cached public key and shared key for a peer so the next
    /// request refetches them.
    pub async fn evict(&self, peer_id: &str) {
        self.keys_cache.lock().await.remove(peer_id);
        self.secrets_cache.lock().await.remove(peer_id);
    }

    /// The peer's public key, fetched on first use and cached.
    ///
    /// Fails with [`ErrorKind::NotFound`] for an unregistered peer, otherwise
    /// with the fetcher's error.
    pub async fn get_key(&self, peer_id: &str) -> Result<PublicKeys, Error> {
        if let Some(value) = self.keys_cache.lock().await.get(peer_id) {
            return Ok(value.clone());
        }

        let peer = self
            .peers
            .get(peer_id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("unknown peer {peer_id}")))?;

        let keys = self.fetcher.fetch(peer).await?;
        self.keys_cache
            .lock()
            .await
            .insert(peer_id.to_string(), keys.clone());
        Ok(keys)
    }

    /// The shared key with `peer_id`, derived on first use and cached.
    ///
    /// Fails with [`ErrorKind::NotFound`] for an unregistered peer,
    /// [`ErrorKind::InvalidData`] when this service's private key is empty or
    /// either key is malformed, otherwise with the fetcher's error.
    pub async fn get_shared_secret(
        &self,
        peer_id: &str,
        own_private_key_hex: &str,
    ) -> Result<PrecomputedKey, Error> {
        if let Some(secret) = self.secrets_cache.lock().await.get(peer_id) {
            return Ok(secret.clone());
        }

        if !self.peers.contains_key(peer_id) {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("unknown peer {peer_id}"),
            ));
        }

        if own_private_key_hex.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ed25519 private key is not configured",
            ));
        }

        let keys = self.get_key(peer_id).await?;
        let shared = compute_shared_secret(own_private_key_hex, &keys.ed25519.public_key)?;

        self.secrets_cache
            .lock()
            .await
            .insert(peer_id.to_string(), shared.clone());
        Ok(shared)
    }
}
