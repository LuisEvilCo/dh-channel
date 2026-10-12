//! Replay protection for sealed requests.
//!
//! Every accepted request id is remembered for the freshness window so the
//! same envelope cannot be accepted twice, even if it reaches a different
//! task. With more than one process the store must be shared (Redis):
//! implement [`ReplayStore`] over your Redis client with
//! `SET <key> 1 NX EX 60`, where the key is [`replay_key`]. The crate ships
//! no Redis client of its own so it does not pin one version for every
//! consumer.

use async_trait::async_trait;
use std::collections::HashMap;
use std::io::Error;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an accepted request id is remembered, in seconds. Matches the
/// freshness window, so an id older than this is rejected as stale anyway.
pub const REPLAY_TTL_SECONDS: u64 = 60;

/// The store key for an accepted request: `dh:req:{service_id}:{request_id}`.
/// Namespaced by sender so two services cannot collide on an id.
pub fn replay_key(service_id: &str, request_id: &str) -> String {
    format!("dh:req:{service_id}:{request_id}")
}

/// Remembers accepted request ids.
#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Records the request id. Returns `Ok(true)` the first time an id is
    /// seen and `Ok(false)` if it was already claimed within the TTL. An
    /// error means the store is unavailable; the receiver answers 503.
    async fn claim(&self, service_id: &str, request_id: &str) -> Result<bool, Error>;
}

/// Process-local store. Not safe with more than one task; use it for tests
/// and single-instance deployments only.
pub struct InMemoryReplayStore {
    ttl: Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

impl Default for InMemoryReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryReplayStore {
    /// A store with the standard TTL.
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(REPLAY_TTL_SECONDS))
    }

    /// A store with a custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        InMemoryReplayStore {
            ttl,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Number of ids currently remembered (expired ones are dropped first).
    pub fn len(&self) -> usize {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        seen.retain(|_, expires| *expires > now);
        seen.len()
    }

    /// True when nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl ReplayStore for InMemoryReplayStore {
    async fn claim(&self, service_id: &str, request_id: &str) -> Result<bool, Error> {
        let key = replay_key(service_id, request_id);
        let now = Instant::now();
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, expires| *expires > now);
        if seen.contains_key(&key) {
            return Ok(false);
        }
        seen.insert(key, now + self.ttl);
        Ok(true)
    }
}
