//! Replay protection: the key layout and the in-memory store.

use dh_channel::replay::{InMemoryReplayStore, REPLAY_TTL_SECONDS, ReplayStore, replay_key};
use std::time::Duration;

#[test]
fn keys_are_namespaced_by_sender() {
    assert_eq!(replay_key("auth", "abc"), "dh:req:auth:abc");
    assert_eq!(replay_key("contacts", "abc"), "dh:req:contacts:abc");
    assert_eq!(REPLAY_TTL_SECONDS, 60);
}

#[tokio::test]
async fn accepts_an_id_once() {
    let store = InMemoryReplayStore::new();
    assert!(store.claim("auth", "r1").await.unwrap());
    assert!(!store.claim("auth", "r1").await.unwrap());
    assert_eq!(store.len(), 1);
}

#[tokio::test]
async fn keeps_senders_apart() {
    let store = InMemoryReplayStore::default();
    assert!(store.is_empty());
    assert!(store.claim("auth", "r1").await.unwrap());
    assert!(store.claim("contacts", "r1").await.unwrap());
    assert_eq!(store.len(), 2);
}

#[tokio::test]
async fn forgets_ids_after_the_ttl() {
    let store = InMemoryReplayStore::with_ttl(Duration::from_millis(50));
    assert!(store.claim("auth", "r1").await.unwrap());
    assert!(!store.claim("auth", "r1").await.unwrap());

    tokio::time::sleep(Duration::from_millis(80)).await;

    assert!(store.is_empty());
    assert!(store.claim("auth", "r1").await.unwrap());
    assert_eq!(store.len(), 1);
}

#[tokio::test]
async fn is_usable_behind_a_trait_object() {
    let store: std::sync::Arc<dyn ReplayStore> = std::sync::Arc::new(InMemoryReplayStore::new());
    assert!(store.claim("auth", "r1").await.unwrap());
    assert!(!store.claim("auth", "r1").await.unwrap());
}
