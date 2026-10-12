//! Peer registry, lazy key fetch, caching and the HTTP fetcher.

use dh_channel::crypto::{compute_shared_secret, generate_keypair_hex};
use dh_channel::key_manager::{FetchFuture, HttpKeyFetcher, KeyFetcher, KeyManager, Peer};
use dh_channel::keys::PublicKeys;
use serde_json::json;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A fetcher that answers with a fixed key and counts calls.
struct CountingFetcher {
    public_key_hex: String,
    calls: Arc<AtomicUsize>,
}

impl KeyFetcher for CountingFetcher {
    fn fetch(&self, _peer: &Peer) -> FetchFuture {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let pk = self.public_key_hex.clone();
        Box::pin(async move { Ok(PublicKeys::new(pk)) })
    }
}

fn failing_fetcher(message: &'static str) -> Box<dyn KeyFetcher> {
    Box::new(move |_peer: &Peer| -> FetchFuture {
        Box::pin(async move { Err(Error::new(ErrorKind::ConnectionRefused, message)) })
    })
}

fn peers() -> Vec<Peer> {
    vec![
        Peer::new("auth", "auth.internal:20060"),
        Peer::new("contacts", "https://contacts.internal/"),
        Peer::new("sync", "http://sync.internal"),
    ]
}

mod peer_tests {
    use super::*;

    #[test]
    fn normalises_the_keys_url() {
        assert_eq!(
            Peer::new("auth", "auth.internal:20060").keys_url,
            "https://auth.internal:20060/keys"
        );
        assert_eq!(
            Peer::new("contacts", "https://contacts.internal/").keys_url,
            "https://contacts.internal/keys"
        );
        assert_eq!(
            Peer::new("sync", "http://sync.internal").keys_url,
            "http://sync.internal/keys"
        );
        assert_eq!(
            Peer::new("edge", " edge.internal ").keys_url,
            "https://edge.internal/keys"
        );
    }

    #[test]
    fn custom_keys_path_and_full_url() {
        assert_eq!(
            Peer::with_keys_path("a", "a.internal", "public-keys").keys_url,
            "https://a.internal/public-keys"
        );
        assert_eq!(
            Peer::with_keys_path("a", "a.internal", "/public-keys").keys_url,
            "https://a.internal/public-keys"
        );
        let peer = Peer::with_keys_url("a", "http://localhost:1234/x/keys");
        assert_eq!(peer.id, "a");
        assert_eq!(peer.keys_url, "http://localhost:1234/x/keys");
    }

    #[test]
    fn a_host_with_a_colon_port_is_not_a_scheme() {
        assert_eq!(
            Peer::new("a", "localhost:3000").keys_url,
            "https://localhost:3000/keys"
        );
    }
}

mod registry_tests {
    use super::*;

    #[test]
    fn registers_peers_from_the_list() {
        let manager = KeyManager::with_fetcher(peers(), failing_fetcher("unused"));
        let mut ids = manager.peer_ids();
        ids.sort();
        assert_eq!(ids, ["auth", "contacts", "sync"]);
        assert!(manager.is_known_peer("auth"));
        assert!(!manager.is_known_peer("edge"));
        assert!(!manager.is_known_peer(""));
        assert_eq!(
            manager.peer("auth").unwrap().keys_url,
            "https://auth.internal:20060/keys"
        );
        assert!(manager.peer("nobody").is_none());
        assert!(format!("{manager:?}").contains("auth"));
    }

    #[test]
    fn later_peers_with_the_same_id_win() {
        let manager = KeyManager::with_fetcher(
            vec![
                Peer::new("auth", "old.internal"),
                Peer::new("auth", "new.internal"),
            ],
            failing_fetcher("unused"),
        );
        assert_eq!(manager.peer_ids(), ["auth"]);
        assert_eq!(
            manager.peer("auth").unwrap().keys_url,
            "https://new.internal/keys"
        );
    }
}

mod get_key_tests {
    use super::*;

    fn manager_with(pk: &str) -> (KeyManager, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = CountingFetcher {
            public_key_hex: pk.to_string(),
            calls: calls.clone(),
        };
        (KeyManager::with_fetcher(peers(), Box::new(fetcher)), calls)
    }

    #[tokio::test]
    async fn fetches_once_and_caches() {
        let (manager, calls) = manager_with("abcd");
        let first = manager.get_key("auth").await.unwrap();
        let second = manager.get_key("auth").await.unwrap();
        assert_eq!(first, PublicKeys::new("abcd"));
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn caches_per_peer() {
        let (manager, calls) = manager_with("abcd");
        manager.get_key("auth").await.unwrap();
        manager.get_key("sync").await.unwrap();
        manager.get_key("auth").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn evict_refetches() {
        let (manager, calls) = manager_with("abcd");
        manager.get_key("auth").await.unwrap();
        manager.evict("auth").await;
        manager.get_key("auth").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unknown_peer_is_not_found_without_fetching() {
        let (manager, calls) = manager_with("abcd");
        let err = manager.get_key("mallory").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(err.to_string().contains("mallory"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fetcher_errors_pass_through() {
        let manager = KeyManager::with_fetcher(peers(), failing_fetcher("ECONNREFUSED"));
        let err = manager.get_key("auth").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
        assert_eq!(err.to_string(), "ECONNREFUSED");
    }
}

mod get_shared_secret_tests {
    use super::*;

    #[tokio::test]
    async fn derives_the_key_the_peer_derives_and_caches_it() {
        let (edge_pk, edge_sk) = generate_keypair_hex();
        let (auth_pk, auth_sk) = generate_keypair_hex();
        let calls = Arc::new(AtomicUsize::new(0));
        let manager = KeyManager::with_fetcher(
            vec![Peer::new("auth", "auth.internal")],
            Box::new(CountingFetcher {
                public_key_hex: format!("{auth_pk}\n"),
                calls: calls.clone(),
            }),
        );

        let first = manager.get_shared_secret("auth", &edge_sk).await.unwrap();
        let second = manager.get_shared_secret("auth", &edge_sk).await.unwrap();
        let auth_side = compute_shared_secret(&auth_sk, &edge_pk).unwrap();

        assert_eq!(first.0, auth_side.0);
        assert_eq!(second.0, first.0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn evict_drops_the_shared_key_too() {
        let (_, edge_sk) = generate_keypair_hex();
        let (auth_pk, _) = generate_keypair_hex();
        let calls = Arc::new(AtomicUsize::new(0));
        let manager = KeyManager::with_fetcher(
            vec![Peer::new("auth", "auth.internal")],
            Box::new(CountingFetcher {
                public_key_hex: auth_pk,
                calls: calls.clone(),
            }),
        );
        let _ = manager.get_shared_secret("auth", &edge_sk).await.unwrap();
        manager.evict("auth").await;
        let _ = manager.get_shared_secret("auth", &edge_sk).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unknown_peer_and_missing_own_key_fail_before_fetching() {
        let calls = Arc::new(AtomicUsize::new(0));
        let manager = KeyManager::with_fetcher(
            peers(),
            Box::new(CountingFetcher {
                public_key_hex: "abcd".into(),
                calls: calls.clone(),
            }),
        );
        let (_, sk) = generate_keypair_hex();

        let err = manager.get_shared_secret("mallory", &sk).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);

        let err = manager.get_shared_secret("auth", "  ").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("private key"));

        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn malformed_keys_fail_as_invalid_data() {
        let (_, sk) = generate_keypair_hex();
        let manager = KeyManager::with_fetcher(
            peers(),
            Box::new(CountingFetcher {
                public_key_hex: "not-hex".into(),
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        );
        let err = manager.get_shared_secret("auth", &sk).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);

        let (auth_pk, _) = generate_keypair_hex();
        let manager = KeyManager::with_fetcher(
            peers(),
            Box::new(CountingFetcher {
                public_key_hex: auth_pk,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        );
        let err = manager.get_shared_secret("auth", "test").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn fetch_errors_pass_through() {
        let (_, sk) = generate_keypair_hex();
        let manager = KeyManager::with_fetcher(peers(), failing_fetcher("down"));
        let err = manager.get_shared_secret("auth", &sk).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    }
}

mod http_fetcher_tests {
    use super::*;

    async fn server_answering(status: u16, body: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .and(header("Accept", "application/json"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn reads_an_enveloped_response() {
        let server = server_answering(
            200,
            json!({ "status": "success", "data": { "ed25519": { "publicKey": "abcd\n" } } }),
        )
        .await;
        let manager = KeyManager::new(vec![Peer::new("auth", server.uri())]);
        assert_eq!(
            manager.get_key("auth").await.unwrap(),
            PublicKeys::new("abcd\n")
        );
    }

    #[tokio::test]
    async fn reads_a_bare_response() {
        let server = server_answering(200, json!({ "ed25519": { "publicKey": "abcd" } })).await;
        let fetcher = HttpKeyFetcher::new(reqwest::Client::new());
        let keys = fetcher
            .fetch(&Peer::new("auth", server.uri()))
            .await
            .unwrap();
        assert_eq!(keys, PublicKeys::new("abcd"));
    }

    #[tokio::test]
    async fn non_success_status_is_an_error() {
        let server = server_answering(503, json!({ "status": "error", "data": "nope" })).await;
        let manager = KeyManager::new(vec![Peer::new("auth", server.uri())]);
        let err = manager.get_key("auth").await.unwrap_err();
        assert!(err.to_string().contains("503"), "{err}");
    }

    #[tokio::test]
    async fn missing_key_in_the_body_is_invalid_data() {
        let server = server_answering(200, json!({ "status": "success", "data": {} })).await;
        let manager = KeyManager::new(vec![Peer::new("auth", server.uri())]);
        let err = manager.get_key("auth").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn non_json_body_is_invalid_data() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
            .mount(&server)
            .await;
        let manager = KeyManager::new(vec![Peer::new("auth", server.uri())]);
        let err = manager.get_key("auth").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn unreachable_peer_is_an_error() {
        let manager = KeyManager::new(vec![Peer::new("auth", "http://127.0.0.1:1")]);
        let err = manager.get_key("auth").await.unwrap_err();
        assert!(err.to_string().contains("auth"), "{err}");
    }
}
