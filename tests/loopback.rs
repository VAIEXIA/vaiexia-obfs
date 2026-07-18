//! End-to-end loopback integration tests.
//!
//! Spins up a real Noise-XK TCP server, connects a client, and verifies:
//! - RPC request / response round-trips.
//! - Server-pushed events on subscribed topics.
//! - `Connection::state()` reports `Connected`.

use std::sync::Arc;
use tokio::time::{timeout, Duration};
use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
use vaiexia_core::error::Result;
use vaiexia_core::protocol::{Event, Method, Request, RequestId, Seq, Topic};
use vaiexia_core::server::ServiceBuilder;
use vaiexia_core::transport::{Connection, ConnectionState, Requester, Subscriber};
use vaiexia_core::version::ProtoVersion;
use vaiexia_wire::keypair::generate_keypair;
use vaiexia_obfs::{serve_obfs, AllowAll, ObfsTransport};
use futures_util::StreamExt;

// ── test verifier ─────────────────────────────────────────────────────────────

struct AllowAllVerifier;

impl Verifier for AllowAllVerifier {
    fn verify(
        &self,
        _capability: Option<&Capability>,
        _method: &Method,
    ) -> Result<Subject> {
        Ok(Subject {
            id: SubjectId::new("test-client"),
            scopes: ScopeSet::from_iter(["*"]),
        })
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

async fn start_server(
    service: Arc<vaiexia_core::server::Service>,
    server_kp: &vaiexia_wire::keypair::StaticKeypair,
) -> vaiexia_obfs::ObfsServeHandle {
    serve_obfs(
        "127.0.0.1:0",
        server_kp.private,
        service,
        Arc::new(AllowAll),
    )
    .await
    .expect("server should bind")
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn loopback_request_and_response() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let svc = Arc::new(
        ServiceBuilder::new()
            .verifier(AllowAllVerifier)
            .method(
                Method::new("echo.ping").unwrap(),
                |params, _subject| async move { Ok(params) },
            )
            .build(),
    );

    let handle = start_server(Arc::clone(&svc), &server_kp).await;

    let client = ObfsTransport::connect(
        handle.local_addr(),
        client_kp.private,
        server_kp.public,
    )
    .await
    .expect("client should connect");

    // Verify connection state.
    assert_eq!(client.state(), ConnectionState::Connected);

    // Send a request and receive a response.
    let req = Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new("echo.ping").unwrap(),
        params: serde_json::json!("hello"),
        capability: None,
    };

    let resp = timeout(Duration::from_secs(5), client.request(req))
        .await
        .expect("request should not time out")
        .expect("request should succeed");

    assert!(resp.is_ok(), "outcome should be Ok");
    assert_eq!(resp.value().unwrap(), &serde_json::json!("hello"));
}

#[tokio::test]
async fn loopback_request_and_event() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let topic = Topic::new("metrics.cpu");
    let mut builder = ServiceBuilder::new().verifier(AllowAllVerifier);
    let event_tx = builder.event_source_sender(topic.clone());
    let svc = Arc::new(builder.build());

    let handle = start_server(Arc::clone(&svc), &server_kp).await;

    let client = ObfsTransport::connect(
        handle.local_addr(),
        client_kp.private,
        server_kp.public,
    )
    .await
    .expect("client should connect");

    // Subscribe before the server starts emitting.
    let mut stream = timeout(Duration::from_secs(5), client.subscribe(&topic))
        .await
        .expect("subscribe should not time out")
        .expect("subscribe should succeed");

    // Give the server time to process the Subscribe control message.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Emit two events from the server side.
    let ev1 = Event {
        topic: topic.clone(),
        seq: Seq(1),
        payload: serde_json::json!({"load": 0.42}),
    };
    let ev2 = Event {
        topic: topic.clone(),
        seq: Seq(2),
        payload: serde_json::json!({"load": 0.55}),
    };
    event_tx.send(ev1.clone()).expect("broadcast should have receiver");
    event_tx.send(ev2.clone()).expect("broadcast should have receiver");

    // Receive both events on the client stream.
    let got1 = timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("event 1 should arrive")
        .expect("stream should not end")
        .expect("event 1 should be Ok");

    let got2 = timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("event 2 should arrive")
        .expect("stream should not end")
        .expect("event 2 should be Ok");

    assert_eq!(got1.seq, ev1.seq);
    assert_eq!(got2.seq, ev2.seq);
    assert_eq!(got1.payload, ev1.payload);
    assert_eq!(got2.payload, ev2.payload);
}

#[tokio::test]
async fn connection_state_is_connected() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let svc = Arc::new(ServiceBuilder::new().verifier(AllowAllVerifier).build());
    let handle = start_server(Arc::clone(&svc), &server_kp).await;

    let client = ObfsTransport::connect(
        handle.local_addr(),
        client_kp.private,
        server_kp.public,
    )
    .await
    .expect("client should connect");

    assert_eq!(client.state(), ConnectionState::Connected);
}

#[tokio::test]
async fn wrong_server_key_connection_fails() {
    let server_kp = generate_keypair().unwrap();
    let wrong_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let svc = Arc::new(ServiceBuilder::new().verifier(AllowAllVerifier).build());
    let handle = start_server(Arc::clone(&svc), &server_kp).await;

    let result = timeout(
        Duration::from_secs(5),
        ObfsTransport::connect(
            handle.local_addr(),
            client_kp.private,
            wrong_kp.public, // wrong key
        ),
    )
    .await
    .expect("should not time out");

    assert!(
        result.is_err(),
        "connecting with wrong server key should fail"
    );
}
