//! UDP loopback integration tests.
//!
//! Each test spins up a real UDP server + client and exercises a specific path.
//! All four cases must pass (no #[ignore]).

use std::sync::Arc;
use futures_util::StreamExt;
use tokio::time::{timeout, Duration};
use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
use vaiexia_core::error::Result;
use vaiexia_core::protocol::{Event, Method, Request, RequestId, Seq, Topic};
use vaiexia_core::server::ServiceBuilder;
use vaiexia_core::transport::{Connection, ConnectionState, Requester, Subscriber};
use vaiexia_core::version::ProtoVersion;
use vaiexia_wire::keypair::generate_keypair;
use vaiexia_wire::mimicry::{MimicryConfig, Passthrough, QuicMimic};
use vaiexia_obfs::{connect_udp, serve_obfs_udp, AllowAll, AlwaysOpen, AlwaysUnderLoad};

struct AllowAllVerifier;
impl Verifier for AllowAllVerifier {
    fn verify(&self, _: Option<&Capability>, _: &Method) -> Result<Subject> {
        Ok(Subject { id: SubjectId::new("test"), scopes: ScopeSet::from_iter(["*"]) })
    }
}

fn passthrough_profile() -> Arc<dyn vaiexia_wire::mimicry::DatagramMimicry> {
    Arc::new(Passthrough::new(MimicryConfig::default()))
}

fn quic_mimic_profile() -> Arc<dyn vaiexia_wire::mimicry::DatagramMimicry> {
    Arc::new(QuicMimic::new(MimicryConfig {
        magic_header: [0xDE, 0xAD, 0xBE, 0xEF],
        pad_bucket: 64,
        preamble_junk_len: 0,
        jitter_ms: (0, 0),
    }))
}

fn make_ping_request() -> Request {
    Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new("server.ping").unwrap(),
        params: serde_json::json!(null),
        capability: None,
    }
}

/// Case 1: Passthrough profile, basic RPC ping + subscribe/event.
#[tokio::test(flavor = "multi_thread")]
async fn udp_loopback_passthrough_e2e() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let topic = Topic::new("test.events");

    let mut builder = ServiceBuilder::new().verifier(AllowAllVerifier);
    let event_tx = builder.event_source_sender(topic.clone());
    builder = builder.method(
        Method::new("server.ping").unwrap(),
        |_p, _s| async move { Ok(serde_json::json!("pong")) },
    );
    let svc = Arc::new(builder.build());

    let handle = serve_obfs_udp(
        "127.0.0.1:0",
        server_kp.clone(),
        Arc::clone(&svc),
        Arc::new(AllowAll),
        Arc::new(AlwaysOpen),
        passthrough_profile(),
    ).await.expect("server should bind");

    let client = timeout(
        Duration::from_secs(10),
        connect_udp(
            handle.local_addr(),
            server_kp.public,
            client_kp,
            passthrough_profile(),
            None,
        )
    ).await.expect("connect should not time out").expect("connect should succeed");

    assert_eq!(client.state(), ConnectionState::Connected);

    // RPC ping
    let resp = timeout(
        Duration::from_secs(5),
        client.request(make_ping_request()),
    ).await.expect("request should not time out").expect("request should succeed");
    assert!(resp.is_ok());
    assert_eq!(resp.value().unwrap(), &serde_json::json!("pong"));

    // Subscribe + event
    let mut stream = timeout(Duration::from_secs(5), client.subscribe(&topic))
        .await.expect("subscribe should not time out")
        .expect("subscribe should succeed");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let ev = Event {
        topic: topic.clone(),
        seq: Seq(1),
        payload: serde_json::json!({"hello": "udp"}),
    };
    event_tx.send(ev.clone()).expect("should have receiver");

    let got = timeout(Duration::from_secs(5), stream.next())
        .await.expect("event should arrive")
        .expect("stream should not end")
        .expect("event should be Ok");

    assert_eq!(got.seq, ev.seq);
    assert_eq!(got.payload, ev.payload);
}

/// Case 2: QuicMimic profile, same assertions as passthrough.
#[tokio::test(flavor = "multi_thread")]
async fn udp_loopback_quic_mimic_e2e() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let svc = Arc::new(
        ServiceBuilder::new()
            .verifier(AllowAllVerifier)
            .method(
                Method::new("server.ping").unwrap(),
                |_p, _s| async move { Ok(serde_json::json!("pong")) },
            )
            .build(),
    );

    let handle = serve_obfs_udp(
        "127.0.0.1:0",
        server_kp.clone(),
        Arc::clone(&svc),
        Arc::new(AllowAll),
        Arc::new(AlwaysOpen),
        quic_mimic_profile(),
    ).await.expect("server should bind");

    let client = timeout(
        Duration::from_secs(10),
        connect_udp(
            handle.local_addr(),
            server_kp.public,
            client_kp,
            quic_mimic_profile(),
            None,
        )
    ).await.expect("connect should not time out").expect("connect should succeed");

    let resp = timeout(
        Duration::from_secs(5),
        client.request(make_ping_request()),
    ).await.expect("request should not time out").expect("request should succeed");
    assert!(resp.is_ok());
    assert_eq!(resp.value().unwrap(), &serde_json::json!("pong"));
}

/// Case 3: Server AlwaysUnderLoad — cookie round trip, connect still succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn udp_loopback_cookie_under_load() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let svc = Arc::new(
        ServiceBuilder::new()
            .verifier(AllowAllVerifier)
            .method(
                Method::new("server.ping").unwrap(),
                |_p, _s| async move { Ok(serde_json::json!("pong")) },
            )
            .build(),
    );

    let handle = serve_obfs_udp(
        "127.0.0.1:0",
        server_kp.clone(),
        Arc::clone(&svc),
        Arc::new(AllowAll),
        Arc::new(AlwaysUnderLoad), // always under load → cookie path
        passthrough_profile(),
    ).await.expect("server should bind");

    // Client should complete despite cookie round trip
    let client = timeout(
        Duration::from_secs(10),
        connect_udp(
            handle.local_addr(),
            server_kp.public,
            client_kp,
            passthrough_profile(),
            None,
        )
    ).await.expect("connect should not time out").expect("cookie path connect should succeed");

    let resp = timeout(
        Duration::from_secs(5),
        client.request(make_ping_request()),
    ).await.expect("request should not time out").expect("request should succeed");
    assert!(resp.is_ok());
}

/// Case 4: Wrong server key → connect returns Err (bounded, no hang).
#[tokio::test(flavor = "multi_thread")]
async fn udp_loopback_wrong_key_fails() {
    let server_kp = generate_keypair().unwrap();
    let wrong_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let svc = Arc::new(ServiceBuilder::new().verifier(AllowAllVerifier).build());

    let handle = serve_obfs_udp(
        "127.0.0.1:0",
        server_kp.clone(),
        Arc::clone(&svc),
        Arc::new(AllowAll),
        Arc::new(AlwaysOpen),
        passthrough_profile(),
    ).await.expect("server should bind");

    let result = timeout(
        Duration::from_secs(30), // generous timeout — must complete, not hang
        connect_udp(
            handle.local_addr(),
            wrong_kp.public, // WRONG key
            client_kp,
            passthrough_profile(),
            None,
        )
    ).await.expect("should not hang indefinitely");

    assert!(result.is_err(), "wrong key must fail");
}
