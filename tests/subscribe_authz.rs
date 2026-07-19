//! Authorization tests for Subscribe: verify that server-side topic gating
//! works for both TCP (serve_obfs) and UDP (serve_obfs_udp) paths.
//!
//! Each test uses a `GatingVerifier` that:
//!   - Allows all regular RPC methods unconditionally.
//!   - Allows `server.subscribe` only when the capability token equals
//!     `"valid-sub-token"`.
//!   - Denies `server.subscribe` for any other (or absent) capability.
//!
//! TDD ordering:
//!   1. These tests were written BEFORE the server-side `verify_topic` call.
//!   2. The two `*_denied` tests FAIL on that baseline (no gating → events
//!      flow or no error is sent).
//!   3. After the server fix both `*_denied` AND `*_allowed` pass.

use std::sync::Arc;
use futures_util::StreamExt;
use tokio::time::{timeout, Duration};
use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::error::{CoreError, Result};
use vaiexia_core::protocol::{Event, Method, Seq, Topic};
use vaiexia_core::server::ServiceBuilder;
use vaiexia_core::transport::Subscriber;
use vaiexia_wire::keypair::generate_keypair;
use vaiexia_wire::mimicry::{MimicryConfig, Passthrough};
use vaiexia_obfs::{connect_udp, serve_obfs, serve_obfs_udp, AllowAll, AlwaysOpen, MimicryProfile, ObfsTransport, Vanilla};

// ── gating verifier ───────────────────────────────────────────────────────────

/// Allows everything EXCEPT `server.subscribe` without the right capability.
struct GatingVerifier;

const VALID_TOKEN: &str = "valid-sub-token";
const GATED_METHOD: &str = "server.subscribe";

impl Verifier for GatingVerifier {
    fn verify(&self, capability: Option<&Capability>, method: &Method) -> Result<Subject> {
        if method.as_str() == GATED_METHOD {
            match capability {
                Some(cap) if cap.reveal() == VALID_TOKEN => {}
                _ => {
                    return Err(CoreError::Auth(Diagnostic::error(
                        codes::FORBIDDEN,
                        "subscribe requires valid-sub-token",
                    )));
                }
            }
        }
        Ok(Subject {
            id: SubjectId::new("authz-test"),
            scopes: ScopeSet::from_iter(["*"]),
        })
    }
}

// ── profiles ──────────────────────────────────────────────────────────────────

fn vanilla_profile() -> Arc<dyn MimicryProfile> {
    Arc::new(Vanilla::new(MimicryConfig::default()))
}

fn passthrough_profile() -> Arc<dyn vaiexia_wire::mimicry::DatagramMimicry> {
    Arc::new(Passthrough::new(MimicryConfig::default()))
}

// ── TCP tests ─────────────────────────────────────────────────────────────────

/// Subscribe to a gated topic WITHOUT a capability → must receive SubscribeError
/// and no events.  FAILS before server-side `verify_topic` is added.
#[tokio::test(flavor = "multi_thread")]
async fn tcp_subscribe_denied_without_capability() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let topic = Topic::new("server.logs");

    let mut builder = ServiceBuilder::new().verifier(GatingVerifier);
    let event_tx = builder.event_source_sender(topic.clone());
    let svc = Arc::new(builder.build());

    let handle = serve_obfs(
        "127.0.0.1:0",
        server_kp.private,
        Arc::clone(&svc),
        Arc::new(AllowAll),
        vanilla_profile(),
    )
    .await
    .expect("server should bind");

    // No capability — subscribe should be denied.
    let client = ObfsTransport::connect(
        handle.local_addr(),
        client_kp.private,
        server_kp.public,
        vanilla_profile(),
        None,
        None, // no capability
    )
    .await
    .expect("client should connect");

    let mut stream = timeout(Duration::from_secs(5), client.subscribe(&topic))
        .await
        .expect("subscribe call should not time out")
        .expect("subscribe should return a stream");

    // Let the server process the Subscribe envelope.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Emit an event — it must NOT reach the client (subscription was denied).
    let ev = Event {
        topic: topic.clone(),
        seq: Seq(1),
        payload: serde_json::json!({"secret": "data"}),
    };
    // event_tx may have no receivers if the subscription was correctly denied.
    let _ = event_tx.send(ev);

    // The stream should yield Err(Disconnected) or time out — either way no
    // event should arrive within the window.  A correct server sends
    // SubscribeError and never wires the broadcast, so the client stream
    // will never see an Ok(event).
    let next = timeout(Duration::from_millis(300), stream.next()).await;
    match next {
        Ok(Some(Ok(ev))) => panic!(
            "denied subscription must not deliver events; got seq {}",
            ev.seq.0
        ),
        // Timeout (no event) or Err variant both satisfy the test.
        _ => {}
    }
}

/// Subscribe to a gated topic WITH the correct capability → subscription
/// must succeed and events must flow.
#[tokio::test(flavor = "multi_thread")]
async fn tcp_subscribe_allowed_with_capability() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let topic = Topic::new("server.logs");

    let mut builder = ServiceBuilder::new().verifier(GatingVerifier);
    let event_tx = builder.event_source_sender(topic.clone());
    let svc = Arc::new(builder.build());

    let handle = serve_obfs(
        "127.0.0.1:0",
        server_kp.private,
        Arc::clone(&svc),
        Arc::new(AllowAll),
        vanilla_profile(),
    )
    .await
    .expect("server should bind");

    let cap = Some(Capability::new(VALID_TOKEN));

    let client = ObfsTransport::connect(
        handle.local_addr(),
        client_kp.private,
        server_kp.public,
        vanilla_profile(),
        None,
        cap,
    )
    .await
    .expect("client should connect");

    let mut stream = timeout(Duration::from_secs(5), client.subscribe(&topic))
        .await
        .expect("subscribe call should not time out")
        .expect("subscribe should return a stream");

    // Give the server time to wire the subscription.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let ev = Event {
        topic: topic.clone(),
        seq: Seq(42),
        payload: serde_json::json!({"allowed": true}),
    };
    event_tx.send(ev.clone()).expect("should have receiver");

    let got = timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("event should arrive")
        .expect("stream should not end")
        .expect("event should be Ok");

    assert_eq!(got.seq, ev.seq);
    assert_eq!(got.payload, ev.payload);
}

// ── UDP tests ─────────────────────────────────────────────────────────────────

/// UDP: Subscribe to a gated topic WITHOUT capability → no events.
/// FAILS before server-side `verify_topic` is added to udp/server.rs.
#[tokio::test(flavor = "multi_thread")]
async fn udp_subscribe_denied_without_capability() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let topic = Topic::new("server.logs");

    let mut builder = ServiceBuilder::new().verifier(GatingVerifier);
    let event_tx = builder.event_source_sender(topic.clone());
    let svc = Arc::new(builder.build());

    let handle = serve_obfs_udp(
        "127.0.0.1:0",
        server_kp.clone(),
        Arc::clone(&svc),
        Arc::new(AllowAll),
        Arc::new(AlwaysOpen),
        passthrough_profile(),
    )
    .await
    .expect("server should bind");

    let client = timeout(
        Duration::from_secs(10),
        connect_udp(
            handle.local_addr(),
            server_kp.public,
            client_kp,
            passthrough_profile(),
            None, // no capability
        ),
    )
    .await
    .expect("connect should not time out")
    .expect("connect should succeed");

    let mut stream = timeout(Duration::from_secs(5), client.subscribe(&topic))
        .await
        .expect("subscribe call should not time out")
        .expect("subscribe should return a stream");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let ev = Event {
        topic: topic.clone(),
        seq: Seq(1),
        payload: serde_json::json!({"secret": "udp-data"}),
    };
    let _ = event_tx.send(ev);

    let next = timeout(Duration::from_millis(300), stream.next()).await;
    match next {
        Ok(Some(Ok(ev))) => panic!(
            "denied UDP subscription must not deliver events; got seq {}",
            ev.seq.0
        ),
        _ => {}
    }
}

/// UDP: Subscribe to a gated topic WITH the correct capability → events flow.
#[tokio::test(flavor = "multi_thread")]
async fn udp_subscribe_allowed_with_capability() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let topic = Topic::new("server.logs");

    let mut builder = ServiceBuilder::new().verifier(GatingVerifier);
    let event_tx = builder.event_source_sender(topic.clone());
    let svc = Arc::new(builder.build());

    let handle = serve_obfs_udp(
        "127.0.0.1:0",
        server_kp.clone(),
        Arc::clone(&svc),
        Arc::new(AllowAll),
        Arc::new(AlwaysOpen),
        passthrough_profile(),
    )
    .await
    .expect("server should bind");

    let cap = Some(Capability::new(VALID_TOKEN));

    let client = timeout(
        Duration::from_secs(10),
        connect_udp(
            handle.local_addr(),
            server_kp.public,
            client_kp,
            passthrough_profile(),
            cap,
        ),
    )
    .await
    .expect("connect should not time out")
    .expect("connect should succeed");

    let mut stream = timeout(Duration::from_secs(5), client.subscribe(&topic))
        .await
        .expect("subscribe call should not time out")
        .expect("subscribe should return a stream");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let ev = Event {
        topic: topic.clone(),
        seq: Seq(99),
        payload: serde_json::json!({"allowed": "udp"}),
    };
    event_tx.send(ev.clone()).expect("should have receiver");

    let got = timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("event should arrive")
        .expect("stream should not end")
        .expect("event should be Ok");

    assert_eq!(got.seq, ev.seq);
    assert_eq!(got.payload, ev.payload);
}
