//! End-to-end loopback integration tests under AmneziaJunk mimicry.
//!
//! Proves that the full transport (preamble + handshake + records) works
//! correctly when shaped by `AmneziaJunk`.  Both client and server use the
//! same profile (configured out-of-band, identical on both sides).
//!
//! This is the primary proof that DPI-resistant framing does not break the
//! transport.  Note: real DPI-bypass effectiveness requires testing against
//! actual DPI hardware/software, which is out of scope here.

use std::sync::Arc;
use tokio::time::{timeout, Duration};
use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
use vaiexia_core::error::Result;
use vaiexia_core::protocol::{Event, Method, Request, RequestId, Seq, Topic};
use vaiexia_core::server::ServiceBuilder;
use vaiexia_core::transport::{Requester, Subscriber};
use vaiexia_core::version::ProtoVersion;
use vaiexia_wire::keypair::generate_keypair;
use vaiexia_obfs::{serve_obfs, AllowAll, AmneziaJunk, MimicryConfig, ObfsTransport};
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
            id: SubjectId::new("mimicry-test-client"),
            scopes: ScopeSet::from_iter(["*"]),
        })
    }
}

// ── AmneziaJunk profile used by all tests in this file ───────────────────────

/// Build an `AmneziaJunk` profile matching the spec in the plan:
///  - magic_header = `[0xDE, 0xAD, 0xBE, 0xEF]`
///  - preamble_junk_len = 23
///  - pad_bucket = 128
///  - jitter_ms = (0, 2)
fn amnezia_profile() -> Arc<dyn vaiexia_obfs::MimicryProfile> {
    Arc::new(AmneziaJunk::new(MimicryConfig {
        magic_header: [0xDE, 0xAD, 0xBE, 0xEF],
        preamble_junk_len: 23,
        pad_bucket: 128,
        jitter_ms: (0, 2),
    }))
}

// ── helpers ───────────────────────────────────────────────────────────────────

async fn start_server_amnezia(
    service: Arc<vaiexia_core::server::Service>,
    server_kp: &vaiexia_wire::keypair::StaticKeypair,
) -> vaiexia_obfs::ObfsServeHandle {
    serve_obfs(
        "127.0.0.1:0",
        server_kp.private,
        service,
        Arc::new(AllowAll),
        amnezia_profile(),
    )
    .await
    .expect("server should bind")
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Full e2e loopback: ping RPC + event stream, both sides using AmneziaJunk.
///
/// The profile adds:
/// - 23 bytes of random preamble junk before the first frame
/// - `[0xDE,0xAD,0xBE,0xEF]` magic header on every frame
/// - 128-byte bucket padding
/// - Up to 2 ms timing jitter
///
/// If this test passes, the transport is functionally correct under AmneziaJunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_amnezia_ping_and_event() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let topic = Topic::new("obfs.events");
    let mut builder = ServiceBuilder::new()
        .verifier(AllowAllVerifier)
        .method(
            Method::new("server.ping").unwrap(),
            |_params, _subject| async move {
                Ok(serde_json::json!("pong"))
            },
        );
    let event_tx = builder.event_source_sender(topic.clone());
    let svc = Arc::new(builder.build());

    let handle = start_server_amnezia(Arc::clone(&svc), &server_kp).await;

    let client = ObfsTransport::connect(
        handle.local_addr(),
        client_kp.private,
        server_kp.public,
        amnezia_profile(),
        None,
    )
    .await
    .expect("client should connect under AmneziaJunk");

    // ── RPC ping ──────────────────────────────────────────────────────────────
    let req = Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new("server.ping").unwrap(),
        params: serde_json::json!(null),
        capability: None,
    };

    let resp = timeout(Duration::from_secs(10), client.request(req))
        .await
        .expect("ping should not time out")
        .expect("ping should succeed");

    assert!(resp.is_ok(), "ping response should be Ok");
    assert_eq!(
        resp.value().unwrap(),
        &serde_json::json!("pong"),
        "ping should return 'pong'"
    );

    // ── Event subscription ────────────────────────────────────────────────────
    let mut stream = timeout(Duration::from_secs(5), client.subscribe(&topic))
        .await
        .expect("subscribe should not time out")
        .expect("subscribe should succeed");

    // Give the server time to process the Subscribe control message.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Emit an event from the server side.
    let ev = Event {
        topic: topic.clone(),
        seq: Seq(1),
        payload: serde_json::json!({"mimicry": "AmneziaJunk", "status": "ok"}),
    };
    event_tx
        .send(ev.clone())
        .expect("broadcast should have receiver");

    // Receive the event on the client.
    let got = timeout(Duration::from_secs(10), stream.next())
        .await
        .expect("event should arrive within timeout")
        .expect("stream should not end")
        .expect("event should be Ok");

    assert_eq!(got.seq, ev.seq, "event sequence number should match");
    assert_eq!(
        got.payload, ev.payload,
        "event payload should match"
    );
}
