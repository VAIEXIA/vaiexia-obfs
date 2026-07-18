//! Multiplexing envelope for the obfuscated transport.
//!
//! All messages on the encrypted TCP channel are wrapped in an [`Envelope`],
//! which is serialised to JSON and then encrypted+framed by the wire layer.
//!
//! The envelope carries either:
//! - A [`Request`] from client → server,
//! - A [`Response`] from server → client,
//! - An [`Event`] pushed from server → client (subscription),
//! - A `Subscribe` / `Unsubscribe` control message from client → server, or
//! - A `SubscribeError` diagnostic from server → client.

use serde::{Deserialize, Serialize};
use vaiexia_core::diagnostic::Diagnostic;
use vaiexia_core::protocol::{Event, Request, Response, Topic};

/// The top-level multiplexing envelope.
///
/// Serialised as a JSON object with a `"kind"` discriminant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Envelope {
    /// Client → server: an RPC request.
    Request(Request),
    /// Server → client: the response to a prior `Request`.
    Response(Response),
    /// Server → client: a pushed event on a subscribed topic.
    Event(Event),
    /// Client → server: subscribe to a topic.
    Subscribe {
        topic: Topic,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        filter: Option<serde_json::Value>,
    },
    /// Client → server: unsubscribe from a topic.
    Unsubscribe { topic: Topic },
    /// Server → client: the subscription request was denied.
    SubscribeError { topic: Topic, error: Diagnostic },
    /// Either direction: liveness heartbeat.
    Ping,
    Pong,
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaiexia_core::diagnostic::{codes, Diagnostic};
    use vaiexia_core::protocol::{Event, Method, Outcome, RequestId, Response, Seq, Topic};
    use vaiexia_core::version::ProtoVersion;

    fn make_request() -> Request {
        Request {
            id: RequestId::new(),
            version: ProtoVersion::CURRENT,
            method: Method::new("server.ping").unwrap(),
            params: serde_json::json!(null),
            capability: None,
        }
    }

    fn make_response(req: &Request) -> Response {
        Response {
            id: req.id.clone(),
            server_version: ProtoVersion::CURRENT,
            outcome: Outcome::Ok(serde_json::json!("pong")),
            diagnostics: vec![],
        }
    }

    #[test]
    fn request_roundtrips() {
        let req = make_request();
        let env = Envelope::Request(req.clone());
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back {
            Envelope::Request(r) => assert_eq!(r.id.as_str(), req.id.as_str()),
            _ => panic!("expected Request envelope"),
        }
    }

    #[test]
    fn response_roundtrips() {
        let req = make_request();
        let resp = make_response(&req);
        let env = Envelope::Response(resp.clone());
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back {
            Envelope::Response(r) => assert_eq!(r.id.as_str(), resp.id.as_str()),
            _ => panic!("expected Response envelope"),
        }
    }

    #[test]
    fn event_roundtrips() {
        let ev = Event {
            topic: Topic::new("metrics.cpu"),
            seq: Seq(42),
            payload: serde_json::json!({"load": 0.5}),
        };
        let env = Envelope::Event(ev.clone());
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back {
            Envelope::Event(e) => {
                assert_eq!(e.topic.as_str(), "metrics.cpu");
                assert_eq!(e.seq.0, 42);
            }
            _ => panic!("expected Event envelope"),
        }
    }

    #[test]
    fn subscribe_roundtrips() {
        let env = Envelope::Subscribe {
            topic: Topic::new("server.logs"),
            filter: None,
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Envelope::Subscribe { .. }));
    }

    #[test]
    fn subscribe_error_roundtrips() {
        let env = Envelope::SubscribeError {
            topic: Topic::new("server.logs"),
            error: Diagnostic::error(codes::FORBIDDEN, "not allowed"),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Envelope::SubscribeError { .. }));
    }

    #[test]
    fn ping_pong_roundtrips() {
        for env in [Envelope::Ping, Envelope::Pong] {
            let s = serde_json::to_string(&env).unwrap();
            let back: Envelope = serde_json::from_str(&s).unwrap();
            match (&env, &back) {
                (Envelope::Ping, Envelope::Ping) | (Envelope::Pong, Envelope::Pong) => {}
                _ => panic!("ping/pong roundtrip failed"),
            }
        }
    }
}
