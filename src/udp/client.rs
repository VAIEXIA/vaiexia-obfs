//! UDP client transport: `UdpObfsTransport` over Noise-XK + record layer.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use rand::{rngs::SmallRng, SeedableRng};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{timeout, Duration};
use vaiexia_wire::keypair::StaticKeypair;
use vaiexia_wire::mimicry::DatagramMimicry;
use vaiexia_core::auth::Capability;
use vaiexia_core::error::{CoreError, Result};
use vaiexia_core::protocol::{Event, Request, Response, Topic};
use vaiexia_core::transport::{Connection, ConnectionState, EventStream, Requester, Subscriber};

use crate::envelope::Envelope;
use crate::udp::dataplane::DataChannel;
use crate::udp::handshake::client_udp_handshake;
use crate::{ObfsError, Result as ObfsResult};

type PendingMap = Mutex<HashMap<String, oneshot::Sender<Response>>>;

const REQUEST_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(300);
const MAX_REQUEST_RETRIES: usize = 10;

/// UDP client transport implementing Requester + Subscriber + Connection.
pub struct UdpObfsTransport {
    /// Channel for sending Envelopes to the pump (which seals + sends them).
    outbound_tx: mpsc::UnboundedSender<Envelope>,
    pending: Arc<PendingMap>,
    events: broadcast::Sender<Event>,
    state: Arc<Mutex<ConnectionState>>,
    /// Optional capability attached to every `Subscribe` envelope.
    capability: Option<Capability>,
}

impl UdpObfsTransport {
    fn new(
        outbound_tx: mpsc::UnboundedSender<Envelope>,
        pending: Arc<PendingMap>,
        events: broadcast::Sender<Event>,
        state: Arc<Mutex<ConnectionState>>,
        capability: Option<Capability>,
    ) -> Self {
        Self { outbound_tx, pending, events, state, capability }
    }
}

/// Connect to a UDP server and perform the Noise-XK handshake.
///
/// `capability` is an optional bearer token attached to every `Subscribe`
/// envelope so the server can gate per-topic access.
pub async fn connect_udp(
    addr: impl tokio::net::ToSocketAddrs + std::fmt::Display,
    server_pub: [u8; 32],
    client_keypair: StaticKeypair,
    profile: Arc<dyn DatagramMimicry>,
    capability: Option<Capability>,
) -> ObfsResult<UdpObfsTransport> {
    let server_addr: SocketAddr = tokio::net::lookup_host(addr).await?
        .next()
        .ok_or_else(|| ObfsError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "addr not resolved")))?;

    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    let mut rng = SmallRng::from_entropy();
    let channel = client_udp_handshake(
        Arc::clone(&sock),
        server_addr,
        server_pub,
        client_keypair,
        Arc::clone(&profile),
        &mut rng,
    ).await?;

    let channel = Arc::new(channel);
    let (ev_tx, _) = broadcast::channel::<Event>(256);
    let pending: Arc<PendingMap> = Arc::new(Mutex::new(HashMap::new()));
    let state = Arc::new(Mutex::new(ConnectionState::Connected));

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Envelope>();

    // Spawn the pump task
    let ch2 = Arc::clone(&channel);
    let ev_tx2 = ev_tx.clone();
    let pending2 = Arc::clone(&pending);
    let state2 = Arc::clone(&state);
    let sock2 = Arc::clone(&sock);

    tokio::spawn(udp_pump(
        sock2, server_addr, ch2, out_rx, ev_tx2, pending2, state2,
    ));

    Ok(UdpObfsTransport::new(out_tx, pending, ev_tx, state, capability))
}

/// Background pump task: owns recv + coordinates send.
async fn udp_pump(
    sock: Arc<UdpSocket>,
    server_addr: SocketAddr,
    channel: Arc<DataChannel>,
    mut outbound: mpsc::UnboundedReceiver<Envelope>,
    events: broadcast::Sender<Event>,
    pending: Arc<PendingMap>,
    state: Arc<Mutex<ConnectionState>>,
) {
    let mut rng = SmallRng::from_entropy();
    let mut buf = vec![0u8; 65507];

    loop {
        tokio::select! {
            biased;

            // Send outbound envelopes
            Some(env) = outbound.recv() => {
                if let Ok(wire) = channel.seal_envelope(&env, &mut rng) {
                    let _ = sock.send_to(&wire, server_addr).await;
                }
            }

            // Receive inbound datagrams
            result = sock.recv_from(&mut buf) => {
                match result {
                    Err(_) => break,
                    Ok((n, _src)) => {
                        match channel.open_datagram(&buf[..n]) {
                            Ok(Some(Envelope::Response(resp))) => {
                                let key = resp.id.as_str().to_owned();
                                let tx = pending.lock().unwrap().remove(&key);
                                if let Some(tx) = tx { let _ = tx.send(resp); }
                            }
                            Ok(Some(Envelope::Event(ev))) => {
                                let _ = events.send(ev);
                            }
                            Ok(Some(Envelope::Ping)) => {
                                if let Ok(wire) = channel.seal_envelope(&Envelope::Pong, &mut rng) {
                                    let _ = sock.send_to(&wire, server_addr).await;
                                }
                            }
                            Ok(Some(Envelope::Pong)) => {} // handshake-ready marker or ping reply
                            Ok(Some(_)) | Ok(None) => {}
                            Err(_) => break,
                        }
                    }
                }
            }

            else => break,
        }
    }

    *state.lock().unwrap() = ConnectionState::Down;
    let drained: Vec<_> = {
        let mut map = pending.lock().unwrap();
        map.drain().map(|(_, tx)| tx).collect()
    };
    drop(drained);
}

#[async_trait]
impl Requester for UdpObfsTransport {
    async fn request(&self, req: Request) -> Result<Response> {
        let id = req.id.as_str().to_owned();

        // Retransmit loop: UDP is unreliable, so resend until a response arrives.
        // Server-side idempotency is assumed for v1; request-id dedup is a follow-up.
        for retry in 0..=MAX_REQUEST_RETRIES {
            let (tx, rx) = oneshot::channel::<Response>();
            self.pending.lock().unwrap().insert(id.clone(), tx);

            if self.outbound_tx.send(Envelope::Request(req.clone())).is_err() {
                self.pending.lock().unwrap().remove(&id);
                return Err(CoreError::Disconnected);
            }

            match timeout(REQUEST_RETRANSMIT_INTERVAL, rx).await {
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(_)) => {
                    // Pump gone
                    return Err(CoreError::Disconnected);
                }
                Err(_) => {
                    // Timed out — remove stale entry and retry.
                    self.pending.lock().unwrap().remove(&id);
                    if retry == MAX_REQUEST_RETRIES {
                        return Err(CoreError::Timeout);
                    }
                }
            }
        }

        Err(CoreError::Timeout)
    }
}

#[async_trait]
impl Subscriber for UdpObfsTransport {
    async fn subscribe(&self, topic: &Topic) -> Result<EventStream> {
        self.outbound_tx
            .send(Envelope::Subscribe {
                topic: topic.clone(),
                filter: None,
                capability: self.capability.clone(),
            })
            .map_err(|_| CoreError::Disconnected)?;

        let mut rx = self.events.subscribe();
        let topic_clone = topic.clone();

        let raw = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(ev) => yield Ok(ev),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => {
                        yield Err(CoreError::Disconnected);
                        break;
                    }
                }
            }
        };

        let stream = vaiexia_core::transport::dedup::dedup_by_seq(raw, topic_clone);
        Ok(Box::pin(stream))
    }
}

impl Connection for UdpObfsTransport {
    fn state(&self) -> ConnectionState {
        *self.state.lock().unwrap()
    }
}
