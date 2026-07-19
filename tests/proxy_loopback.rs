//! End-to-end tests: ObfsTransport connects through a mock proxy to a real
//! `serve_obfs` server.
//!
//! Covers:
//! - SOCKS5 proxy → obfs loopback
//! - HTTP CONNECT proxy → obfs loopback

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
use vaiexia_core::error::Result;
use vaiexia_core::protocol::{Method, Request, RequestId};
use vaiexia_core::server::ServiceBuilder;
use vaiexia_core::transport::{Connection, ConnectionState, Requester};
use vaiexia_core::version::ProtoVersion;
use vaiexia_core::transport::proxy::{ProxyConfig, ProxyKind};
use vaiexia_obfs::{serve_obfs, AllowAll, MimicryConfig, ObfsTransport, Vanilla};
use vaiexia_wire::keypair::generate_keypair;

// ── Test verifier ─────────────────────────────────────────────────────────────

struct AllowAllVerifier;

impl Verifier for AllowAllVerifier {
    fn verify(
        &self,
        _capability: Option<&Capability>,
        _method: &Method,
    ) -> Result<Subject> {
        Ok(Subject {
            id: SubjectId::new("proxy-test-client"),
            scopes: ScopeSet::from_iter(["*"]),
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn vanilla_profile() -> Arc<dyn vaiexia_obfs::MimicryProfile> {
    Arc::new(Vanilla::new(MimicryConfig::default()))
}

/// A forwarding mock SOCKS5 proxy (no auth required).
async fn start_mock_socks5_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = handle_socks5(conn).await {
                    eprintln!("proxy_loopback socks5 error: {e}");
                }
            });
        }
    });
    addr
}

async fn handle_socks5(mut conn: TcpStream) -> std::io::Result<()> {
    // Read greeting
    let mut hdr = [0u8; 2];
    conn.read_exact(&mut hdr).await?;
    let nmethods = hdr[1] as usize;
    let mut _methods = vec![0u8; nmethods];
    conn.read_exact(&mut _methods).await?;

    // Accept no-auth
    conn.write_all(&[0x05, 0x00]).await?;

    // Read CONNECT request header
    let mut req_hdr = [0u8; 4];
    conn.read_exact(&mut req_hdr).await?;

    let (target_host, target_port) = read_socks5_target(&mut conn, req_hdr[3]).await?;
    let target_addr = format!("{target_host}:{target_port}");

    let mut target = TcpStream::connect(&target_addr).await?;

    // Reply success (bound 0.0.0.0:0)
    conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;

    let _ = copy_bidirectional(&mut conn, &mut target).await;
    Ok(())
}

async fn read_socks5_target(
    conn: &mut TcpStream,
    atyp: u8,
) -> std::io::Result<(String, u16)> {
    let host = match atyp {
        0x01 => {
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).await?;
            format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3])
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            conn.read_exact(&mut len_buf).await?;
            let mut name = vec![0u8; len_buf[0] as usize];
            conn.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| std::io::Error::other("bad hostname"))?
        }
        0x04 => {
            let mut buf = [0u8; 16];
            conn.read_exact(&mut buf).await?;
            let segs: Vec<String> = buf
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            segs.join(":")
        }
        _ => return Err(std::io::Error::other("unknown atyp")),
    };
    let mut port_buf = [0u8; 2];
    conn.read_exact(&mut port_buf).await?;
    Ok((host, u16::from_be_bytes(port_buf)))
}

/// A forwarding mock HTTP CONNECT proxy (no auth required).
async fn start_mock_http_connect_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = handle_http_connect(conn).await {
                    eprintln!("proxy_loopback http-connect error: {e}");
                }
            });
        }
    });
    addr
}

async fn handle_http_connect(mut conn: TcpStream) -> std::io::Result<()> {
    // Read request until \r\n\r\n
    let mut req_buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        conn.read_exact(&mut byte).await?;
        req_buf.push(byte[0]);
        if req_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if req_buf.len() > 8192 {
            return Err(std::io::Error::other("request too large"));
        }
    }

    let req_str = std::str::from_utf8(&req_buf).unwrap_or_default();
    let first_line = req_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _method = parts.next();
    let target = parts.next().unwrap_or("");

    let mut target_conn = TcpStream::connect(target).await?;
    conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let _ = copy_bidirectional(&mut conn, &mut target_conn).await;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// ObfsTransport → SOCKS5 proxy → serve_obfs: RPC ping round-trip.
#[tokio::test]
async fn proxy_socks5_to_obfs_loopback() {
    let server_kp = generate_keypair().unwrap();

    let svc = Arc::new(
        ServiceBuilder::new()
            .verifier(AllowAllVerifier)
            .method(
                Method::new("echo.ping").unwrap(),
                |params, _subject| async move { Ok(params) },
            )
            .build(),
    );

    let obfs_handle = serve_obfs(
        "127.0.0.1:0",
        server_kp.private,
        svc,
        Arc::new(AllowAll),
        vanilla_profile(),
    )
    .await
    .expect("obfs server should bind");

    let proxy_addr = start_mock_socks5_proxy().await;
    let client_kp = generate_keypair().unwrap();

    let proxy_cfg = ProxyConfig {
        kind: ProxyKind::Socks5,
        addr: proxy_addr.to_string(),
        auth: None,
        chain: vec![],
    };

    let client = timeout(
        Duration::from_secs(5),
        ObfsTransport::connect(
            obfs_handle.local_addr(),
            client_kp.private,
            server_kp.public,
            vanilla_profile(),
            Some(proxy_cfg),
        ),
    )
    .await
    .expect("connect should not time out")
    .expect("ObfsTransport should connect through SOCKS5 proxy");

    assert_eq!(client.state(), ConnectionState::Connected);

    let req = Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new("echo.ping").unwrap(),
        params: serde_json::json!("through-socks5"),
        capability: None,
    };

    let resp = timeout(Duration::from_secs(5), client.request(req))
        .await
        .expect("request should not time out")
        .expect("request should succeed");

    assert!(resp.is_ok(), "response should be Ok");
    assert_eq!(
        resp.value().unwrap(),
        &serde_json::json!("through-socks5")
    );
}

/// ObfsTransport → HTTP CONNECT proxy → serve_obfs: RPC ping round-trip.
#[tokio::test]
async fn proxy_http_connect_to_obfs_loopback() {
    let server_kp = generate_keypair().unwrap();
    let svc = Arc::new(
        ServiceBuilder::new()
            .verifier(AllowAllVerifier)
            .method(
                Method::new("echo.ping").unwrap(),
                |params, _subject| async move { Ok(params) },
            )
            .build(),
    );

    let obfs_handle = serve_obfs(
        "127.0.0.1:0",
        server_kp.private,
        svc,
        Arc::new(AllowAll),
        vanilla_profile(),
    )
    .await
    .expect("obfs server should bind");

    let proxy_addr = start_mock_http_connect_proxy().await;
    let client_kp = generate_keypair().unwrap();

    let proxy_cfg = ProxyConfig {
        kind: ProxyKind::HttpConnect,
        addr: proxy_addr.to_string(),
        auth: None,
        chain: vec![],
    };

    let client = timeout(
        Duration::from_secs(5),
        ObfsTransport::connect(
            obfs_handle.local_addr(),
            client_kp.private,
            server_kp.public,
            vanilla_profile(),
            Some(proxy_cfg),
        ),
    )
    .await
    .expect("connect should not time out")
    .expect("ObfsTransport should connect through HTTP CONNECT proxy");

    assert_eq!(client.state(), ConnectionState::Connected);

    let req = Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new("echo.ping").unwrap(),
        params: serde_json::json!("through-http-connect"),
        capability: None,
    };

    let resp = timeout(Duration::from_secs(5), client.request(req))
        .await
        .expect("request should not time out")
        .expect("request should succeed");

    assert!(resp.is_ok(), "response should be Ok");
    assert_eq!(
        resp.value().unwrap(),
        &serde_json::json!("through-http-connect")
    );
}
