//! Integration tests for proxy chaining via `proxy::dial`.
//!
//! Tests single-hop and two-hop SOCKS5 chains through mock proxies to an
//! echo server.

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use vaiexia_core::transport::proxy::{ProxyConfig, ProxyHop, ProxyKind};

// ── Shared mock helpers ───────────────────────────────────────────────────────

/// Minimal echo server.
async fn start_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Mock SOCKS5 proxy that forwards all CONNECT requests.
async fn start_mock_socks5_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = handle_socks5(conn).await {
                    eprintln!("proxy_chain mock socks5 error: {e}");
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

    // Accept with no-auth
    conn.write_all(&[0x05, 0x00]).await?;

    // Read CONNECT request
    let mut req_hdr = [0u8; 4];
    conn.read_exact(&mut req_hdr).await?;

    let (target_host, target_port) = read_socks5_target(&mut conn, req_hdr[3]).await?;

    // Connect to target
    let target_addr = format!("{target_host}:{target_port}");
    let mut target = TcpStream::connect(&target_addr).await?;

    // Reply success
    conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;

    // Relay
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

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Single-hop: client → proxy → echo server.
#[tokio::test]
async fn single_hop_socks5_chain() {
    let echo_addr = start_echo_server().await;
    let proxy_addr = start_mock_socks5_proxy().await;

    let proxy_cfg = ProxyConfig {
        kind: ProxyKind::Socks5,
        addr: proxy_addr.to_string(),
        auth: None,
        chain: vec![],
    };

    let mut stream = vaiexia_obfs::proxy::dial(
        &proxy_cfg,
        "127.0.0.1",
        echo_addr.port(),
    )
    .await
    .expect("single_hop_socks5_chain: dial should succeed");

    let msg = b"single-hop socks5";
    stream.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, msg);
}

/// Two-hop: client → proxy1 → proxy2 → echo server.
#[tokio::test]
async fn two_hop_socks5_chain() {
    let echo_addr = start_echo_server().await;
    let proxy2_addr = start_mock_socks5_proxy().await;
    let proxy1_addr = start_mock_socks5_proxy().await;

    let proxy_cfg = ProxyConfig {
        kind: ProxyKind::Socks5,
        addr: proxy1_addr.to_string(),
        auth: None,
        chain: vec![ProxyHop {
            kind: ProxyKind::Socks5,
            addr: proxy2_addr.to_string(),
            auth: None,
        }],
    };

    let mut stream = vaiexia_obfs::proxy::dial(
        &proxy_cfg,
        "127.0.0.1",
        echo_addr.port(),
    )
    .await
    .expect("two_hop_socks5_chain: dial should succeed");

    let msg = b"two-hop socks5 chain";
    stream.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, msg);
}
