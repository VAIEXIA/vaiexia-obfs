//! SOCKS5 proxy dialer (RFC 1928 + RFC 1929 username/password auth).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use vaiexia_core::transport::proxy::ProxyAuth;

// ── Public API ────────────────────────────────────────────────────────────────

/// Connect to `proxy_addr` via TCP, then perform SOCKS5 CONNECT to
/// `target_host:target_port`.  Returns the ready-to-use stream.
pub async fn dial_socks5(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    auth: Option<&ProxyAuth>,
) -> crate::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    tunnel_socks5(&mut stream, target_host, target_port, auth).await?;
    Ok(stream)
}

/// Run the SOCKS5 CONNECT negotiation on an already-connected stream.
///
/// On success the stream is positioned immediately after the SOCKS5 reply
/// and can be used to talk to the target.
pub async fn tunnel_socks5<S>(
    io: &mut S,
    target_host: &str,
    target_port: u16,
    auth: Option<&ProxyAuth>,
) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ── Greeting ──────────────────────────────────────────────────────────────
    // VER=5, NMETHODS, [methods…]
    // We advertise: NO_AUTH (00) always; USERNAME_PASSWORD (02) if creds given.
    let methods: &[u8] = if auth.is_some() { &[0x00, 0x02] } else { &[0x00] };
    let mut greeting = vec![0x05u8, methods.len() as u8];
    greeting.extend_from_slice(methods);
    io.write_all(&greeting).await?;

    // ── Server method selection ───────────────────────────────────────────────
    let mut method_reply = [0u8; 2];
    io.read_exact(&mut method_reply).await?;
    if method_reply[0] != 0x05 {
        return Err(io_err("SOCKS5: invalid greeting reply version"));
    }
    let selected = method_reply[1];
    if selected == 0xFF {
        return Err(io_err("SOCKS5: no acceptable authentication method"));
    }

    // ── Auth sub-negotiation (RFC 1929) ───────────────────────────────────────
    if selected == 0x02 {
        let creds = auth
            .ok_or_else(|| io_err("SOCKS5: server requires auth but none provided"))?;
        let user = creds.user.as_bytes();
        let pass = creds.pass.as_bytes();
        if user.len() > 255 || pass.len() > 255 {
            return Err(io_err("SOCKS5: username or password too long"));
        }
        let mut sub = Vec::with_capacity(3 + user.len() + pass.len());
        sub.push(0x01); // VER=1 (sub-negotiation version)
        sub.push(user.len() as u8);
        sub.extend_from_slice(user);
        sub.push(pass.len() as u8);
        sub.extend_from_slice(pass);
        io.write_all(&sub).await?;

        let mut auth_reply = [0u8; 2];
        io.read_exact(&mut auth_reply).await?;
        if auth_reply[1] != 0x00 {
            return Err(io_err("SOCKS5: authentication failed"));
        }
    }

    // ── CONNECT request ───────────────────────────────────────────────────────
    // VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAINNAME(3), DSTADDR, DSTPORT
    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(io_err("SOCKS5: target hostname too long"));
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xFF) as u8);
    io.write_all(&req).await?;

    // ── CONNECT reply ─────────────────────────────────────────────────────────
    // VER REP RSV ATYP [BND.ADDR] [BND.PORT]
    let mut reply_hdr = [0u8; 4];
    io.read_exact(&mut reply_hdr).await?;
    if reply_hdr[0] != 0x05 {
        return Err(io_err("SOCKS5: invalid reply version"));
    }
    if reply_hdr[1] != 0x00 {
        let msg = match reply_hdr[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(io_err(&format!("SOCKS5: CONNECT failed: {msg}")));
    }

    // Consume BND.ADDR + BND.PORT to leave the stream at the right offset.
    consume_bnd_addr(io, reply_hdr[3]).await?;

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn io_err(msg: &str) -> crate::ObfsError {
    crate::ObfsError::Io(std::io::Error::other(msg))
}

/// Read and discard the BND.ADDR and BND.PORT bytes from the SOCKS5 reply.
async fn consume_bnd_addr<S>(io: &mut S, atyp: u8) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match atyp {
        0x01 => {
            // IPv4: 4 bytes addr + 2 bytes port
            let mut buf = [0u8; 6];
            io.read_exact(&mut buf).await?;
        }
        0x03 => {
            // Domain: 1 byte length, N bytes name, 2 bytes port
            let mut len_buf = [0u8; 1];
            io.read_exact(&mut len_buf).await?;
            let n = len_buf[0] as usize;
            let mut buf = vec![0u8; n + 2];
            io.read_exact(&mut buf).await?;
        }
        0x04 => {
            // IPv6: 16 bytes addr + 2 bytes port
            let mut buf = [0u8; 18];
            io.read_exact(&mut buf).await?;
        }
        _ => {
            return Err(io_err("SOCKS5: unknown address type in reply"));
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A minimal echo server: echoes back every byte it receives.
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

    /// A mock SOCKS5 proxy server.
    ///
    /// `required_auth`: if `Some((user, pass))`, the server requires
    /// username/password auth; if `None`, no auth is required.
    async fn start_mock_socks5(
        required_auth: Option<(String, String)>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let auth_clone = required_auth.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_conn(conn, auth_clone).await {
                        eprintln!("mock socks5 error: {e}");
                    }
                });
            }
        });
        addr
    }

    async fn handle_socks5_conn(
        mut conn: TcpStream,
        required_auth: Option<(String, String)>,
    ) -> std::io::Result<()> {
        // Read greeting: VER NMETHODS [METHODS...]
        let mut hdr = [0u8; 2];
        conn.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 {
            return Err(std::io::Error::other("bad version"));
        }
        let nmethods = hdr[1] as usize;
        let mut methods = vec![0u8; nmethods];
        conn.read_exact(&mut methods).await?;

        // Select method
        if let Some((req_user, req_pass)) = required_auth.clone() {
            // Require USERNAME_PASSWORD (0x02)
            if !methods.contains(&0x02) {
                conn.write_all(&[0x05, 0xFF]).await?;
                return Ok(());
            }
            conn.write_all(&[0x05, 0x02]).await?;

            // Read username/password sub-negotiation
            let mut sub_ver = [0u8; 1];
            conn.read_exact(&mut sub_ver).await?;
            let mut ulen_buf = [0u8; 1];
            conn.read_exact(&mut ulen_buf).await?;
            let ulen = ulen_buf[0] as usize;
            let mut user_bytes = vec![0u8; ulen];
            conn.read_exact(&mut user_bytes).await?;
            let mut plen_buf = [0u8; 1];
            conn.read_exact(&mut plen_buf).await?;
            let plen = plen_buf[0] as usize;
            let mut pass_bytes = vec![0u8; plen];
            conn.read_exact(&mut pass_bytes).await?;

            let user = String::from_utf8_lossy(&user_bytes);
            let pass = String::from_utf8_lossy(&pass_bytes);

            if user != req_user || pass != req_pass {
                // Auth failed
                conn.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }
            // Auth success
            conn.write_all(&[0x01, 0x00]).await?;
        } else {
            // No auth required
            conn.write_all(&[0x05, 0x00]).await?;
        }

        // Read CONNECT request
        let mut req_hdr = [0u8; 4];
        conn.read_exact(&mut req_hdr).await?;
        if req_hdr[0] != 0x05 || req_hdr[1] != 0x01 {
            return Err(std::io::Error::other("only CONNECT supported"));
        }

        // Read target address
        let (target_host, target_port) = read_socks5_addr(&mut conn, req_hdr[3]).await?;

        // Connect to target
        let target_addr = format!("{target_host}:{target_port}");
        let mut target = TcpStream::connect(&target_addr).await?;

        // Reply: success, bound addr 0.0.0.0:0
        conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;

        // Relay bidirectional
        let _ = copy_bidirectional(&mut conn, &mut target).await;
        Ok(())
    }

    async fn read_socks5_addr(
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
                String::from_utf8(name)
                    .map_err(|_| std::io::Error::other("invalid hostname"))?
            }
            0x04 => {
                let mut buf = [0u8; 16];
                conn.read_exact(&mut buf).await?;
                // Basic IPv6 formatting
                let segments: Vec<String> = buf
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                segments.join(":")
            }
            _ => return Err(std::io::Error::other("unknown atyp")),
        };
        let mut port_buf = [0u8; 2];
        conn.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);
        Ok((host, port))
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn socks5_tunnel_no_auth() {
        let echo_addr = start_echo_server().await;
        let proxy_addr = start_mock_socks5(None).await;

        let mut stream = dial_socks5(
            &proxy_addr.to_string(),
            "127.0.0.1",
            echo_addr.port(),
            None,
        )
        .await
        .expect("dial_socks5 should succeed");

        let msg = b"hello socks5";
        stream.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg);
    }

    #[tokio::test]
    async fn socks5_tunnel_auth_success() {
        let echo_addr = start_echo_server().await;
        let proxy_addr =
            start_mock_socks5(Some(("alice".to_string(), "s3cr3t".to_string()))).await;

        let auth = ProxyAuth {
            user: "alice".to_string(),
            pass: "s3cr3t".to_string(),
        };
        let mut stream = dial_socks5(
            &proxy_addr.to_string(),
            "127.0.0.1",
            echo_addr.port(),
            Some(&auth),
        )
        .await
        .expect("dial_socks5 with auth should succeed");

        let msg = b"authenticated round-trip";
        stream.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg);
    }

    #[tokio::test]
    async fn socks5_tunnel_auth_wrong_password() {
        let _echo_addr = start_echo_server().await;
        let proxy_addr =
            start_mock_socks5(Some(("alice".to_string(), "correct".to_string()))).await;

        let auth = ProxyAuth {
            user: "alice".to_string(),
            pass: "wrong".to_string(),
        };
        let result = dial_socks5(
            &proxy_addr.to_string(),
            "127.0.0.1",
            1234, // port doesn't matter — we never get to connect
            Some(&auth),
        )
        .await;

        assert!(
            result.is_err(),
            "wrong password should return an error, got Ok"
        );
    }
}
