//! HTTP CONNECT proxy dialer (RFC 7231 §4.3.6).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use vaiexia_core::transport::proxy::ProxyAuth;

// ── Public API ────────────────────────────────────────────────────────────────

/// Connect to `proxy_addr` via TCP, then perform HTTP CONNECT to
/// `target_host:target_port`.  Returns the ready-to-use stream.
pub async fn dial_http_connect(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    auth: Option<&ProxyAuth>,
) -> crate::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    tunnel_http_connect(&mut stream, target_host, target_port, auth).await?;
    Ok(stream)
}

/// Run the HTTP CONNECT tunnel negotiation on an already-connected stream.
///
/// On success the stream is positioned immediately after the blank line
/// terminating the proxy response and can be used to talk to the target.
pub async fn tunnel_http_connect<S>(
    io: &mut S,
    target_host: &str,
    target_port: u16,
    auth: Option<&ProxyAuth>,
) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ── Build the CONNECT request ─────────────────────────────────────────────
    let mut request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n",
        host = target_host,
        port = target_port,
    );

    if let Some(creds) = auth {
        let credentials = format!("{}:{}", creds.user, creds.pass);
        let encoded = base64_encode(credentials.as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }

    request.push_str("\r\n");
    io.write_all(request.as_bytes()).await?;

    // ── Read response until \r\n\r\n ──────────────────────────────────────────
    // Buffer byte-by-byte, limit to 8192 bytes to avoid memory blow-up.
    let mut response_buf = Vec::with_capacity(256);
    const MAX_RESPONSE: usize = 8192;
    let mut byte = [0u8; 1];

    loop {
        io.read_exact(&mut byte).await?;
        response_buf.push(byte[0]);

        if response_buf.len() > MAX_RESPONSE {
            return Err(io_err("HTTP CONNECT: response header too large"));
        }

        // Detect end of headers: \r\n\r\n
        if response_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    // ── Parse status line ─────────────────────────────────────────────────────
    // e.g. "HTTP/1.1 200 Connection Established"
    let response_str = std::str::from_utf8(&response_buf)
        .map_err(|_| io_err("HTTP CONNECT: non-UTF8 response"))?;

    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| io_err("HTTP CONNECT: empty response"))?;

    // Split off the version token, then parse the status code.
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next(); // e.g. "HTTP/1.1"
    let code_str = parts
        .next()
        .ok_or_else(|| io_err("HTTP CONNECT: malformed status line"))?;

    let status_code: u16 = code_str
        .parse()
        .map_err(|_| io_err("HTTP CONNECT: non-numeric status code"))?;

    if status_code != 200 {
        return Err(io_err(&format!(
            "HTTP CONNECT: proxy returned status {status_code}"
        )));
    }

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn io_err(msg: &str) -> crate::ObfsError {
    crate::ObfsError::Io(std::io::Error::other(msg))
}

/// Standard Base64 encoder — no external dependencies.
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[(n >> 18) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

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

    /// Mock HTTP CONNECT proxy.
    ///
    /// `required_auth`: `Some((user, pass))` → require Proxy-Authorization header.
    /// `respond_with`: the HTTP status line to send (without trailing CRLF) — e.g.
    ///   `"HTTP/1.1 200 Connection Established"` for success,
    ///   `"HTTP/1.1 407 Proxy Auth Required"` to test failure.
    async fn start_mock_http_connect(
        required_auth: Option<(String, String)>,
        respond_with: &'static str,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let auth_clone = required_auth.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_http_connect_conn(conn, auth_clone, respond_with).await
                    {
                        eprintln!("mock http-connect error: {e}");
                    }
                });
            }
        });
        addr
    }

    async fn handle_http_connect_conn(
        mut conn: TcpStream,
        required_auth: Option<(String, String)>,
        respond_with: &str,
    ) -> std::io::Result<()> {
        // Read request until \r\n\r\n
        let mut req_buf = Vec::with_capacity(256);
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

        // Check auth if required
        if let Some((req_user, req_pass)) = required_auth {
            let expected_creds = format!("{}:{}", req_user, req_pass);
            let expected_b64 = super::base64_encode(expected_creds.as_bytes());
            let auth_header = format!("Proxy-Authorization: Basic {expected_b64}");
            if !req_str.contains(&auth_header) {
                // Auth failed — send 407 and bail
                conn.write_all(b"HTTP/1.1 407 Proxy Auth Required\r\n\r\n")
                    .await?;
                return Ok(());
            }
        }

        // Parse CONNECT target from first line
        // "CONNECT host:port HTTP/1.1"
        let first_line = req_str.lines().next().unwrap_or("");
        let mut parts = first_line.split_whitespace();
        let _method = parts.next(); // "CONNECT"
        let target = parts.next().unwrap_or("");

        // Build response
        conn.write_all(format!("{respond_with}\r\n\r\n").as_bytes())
            .await?;

        // Only relay if 200
        if respond_with.contains("200") {
            let mut target_conn = TcpStream::connect(target).await?;
            let _ = copy_bidirectional(&mut conn, &mut target_conn).await;
        }

        Ok(())
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn http_connect_tunnel_no_auth() {
        let echo_addr = start_echo_server().await;
        let proxy_addr =
            start_mock_http_connect(None, "HTTP/1.1 200 Connection Established").await;

        let mut stream = dial_http_connect(
            &proxy_addr.to_string(),
            "127.0.0.1",
            echo_addr.port(),
            None,
        )
        .await
        .expect("dial_http_connect should succeed");

        let msg = b"http-connect round-trip";
        stream.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg);
    }

    #[tokio::test]
    async fn http_connect_tunnel_auth_success() {
        let echo_addr = start_echo_server().await;
        let proxy_addr = start_mock_http_connect(
            Some(("bob".to_string(), "passw0rd".to_string())),
            "HTTP/1.1 200 Connection Established",
        )
        .await;

        let auth = ProxyAuth {
            user: "bob".to_string(),
            pass: "passw0rd".to_string(),
        };
        let mut stream = dial_http_connect(
            &proxy_addr.to_string(),
            "127.0.0.1",
            echo_addr.port(),
            Some(&auth),
        )
        .await
        .expect("dial_http_connect with auth should succeed");

        let msg = b"authenticated http-connect";
        stream.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg);
    }

    #[tokio::test]
    async fn http_connect_non_200_response() {
        let proxy_addr =
            start_mock_http_connect(None, "HTTP/1.1 407 Proxy Auth Required").await;

        let result = dial_http_connect(
            &proxy_addr.to_string(),
            "127.0.0.1",
            1234, // port doesn't matter
            None,
        )
        .await;

        assert!(
            result.is_err(),
            "non-200 response should return an error, got Ok"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("407"),
            "error should mention status 407, got: {err}"
        );
    }
}
