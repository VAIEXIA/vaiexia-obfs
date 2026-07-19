pub mod http_connect;
pub mod socks5;

use tokio::net::TcpStream;
use vaiexia_core::transport::proxy::{ProxyAuth, ProxyConfig, ProxyKind};

/// Parse `"host:port"` into `(host, port)`.
pub(crate) fn parse_addr(addr: &str) -> crate::Result<(String, u16)> {
    let colon = addr
        .rfind(':')
        .ok_or_else(|| crate::ObfsError::Io(std::io::Error::other("invalid proxy addr")))?;
    let host = addr[..colon].to_string();
    let port: u16 = addr[colon + 1..]
        .parse()
        .map_err(|_| crate::ObfsError::Io(std::io::Error::other("invalid proxy port")))?;
    Ok((host, port))
}

/// Dial through a (possibly chained) proxy to `target_host:target_port`.
///
/// Builds the full hop list (first-hop from `proxy` fields, then `proxy.chain`),
/// connects TCP to the first hop, and runs the appropriate tunnel negotiation
/// for each hop in sequence.
pub async fn dial(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> crate::Result<TcpStream> {
    // Build a flat hop list: (kind, addr, auth_ref)
    // We store clones so we can reference them during iteration.
    #[derive(Clone)]
    struct Hop {
        kind: ProxyKind,
        addr: String,
        auth: Option<ProxyAuth>,
    }

    let mut hops: Vec<Hop> = Vec::with_capacity(1 + proxy.chain.len());
    hops.push(Hop {
        kind: proxy.kind.clone(),
        addr: proxy.addr.clone(),
        auth: proxy.auth.clone(),
    });
    for h in &proxy.chain {
        hops.push(Hop {
            kind: h.kind.clone(),
            addr: h.addr.clone(),
            auth: h.auth.clone(),
        });
    }

    // Connect TCP to the first hop.
    let mut stream = TcpStream::connect(&hops[0].addr).await?;

    // For each hop, tunnel to the next destination.
    for i in 0..hops.len() {
        let (next_host, next_port) = if i + 1 < hops.len() {
            parse_addr(&hops[i + 1].addr)?
        } else {
            (target_host.to_string(), target_port)
        };

        match hops[i].kind {
            ProxyKind::Socks5 => {
                socks5::tunnel_socks5(
                    &mut stream,
                    &next_host,
                    next_port,
                    hops[i].auth.as_ref(),
                )
                .await?
            }
            ProxyKind::HttpConnect => {
                http_connect::tunnel_http_connect(
                    &mut stream,
                    &next_host,
                    next_port,
                    hops[i].auth.as_ref(),
                )
                .await?
            }
        }
    }

    Ok(stream)
}
