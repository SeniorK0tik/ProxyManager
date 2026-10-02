//! Mock upstream proxy servers for tests (SOCKS5 and HTTP CONNECT).

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{ProxyKind, ProxyProfile};
use crate::proxy::Target;

/// What the mock does after a successful handshake.
#[derive(Debug, Clone)]
pub enum MockMode {
    /// Connect to the requested target and pipe data.
    Forward,
    /// Read the client's first chunk and answer with fixed bytes, then close.
    Respond(Vec<u8>),
    /// Refuse every CONNECT request.
    Refuse,
}

/// A running mock proxy.
pub struct MockProxy {
    pub addr: SocketAddr,
    pub kind: ProxyKind,
    auth: Option<(String, String)>,
    requests: Arc<Mutex<Vec<Target>>>,
}

impl MockProxy {
    pub async fn start(kind: ProxyKind, auth: Option<(&str, &str)>, mode: MockMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock proxy");
        let addr = listener.local_addr().unwrap();
        let auth = auth.map(|(u, p)| (u.to_string(), p.to_string()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (srv_auth, srv_requests) = (auth.clone(), requests.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (auth, requests, mode) = (srv_auth.clone(), srv_requests.clone(), mode.clone());
                tokio::spawn(async move {
                    let _ = serve(stream, kind, auth, requests, mode).await;
                });
            }
        });
        Self {
            addr,
            kind,
            auth,
            requests,
        }
    }

    /// A profile pointing at this mock.
    pub fn profile(&self, name: &str) -> ProxyProfile {
        let mut p = ProxyProfile::new(
            name,
            self.kind,
            self.addr.ip().to_string(),
            self.addr.port(),
        );
        if let Some((u, pw)) = &self.auth {
            p = p.with_auth(u.clone(), pw.clone());
        }
        p
    }

    /// Targets requested so far.
    pub fn requests(&self) -> Vec<Target> {
        self.requests.lock().clone()
    }
}

async fn serve(
    mut s: TcpStream,
    kind: ProxyKind,
    auth: Option<(String, String)>,
    requests: Arc<Mutex<Vec<Target>>>,
    mode: MockMode,
) -> std::io::Result<()> {
    let target = match kind {
        ProxyKind::Socks5 => socks5_handshake(&mut s, &auth).await?,
        ProxyKind::Http => http_handshake(&mut s, &auth).await?,
    };
    let Some(target) = target else { return Ok(()) };
    requests.lock().push(target.clone());

    let ok = !matches!(mode, MockMode::Refuse);
    match kind {
        ProxyKind::Socks5 => {
            let rep = if ok { 0 } else { 5 };
            s.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        }
        ProxyKind::Http => {
            let line: &[u8] = if ok {
                b"HTTP/1.1 200 Connection established\r\n\r\n"
            } else {
                b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
            };
            s.write_all(line).await?;
        }
    }

    match mode {
        MockMode::Refuse => Ok(()),
        MockMode::Respond(bytes) => {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await?;
            s.write_all(&bytes).await?;
            s.shutdown().await
        }
        MockMode::Forward => {
            let mut upstream = match &target {
                Target::Ip(addr) => TcpStream::connect(addr).await?,
                Target::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await?,
            };
            tokio::io::copy_bidirectional(&mut s, &mut upstream)
                .await
                .map(|_| ())
        }
    }
}

async fn socks5_handshake(
    s: &mut TcpStream,
    auth: &Option<(String, String)>,
) -> std::io::Result<Option<Target>> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut methods).await?;
    match auth {
        None => s.write_all(&[5, 0]).await?,
        Some((user, pass)) => {
            if !methods.contains(&2) {
                s.write_all(&[5, 0xff]).await?;
                return Ok(None);
            }
            s.write_all(&[5, 2]).await?;
            let mut ver_ulen = [0u8; 2];
            s.read_exact(&mut ver_ulen).await?;
            let mut u = vec![0u8; usize::from(ver_ulen[1])];
            s.read_exact(&mut u).await?;
            let plen = s.read_u8().await?;
            let mut p = vec![0u8; usize::from(plen)];
            s.read_exact(&mut p).await?;
            let ok = u == user.as_bytes() && p == pass.as_bytes();
            s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
            if !ok {
                return Ok(None);
            }
        }
    }
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    let target = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            let port = s.read_u16().await?;
            Target::Ip(SocketAddr::from((ip, port)))
        }
        4 => {
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip).await?;
            let port = s.read_u16().await?;
            Target::Ip(SocketAddr::from((ip, port)))
        }
        _ => {
            let len = s.read_u8().await?;
            let mut host = vec![0u8; usize::from(len)];
            s.read_exact(&mut host).await?;
            let port = s.read_u16().await?;
            Target::Domain(String::from_utf8_lossy(&host).into_owned(), port)
        }
    };
    Ok(Some(target))
}

async fn http_handshake(
    s: &mut TcpStream,
    auth: &Option<(String, String)>,
) -> std::io::Result<Option<Target>> {
    let mut req = Vec::new();
    let mut byte = [0u8; 1];
    // Byte by byte so that no tunnelled data is consumed.
    while !req.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        req.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&req).into_owned();
    if let Some((user, pass)) = auth {
        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        if !text.contains(&format!("Proxy-Authorization: Basic {token}")) {
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await?;
            return Ok(None);
        }
    }
    let authority = text
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let target = match authority.parse::<SocketAddr>() {
        Ok(addr) => Target::Ip(addr),
        Err(_) => {
            let (host, port) = authority.rsplit_once(':').unwrap_or((&authority, "80"));
            Target::Domain(host.to_string(), port.parse().unwrap_or(80))
        }
    };
    Ok(Some(target))
}

/// A TCP echo server, used as the final destination in tests.
pub async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}
