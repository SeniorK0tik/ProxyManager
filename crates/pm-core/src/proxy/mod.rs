//! Upstream proxy clients.

mod http;
mod socks5;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{ProxyKind, ProxyProfile};

pub use http::http_connect;
pub use socks5::socks5_connect;

/// Where the tunnel should lead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Target::Ip(addr) => addr.port(),
            Target::Domain(_, port) => *port,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(addr) => write!(f, "{addr}"),
            Target::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

impl From<SocketAddr> for Target {
    fn from(addr: SocketAddr) -> Self {
        Target::Ip(addr)
    }
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("не удалось подключиться к прокси: {0}")]
    Connect(#[source] io::Error),
    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] io::Error),
    #[error("превышено время ожидания")]
    Timeout,
    #[error("прокси не поддерживает предложенные способы аутентификации")]
    NoAcceptableAuth,
    #[error("прокси требует логин и пароль")]
    AuthRequired,
    #[error("прокси отклонил логин или пароль")]
    AuthRejected,
    #[error("SOCKS5: {}", socks5::reply_message(*.0))]
    Socks(u8),
    #[error("HTTP-прокси ответил: {0}")]
    Http(String),
    #[error("нарушение протокола: {0}")]
    Protocol(String),
}

/// Opens a tunnel to `target` through `profile`.
///
/// Returns the stream and any bytes the proxy sent after its handshake response;
/// those belong to the tunnelled connection and must be forwarded first.
pub async fn connect(
    profile: &ProxyProfile,
    target: &Target,
    timeout: Duration,
) -> Result<(TcpStream, Vec<u8>), ProxyError> {
    let work = async {
        let mut stream = TcpStream::connect((profile.host.as_str(), profile.port))
            .await
            .map_err(ProxyError::Connect)?;
        stream.set_nodelay(true).ok();
        let leftover = handshake(&mut stream, profile, target).await?;
        Ok((stream, leftover))
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| ProxyError::Timeout)?
}

/// Runs the proxy handshake on an already connected stream.
pub async fn handshake<S>(
    stream: &mut S,
    profile: &ProxyProfile,
    target: &Target,
) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match profile.kind {
        ProxyKind::Socks5 => socks5_connect(stream, target, profile.credentials())
            .await
            .map(|()| Vec::new()),
        ProxyKind::Http => http_connect(stream, target, profile.credentials()).await,
    }
}

/// Result of a successful proxy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// Time to establish the tunnel.
    pub connect_time: Duration,
    /// Total time including the HTTP probe.
    pub total_time: Duration,
    /// First line of the HTTP response received through the tunnel.
    pub status_line: String,
}

/// Default host used by the "check proxy" button.
pub const CHECK_HOST: &str = "detectportal.firefox.com";
pub const CHECK_PATH: &str = "/success.txt";

/// Checks a proxy end-to-end: opens a tunnel to `host:port` and sends an HTTP GET.
pub async fn check(
    profile: &ProxyProfile,
    host: &str,
    port: u16,
    path: &str,
    timeout: Duration,
) -> Result<CheckReport, ProxyError> {
    let started = Instant::now();
    let work = async {
        let target = match host.parse() {
            Ok(ip) => Target::Ip(SocketAddr::new(ip, port)),
            Err(_) => Target::Domain(host.to_string(), port),
        };
        let mut stream = TcpStream::connect((profile.host.as_str(), profile.port))
            .await
            .map_err(ProxyError::Connect)?;
        let mut response = handshake(&mut stream, profile, &target).await?;
        let connect_time = started.elapsed();

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ProxyManager\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let mut buf = [0u8; 1024];
        while !response.contains(&b'\n') {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
        }
        let status_line = String::from_utf8_lossy(&response)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if !status_line.starts_with("HTTP/") {
            return Err(ProxyError::Protocol(format!(
                "неожиданный ответ сервера: «{status_line}»"
            )));
        }
        Ok(CheckReport {
            connect_time,
            total_time: started.elapsed(),
            status_line,
        })
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| ProxyError::Timeout)?
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn target_display_and_port() {
        let t = Target::from("[::1]:443".parse::<SocketAddr>().unwrap());
        assert_eq!(t.to_string(), "[::1]:443");
        assert_eq!(t.port(), 443);
        let t = Target::Domain("example.com".into(), 80);
        assert_eq!(t.to_string(), "example.com:80");
        assert_eq!(t.port(), 80);
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            ProxyError::Socks(5).to_string(),
            "SOCKS5: соединение отклонено целевым узлом"
        );
        assert_eq!(ProxyError::Timeout.to_string(), "превышено время ожидания");
        assert!(ProxyError::Http("407".into()).to_string().contains("407"));
    }

    /// Mock HTTP CONNECT proxy that serves a fixed response itself instead of connecting anywhere.
    async fn fake_http_proxy(response: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut got = Vec::new();
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
            }
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            // Read the probe request, then answer.
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(response).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn check_reports_status_line() {
        let addr = fake_http_proxy(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nsuccess").await;
        let profile = ProxyProfile::new("t", ProxyKind::Http, addr.ip().to_string(), addr.port());
        let report = check(&profile, CHECK_HOST, 80, CHECK_PATH, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(report.status_line, "HTTP/1.1 200 OK");
        assert!(report.total_time >= report.connect_time);
    }

    #[tokio::test]
    async fn check_rejects_non_http_answer() {
        let addr = fake_http_proxy(b"garbage\n").await;
        let profile = ProxyProfile::new("t", ProxyKind::Http, addr.ip().to_string(), addr.port());
        let err = check(&profile, "1.2.3.4", 80, "/", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Protocol(_)), "{err}");
    }

    #[tokio::test]
    async fn check_handles_empty_answer() {
        let addr = fake_http_proxy(b"").await;
        let profile = ProxyProfile::new("t", ProxyKind::Http, addr.ip().to_string(), addr.port());
        let err = check(&profile, "1.2.3.4", 80, "/", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Protocol(_)), "{err}");
    }

    #[tokio::test]
    async fn connect_and_check_fail_when_proxy_is_down() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let profile = ProxyProfile::new("t", ProxyKind::Socks5, "127.0.0.1", port);
        let target = Target::Ip("1.2.3.4:80".parse().unwrap());
        let err = connect(&profile, &target, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Connect(_)), "{err}");
        let err = check(&profile, "x", 80, "/", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Connect(_)), "{err}");
    }

    #[tokio::test]
    async fn connect_and_check_time_out_on_silent_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (s, _) = listener.accept().await.unwrap();
                held.push(s);
            }
        });
        let profile = ProxyProfile::new("t", ProxyKind::Socks5, "127.0.0.1", addr.port());
        let target = Target::Ip("1.2.3.4:80".parse().unwrap());
        let err = connect(&profile, &target, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Timeout));
        let err = check(&profile, "x", 80, "/", Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Timeout));
    }
}
