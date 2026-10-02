//! HTTP CONNECT client with Basic authentication.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ProxyError, Target};

const MAX_RESPONSE_HEADER: usize = 16 * 1024;

/// Sends `CONNECT` and waits for a 2xx response.
/// Returns bytes received after the response header (start of the tunnelled stream).
pub async fn http_connect<S>(
    stream: &mut S,
    target: &Target,
    auth: Option<(&str, &str)>,
) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(build_request(target, auth).as_bytes())
        .await?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_RESPONSE_HEADER {
            return Err(ProxyError::Protocol(
                "слишком длинный ответ HTTP-прокси".into(),
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(ProxyError::Protocol("HTTP-прокси закрыл соединение".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header = String::from_utf8_lossy(&buf[..header_end]);
    let status_line = header.lines().next().unwrap_or_default().trim().to_string();
    match parse_status(&status_line) {
        Some(code) if (200..300).contains(&code) => Ok(buf[header_end + 4..].to_vec()),
        Some(407) => Err(if auth.is_some() {
            ProxyError::AuthRejected
        } else {
            ProxyError::AuthRequired
        }),
        Some(_) => Err(ProxyError::Http(status_line)),
        None => Err(ProxyError::Protocol(format!(
            "некорректная строка статуса «{status_line}»"
        ))),
    }
}

fn build_request(target: &Target, auth: Option<(&str, &str)>) -> String {
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((user, pass)) = auth {
        let token = STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    req
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn run(
        target: Target,
        auth: Option<(&str, &str)>,
        response: &'static [u8],
    ) -> (Result<Vec<u8>, ProxyError>, String) {
        let (mut client, mut server) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut req = Vec::new();
            let mut buf = [0u8; 256];
            while find_header_end(&req).is_none() {
                let n = server.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
            }
            // Send in small pieces to exercise the read loop.
            for piece in response.chunks(7) {
                if server.write_all(piece).await.is_err() {
                    break;
                }
            }
            String::from_utf8(req).unwrap()
        });
        let res = http_connect(&mut client, &target, auth).await;
        drop(client);
        (res, server.await.unwrap())
    }

    #[tokio::test]
    async fn success_with_leftover() {
        let target = Target::Ip("1.2.3.4:443".parse().unwrap());
        let (res, req) = run(
            target,
            None,
            b"HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\nHELLO",
        )
        .await;
        assert_eq!(res.unwrap(), b"HELLO");
        assert!(req.starts_with("CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4:443\r\n"));
        assert!(!req.contains("Proxy-Authorization"));
    }

    #[tokio::test]
    async fn ipv6_target_and_basic_auth() {
        let target = Target::Ip("[2001:db8::1]:443".parse().unwrap());
        let (res, req) = run(target, Some(("user", "pass")), b"HTTP/1.0 200 OK\r\n\r\n").await;
        assert!(res.unwrap().is_empty());
        assert!(req.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1"));
        assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[tokio::test]
    async fn error_statuses() {
        let t = || Target::Domain("example.com".into(), 443);
        let (res, _) = run(
            t(),
            None,
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        )
        .await;
        assert!(matches!(res, Err(ProxyError::AuthRequired)));
        let (res, _) = run(
            t(),
            Some(("u", "p")),
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        )
        .await;
        assert!(matches!(res, Err(ProxyError::AuthRejected)));
        let (res, _) = run(t(), None, b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        assert!(matches!(res, Err(ProxyError::Http(ref s)) if s == "HTTP/1.1 403 Forbidden"));
        let (res, _) = run(t(), None, b"SSH-2.0-OpenSSH\r\n\r\n").await;
        assert!(matches!(res, Err(ProxyError::Protocol(_))));
        let (res, _) = run(t(), None, b"HTTP/1.1 abc\r\n\r\n").await;
        assert!(matches!(res, Err(ProxyError::Protocol(_))));
    }

    #[tokio::test]
    async fn closed_or_oversized_response() {
        let t = || Target::Domain("example.com".into(), 443);
        let (res, _) = run(t(), None, b"HTTP/1.1 200").await;
        assert!(matches!(res, Err(ProxyError::Protocol(ref m)) if m.contains("закрыл")));

        static HUGE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            let mut v = b"HTTP/1.1 200 OK\r\n".to_vec();
            v.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_HEADER + 10));
            v
        });
        let (res, _) = run(t(), None, HUGE.as_slice()).await;
        assert!(matches!(res, Err(ProxyError::Protocol(ref m)) if m.contains("длинный")));
    }

    #[test]
    fn status_parsing() {
        assert_eq!(parse_status("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status("HTTP/1.1 200"), Some(200));
        assert_eq!(parse_status("HTTP/1.1"), None);
        assert_eq!(parse_status(""), None);
        assert_eq!(parse_status("FTP 200"), None);
    }
}
