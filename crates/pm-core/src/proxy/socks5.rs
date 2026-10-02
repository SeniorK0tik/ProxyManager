//! SOCKS5 client (RFC 1928) with username/password authentication (RFC 1929).

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ProxyError, Target};

const VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub(super) fn reply_message(code: u8) -> &'static str {
    match code {
        0x01 => "общая ошибка SOCKS-сервера",
        0x02 => "соединение запрещено правилами сервера",
        0x03 => "сеть недоступна",
        0x04 => "узел недоступен",
        0x05 => "соединение отклонено целевым узлом",
        0x06 => "истёк TTL",
        0x07 => "команда не поддерживается",
        0x08 => "тип адреса не поддерживается",
        _ => "неизвестная ошибка",
    }
}

/// Performs the SOCKS5 greeting, optional authentication and CONNECT request.
pub async fn socks5_connect<S>(
    stream: &mut S,
    target: &Target,
    auth: Option<(&str, &str)>,
) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let greeting: &[u8] = if auth.is_some() {
        &[VERSION, 2, AUTH_NONE, AUTH_PASSWORD]
    } else {
        &[VERSION, 1, AUTH_NONE]
    };
    stream.write_all(greeting).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != VERSION {
        return Err(ProxyError::Protocol(format!(
            "сервер ответил версией SOCKS {}",
            reply[0]
        )));
    }
    match (reply[1], auth) {
        (AUTH_NONE, _) => {}
        (AUTH_PASSWORD, Some((user, pass))) => authenticate(stream, user, pass).await?,
        (AUTH_PASSWORD, None) => return Err(ProxyError::AuthRequired),
        (AUTH_NO_ACCEPTABLE, _) => return Err(ProxyError::NoAcceptableAuth),
        (method, _) => {
            return Err(ProxyError::Protocol(format!(
                "сервер выбрал неизвестный метод аутентификации {method:#04x}"
            )));
        }
    }

    stream.write_all(&connect_request(target)?).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(ProxyError::Protocol(format!(
            "сервер ответил версией SOCKS {}",
            head[0]
        )));
    }
    if head[1] != 0 {
        return Err(ProxyError::Socks(head[1]));
    }
    // Skip the bound address and port.
    let addr_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => usize::from(stream.read_u8().await?),
        other => {
            return Err(ProxyError::Protocol(format!(
                "неизвестный тип адреса {other:#04x}"
            )));
        }
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream.read_exact(&mut bound).await?;
    Ok(())
}

async fn authenticate<S>(stream: &mut S, user: &str, pass: &str) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (user, pass) = (user.as_bytes(), pass.as_bytes());
    let (Ok(ulen), Ok(plen)) = (u8::try_from(user.len()), u8::try_from(pass.len())) else {
        return Err(ProxyError::Protocol(
            "логин или пароль длиннее 255 байт".into(),
        ));
    };
    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.push(0x01);
    msg.push(ulen);
    msg.extend_from_slice(user);
    msg.push(plen);
    msg.extend_from_slice(pass);
    stream.write_all(&msg).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(ProxyError::AuthRejected);
    }
    Ok(())
}

fn connect_request(target: &Target) -> Result<Vec<u8>, ProxyError> {
    let mut req = vec![VERSION, CMD_CONNECT, 0x00];
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&a.ip().octets());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&a.ip().octets());
        }
        Target::Domain(host, _) => {
            let len = u8::try_from(host.len())
                .ok()
                .filter(|&l| l > 0)
                .ok_or_else(|| ProxyError::Protocol("недопустимая длина доменного имени".into()))?;
            req.push(ATYP_DOMAIN);
            req.push(len);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Runs the client against a scripted server: `script` gets the server half of the pipe.
    async fn run<F, Fut>(
        target: Target,
        auth: Option<(&str, &str)>,
        script: F,
    ) -> Result<(), ProxyError>
    where
        F: FnOnce(tokio::io::DuplexStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (mut client, server) = duplex(1024);
        let server = tokio::spawn(script(server));
        let res = socks5_connect(&mut client, &target, auth).await;
        drop(client);
        server.await.unwrap();
        res
    }

    async fn expect(s: &mut tokio::io::DuplexStream, bytes: &[u8]) {
        let mut buf = vec![0u8; bytes.len()];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, bytes);
    }

    fn v4() -> Target {
        Target::Ip("1.2.3.4:443".parse().unwrap())
    }

    #[tokio::test]
    async fn no_auth_ipv4() {
        run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 0]).await.unwrap();
            expect(&mut s, &[5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xbb]).await;
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn password_auth_ipv6_and_domain_bind() {
        let target = Target::Ip("[2001:db8::1]:80".parse().unwrap());
        run(target, Some(("user", "pw")), |mut s| async move {
            expect(&mut s, &[5, 2, 0, 2]).await;
            s.write_all(&[5, 2]).await.unwrap();
            expect(&mut s, &[1, 4, b'u', b's', b'e', b'r', 2, b'p', b'w']).await;
            s.write_all(&[1, 0]).await.unwrap();
            let mut req = vec![5, 1, 0, 4, 0x20, 0x01, 0x0d, 0xb8];
            req.extend_from_slice(&[0; 11]);
            req.extend_from_slice(&[1, 0, 80]);
            expect(&mut s, &req).await;
            s.write_all(&[5, 0, 0, 3, 3, b'a', b'b', b'c', 0, 1])
                .await
                .unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn domain_target_and_ipv6_bind() {
        let target = Target::Domain("example.com".into(), 8080);
        run(target, None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = vec![5, 1, 0, 3, 11];
            req.extend_from_slice(b"example.com");
            req.extend_from_slice(&8080u16.to_be_bytes());
            expect(&mut s, &req).await;
            let mut reply = vec![5, 0, 0, 4];
            reply.extend_from_slice(&[0; 18]);
            s.write_all(&reply).await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn auth_failures() {
        let err = run(v4(), Some(("u", "bad")), |mut s| async move {
            expect(&mut s, &[5, 2, 0, 2]).await;
            s.write_all(&[5, 2]).await.unwrap();
            expect(&mut s, &[1, 1, b'u', 3, b'b', b'a', b'd']).await;
            s.write_all(&[1, 1]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::AuthRejected));

        let err = run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 2]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::AuthRequired));

        let err = run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 0xff]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::NoAcceptableAuth));

        let err = run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 0x80]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::Protocol(_)));
    }

    #[tokio::test]
    async fn too_long_credentials() {
        let long = "x".repeat(300);
        let err = run(v4(), Some((&long, "p")), |mut s| async move {
            expect(&mut s, &[5, 2, 0, 2]).await;
            s.write_all(&[5, 2]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::Protocol(_)));
    }

    #[tokio::test]
    async fn connect_refused_and_protocol_errors() {
        let err = run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[5, 5, 0, 1]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::Socks(5)));

        let err = run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[4, 0]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(
            matches!(err, ProxyError::Protocol(_)),
            "bad greeting version"
        );

        let err = run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[4, 0, 0, 1]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::Protocol(_)), "bad reply version");

        let err = run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[5, 0, 0, 9]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::Protocol(_)), "bad address type");

        let err = run(v4(), None, |mut s| async move {
            expect(&mut s, &[5, 1, 0]).await;
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[5, 0, 0, 1, 1]).await.unwrap();
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::Io(_)), "truncated reply");
    }

    #[test]
    fn invalid_domains() {
        assert!(connect_request(&Target::Domain(String::new(), 1)).is_err());
        assert!(connect_request(&Target::Domain("a".repeat(256), 1)).is_err());
    }

    #[test]
    fn reply_messages() {
        for code in 0..=9u8 {
            assert!(!reply_message(code).is_empty());
        }
        assert_eq!(reply_message(0x07), "команда не поддерживается");
    }
}
