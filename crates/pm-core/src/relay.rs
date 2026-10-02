//! Local relay: accepts redirected connections and tunnels them through upstream proxies.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::nat::{NatTable, nat_key};
use crate::proxy::{self, Target};
use crate::rules::ResolvedAction;
use crate::tracker::{ConnHandle, ConnMeta, Tracker};

/// IPv4 and (when available) IPv6 listeners sharing one port.
pub struct RelayListeners {
    pub port: u16,
    v4: TcpListener,
    v6: Option<TcpListener>,
}

impl RelayListeners {
    pub fn has_ipv6(&self) -> bool {
        self.v6.is_some()
    }

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        match &self.v6 {
            Some(v6) => tokio::select! {
                r = self.v4.accept() => r,
                r = v6.accept() => r,
            },
            None => self.v4.accept().await,
        }
    }
}

fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Binds the relay on all interfaces. With `port == 0` an ephemeral port is chosen
/// that is free for both IPv4 and IPv6. Must be called inside a Tokio runtime.
pub async fn bind(port: u16) -> io::Result<RelayListeners> {
    let attempts = if port == 0 { 16 } else { 1 };
    let mut last_v6_error = None;
    for _ in 0..attempts {
        let v4 = listen(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
        let actual = v4.local_addr()?.port();
        match listen(SocketAddr::from((Ipv6Addr::UNSPECIFIED, actual))) {
            Ok(v6) => {
                return Ok(RelayListeners {
                    port: actual,
                    v4,
                    v6: Some(v6),
                });
            }
            Err(e) => last_v6_error = Some(e),
        }
    }
    // IPv6 may be disabled on the machine: work with IPv4 only.
    warn!(error = ?last_v6_error, "relay: IPv6 listener unavailable, IPv6 traffic will not be proxied");
    let v4 = listen(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
    Ok(RelayListeners {
        port: v4.local_addr()?.port(),
        v4,
        v6: None,
    })
}

/// Serves connections redirected by the NAT engine.
pub struct Relay {
    nat: Arc<NatTable>,
    tracker: Arc<Tracker>,
    connect_timeout_ms: AtomicU64,
}

impl Relay {
    pub fn new(nat: Arc<NatTable>, tracker: Arc<Tracker>, connect_timeout: Duration) -> Self {
        Self {
            nat,
            tracker,
            connect_timeout_ms: AtomicU64::new(connect_timeout.as_millis() as u64),
        }
    }

    pub fn set_connect_timeout(&self, timeout: Duration) {
        self.connect_timeout_ms
            .store(timeout.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.load(Ordering::Relaxed))
    }

    /// Accept loop. Returns when `shutdown` becomes `true` (or its sender is dropped);
    /// all connections in flight are aborted.
    pub async fn run(
        self: Arc<Self>,
        listeners: RelayListeners,
        mut shutdown: watch::Receiver<bool>,
    ) {
        info!(
            port = listeners.port,
            ipv6 = listeners.has_ipv6(),
            "relay started"
        );
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                () = stopped(&mut shutdown) => break,
                res = listeners.accept() => match res {
                    Ok((stream, peer)) => {
                        tasks.spawn(self.clone().serve(stream, peer));
                    }
                    Err(e) => {
                        warn!(error = %e, "relay: accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.shutdown().await;
        info!("relay stopped");
    }

    async fn serve(self: Arc<Self>, client: TcpStream, peer: SocketAddr) {
        let key = nat_key(peer.ip(), peer.port());
        let Some(guard) = self.nat.claim(key) else {
            debug!(%peer, "relay: connection without NAT entry rejected");
            reset(&client);
            return;
        };
        let entry = guard.entry().clone();
        let ResolvedAction::Proxy(profile) = &entry.decision.action else {
            reset(&client);
            return;
        };
        let conn = self.tracker.open(ConnMeta {
            pid: entry.decision.pid,
            process: entry.decision.process.clone(),
            rule: entry.decision.rule.clone(),
            proxy: Arc::from(profile.name.as_str()),
            target: entry.orig_dst,
        });
        client.set_nodelay(true).ok();

        match proxy::connect(profile, &Target::Ip(entry.orig_dst), self.connect_timeout()).await {
            Ok((upstream, leftover)) => {
                conn.established();
                debug!(target = %entry.orig_dst, proxy = %profile.name, "tunnel established");
                if let Err(e) = pipe(client, upstream, leftover, &conn).await {
                    debug!(target = %entry.orig_dst, error = %e, "tunnel closed with error");
                }
            }
            Err(e) => {
                warn!(target = %entry.orig_dst, proxy = %profile.name, process = ?entry.decision.process, error = %e, "tunnel failed");
                conn.fail(e.to_string());
                reset(&client);
            }
        }
        drop(guard);
    }
}

/// Resolves once the flag becomes `true` or the sender is gone.
async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

/// Closes the socket with RST so the application fails fast.
fn reset(stream: &TcpStream) {
    let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

async fn pipe(
    client: TcpStream,
    upstream: TcpStream,
    leftover: Vec<u8>,
    conn: &ConnHandle,
) -> io::Result<()> {
    let mut client = Counted::new(client, conn.up_counter());
    let mut upstream = Counted::new(upstream, conn.down_counter());
    if !leftover.is_empty() {
        client.write_all(&leftover).await?;
        conn.down_counter()
            .fetch_add(leftover.len() as u64, Ordering::Relaxed);
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Counts bytes read from the inner stream.
pub struct Counted<S> {
    inner: S,
    read: Arc<AtomicU64>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, read: Arc<AtomicU64>) -> Self {
        Self { inner, read }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.read.fetch_add(n as u64, Ordering::Relaxed);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyKind, ProxyProfile};
    use crate::policy::FlowDecision;
    use crate::testing::{MockMode, MockProxy, echo_server};
    use crate::tracker::ConnStatus;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpSocket;

    struct Harness {
        relay: Arc<Relay>,
        nat: Arc<NatTable>,
        tracker: Arc<Tracker>,
        port: u16,
        stop: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
    }

    async fn harness() -> Harness {
        let nat = Arc::new(NatTable::default());
        let tracker = Arc::new(Tracker::default());
        let relay = Arc::new(Relay::new(
            nat.clone(),
            tracker.clone(),
            Duration::from_secs(5),
        ));
        let listeners = bind(0).await.unwrap();
        let port = listeners.port;
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(relay.clone().run(listeners, rx));
        Harness {
            relay,
            nat,
            tracker,
            port,
            stop,
            task,
        }
    }

    fn decision(action: ResolvedAction) -> FlowDecision {
        FlowDecision {
            pid: Some(7),
            process: Some(Arc::from("C:\\app.exe")),
            rule: Some(Arc::from("rule")),
            action,
        }
    }

    /// Connects to the relay from a known local port after registering a NAT entry for it.
    async fn connect_redirected(
        h: &Harness,
        orig_dst: SocketAddr,
        action: Option<ResolvedAction>,
    ) -> TcpStream {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = socket.local_addr().unwrap();
        if let Some(action) = action {
            h.nat.insert(
                nat_key(local.ip(), local.port()),
                orig_dst,
                decision(action),
            );
        }
        socket
            .connect(SocketAddr::from(([127, 0, 0, 1], h.port)))
            .await
            .unwrap()
    }

    async fn roundtrip(stream: &mut TcpStream, data: &[u8]) -> Vec<u8> {
        stream.write_all(data).await.unwrap();
        let mut buf = vec![0u8; data.len()];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    }

    async fn wait_until(mut cond: impl FnMut() -> bool) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test]
    async fn tunnels_through_socks5() {
        let h = harness().await;
        let echo = echo_server().await;
        let proxy = MockProxy::start(ProxyKind::Socks5, Some(("u", "p")), MockMode::Forward).await;
        let profile = Arc::new(proxy.profile("socks"));

        let mut s = connect_redirected(&h, echo, Some(ResolvedAction::Proxy(profile))).await;
        assert_eq!(roundtrip(&mut s, b"hello relay").await, b"hello relay");
        assert_eq!(proxy.requests(), vec![Target::Ip(echo)]);

        let snap = h.tracker.snapshot();
        assert_eq!(snap.active.len(), 1);
        let c = &snap.active[0];
        assert_eq!(c.status, ConnStatus::Open);
        assert_eq!(
            (c.meta.pid, c.meta.target, c.meta.proxy.as_ref()),
            (Some(7), echo, "socks")
        );
        assert_eq!((c.up, c.down), (11, 11));

        drop(s);
        wait_until(|| h.tracker.active_count() == 0).await;
        assert_eq!(h.tracker.snapshot().recent[0].status, ConnStatus::Closed);
        h.stop.send(true).unwrap();
        h.task.await.unwrap();
    }

    #[tokio::test]
    async fn tunnels_through_http_connect() {
        let h = harness().await;
        let echo = echo_server().await;
        let proxy =
            MockProxy::start(ProxyKind::Http, Some(("user", "secret")), MockMode::Forward).await;
        let mut s = connect_redirected(
            &h,
            echo,
            Some(ResolvedAction::Proxy(Arc::new(proxy.profile("http")))),
        )
        .await;
        assert_eq!(roundtrip(&mut s, b"ping").await, b"ping");
        assert_eq!(proxy.requests(), vec![Target::Ip(echo)]);
    }

    #[tokio::test]
    async fn forwards_bytes_sent_with_the_connect_response() {
        let h = harness().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\nWELCOME")
                .await
                .unwrap();
            let mut hold = [0u8; 1];
            let _ = s.read(&mut hold).await;
        });
        let profile = ProxyProfile::new("http", ProxyKind::Http, "127.0.0.1", addr.port());
        let mut s = connect_redirected(
            &h,
            "1.2.3.4:80".parse().unwrap(),
            Some(ResolvedAction::Proxy(Arc::new(profile))),
        )
        .await;
        let mut buf = [0u8; 7];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"WELCOME");
        wait_until(|| h.tracker.snapshot().total_down == 7).await;
    }

    async fn assert_closed(mut s: TcpStream) {
        let mut buf = [0u8; 16];
        let res = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("closed in time");
        assert!(matches!(res, Ok(0) | Err(_)), "{res:?}");
    }

    #[tokio::test]
    async fn rejects_unknown_peers_and_non_proxy_entries() {
        let h = harness().await;
        let s = connect_redirected(&h, "1.2.3.4:80".parse().unwrap(), None).await;
        assert_closed(s).await;
        let s = connect_redirected(
            &h,
            "1.2.3.4:80".parse().unwrap(),
            Some(ResolvedAction::Direct),
        )
        .await;
        assert_closed(s).await;
        assert_eq!(h.tracker.snapshot().total_connections, 0);
    }

    #[tokio::test]
    async fn proxy_failure_is_tracked_and_closes_client() {
        let h = harness().await;
        let proxy = MockProxy::start(ProxyKind::Socks5, None, MockMode::Refuse).await;
        let s = connect_redirected(
            &h,
            "1.2.3.4:80".parse().unwrap(),
            Some(ResolvedAction::Proxy(Arc::new(proxy.profile("p")))),
        )
        .await;
        assert_closed(s).await;
        wait_until(|| h.tracker.snapshot().failed_connections == 1).await;
        let snap = h.tracker.snapshot();
        assert!(matches!(&snap.recent[0].status, ConnStatus::Failed(m) if m.contains("отклонено")));
    }

    #[tokio::test]
    async fn nat_entry_is_released_after_close() {
        let h = harness().await;
        let echo = echo_server().await;
        let proxy = MockProxy::start(ProxyKind::Socks5, None, MockMode::Forward).await;
        let mut s = connect_redirected(
            &h,
            echo,
            Some(ResolvedAction::Proxy(Arc::new(proxy.profile("p")))),
        )
        .await;
        let key = nat_key(s.local_addr().unwrap().ip(), s.local_addr().unwrap().port());
        roundtrip(&mut s, b"x").await;
        assert_eq!(
            h.nat.get(&key).unwrap().state,
            crate::nat::EntryState::Active
        );
        drop(s);
        wait_until(|| {
            matches!(
                h.nat.get(&key).map(|e| e.state),
                Some(crate::nat::EntryState::Closed(_))
            )
        })
        .await;
    }

    #[tokio::test]
    async fn shutdown_aborts_open_connections() {
        let h = harness().await;
        let echo = echo_server().await;
        let proxy = MockProxy::start(ProxyKind::Socks5, None, MockMode::Forward).await;
        let mut s = connect_redirected(
            &h,
            echo,
            Some(ResolvedAction::Proxy(Arc::new(proxy.profile("p")))),
        )
        .await;
        roundtrip(&mut s, b"x").await;
        h.stop.send(true).unwrap();
        h.task.await.unwrap();
        assert_closed(s).await;
        assert_eq!(h.tracker.active_count(), 0);
    }

    #[tokio::test]
    async fn dropping_the_sender_also_stops() {
        let h = harness().await;
        drop(h.stop);
        tokio::time::timeout(Duration::from_secs(5), h.task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn timeout_is_adjustable() {
        let h = harness().await;
        assert_eq!(h.relay.connect_timeout(), Duration::from_secs(5));
        h.relay.set_connect_timeout(Duration::from_millis(1500));
        assert_eq!(h.relay.connect_timeout(), Duration::from_millis(1500));
    }

    #[tokio::test]
    async fn bind_fixed_port_and_ipv6() {
        let first = bind(0).await.unwrap();
        assert!(first.port != 0);
        // The same port cannot be bound twice.
        assert!(bind(first.port).await.is_err());
        if first.has_ipv6() {
            let s = TcpStream::connect(SocketAddr::from((Ipv6Addr::LOCALHOST, first.port)))
                .await
                .unwrap();
            let (_, peer) = first.accept().await.unwrap();
            assert_eq!(peer, s.local_addr().unwrap());
        }
    }
}
