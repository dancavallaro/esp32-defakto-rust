//! Closes a connection that stalls before hyper knows its HTTP version. hyper-util's `auto` builder
//! reads up to the HTTP/2 preface with no timer, and its header and keep-alive timers start only after.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use axum_server::accept::Accept;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{sleep, Sleep};

/// Must match hyper-util's `H2_PREFACE` in `server::conn::auto`.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Wraps an acceptor so each stream it yields must finish protocol detection within `timeout`.
#[derive(Clone)]
pub struct DetectTimeout<A> {
    inner: A,
    timeout: Duration,
}

impl<A> DetectTimeout<A> {
    pub fn new(inner: A, timeout: Duration) -> Self {
        DetectTimeout { inner, timeout }
    }
}

impl<A, I, S> Accept<I, S> for DetectTimeout<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = TimedStream<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accepted = self.inner.accept(stream, service);
        let timeout = self.timeout;
        Box::pin(async move {
            let (stream, service) = accepted.await?;
            Ok((TimedStream::new(stream, timeout), service))
        })
    }
}

pub struct TimedStream<T> {
    inner: T,
    /// Cleared once hyper's protocol detection is over.
    deadline: Option<Pin<Box<Sleep>>>,
    preface_matched: usize,
}

impl<T> TimedStream<T> {
    fn new(inner: T, timeout: Duration) -> Self {
        TimedStream { inner, deadline: Some(Box::pin(sleep(timeout))), preface_matched: 0 }
    }

    /// Mirrors hyper-util's `ReadVersion`: detection ends at EOF, at the first byte that diverges
    /// from the HTTP/2 preface, or once the whole preface has arrived.
    fn detection_finished(&mut self, read: &[u8]) -> bool {
        let expected = &H2_PREFACE[self.preface_matched..];
        let n = read.len().min(expected.len());
        if read.is_empty() || read[..n] != expected[..n] {
            return true;
        }
        self.preface_matched += n;
        self.preface_matched == H2_PREFACE.len()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TimedStream<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        let Some(deadline) = this.deadline.as_mut() else {
            return polled;
        };
        match polled {
            Poll::Pending => {
                ready!(deadline.as_mut().poll(cx));
                Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
            }
            Poll::Ready(Ok(())) => {
                if this.detection_finished(&buf.filled()[before..]) {
                    this.deadline = None;
                }
                Poll::Ready(Ok(()))
            }
            failed => failed,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TimedStream<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn timed(inner: tokio::io::DuplexStream, timeout: Duration) -> TimedStream<tokio::io::DuplexStream> {
        TimedStream::new(inner, timeout)
    }

    #[tokio::test]
    async fn silent_stream_times_out() {
        let (_client, server) = duplex(64);
        let mut stream = timed(server, Duration::from_millis(50));

        let err = stream.read_u8().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn stream_that_has_sent_a_byte_is_left_alone() {
        let (mut client, server) = duplex(64);
        let mut stream = timed(server, Duration::from_millis(50));

        client.write_all(b"a").await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'a');
        tokio::time::sleep(Duration::from_millis(120)).await;
        client.write_all(b"b").await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'b');
    }

    async fn read_n(stream: &mut TimedStream<tokio::io::DuplexStream>, n: usize) -> Vec<u8> {
        let mut buf = vec![0; n];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    }

    async fn assert_idle_read_stays_pending(stream: &mut TimedStream<tokio::io::DuplexStream>) {
        let idle = tokio::time::timeout(Duration::from_millis(150), stream.read_u8()).await;
        assert!(idle.is_err(), "idle read finished early: {idle:?}");
    }

    #[tokio::test]
    async fn partial_h2_preface_times_out() {
        let (mut client, server) = duplex(64);
        let mut stream = timed(server, Duration::from_millis(50));

        client.write_all(b"PRI * HT").await.unwrap();
        assert_eq!(read_n(&mut stream, 8).await, b"PRI * HT");
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read_u8()).await;
        let err = read.expect("the deadline never fired").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn full_h2_preface_clears_deadline() {
        let (mut client, server) = duplex(64);
        let mut stream = timed(server, Duration::from_millis(50));

        client.write_all(&H2_PREFACE[..10]).await.unwrap();
        assert_eq!(read_n(&mut stream, 10).await, &H2_PREFACE[..10]);
        client.write_all(&H2_PREFACE[10..]).await.unwrap();
        assert_eq!(read_n(&mut stream, 14).await, &H2_PREFACE[10..]);
        assert_idle_read_stays_pending(&mut stream).await;
    }

    #[tokio::test]
    async fn h1_request_clears_deadline_on_divergence() {
        let (mut client, server) = duplex(64);
        let mut stream = timed(server, Duration::from_millis(50));

        client.write_all(b"GET ").await.unwrap();
        assert_eq!(read_n(&mut stream, 4).await, b"GET ");
        assert_idle_read_stays_pending(&mut stream).await;
    }

    #[tokio::test]
    async fn preface_split_across_reads_is_tracked() {
        let (mut client, server) = duplex(64);
        let mut stream = timed(server, Duration::from_millis(50));

        client.write_all(b"PRI * ").await.unwrap();
        assert_eq!(read_n(&mut stream, 6).await, b"PRI * ");
        assert!(stream.deadline.is_some(), "deadline cleared mid-preface");
        client.write_all(b"HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        assert_eq!(read_n(&mut stream, 18).await, &H2_PREFACE[6..]);
        assert!(stream.deadline.is_none(), "deadline kept after the full preface");
    }
}
