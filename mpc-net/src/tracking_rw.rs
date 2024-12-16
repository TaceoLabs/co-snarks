use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A wrapper around [`AsyncRead`] types that keeps track of the number of read bytes
pub(crate) struct TrackingAsyncReader<R> {
    inner: R,
    bytes_read: Arc<AtomicUsize>,
}

impl<R: AsyncRead> TrackingAsyncReader<R> {
    pub fn new(inner: R, bytes_read: Arc<AtomicUsize>) -> Self {
        Self { inner, bytes_read }
    }

    #[allow(unused)]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for TrackingAsyncReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = Pin::new(&mut self.inner);
        let initial_len = buf.filled().len();
        let res = inner.poll_read(cx, buf);

        // if the read was ok, update bytes_read
        if let Poll::Ready(Ok(())) = &res {
            self.bytes_read
                .fetch_add(buf.filled().len() - initial_len, Ordering::SeqCst);
        }

        res
    }
}

/// A wrapper around [`AsyncWrite`] types that keeps track of the number of written bytes
pub(crate) struct TrackingAsyncWriter<W> {
    inner: W,
    bytes_written: Arc<AtomicUsize>,
}

impl<W: AsyncWrite> TrackingAsyncWriter<W> {
    pub fn new(inner: W, bytes_written: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            bytes_written,
        }
    }

    #[allow(unused)]
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TrackingAsyncWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = Pin::new(&mut self.inner);
        let res = inner.poll_write(cx, buf);

        // if the write was ok, update bytes_written
        if let Poll::Ready(Ok(bytes_written)) = &res {
            self.bytes_written
                .fetch_add(*bytes_written, Ordering::SeqCst);
        }

        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let inner = Pin::new(&mut self.inner);
        let res = inner.poll_write_vectored(cx, bufs);

        // if the write was ok, update bytes_written
        if let Poll::Ready(Ok(bytes_written)) = &res {
            self.bytes_written
                .fetch_add(*bytes_written, Ordering::SeqCst);
        }

        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
