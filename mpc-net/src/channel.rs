//! A channel abstraction for sending and receiving messages.
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::{io, marker::Unpin, pin::Pin};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Handle,
    sync::{mpsc, oneshot},
    task::{JoinError, JoinHandle},
};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::codecs::BincodeCodec;

/// A read end of the channel, just a type alias for [`FramedRead`].
pub type ReadChannel<T, D> = FramedRead<T, D>;
/// A write end of the channel, just a type alias for [`FramedWrite`].
pub type WriteChannel<T, E> = FramedWrite<T, E>;

/// A channel that uses a [`Encoder`] and [`Decoder`] to send and receive messages.
#[derive(Debug)]
pub struct Channel<R, W, C> {
    read_conn: ReadChannel<R, C>,
    write_conn: WriteChannel<W, C>,
}

/// A channel that uses a [`LengthDelimitedCodec`] to send and receive messages.
pub type BytesChannel<R, W> = Channel<R, W, LengthDelimitedCodec>;

/// A channel that uses a [`BincodeCodec`] to send and receive messages.
pub type BincodeChannel<R, W, M> = Channel<R, W, BincodeCodec<M>>;

impl<R, W, C> Channel<R, W, C> {
    /// Create a new [`Channel`], backed by a read and write half. Read and write buffers
    /// are automatically handled by [`LengthDelimitedCodec`].
    pub fn new<MSend>(read_half: R, write_half: W, codec: C) -> Self
    where
        C: Clone + Decoder + Encoder<MSend>,
        R: AsyncReadExt,
        W: AsyncWriteExt,
    {
        Channel {
            write_conn: FramedWrite::new(write_half, codec.clone()),
            read_conn: FramedRead::new(read_half, codec),
        }
    }

    /// Split Connection into a ([`WriteChannel`],[`ReadChannel`]) pair.
    pub fn split(self) -> (WriteChannel<W, C>, ReadChannel<R, C>) {
        (self.write_conn, self.read_conn)
    }

    /// Join ([`WriteChannel`],[`ReadChannel`]) pair back into a [`Channel`].
    pub fn join(write_conn: WriteChannel<W, C>, read_conn: ReadChannel<R, C>) -> Self {
        Self {
            write_conn,
            read_conn,
        }
    }

    /// Returns mutable reference to the ([`WriteChannel`],[`ReadChannel`]) pair.
    pub fn inner_ref(&mut self) -> (&mut WriteChannel<W, C>, &mut ReadChannel<R, C>) {
        (&mut self.write_conn, &mut self.read_conn)
    }

    /// Closes the channel, flushing the write buffer and checking that there is no unread data.
    pub async fn close<MSend>(self) -> Result<(), io::Error>
    where
        C: Encoder<MSend, Error = std::io::Error> + Decoder<Error = std::io::Error>,
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let Channel {
            mut read_conn,
            mut write_conn,
            ..
        } = self;
        write_conn.flush().await?;
        write_conn.close().await?;
        if let Some(x) = read_conn.next().await {
            match x {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unexpected data on read channel when closing connections",
                    ));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}
impl<R, W: AsyncWriteExt + Unpin, MSend, C: Encoder<MSend, Error = io::Error>> Sink<MSend>
    for Channel<R, W, C>
where
    Self: Unpin,
{
    type Error = <C as Encoder<MSend>>::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.write_conn.poll_ready_unpin(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: MSend) -> Result<(), Self::Error> {
        self.write_conn.start_send_unpin(item)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.write_conn.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.write_conn.poll_close_unpin(cx)
    }
}
impl<R: AsyncReadExt + Unpin, W, MRecv, C: Decoder<Item = MRecv, Error = io::Error>> Stream
    for Channel<R, W, C>
where
    Self: Unpin,
{
    type Item = Result<MRecv, <C as Decoder>::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.read_conn.poll_next_unpin(cx)
    }
}

struct WriteJob<MSend> {
    data: MSend,
    ret: oneshot::Sender<Result<(), io::Error>>,
}

struct ReadJob<MRecv> {
    ret: oneshot::Sender<Result<MRecv, io::Error>>,
}

/// A handle to a channel that allows sending and receiving messages.
#[derive(Debug)]
pub struct ChannelHandle<MSend, MRecv> {
    write_job_queue: mpsc::Sender<WriteJob<MSend>>,
    read_job_queue: mpsc::Sender<ReadJob<MRecv>>,
}

impl<MSend, MRecv> ChannelHandle<MSend, MRecv>
where
    MRecv: Send + std::fmt::Debug + 'static,
    MSend: Send + std::fmt::Debug + 'static,
{
    /// Instructs the channel to send a message. Returns a [oneshot::Receiver] that will return the result of the send operation.
    pub async fn send(&mut self, data: MSend) -> oneshot::Receiver<Result<(), io::Error>> {
        let (ret, recv) = oneshot::channel();
        let job = WriteJob { data, ret };
        match self.write_job_queue.send(job).await {
            Ok(_) => {}
            Err(job) => job
                .0
                .ret
                .send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ChannelHandle: send Channel is gone",
                )))
                .unwrap(),
        }
        recv
    }

    /// Instructs the channel to receive a message. Returns a [oneshot::Receiver] that will return the result of the receive operation.
    pub async fn recv(&mut self) -> oneshot::Receiver<Result<MRecv, io::Error>> {
        let (ret, recv) = oneshot::channel();
        let job = ReadJob { ret };
        match self.read_job_queue.send(job).await {
            Ok(_) => {}
            Err(job) => job
                .0
                .ret
                .send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ChannelHandle: recv Channel is gone",
                )))
                .unwrap(),
        }
        recv
    }

    /// A blocking version of [ChannelHandle::send]. This will block until the send operation is complete.
    pub fn blocking_send(&mut self, data: MSend) -> oneshot::Receiver<Result<(), io::Error>> {
        let (ret, recv) = oneshot::channel();
        let job = WriteJob { data, ret };
        match self.write_job_queue.blocking_send(job) {
            Ok(_) => {}
            Err(job) => job
                .0
                .ret
                .send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ChannelHandle: send Channel is gone",
                )))
                .unwrap(),
        }
        recv
    }

    /// A blocking version of [ChannelHandle::recv]. This will block until the receive operation is complete.
    pub fn blocking_recv(&mut self) -> oneshot::Receiver<Result<MRecv, io::Error>> {
        let (ret, recv) = oneshot::channel();
        let job = ReadJob { ret };
        match self.read_job_queue.blocking_send(job) {
            Ok(_) => {}
            Err(job) => job
                .0
                .ret
                .send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ChannelHandle: recv Channel is gone",
                )))
                .unwrap(),
        }
        recv
    }
}

/// Handles spawing and shutdown of channels. On drop, joins all [`JoinHandle`]s. The [`Handle`] musst be valid for the entire lifetime of this type.
#[derive(Debug)]
pub struct ChannelTasks {
    tasks: Vec<JoinHandle<()>>,
    handle: Handle,
}

impl ChannelTasks {
    /// Create a new [`ChannelTasks`] instance.
    pub fn new(handle: Handle) -> Self {
        Self {
            tasks: Vec::new(),
            handle,
        }
    }

    /// Create a new [`ChannelHandle`] from a [`Channel`]. This spawns a new tokio task that handles the read and write jobs so they can happen concurrently.
    pub fn spawn<MSend, MRecv, R, W, C>(
        &mut self,
        chan: Channel<R, W, C>,
    ) -> ChannelHandle<MSend, MRecv>
    where
        C: 'static,
        R: AsyncReadExt + Unpin + 'static,
        W: AsyncWriteExt + Unpin + std::marker::Send + 'static,
        FramedRead<R, C>: Stream<Item = Result<MRecv, io::Error>> + Send,
        FramedWrite<W, C>: Sink<MSend, Error = io::Error> + Send,
        MRecv: Send + std::fmt::Debug + 'static,
        MSend: Send + std::fmt::Debug + 'static,
    {
        let (write_send, mut write_recv) = mpsc::channel::<WriteJob<MSend>>(1024);
        let (read_send, mut read_recv) = mpsc::channel::<ReadJob<MRecv>>(1024);

        let (mut write, mut read) = chan.split();

        self.tasks.push(self.handle.spawn(async move {
            while let Some(frame) = read.next().await {
                let job = read_recv.recv().await;
                match job {
                    Some(job) => {
                        if job.ret.send(frame).is_err() {
                            tracing::warn!("Warning: Read Job finished but receiver is gone!");
                        }
                    }
                    None => {
                        if frame.is_ok() {
                            tracing::warn!("Warning: received Ok frame but receiver is gone!");
                        }
                        break;
                    }
                }
            }
        }));
        self.tasks.push(self.handle.spawn(async move {
            while let Some(write_job) = write_recv.recv().await {
                let write_result = write.send(write_job.data).await;
                // we don't really care if the receiver for a write job is gone, as this is a common case
                // therefore we only emit a trace message
                match write_job.ret.send(write_result) {
                    Ok(_) => {}
                    Err(_) => {
                        tracing::trace!("Debug: Write Job finished but receiver is gone!");
                    }
                }
            }
            // make sure all data is sent
            if write.into_inner().shutdown().await.is_err() {
                tracing::warn!("Warning: shutdown of stream failed!");
            }
        }));

        ChannelHandle {
            write_job_queue: write_send,
            read_job_queue: read_send,
        }
    }

    /// Join all [`JoinHandle`]s and remove them.
    pub async fn shutdown(&mut self) -> Result<(), JoinError> {
        futures::future::try_join_all(std::mem::take(&mut self.tasks))
            .await
            .map(|_| ())
    }
}

impl Clone for ChannelTasks {
    fn clone(&self) -> Self {
        Self {
            tasks: Vec::new(),
            handle: self.handle.clone(),
        }
    }
}

impl Drop for ChannelTasks {
    fn drop(&mut self) {
        self.handle.block_on(async {
            futures::future::try_join_all(std::mem::take(&mut self.tasks))
                .await
                .expect("can join all tasks");
        });
    }
}
