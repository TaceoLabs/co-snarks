//! Shared core for the async, task-per-peer transports (QUIC, ephemeral TCP sessions).
//!
//! Once a peer's framed duplex is established, both transports behave identically: a
//! tokio task drains a bounded send queue into the sink, another forwards frames from
//! the source into a bounded receive queue, and the synchronous [`Network`](crate::Network)
//! methods block on those queues. The only differences are how the framed duplex is
//! obtained (quinn bidi streams vs a split `Framed<TcpStream>`) and which runtime the
//! tasks are spawned on, both of which are decided by the caller of [`AsyncChannels::add_peer`].

use std::{
    collections::HashMap,
    io,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use eyre::ContextCompat as _;
use futures::{Sink, SinkExt as _, Stream, StreamExt as _};
use parking_lot::Mutex;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::ConnectionStats;

/// Capacity (in frames) of each per-peer send/receive queue.
pub(crate) const ASYNC_QUEUE_CAP: usize = 32;

/// A message handed to a peer's write pump.
enum WriteMsg {
    /// A frame payload to write to the sink.
    Frame(Bytes),
    /// Flush the sink and acknowledge on the given channel.
    Flush(oneshot::Sender<()>),
}

type SendEntry = (mpsc::Sender<WriteMsg>, AtomicUsize);
type RecvEntry = (Mutex<mpsc::Receiver<eyre::Result<Bytes>>>, AtomicUsize);

/// Per-peer send/receive queues (and byte counters) shared by the async transports.
#[derive(Debug)]
pub(crate) struct AsyncChannels {
    send: HashMap<usize, SendEntry>,
    recv: HashMap<usize, RecvEntry>,
    /// Handle to the runtime the pump tasks run on, used to bound the shutdown barrier.
    handle: Handle,
    /// Bounds how long the shutdown barrier waits for a peer's sentinel.
    timeout: Duration,
    cancellation: CancellationToken,
    // Cancels the reader tasks when this struct is dropped.
    _drop_guard: DropGuard,
}

impl AsyncChannels {
    /// Create an empty set of channels. `handle` must reference the runtime the pump
    /// tasks are spawned on; `timeout` bounds the shutdown barrier's receive.
    pub(crate) fn new(handle: Handle, timeout: Duration) -> Self {
        let cancellation = CancellationToken::new();
        Self {
            send: HashMap::new(),
            recv: HashMap::new(),
            handle,
            timeout,
            _drop_guard: cancellation.clone().drop_guard(),
            cancellation,
        }
    }
}

impl AsyncChannels {
    /// Spawn the read/write pump tasks for `other_id` over an already-framed duplex and
    /// register the synchronous-side queue endpoints.
    ///
    /// Must be called from within a tokio runtime context (the tasks are spawned with
    /// [`tokio::spawn`] onto the ambient runtime).
    pub(crate) fn add_peer<Si, St>(&mut self, other_id: usize, mut sink: Si, mut source: St)
    where
        Si: Sink<Bytes> + Send + Unpin + 'static,
        St: Stream<Item = Result<BytesMut, io::Error>> + Send + Unpin + 'static,
    {
        let (send_tx, mut send_rx) = mpsc::channel::<WriteMsg>(ASYNC_QUEUE_CAP);
        let (recv_tx, recv_rx) = mpsc::channel::<eyre::Result<Bytes>>(ASYNC_QUEUE_CAP);

        tokio::spawn(async move {
            while let Some(msg) = send_rx.recv().await {
                match msg {
                    WriteMsg::Frame(frame) => {
                        if sink.send(frame).await.is_err() {
                            tracing::warn!("failed to send data to party {other_id}");
                            break;
                        }
                    }
                    WriteMsg::Flush(ack) => {
                        if sink.flush().await.is_err() {
                            tracing::warn!("failed to flush data to party {other_id}");
                            let _ = ack.send(());
                            break;
                        }
                        let _ = ack.send(());
                    }
                }
            }
        });

        let cancellation = self.cancellation.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    msg = source.next() => match msg {
                        Some(Ok(frame)) => {
                            if recv_tx.send(Ok(frame.into())).await.is_err() {
                                tracing::warn!("recv receiver for party {other_id} dropped");
                                break;
                            }
                        }
                        Some(Err(err)) => {
                            let _ = recv_tx
                                .send(Err(eyre::eyre!("recv error from party {other_id}: {err}")))
                                .await;
                            break;
                        }
                        None => break,
                    }
                }
            }
        });

        self.send
            .insert(other_id, (send_tx, AtomicUsize::default()));
        self.recv
            .insert(other_id, (Mutex::new(recv_rx), AtomicUsize::default()));
    }

    /// Enqueue `data` to `to`.
    pub(crate) fn send(&self, to: usize, data: Bytes, max_frame_length: usize) -> eyre::Result<()> {
        if data.len() > max_frame_length {
            eyre::bail!("frame len {} > max {}", data.len(), max_frame_length);
        }
        let (tx, sent_bytes) = self.send.get(&to).context("party id out-of-bounds")?;
        sent_bytes.fetch_add(data.len(), Ordering::Relaxed);
        tx.blocking_send(WriteMsg::Frame(data))
            .map_err(|_| eyre::eyre!("write task for party {to} terminated"))?;
        Ok(())
    }

    /// Drain every peer's write pump and flush its sink, surfacing any failure.
    pub(crate) fn flush(&self) -> eyre::Result<()> {
        for (to, (tx, _)) in self.send.iter() {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.blocking_send(WriteMsg::Flush(ack_tx))
                .map_err(|_| eyre::eyre!("write task for party {to} terminated"))?;
            ack_rx
                .blocking_recv()
                .map_err(|_| eyre::eyre!("write task for party {to} dropped flush ack"))?;
        }
        Ok(())
    }

    /// Flush, then run an all-to-all sentinel barrier so every peer has received all of
    /// this party's frames (and vice versa) before any connection is torn down. Must be
    /// called by all parties after they have finished exchanging protocol data.
    pub(crate) fn shutdown(&self, max_frame_length: usize) -> eyre::Result<()> {
        self.flush()?;
        let peers: Vec<usize> = self.send.keys().copied().collect();
        for &to in &peers {
            self.send(to, Bytes::new(), max_frame_length)?;
        }
        for &from in &peers {
            // Bounded so a peer that never sends its sentinel (e.g. crashed) surfaces an
            // error instead of hanging shutdown forever.
            self.recv_timed(from)?;
        }
        Ok(())
    }

    /// Like [`recv`](Self::recv) but bounded by the configured timeout. Used by the
    /// shutdown barrier; the hot-path `recv` stays an unbounded, lightweight blocking
    /// wait (a protocol receive is expected to wait for its peer's frame).
    fn recv_timed(&self, from: usize) -> eyre::Result<Bytes> {
        let (receiver, recv_bytes) = self.recv.get(&from).context("party id out-of-bounds")?;
        let mut guard = receiver.lock();
        let received = self
            .handle
            .block_on(async { tokio::time::timeout(self.timeout, guard.recv()).await });
        let data = match received {
            Ok(Some(frame)) => frame?,
            Ok(None) => eyre::bail!("receiver sender dropped"),
            Err(_) => eyre::bail!(
                "shutdown timed out after {:?} waiting for party {from}",
                self.timeout
            ),
        };
        recv_bytes.fetch_add(data.len(), Ordering::Relaxed);
        Ok(data)
    }

    /// Receive the next frame from `from`, blocking until one is available.
    pub(crate) fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        let (receiver, recv_bytes) = self.recv.get(&from).context("party id out-of-bounds")?;
        let data = receiver
            .lock()
            .blocking_recv()
            .context("receiver sender dropped")??;
        recv_bytes.fetch_add(data.len(), Ordering::Relaxed);
        Ok(data)
    }

    /// Application-level (sent, received) byte counts per peer.
    pub(crate) fn stats(&self, my_id: usize) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        for (id, (_, sent_bytes)) in self.send.iter() {
            let recv_bytes = &self.recv.get(id).expect("was in send so must be in recv").1;
            stats.insert(
                *id,
                (
                    sent_bytes.load(Ordering::Relaxed),
                    recv_bytes.load(Ordering::Relaxed),
                ),
            );
        }
        ConnectionStats::new(my_id, stats)
    }
}
