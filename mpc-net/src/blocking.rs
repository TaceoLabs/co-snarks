//! Shared core for the blocking, thread-per-peer transports (TCP, TLS).
//!
//! Both transports are the same once a connection is established: a length-prefixed
//! framing, a background writer thread draining a bounded send queue, and a background
//! reader thread feeding a bounded receive queue. The only difference is the concrete
//! stream type and how the two directions are obtained (TCP clones one socket; TLS uses
//! two separate connections), which is abstracted here behind the `Write`/`Read` halves
//! handed to [`BlockingChannels::add_peer`].

use std::{
    io::{IoSlice, Read, Write},
    sync::{Arc, atomic::AtomicUsize, atomic::Ordering},
    time::Duration,
};

use byteorder::{BigEndian, ReadBytesExt as _};
use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, bounded};
use eyre::ContextCompat as _;
use intmap::IntMap;
use parking_lot::Mutex;

use crate::ConnectionStats;

/// Capacity (in frames) of each per-peer send queue. Bounds buffered-but-unsent
/// memory and applies backpressure to `send` when a peer cannot keep up.
pub(crate) const SEND_QUEUE_CAP: usize = 32;
/// Capacity (in frames) of each per-peer receive queue.
pub(crate) const RECV_QUEUE_CAP: usize = 32;

/// A shared, interior-mutable error slot set by a writer thread on failure.
type ErrSlot = Arc<Mutex<Option<String>>>;
type SendEntry = (Sender<WriteMsg>, AtomicUsize, ErrSlot);
type RecvEntry = (Receiver<eyre::Result<Bytes>>, AtomicUsize);

/// A message handed to a peer's background writer thread.
pub(crate) enum WriteMsg {
    /// A frame payload to write. The length prefix is written by the writer thread via
    /// a vectored write, so the payload itself is never copied to prepend the header.
    Frame(Bytes),
    /// Flush the stream and acknowledge on the given channel.
    Flush(Sender<()>),
}

/// The per-peer send/receive queues (and byte counters) shared by the blocking transports.
#[derive(Debug, Default)]
pub(crate) struct BlockingChannels {
    send: IntMap<usize, SendEntry>,
    recv: IntMap<usize, RecvEntry>,
}

impl BlockingChannels {
    /// Register a peer from its already-handshaked writer and reader stream halves,
    /// spawning the background writer and reader threads.
    pub(crate) fn add_peer<W, R>(
        &mut self,
        other_id: usize,
        write_stream: W,
        read_stream: R,
        max_frame_length: usize,
    ) where
        W: Write + Send + 'static,
        R: Read + Send + 'static,
    {
        let (send_tx, send_rx) = bounded(SEND_QUEUE_CAP);
        let err: ErrSlot = Arc::new(Mutex::new(None));
        {
            let err = Arc::clone(&err);
            std::thread::spawn(move || writer_loop(write_stream, send_rx, err));
        }
        self.send
            .insert(other_id, (send_tx, AtomicUsize::default(), err));

        let (recv_tx, recv_rx) = bounded(RECV_QUEUE_CAP);
        std::thread::spawn(move || reader_loop(read_stream, recv_tx, max_frame_length));
        self.recv.insert(other_id, (recv_rx, AtomicUsize::default()));
    }

    /// Enqueue `data` to `to`. Coalesces the length prefix and payload into one buffer
    /// so each frame is a single write on the writer thread.
    pub(crate) fn send(&self, to: usize, data: Bytes, max_frame_length: usize) -> eyre::Result<()> {
        if data.len() > max_frame_length {
            eyre::bail!("frame len {} > max {}", data.len(), max_frame_length);
        }
        let (tx, sent_bytes, err) = self.send.get(to).context("party id out-of-bounds")?;
        if let Some(e) = err.lock().clone() {
            eyre::bail!("connection to party {to} previously failed: {e}");
        }
        sent_bytes.fetch_add(data.len(), Ordering::Relaxed);
        // The payload moves into the queue unchanged; the writer thread prepends the
        // length prefix with a vectored write (no copy of the payload).
        tx.send(WriteMsg::Frame(data))
            .map_err(|_| eyre::eyre!("writer thread for party {to} terminated"))?;
        Ok(())
    }

    /// Receive the next frame from `from`, blocking up to `timeout`.
    pub(crate) fn recv(&self, from: usize, timeout: Duration) -> eyre::Result<Bytes> {
        let (queue, recv_bytes) = self.recv.get(from).context("party id out-of-bounds")?;
        let data = queue.recv_timeout(timeout)??;
        recv_bytes.fetch_add(data.len(), Ordering::Relaxed);
        Ok(data)
    }

    /// Drain every peer's send queue and surface any writer-thread error.
    pub(crate) fn flush(&self, timeout: Duration) -> eyre::Result<()> {
        for (to, (tx, _, err)) in self.send.iter() {
            let (ack_tx, ack_rx) = bounded(1);
            tx.send(WriteMsg::Flush(ack_tx))
                .map_err(|_| eyre::eyre!("writer thread for party {to} terminated"))?;
            ack_rx
                .recv_timeout(timeout)
                .map_err(|_| eyre::eyre!("timed out flushing send queue for party {to}"))?;
            if let Some(e) = err.lock().clone() {
                eyre::bail!("connection to party {to} failed: {e}");
            }
        }
        Ok(())
    }

    /// Application-level (sent, received) byte counts per peer.
    pub(crate) fn stats(&self, my_id: usize) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        for (id, (_, sent_bytes, _)) in self.send.iter() {
            let recv_bytes = &self.recv.get(id).expect("was in send so must be in recv").1;
            stats.insert(
                id,
                (
                    sent_bytes.load(Ordering::Relaxed),
                    recv_bytes.load(Ordering::Relaxed),
                ),
            );
        }
        ConnectionStats::new(my_id, stats)
    }
}

/// Drains [`WriteMsg`]s for a single peer, writing them to `stream`. On the first write
/// error it records the error in `err` and exits; subsequent `send`/`flush` calls observe
/// it. Exits cleanly when all senders are dropped.
fn writer_loop<W: Write>(mut stream: W, rx: Receiver<WriteMsg>, err: ErrSlot) {
    for msg in rx.iter() {
        match msg {
            WriteMsg::Frame(payload) => {
                if let Err(e) = write_frame(&mut stream, &payload) {
                    *err.lock() = Some(e.to_string());
                    break;
                }
            }
            WriteMsg::Flush(ack) => {
                if let Err(e) = stream.flush() {
                    *err.lock() = Some(e.to_string());
                    let _ = ack.send(());
                    break;
                }
                let _ = ack.send(());
            }
        }
    }
}

/// Write one length-prefixed frame with a single vectored write, avoiding a copy to
/// prepend the length. On a stream whose `write_vectored` does the real thing (e.g. a
/// TCP socket's `writev`) the payload is never copied. On a partial write, the remainder
/// is finished with plain `write_all`.
fn write_frame<W: Write>(stream: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let header = (payload.len() as u64).to_be_bytes();
    let total = header.len() + payload.len();
    let n = stream.write_vectored(&[IoSlice::new(&header), IoSlice::new(payload)])?;
    if n >= total {
        return Ok(());
    }
    if n < header.len() {
        stream.write_all(&header[n..])?;
        stream.write_all(payload)?;
    } else {
        stream.write_all(&payload[n - header.len()..])?;
    }
    Ok(())
}

/// Reads length-prefixed frames from `stream` and forwards them. Exits when the receiver
/// is dropped or a read fails (the error is delivered as the final item).
fn reader_loop<R: Read>(mut stream: R, tx: Sender<eyre::Result<Bytes>>, max_frame_length: usize) {
    loop {
        let frame = read_next_frame(&mut stream, max_frame_length);
        if tx.send(frame).is_err() {
            break;
        }
    }
}

fn read_next_frame<R: Read>(stream: &mut R, max_frame_length: usize) -> eyre::Result<Bytes> {
    let len = stream.read_u64::<BigEndian>()? as usize;
    if len > max_frame_length {
        eyre::bail!("frame len {len} > max {max_frame_length}");
    }
    let mut data = vec![0; len];
    stream.read_exact(&mut data)?;
    Ok(Bytes::from(data))
}
