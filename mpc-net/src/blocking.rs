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

use bytes::{Buf as _, Bytes, BytesMut};
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
#[derive(Debug)]
pub(crate) struct BlockingChannels {
    send: IntMap<usize, SendEntry>,
    recv: IntMap<usize, RecvEntry>,
    timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
    max_frame_length: usize,
}

impl BlockingChannels {
    /// Create an empty set of channels.
    pub(crate) fn new(
        timeout: Option<Duration>,
        flush_timeout: Option<Duration>,
        max_frame_length: usize,
    ) -> Self {
        Self {
            send: IntMap::new(),
            recv: IntMap::new(),
            timeout,
            flush_timeout,
            max_frame_length,
        }
    }
}

impl BlockingChannels {
    /// Register a peer from its already-handshaked writer and reader stream halves,
    /// spawning the background writer and reader threads.
    pub(crate) fn add_peer<W, R>(&mut self, other_id: usize, write_stream: W, read_stream: R)
    where
        W: Write + Send + 'static,
        R: Read + Send + 'static,
    {
        let max_frame_length = self.max_frame_length;
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
        self.recv
            .insert(other_id, (recv_rx, AtomicUsize::default()));
    }

    /// Enqueue `data` to `to`. Coalesces the length prefix and payload into one buffer
    /// so each frame is a single write on the writer thread.
    pub(crate) fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        if data.len() > self.max_frame_length {
            eyre::bail!("frame len {} > max {}", data.len(), self.max_frame_length);
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

    /// Receive the next frame from `from`.
    pub(crate) fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        let (queue, recv_bytes) = self.recv.get(from).context("party id out-of-bounds")?;
        let data = if let Some(timeout) = self.timeout {
            queue.recv_timeout(timeout)??
        } else {
            queue.recv()??
        };
        recv_bytes.fetch_add(data.len(), Ordering::Relaxed);
        Ok(data)
    }

    /// Drain every peer's send queue and surface any writer-thread error.
    pub(crate) fn flush(&self) -> eyre::Result<()> {
        for (to, (tx, _, err)) in self.send.iter() {
            let (ack_tx, ack_rx) = bounded(1);
            tx.send(WriteMsg::Flush(ack_tx))
                .map_err(|_| eyre::eyre!("writer thread for party {to} terminated"))?;
            if let Some(timeout) = self.flush_timeout {
                ack_rx
                    .recv_timeout(timeout)
                    .map_err(|_| eyre::eyre!("timed out flushing send queue for party {to}"))?;
            } else {
                ack_rx
                    .recv()
                    .map_err(|_| eyre::eyre!("writer thread for party {to} terminated"))?;
            }
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
/// is written in a loop until the whole frame is sent or an error occurs.
fn write_frame<W: Write>(stream: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let header = (payload.len() as u64).to_be_bytes();
    let mut bufs = [IoSlice::new(&header), IoSlice::new(payload)];
    write_all_vectored(stream, &mut bufs)
}

/// Write all of the given slices to the stream, looping on partial writes. This is
/// similar to [`std::io::Write::write_all`] but for vectored writes.
///
/// This is copied from [`std::io::Write::write_all_vectored`], which is still unstable.
fn write_all_vectored<W: Write>(
    writer: &mut W,
    mut bufs: &mut [IoSlice<'_>],
) -> std::io::Result<()> {
    // Guarantee that bufs is empty if it contains no data,
    // to avoid calling write_vectored if there is no data to be written.
    IoSlice::advance_slices(&mut bufs, 0);
    while !bufs.is_empty() {
        match writer.write_vectored(bufs) {
            Ok(0) => {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
            }
            Ok(n) => IoSlice::advance_slices(&mut bufs, n),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Amount of zeroed space appended to the receive buffer per read syscall.
const READ_CHUNK: usize = 64 * 1024;

/// Reads length-prefixed frames from `stream`, forwarding each into `tx`. A single read
/// can yield several frames (amortizing syscalls) and frames are sliced out of the read
/// buffer without copying. Exits when the receiver is dropped or a read fails (the error
/// is delivered as the final item, then the loop stops).
fn reader_loop<R: Read>(stream: R, tx: Sender<eyre::Result<Bytes>>, max_frame_length: usize) {
    let mut reader = FrameReader {
        stream,
        buf: BytesMut::new(),
        max_frame_length,
    };
    loop {
        match reader.next_frame() {
            Ok(frame) => {
                if tx.send(Ok(frame)).is_err() {
                    break;
                }
            }
            Err(err) => {
                let _ = tx.send(Err(err));
                break;
            }
        }
    }
}

/// A buffered, length-delimited frame reader over a blocking [`Read`]. This is the
/// synchronous counterpart of `tokio_util`'s `LengthDelimitedCodec`: one growable,
/// reused buffer; multiple frames parsed per read; zero-copy frame extraction via
/// [`BytesMut::split_to`].
struct FrameReader<R> {
    stream: R,
    buf: BytesMut,
    max_frame_length: usize,
}

impl<R: Read> FrameReader<R> {
    fn next_frame(&mut self) -> eyre::Result<Bytes> {
        loop {
            if self.buf.len() >= 8 {
                let len = u64::from_be_bytes(self.buf[..8].try_into().expect("8 bytes")) as usize;
                if len > self.max_frame_length {
                    eyre::bail!("frame len {len} > max {}", self.max_frame_length);
                }
                if self.buf.len() >= 8 + len {
                    // Whole frame buffered: drop the header and slice out the payload
                    // (a refcounted view into the read buffer, no copy).
                    self.buf.advance(8);
                    return Ok(self.buf.split_to(len).freeze());
                }
                // Reserve room for the rest of this frame so subsequent reads don't realloc.
                self.buf.reserve(8 + len - self.buf.len());
            }
            self.fill()?;
        }
    }

    /// Append one chunk read from the stream to the buffer.
    fn fill(&mut self) -> eyre::Result<()> {
        let old = self.buf.len();
        // Zero-extend by a chunk, read into the fresh space, then trim to bytes read.
        self.buf.resize(old + READ_CHUNK, 0);
        match self.stream.read(&mut self.buf[old..]) {
            Ok(0) => {
                self.buf.truncate(old);
                eyre::bail!("connection closed by peer");
            }
            Ok(n) => {
                self.buf.truncate(old + n);
                Ok(())
            }
            Err(e) => {
                self.buf.truncate(old);
                Err(e.into())
            }
        }
    }
}
