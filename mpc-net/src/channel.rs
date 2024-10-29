//! A channel abstraction for sending and receiving messages.
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Bytes, BytesMut};
use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

#[derive(Debug)]
/// A channel that sends length delimited frames and tracks the number of bytes.
pub struct Channel<R: Read, W: Write> {
    reader: FramedReader<R>,
    writer: FramedWriter<W>,
    // TODO maybe move this so that split can also track?
    bytes_read: Arc<AtomicUsize>,
    bytes_written: Arc<AtomicUsize>,
}

impl<R: Read, W: Write> Channel<R, W> {
    /// Create a new [`Channel`].
    pub fn new(
        read: R,
        write: W,
        bytes_read: Arc<AtomicUsize>,
        bytes_written: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            reader: FramedReader::new(read),
            writer: FramedWriter::new(write),
            bytes_read,
            bytes_written,
        }
    }

    /// Send a frame and increse the amount of written bytes.
    pub fn send(&mut self, data: Bytes) -> std::io::Result<()> {
        self.bytes_written.fetch_add(data.len(), Ordering::SeqCst);
        self.writer.write(data)
    }

    /// Receive a frame and increase the amount of read bytes.
    pub fn recv(&mut self) -> std::io::Result<BytesMut> {
        let data = self.reader.read()?;
        self.bytes_read.fetch_add(data.len(), Ordering::SeqCst);
        Ok(data)
    }

    /// Split the channel into a read and write half. Halfs do not track read and wirtten bytes.
    pub fn split(self) -> (FramedReader<R>, FramedWriter<W>) {
        (self.reader, self.writer)
    }
}

#[derive(Debug)]
/// A framed writer
pub struct FramedWriter<W: Write> {
    inner: BufWriter<W>,
}

impl<W: Write> FramedWriter<W> {
    /// Create a new [`FramedWriter`]
    pub fn new(inner: W) -> Self {
        Self {
            inner: BufWriter::new(inner),
        }
    }

    /// Write a frame
    pub fn write(&mut self, data: Bytes) -> std::io::Result<()> {
        self.inner.write_u32::<NetworkEndian>(data.len() as u32)?;
        self.inner.write_all(&data)?;
        self.inner.flush()?;
        Ok(())
    }
}

#[derive(Debug)]
/// A framed reader
pub struct FramedReader<R: Read> {
    inner: BufReader<R>,
}

impl<R: Read> FramedReader<R> {
    /// Create a new [`FramedReader`]
    pub fn new(inner: R) -> Self {
        Self {
            inner: BufReader::new(inner),
        }
    }

    /// Read a frame
    pub fn read(&mut self) -> std::io::Result<BytesMut> {
        let len = self.inner.read_u32::<NetworkEndian>()? as usize;
        let mut buf = BytesMut::with_capacity(len);
        buf.resize(len, 0);
        self.inner.read_exact(&mut buf[..len])?;
        Ok(buf)
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
    write_job_queue: std::sync::mpsc::Sender<WriteJob<MSend>>,
    read_job_queue: std::sync::mpsc::Sender<ReadJob<MRecv>>,
}

impl<MSend, MRecv> ChannelHandle<MSend, MRecv>
where
    MRecv: Send + std::fmt::Debug + 'static,
    MSend: Send + std::fmt::Debug + 'static,
{
    /// A blocking version of [ChannelHandle::send]. This will block until the send operation is complete.
    pub fn send(&mut self, data: MSend) -> oneshot::Receiver<Result<(), io::Error>> {
        let (ret, recv) = oneshot::channel();
        let job = WriteJob { data, ret };
        match self.write_job_queue.send(job) {
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
    pub fn recv(&mut self) -> oneshot::Receiver<Result<MRecv, io::Error>> {
        let (ret, recv) = oneshot::channel();
        let job = ReadJob { ret };
        match self.read_job_queue.send(job) {
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
pub(crate) struct ChannelTasks {
    tasks: Vec<JoinHandle<()>>,
}

impl ChannelTasks {
    /// Create a new [`ChannelTasks`] instance.
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Create a new [`ChannelHandle`] from a [`Channel`]. This spawns a new tokio task that handles the read and write jobs so they can happen concurrently.
    pub(crate) fn spawn<R, W>(&mut self, chan: Channel<R, W>) -> ChannelHandle<Bytes, BytesMut>
    where
        W: Write + std::marker::Send + 'static,
        R: Read + std::marker::Send + 'static,
    {
        let (write_send, write_recv) = std::sync::mpsc::channel::<WriteJob<Bytes>>();
        let (read_send, read_recv) = std::sync::mpsc::channel::<ReadJob<BytesMut>>();

        let bytes_read = chan.bytes_read.clone();
        let bytes_written = chan.bytes_written.clone();

        let (mut read, mut write) = chan.split();

        self.tasks.push(std::thread::spawn(move || {
            while let Ok(frame) = read.read() {
                bytes_read.fetch_add(frame.len(), Ordering::SeqCst);
                let job = read_recv.recv();
                match job {
                    Ok(job) => {
                        if job.ret.send(Ok(frame)).is_err() {
                            tracing::warn!("Warning: Read Job finished but receiver is gone!");
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }));
        self.tasks.push(std::thread::spawn(move || {
            while let Ok(write_job) = write_recv.recv() {
                bytes_written.fetch_add(write_job.data.len(), Ordering::SeqCst);
                let write_result = write.write(write_job.data);
                // we don't really care if the receiver for a write job is gone, as this is a common case
                // therefore we only emit a trace message
                match write_job.ret.send(write_result) {
                    Ok(_) => {}
                    Err(_) => {
                        tracing::trace!("Debug: Write Job finished but receiver is gone!");
                    }
                }
            }
            // TODO?
            // // make sure all data is sent
            // if write.into_inner().shutdown().await.is_err() {
            //     tracing::warn!("Warning: shutdown of stream failed!");
            // }
        }));

        ChannelHandle {
            write_job_queue: write_send,
            read_job_queue: read_send,
        }
    }

    // /// Join all [`JoinHandle`]s and remove them.
    // pub(crate) async fn shutdown(&mut self) -> Result<(), JoinError> {
    //     futures::future::try_join_all(std::mem::take(&mut self.tasks))
    //         .await
    //         .map(|_| ())
    // }
}

impl Drop for ChannelTasks {
    fn drop(&mut self) {
        // tokio::task::block_in_place(move || {
        //     self.handle
        //         .block_on(futures::future::try_join_all(std::mem::take(
        //             &mut self.tasks,
        //         )))
        //         .expect("can join all tasks");
        // });
        // for handle in std::mem::take(&mut self.tasks) {
        //     handle.join();
        // }
    }
}
