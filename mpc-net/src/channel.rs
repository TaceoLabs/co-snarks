//! A channel abstraction for sending and receiving messages.
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Bytes, BytesMut};
use std::{
    io::{BufReader, BufWriter, Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[derive(Debug)]
/// A channel that sends length delimited frames and tracks the number of bytes.
pub struct Channel<R: Read, W: Write> {
    reader: FramedReader<R>,
    writer: FramedWriter<W>,
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
