//! Network-to-Channel adapter.
//!
//! Wraps our `mpc_net::Network` trait as a `scuttlebutt::AbstractChannel`
//! so we can use ocelot's OT implementations.

use mpc_net::Network;

/// Adapter: wraps a `&Network` as an `AbstractChannel` for ocelot OT.
///
/// Reads/writes go to/from the other party (party_id XOR 1 for 2PC).
pub struct NetworkChannel<'a, N: Network> {
    net: &'a N,
    other_id: usize,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<'a, N: Network> NetworkChannel<'a, N> {
    pub fn new(net: &'a N) -> Self {
        let other_id = 1 - net.id();
        Self {
            net,
            other_id,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<'a, N: Network> scuttlebutt::AbstractChannel for NetworkChannel<'a, N> {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        // If we have buffered data, use it
        while self.read_pos < self.read_buf.len() && bytes.len() > 0 {
            let available = self.read_buf.len() - self.read_pos;
            let to_copy = available.min(bytes.len());
            bytes[..to_copy].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;
            if to_copy == bytes.len() {
                return Ok(());
            }
            // Need more data
            break;
        }

        // Receive a new chunk from the network
        let data = self.net.recv(self.other_id)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        if data.len() >= bytes.len() {
            bytes.copy_from_slice(&data[..bytes.len()]);
            // Buffer the rest
            self.read_buf = data;
            self.read_pos = bytes.len();
        } else {
            // Partial read — copy what we have and wait for more
            bytes[..data.len()].copy_from_slice(&data);
            // This shouldn't happen with our Network trait (recv returns full message)
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Partial read from network",
            ));
        }

        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.net.send(self.other_id, bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(()) // Network sends are immediate
    }
}
