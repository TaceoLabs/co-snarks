//! Streaming helpers for deterministic execution fingerprints.

use ark_serialize::CanonicalSerialize;
use eyre::Result;
use serde::Serialize;
use std::io::{self, Write};

/// A domain-separated BLAKE3 writer. Serializing directly into the hasher avoids a
/// second program-sized allocation for large compiled circuits.
pub(crate) struct FingerprintWriter {
    hasher: blake3::Hasher,
}

impl FingerprintWriter {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        Self { hasher }
    }

    pub(crate) fn serialize(&mut self, value: &impl Serialize) -> Result<()> {
        bincode::serialize_into(self, value)?;
        Ok(())
    }

    pub(crate) fn serialize_canonical(&mut self, value: &impl CanonicalSerialize) -> Result<()> {
        value.serialize_compressed(self)?;
        Ok(())
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl Write for FingerprintWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
