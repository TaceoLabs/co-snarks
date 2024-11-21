//! # REP3 Ring
//!
//! This module implements the rep3 share and combine operations for rings

pub mod arithmetic;
pub mod binary;
pub mod conversion;
mod detail;
pub(crate) mod ring;

use ring::bit::Bit;

pub type Rep3BitShare = Rep3RingShare<Bit>;

pub use arithmetic::types::Rep3RingShare;
