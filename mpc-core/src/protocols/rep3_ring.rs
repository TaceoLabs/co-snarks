//! # REP3 Ring
//!
//! This module implements the rep3 share and combine operations for rings

pub mod arithmetic;
pub mod binary;
pub mod casts;
pub mod conversion;
mod detail;
pub mod gadgets;
pub mod lut;
pub mod yao;

pub use mpc_types::protocols::rep3_ring::{
    combine_ring_element, combine_ring_element_binary, combine_ring_elements, ring,
    share_ring_element, share_ring_element_binary, share_ring_elements, share_ring_elements_binary,
    Rep3BitShare, Rep3RingShare,
};
