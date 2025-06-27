//! # REP3
//!
//! This module implements the rep3 share and combine operations

pub mod arithmetic;
pub mod binary;
pub mod conversion;
mod detail;
pub mod gadgets;
pub mod network;
pub mod pointshare;
pub mod poly;
pub mod rngs;
pub mod yao;

pub use mpc_types::protocols::rep3::{
    Rep3BigUintShare, Rep3PointShare, Rep3PrimeFieldShare, combine_binary_element,
    combine_curve_point, combine_field_element, combine_field_elements, id::PartyID, share_biguint,
    share_curve_point, share_field_element, share_field_elements,
};
