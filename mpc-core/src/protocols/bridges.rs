//! # MPC Bridges
//!
//! This module implements bridges between multiple MPC protocols. Currently, one can switch from Rep3 to a 3-party Shamir secret sharing protocol.

pub mod network;
mod rep3_to_shamir;
