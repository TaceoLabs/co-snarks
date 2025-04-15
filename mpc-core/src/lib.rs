//! # MPC Core
//!
//! This crate implements the core MPC functionalities, which are then used by the other crates. Currently, semi-honest versions of 3-party [replicated secret sharing](https://eprint.iacr.org/2018/403.pdf) and [Shamir secret sharing](https://www.iacr.org/archive/crypto2007/46220565/46220565.pdf) are implemented.

#![warn(missing_docs)]

pub mod gadgets;
pub mod lut;
pub mod protocols;

pub use mpc_types::serde_compat::{ark_de, ark_se};

pub(crate) type RngType = rand_chacha::ChaCha12Rng;
pub(crate) type IoResult<T> = std::io::Result<T>;
pub(crate) const SEED_SIZE: usize = std::mem::size_of::<<RngType as rand::SeedableRng>::Seed>();

fn downcast<A: 'static, B: 'static>(a: &A) -> Option<&B> {
    (a as &dyn std::any::Any).downcast_ref::<B>()
}
