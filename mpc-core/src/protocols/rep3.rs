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

use ark_ff::PrimeField;
use co_circom_types::{CompressedRep3SharedWitness, Rep3SharedWitness};
use mpc_types::protocols::rep3::Rep3ShareVecType;
pub use mpc_types::protocols::rep3::{
    combine_binary_element, combine_curve_point, combine_field_element, combine_field_elements,
    id::PartyID, share_biguint, share_curve_point, share_field_element, share_field_elements,
    Rep3BigUintShare, Rep3PointShare, Rep3PrimeFieldShare,
};
use network::Rep3Network;

fn reshare_vec<F: PrimeField, N: Rep3Network>(
    vec: Vec<F>,
    mpc_net: &mut N,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let b: Vec<F> = mpc_net.reshare_many(&vec)?;

    if vec.len() != b.len() {
        return Err(eyre::eyre!("reshare_vec: vec and b have different lengths"));
    }

    let shares = vec
        .into_iter()
        .zip(b)
        .map(|(a, b)| Rep3PrimeFieldShare { a, b })
        .collect();

    Ok(shares)
}

/// Uncompress into [`Rep3SharedWitness`].
pub fn uncompress_shared_witness<F: PrimeField, N: Rep3Network>(
    compressed_witness: CompressedRep3SharedWitness<F>,
    mpc_net: &mut N,
) -> eyre::Result<Rep3SharedWitness<F>> {
    let public_inputs = compressed_witness.public_inputs;
    let witness = compressed_witness.witness;
    let witness = match witness {
        Rep3ShareVecType::Replicated(vec) => vec,
        Rep3ShareVecType::SeededReplicated(replicated_seed_type) => {
            replicated_seed_type.expand_vec()?
        }
        Rep3ShareVecType::Additive(vec) => reshare_vec(vec, mpc_net)?,
        Rep3ShareVecType::SeededAdditive(seeded_type) => {
            reshare_vec(seeded_type.expand_vec(), mpc_net)?
        }
    };

    Ok(Rep3SharedWitness {
        public_inputs,
        witness,
    })
}
