//! # CoCircom

#![warn(missing_docs)]

use ark_ff::PrimeField;
use circom_mpc_vm::{Rep3VmType, mpc_vm::Rep3WitnessExtension};
use co_circom_types::{CompressedRep3SharedWitness, Rep3InputType, SharedWitness};
use color_eyre::eyre::{self, Context};
use mpc_core::protocols::{
    rep3::{self, Rep3ShareVecType},
    shamir::{ShamirPreprocessing, ShamirState},
};
use mpc_net::Network;

pub use ark_bls12_381::Bls12_381;
pub use ark_bn254::Bn254;
pub use ark_ec::pairing::Pairing;
pub use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
pub use circom_mpc_vm::{mpc_vm::VMConfig, types::CoCircomCompilerParsed};
pub use circom_types::{
    CheckElement, R1CS, Witness,
    groth16::{
        Proof as CircomGroth16Proof, VerificationKey as Groth16JsonVerificationKey,
        Zkey as Groth16ZKey,
    },
    plonk::{PlonkProof, VerificationKey as PlonkJsonVerificationKey, Zkey as PlonkZKey},
    traits::CircomArkworksPairingBridge,
};
pub use co_circom_types::{
    Compression, Input, Rep3SharedInput, Rep3SharedWitness, ShamirSharedWitness,
};
pub use co_groth16::{CircomReduction, ConstraintMatrices, ProvingKey};
pub use co_groth16::{Groth16, Rep3CoGroth16, ShamirCoGroth16};
pub use co_plonk::{Plonk, Rep3CoPlonk, ShamirCoPlonk};
pub use serde_json::Number;
pub use serde_json::Value;

pub use co_circom_types::merge_input_shares;
pub use co_circom_types::split_input;

/// Split the witness into REP3 shares
pub fn split_witness_rep3<F: PrimeField>(
    num_inputs: usize,
    witness: Witness<F>,
    compression: Compression,
) -> [CompressedRep3SharedWitness<F>; 3] {
    let mut rng = rand::thread_rng();
    // create witness shares
    CompressedRep3SharedWitness::share_rep3(witness, num_inputs, &mut rng, compression)
}

/// Uncompress into [`Rep3SharedWitness`].
pub fn uncompress_shared_witness<F: PrimeField, N: Network>(
    compressed_witness: CompressedRep3SharedWitness<F>,
    net: &N,
) -> eyre::Result<Rep3SharedWitness<F>> {
    let public_inputs = compressed_witness.public_inputs;
    let witness = compressed_witness.witness;
    let witness = match witness {
        Rep3ShareVecType::Replicated(vec) => vec,
        Rep3ShareVecType::SeededReplicated(replicated_seed_type) => {
            replicated_seed_type.expand_vec()?
        }
        Rep3ShareVecType::Additive(vec) => rep3::arithmetic::reshare_vec(vec, net)?,
        Rep3ShareVecType::SeededAdditive(seeded_type) => {
            rep3::arithmetic::reshare_vec(seeded_type.expand_vec(), net)?
        }
    };

    Ok(Rep3SharedWitness {
        public_inputs,
        witness,
    })
}

/// Split the witness into shamir shares
pub fn split_witness_shamir<F: PrimeField>(
    num_inputs: usize,
    witness: Witness<F>,
    threshold: usize,
    num_parties: usize,
) -> Vec<ShamirSharedWitness<F>> {
    let mut rng = rand::thread_rng();
    // create witness shares
    ShamirSharedWitness::<F>::share_shamir(witness, num_inputs, threshold, num_parties, &mut rng)
}

/// Translate the REP3 shared witness into a shamir shared witness
pub fn translate_witness<F: PrimeField, N: Network>(
    witness: CompressedRep3SharedWitness<F>,
    net: &N,
) -> eyre::Result<ShamirSharedWitness<F>> {
    let witness = SharedWitness::from(witness);
    // init MPC protocol
    let num_parties = 3;
    let threshold = 1;
    let num_pairs = witness.witness.len();
    let preprocessing = ShamirPreprocessing::new(num_parties, threshold, num_pairs, net)
        .context("while shamir preprocessing")?;
    let mut protocol = ShamirState::from(preprocessing);
    // Translate witness to shamir shares
    let translated_witness = protocol
        .translate_primefield_addshare_vec(witness.witness, net)
        .context("while translating witness")?;
    let shamir_witness_share: ShamirSharedWitness<F> = SharedWitness {
        public_inputs: witness.public_inputs,
        witness: translated_witness,
    };

    Ok(shamir_witness_share)
}

/// Generate a REP3 shared witness
pub fn generate_witness_rep3<F: PrimeField, N: Network>(
    circuit: &CoCircomCompilerParsed<F>,
    input: Rep3SharedInput<F>,
    config: VMConfig,
    net0: &N,
    net1: &N,
) -> eyre::Result<Rep3SharedWitness<F>> {
    // init MPC protocol
    let rep3_vm = Rep3WitnessExtension::new(net0, net1, circuit, config)
        .context("while constructing MPC VM")?;

    let num_public_inputs = input
        .values()
        .filter(|i| matches!(i, Rep3InputType::Public(_)))
        .count();
    let input = input
        .into_iter()
        .map(|(name, vale)| (name, Rep3VmType::from(vale)))
        .collect();

    // execute witness generation in MPC
    let witness_share = rep3_vm
        .run(input, num_public_inputs)
        .context("while running witness generation")?;

    Ok(witness_share.into_shared_witness())
}
