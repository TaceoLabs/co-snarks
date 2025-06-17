//! # CoCircom

#![warn(missing_docs)]

use ark_ff::PrimeField;
use circom_mpc_vm::mpc_vm::Rep3WitnessExtension;
use co_circom_types::{CompressedRep3SharedWitness, SharedWitness};
use color_eyre::eyre::{self, Context};
use mpc_core::protocols::{
    rep3::{self},
    shamir::{ShamirPreprocessing, ShamirState},
};
use mpc_net::Network;
use mpc_types::protocols::rep3::Rep3ShareVecType;

pub use ark_bls12_381::Bls12_381;
pub use ark_bn254::Bn254;
pub use ark_ec::pairing::Pairing;
pub use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
pub use circom_mpc_vm::{mpc_vm::VMConfig, types::CoCircomCompilerParsed};
pub use circom_types::{
    R1CS, Witness,
    groth16::{
        CircomGroth16Proof, JsonVerificationKey as Groth16JsonVerificationKey, ZKey as Groth16ZKey,
    },
    plonk::{JsonVerificationKey as PlonkJsonVerificationKey, PlonkProof, ZKey as PlonkZKey},
    traits::{CheckElement, CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
};
pub use co_circom_types::{
    Compression, Input, Rep3SharedInput, Rep3SharedWitness, ShamirSharedWitness,
};
pub use co_groth16::{CircomReduction, ConstraintMatrices, ProvingKey};
pub use co_groth16::{Groth16, Rep3CoGroth16, ShamirCoGroth16};
pub use co_plonk::{Plonk, Rep3CoPlonk, ShamirCoPlonk};
pub use mpc_net::config::{Address, NetworkConfig, NetworkParty, ParseAddressError};
pub use serde_json::Number;
pub use serde_json::Value;

/// Split the input into REP3 shares
pub fn split_input<P: Pairing>(
    input: Input,
    public_inputs: &[String],
) -> eyre::Result<[Rep3SharedInput<P::ScalarField>; 3]> {
    co_circom_types::split_input(input, public_inputs)
}

/// Merge multiple REP3 shared inputs into one
pub fn merge_input_shares<P: Pairing>(
    inputs: Vec<Rep3SharedInput<P::ScalarField>>,
) -> eyre::Result<Rep3SharedInput<P::ScalarField>> {
    co_circom_types::merge_input_shares(inputs)
}

/// Split the witness into REP3 shares
pub fn split_witness_rep3<P: Pairing>(
    num_inputs: usize,
    witness: Witness<P::ScalarField>,
    compression: Compression,
) -> [CompressedRep3SharedWitness<P::ScalarField>; 3] {
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
pub fn split_witness_shamir<P: Pairing>(
    num_inputs: usize,
    witness: Witness<P::ScalarField>,
    threshold: usize,
    num_parties: usize,
) -> Vec<ShamirSharedWitness<P::ScalarField>> {
    let mut rng = rand::thread_rng();
    // create witness shares
    ShamirSharedWitness::<P::ScalarField>::share_shamir(
        witness,
        num_inputs,
        threshold,
        num_parties,
        &mut rng,
    )
}

/// Translate the REP3 shared witness into a shamir shared witness
pub fn translate_witness<P, N: Network>(
    witness: CompressedRep3SharedWitness<P::ScalarField>,
    net: &N,
) -> eyre::Result<ShamirSharedWitness<P::ScalarField>>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
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
    let shamir_witness_share: ShamirSharedWitness<P::ScalarField> = SharedWitness {
        public_inputs: witness.public_inputs,
        witness: translated_witness,
    };

    Ok(shamir_witness_share)
}

/// Generate a REP3 shared witness
pub fn generate_witness_rep3<P, N: Network>(
    circuit: &CoCircomCompilerParsed<P::ScalarField>,
    input: Rep3SharedInput<P::ScalarField>,
    config: VMConfig,
    net0: &N,
    net1: &N,
) -> eyre::Result<Rep3SharedWitness<P::ScalarField>>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    if !input.maybe_shared_inputs.is_empty() {
        eyre::bail!("still unmerged elements left");
    }

    // init MPC protocol
    let rep3_vm = Rep3WitnessExtension::new(net0, net1, circuit, config)
        .context("while constructing MPC VM")?;

    // execute witness generation in MPC
    let witness_share = rep3_vm
        .run(input)
        .context("while running witness generation")?;

    Ok(witness_share.into_shared_witness())
}
