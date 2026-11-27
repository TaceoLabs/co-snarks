//! # CoCircom

#![warn(missing_docs)]

use ark_ff::PrimeField;
use circom_mpc_vm::{
    Rep3VmType, ShamirVmType,
    mpc_vm::{Rep3WitnessExtension, ShamirWitnessExtension},
};
use co_circom_types::{CompressedRep3SharedWitness, Rep3InputType, ShamirInputType, SharedWitness};
use color_eyre::eyre::{self, Context};
use mpc_core::protocols::{
    rep3::{self, Rep3ShareVecType, id::PartyID},
    shamir::{ShamirPreprocessing, ShamirState},
};
use mpc_core::uint::FieldUint;
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
    Compression, Input, Rep3SharedInput, Rep3SharedWitness, ShamirSharedInput, ShamirSharedWitness,
};
pub use co_groth16::{CircomReduction, ConstraintMatrices, ProvingKey};
pub use co_groth16::{Groth16, Rep3CoGroth16, ShamirCoGroth16};
pub use co_plonk::{Plonk, Rep3CoPlonk, ShamirCoPlonk};
pub use serde_json::Number;
pub use serde_json::Value;

pub use co_circom_types::merge_input_shares;
pub use co_circom_types::split_input;
pub use co_circom_types::split_input_shamir;

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
    let public_inputs = witness.public_inputs;
    let translated_witness = match witness.witness {
        Rep3ShareVecType::Replicated(vec) => {
            ShamirState::translate_primefield_repshare_vec(vec, PartyID::try_from(net.id())?)
        }
        Rep3ShareVecType::SeededReplicated(replicated_seed_type) => {
            let vec = replicated_seed_type.expand_vec()?;
            ShamirState::translate_primefield_repshare_vec(vec, PartyID::try_from(net.id())?)
        }
        Rep3ShareVecType::Additive(vec) => {
            // init MPC protocol
            let preprocessing = ShamirPreprocessing::new(3, 1, vec.len(), net)
                .context("while shamir preprocessing")?;
            let mut protocol = ShamirState::from(preprocessing);
            // Translate witness to shamir shares
            protocol
                .translate_primefield_addshare_vec(vec, net)
                .context("while translating witness")?
        }
        Rep3ShareVecType::SeededAdditive(seeded_type) => {
            let vec = seeded_type.expand_vec();
            // init MPC protocol
            let preprocessing = ShamirPreprocessing::new(3, 1, vec.len(), net)
                .context("while shamir preprocessing")?;
            let mut protocol = ShamirState::from(preprocessing);
            // Translate witness to shamir shares
            protocol
                .translate_primefield_addshare_vec(vec, net)
                .context("while translating witness")?
        }
    };

    let shamir_witness_share = SharedWitness {
        public_inputs,
        witness: translated_witness,
    };

    Ok(shamir_witness_share)
}

/// Checks that none of the inputs provided as shares is a public input of the circuit.
///
/// The public inputs are opened after the witness generation, so a party that provides one of them as a share would have its secret value revealed. Note that the opposite is allowed: A private input of the circuit can be provided as a public value. It stays part of the shared witness and is not opened by the witness generation.
fn check_public_inputs<'a, F: PrimeField>(
    circuit: &CoCircomCompilerParsed<F>,
    shared_inputs: impl Iterator<Item = &'a str>,
) -> eyre::Result<()> {
    for name in shared_inputs {
        // array inputs have a trailing [\d+]
        let orig_name = name.split('[').next().unwrap_or(name);
        if circuit.public_inputs().iter().any(|p| p == orig_name) {
            eyre::bail!(
                "Input '{name}' is a public input of the circuit, but was provided as a share"
            );
        }
    }
    Ok(())
}

/// Generate a REP3 shared witness
pub fn generate_witness_rep3<F: PrimeField + FieldUint, N: Network>(
    circuit: &CoCircomCompilerParsed<F>,
    input: Rep3SharedInput<F>,
    config: VMConfig,
    net: &N,
) -> eyre::Result<Rep3SharedWitness<F>> {
    // init MPC protocol
    let rep3_vm =
        Rep3WitnessExtension::new(net, circuit, config).context("while constructing MPC VM")?;

    check_public_inputs(
        circuit,
        input
            .iter()
            .filter(|(_, value)| matches!(value, Rep3InputType::Shared(_)))
            .map(|(name, _)| name.as_str()),
    )?;
    let input = input
        .into_iter()
        .map(|(name, vale)| (name, Rep3VmType::from(vale)))
        .collect();

    // execute witness generation in MPC
    let witness_share = rep3_vm
        .run(input)
        .context("while running witness generation")?;

    Ok(witness_share.into_shared_witness())
}

/// Generate a Shamir shared witness
pub fn generate_witness_shamir<F: PrimeField + FieldUint, N: Network>(
    circuit: &CoCircomCompilerParsed<F>,
    input: ShamirSharedInput<F>,
    config: VMConfig,
    net: &N,
    num_parties: usize,
    threshold: usize,
) -> eyre::Result<ShamirSharedWitness<F>> {
    // init MPC protocol
    // TODO we are not creating any randomness here
    let shamir_vm = ShamirWitnessExtension::new(net, num_parties, threshold, 0, circuit, config)
        .context("while constructing MPC VM")?;

    check_public_inputs(
        circuit,
        input
            .iter()
            .filter(|(_, value)| matches!(value, ShamirInputType::Shared(_)))
            .map(|(name, _)| name.as_str()),
    )?;
    let input = input
        .into_iter()
        .map(|(name, vale)| (name, ShamirVmType::from(vale)))
        .collect();

    // execute witness generation in MPC
    let witness_share = shamir_vm
        .run(input)
        .context("while running witness generation")?;

    Ok(witness_share.into_shared_witness())
}
