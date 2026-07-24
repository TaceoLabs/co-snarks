//! # CoCircom

#![warn(missing_docs)]

use ark_ff::PrimeField;
use circom_mpc_vm::{ShamirVmType, mpc_vm::ShamirWitnessExtension};
use circom_mpc_vm2::{api::Rep3WitnessExtension, drivers::rep3::Rep3VmType};
use co_circom_types::{CompressedRep3SharedWitness, Rep3InputType, ShamirInputType, SharedWitness};
use color_eyre::eyre::{self, Context};
use mpc_core::protocols::{
    rep3::{self, Rep3ShareVecType},
    shamir::{ShamirPreprocessing, ShamirState},
};
use mpc_net::Network;
use std::sync::Arc;

pub use ark_bls12_381::Bls12_381;
pub use ark_bn254::Bn254;
pub use ark_ec::pairing::Pairing;
pub use circom_mpc_compiler2::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
pub use circom_mpc_vm2::program::{CompiledProgram, VMConfig};

/// Types of the legacy (stack-based) pipeline, still used for the Shamir witness extension,
/// which the new register-based VM does not implement.
pub mod legacy {
    pub use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
    pub use circom_mpc_vm::{mpc_vm::VMConfig, types::CoCircomCompilerParsed};
}

/// Maps a (new-pipeline) [`CompilerConfig`] onto the legacy compiler's config.
///
/// The new pipeline's [`UnrollConfig`](circom_mpc_compiler2::UnrollConfig) has no legacy
/// equivalent and is dropped.
pub fn to_legacy_compiler_config(config: &CompilerConfig) -> legacy::CompilerConfig {
    legacy::CompilerConfig {
        version: config.version.clone(),
        allow_leaky_loops: config.allow_leaky_loops,
        link_library: config.link_library.clone(),
        simplification: match config.simplification {
            SimplificationLevel::O0 => legacy::SimplificationLevel::O0,
            SimplificationLevel::O1 => legacy::SimplificationLevel::O1,
            SimplificationLevel::O2(rounds) => legacy::SimplificationLevel::O2(rounds),
        },
        verbose: config.verbose,
        inspect: config.inspect,
        debug: config.debug,
    }
}

/// Maps a (new-pipeline) [`VMConfig`] onto the legacy VM's config.
pub fn to_legacy_vm_config(config: &VMConfig) -> legacy::VMConfig {
    legacy::VMConfig {
        allow_leaky_logs: config.allow_leaky_logs,
        a2b_type: config.a2b_type,
        accelerator: circom_mpc_vm::MpcAcceleratorConfig {
            sqrt: config.accelerator.sqrt,
            num2bits: config.accelerator.num2bits,
            addbits: config.accelerator.addbits,
            iszero: config.accelerator.iszero,
            poseidon2: config.accelerator.poseidon2,
        },
    }
}
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

/// Generate a REP3 shared witness (runs on the register-based `circom-mpc-vm2` pipeline)
pub fn generate_witness_rep3<F: PrimeField, N: Network>(
    circuit: Arc<CompiledProgram<F>>,
    input: Rep3SharedInput<F>,
    config: VMConfig,
    net0: &N,
    net1: &N,
) -> eyre::Result<Rep3SharedWitness<F>> {
    // init MPC protocol
    let rep3_vm = Rep3WitnessExtension::new_rep3(net0, net1, circuit, config)
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

/// Generate a Shamir shared witness (runs on the legacy stack-based pipeline — the new VM
/// has no Shamir driver)
pub fn generate_witness_shamir<F: PrimeField, N: Network>(
    circuit: &legacy::CoCircomCompilerParsed<F>,
    input: ShamirSharedInput<F>,
    config: legacy::VMConfig,
    net: &N,
    num_parties: usize,
    threshold: usize,
) -> eyre::Result<ShamirSharedWitness<F>> {
    // init MPC protocol
    // TODO we are not creating any randomness here
    let shamir_vm = ShamirWitnessExtension::new(net, num_parties, threshold, 0, circuit, config)
        .context("while constructing MPC VM")?;

    let num_public_inputs = input
        .values()
        .filter(|i| matches!(i, ShamirInputType::Public(_)))
        .count();
    let input = input
        .into_iter()
        .map(|(name, vale)| (name, ShamirVmType::from(vale)))
        .collect();

    // execute witness generation in MPC
    let witness_share = shamir_vm
        .run(input, num_public_inputs)
        .context("while running witness generation")?;

    Ok(witness_share.into_shared_witness())
}
