#![warn(missing_docs)]
//! This crate provides a binary and associated helper library for running collaborative SNARK proofs.
use std::{io::Read, path::PathBuf};

use ark_bn254::Bn254;
use ark_groth16::Proof;
use circom_mpc_compiler::CompilerBuilder;
use circom_types::groth16::zkey::ZKey;
use clap::ValueEnum;
use collaborative_groth16::groth16::{CollaborativeGroth16, SharedInput, SharedWitness};
use color_eyre::eyre::Context;
use mpc_core::protocols::rep3::{network::Rep3MpcNet, Rep3Protocol};
use mpc_net::config::NetworkConfig;

/// A module for file utility functions.
pub mod file_utils;

/// An enum representing the MPC protocol to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MPCProtocol {
    /// A protocol based on the Replicated Secret Sharing Scheme for 3 parties.
    /// For more information see <https://eprint.iacr.org/2018/403.pdf>.
    REP3,
}

impl ValueEnum for MPCProtocol {
    fn value_variants<'a>() -> &'a [Self] {
        &[MPCProtocol::REP3]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            MPCProtocol::REP3 => Some(clap::builder::PossibleValue::new("REP3")),
        }
    }
}

impl std::fmt::Display for MPCProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MPCProtocol::REP3 => write!(f, "REP3"),
        }
    }
}

/// Try to parse a [SharedWitness] from a [Read]er.
pub fn parse_witness_share<R: Read>(
    reader: R,
) -> color_eyre::Result<SharedWitness<Rep3Protocol<ark_bn254::Fr, Rep3MpcNet>, Bn254>> {
    bincode::deserialize_from(reader).context("trying to parse witness share file")
}

/// Try to parse a [SharedInput] from a [Read]er.
pub fn parse_shared_input<R: Read>(
    reader: R,
) -> color_eyre::Result<SharedInput<Rep3Protocol<ark_bn254::Fr, Rep3MpcNet>, Bn254>> {
    bincode::deserialize_from(reader).context("trying to parse input share file")
}

/// Invoke the MPC witness generation process. It will return a [SharedWitness] if successful.
/// It executes several steps:
/// 1. Parse the circuit file.
/// 2. Compile the circuit to MPC VM bytecode.
/// 3. Set up a network connection to the MPC network.
/// 4. Execute the bytecode on the MPC VM to generate the witness.
pub fn generate_witness(
    circuit: String,
    link_library: Vec<String>,
    input_share: SharedInput<Rep3Protocol<ark_bn254::Fr, Rep3MpcNet>, Bn254>,
    config: NetworkConfig,
) -> color_eyre::Result<SharedWitness<Rep3Protocol<ark_bn254::Fr, Rep3MpcNet>, Bn254>> {
    let circuit_path = PathBuf::from(&circuit);
    file_utils::check_file_exists(&circuit_path)?;

    // parse circuit file & put through our compiler
    let mut builder = CompilerBuilder::<Bn254>::new(circuit);
    for lib in link_library {
        builder = builder.link_library(lib);
    }
    let parsed_circom_circuit = builder
        .build()
        .parse()
        .context("while parsing circuit file")?;

    // connect to network
    let net = Rep3MpcNet::new(config).context("while connecting to network")?;

    // init MPC protocol
    let rep3_vm = parsed_circom_circuit
        .to_rep3_vm_with_network(net)
        .context("while constructing MPC VM")?;

    // execute witness generation in MPC
    let result_witness_share = rep3_vm
        .run(input_share)
        .context("while running witness generation")?;
    Ok(result_witness_share)
}

/// Invoke the MPC proof generation process. It will return a [Proof] if successful.
/// It executes several steps:
/// 1. Construct a [Rep3Protocol] from the network configuration.
/// 2. Construct a [CollaborativeGroth16] prover from the protocol.
/// 3. Execute the proof in MPC
pub fn prove_with_matrices(
    witness_share: SharedWitness<Rep3Protocol<ark_bn254::Fr, Rep3MpcNet>, Bn254>,
    config: NetworkConfig,
    zkey: ZKey<Bn254>,
) -> color_eyre::Result<Proof<Bn254>> {
    let (pk, matrices) = zkey.split();
    tracing::info!("establishing network....");
    // connect to network
    let net = Rep3MpcNet::new(config)?;
    tracing::info!("done!");
    // init MPC protocol
    tracing::info!("building protocol...");
    let protocol = Rep3Protocol::<ark_bn254::Fr, _>::new(net)?;
    tracing::info!("done!");
    let mut prover = CollaborativeGroth16::<Rep3Protocol<ark_bn254::Fr, _>, Bn254>::new(protocol);
    tracing::info!("starting prover...");
    // execute prover in MPC
    prover.prove_with_matrices(&pk, &matrices, witness_share)
}
