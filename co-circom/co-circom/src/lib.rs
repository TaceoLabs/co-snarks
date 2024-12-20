#![warn(missing_docs)]
//! This crate provides a binary and associated helper library for running collaborative SNARK proofs.
use std::io::Read;

use ark_ff::PrimeField;
use co_circom_snarks::{CompressedRep3SharedWitness, SharedWitness};
use color_eyre::eyre::{self, bail, Context, ContextCompat};
use mpc_core::protocols::{
    bridges::network::RepToShamirNetwork,
    shamir::{ShamirPreprocessing, ShamirProtocol},
};
use num_bigint::BigUint;
use num_traits::Num;

pub use ark_bls12_381::Bls12_381;
pub use ark_bn254::Bn254;
pub use ark_ec::pairing::Pairing;
pub use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
pub use circom_mpc_vm::{mpc_vm::VMConfig, types::CoCircomCompilerParsed};
pub use circom_types::{
    groth16::{
        Groth16Proof, JsonVerificationKey as Groth16JsonVerificationKey, ZKey as Groth16ZKey,
    },
    plonk::{JsonVerificationKey as PlonkJsonVerificationKey, PlonkProof, ZKey as PlonkZKey},
    traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
    Witness, R1CS,
};
pub use co_circom_snarks::{Compression, Rep3SharedInput, Rep3SharedWitness, ShamirSharedWitness};
pub use co_groth16::{Groth16, Rep3CoGroth16, ShamirCoGroth16};
pub use co_plonk::{Plonk, Rep3CoPlonk, ShamirCoPlonk};
pub use mpc_core::protocols::{
    rep3::{id::PartyID, network::Rep3MpcNet},
    shamir::network::ShamirMpcNet,
};
pub use mpc_net::config::{Address, NetworkConfig, NetworkParty, ParseAddressError};

/// Splits the input according to the provided parameters.
pub fn split_input<P>(
    input: impl Read,
    public_inputs: &[String],
) -> color_eyre::Result<[Rep3SharedInput<P::ScalarField>; 3]>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    let input: serde_json::Map<String, serde_json::Value> =
        serde_json::from_reader(input).context("while parsing input")?;

    // create input shares
    let mut shares = [
        Rep3SharedInput::<P::ScalarField>::default(),
        Rep3SharedInput::<P::ScalarField>::default(),
        Rep3SharedInput::<P::ScalarField>::default(),
    ];

    let mut rng = rand::thread_rng();
    for (name, val) in input {
        let parsed_vals = if val.is_array() {
            parse_array(&val)?
        } else if val.is_boolean() {
            vec![Some(parse_boolean(&val)?)]
        } else {
            vec![Some(parse_field(&val)?)]
        };
        if public_inputs.contains(&name) {
            let parsed_vals = parsed_vals
                .into_iter()
                .collect::<Option<Vec<P::ScalarField>>>()
                .context("Public inputs must not be unkown")?;
            shares[0]
                .public_inputs
                .insert(name.clone(), parsed_vals.clone());
            shares[1]
                .public_inputs
                .insert(name.clone(), parsed_vals.clone());
            shares[2].public_inputs.insert(name.clone(), parsed_vals);
        } else {
            // if all elements are Some, then we can share normally
            // else we can only share as Vec<Option<T>> and we have to merge unknown inputs later
            if parsed_vals.iter().all(Option::is_some) {
                let parsed_vals = parsed_vals
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .expect("all are Some");
                let [share0, share1, share2] = Rep3SharedInput::share_rep3(&parsed_vals, &mut rng);
                shares[0].shared_inputs.insert(name.clone(), share0);
                shares[1].shared_inputs.insert(name.clone(), share1);
                shares[2].shared_inputs.insert(name.clone(), share2);
            } else {
                let [share0, share1, share2] =
                    Rep3SharedInput::maybe_share_rep3(&parsed_vals, &mut rng);
                shares[0].maybe_shared_inputs.insert(name.clone(), share0);
                shares[1].maybe_shared_inputs.insert(name.clone(), share1);
                shares[2].maybe_shared_inputs.insert(name.clone(), share2);
            };
        }
    }
    Ok(shares)
}

/// Merge multiple REP3 shared inputs into one
#[tracing::instrument(name = "time_merge_input_shares", skip_all)]
pub fn merge_input_shares<F: PrimeField>(
    mut inputs: Vec<Rep3SharedInput<F>>,
) -> color_eyre::Result<Rep3SharedInput<F>> {
    let start_item = inputs.pop().context("we have at least two inputs")?;
    let merged = inputs.into_iter().try_fold(start_item, |a, b| {
        a.merge(b).context("while merging input shares")
    })?;
    Ok(merged)
}

/// Split the witness into REP3 shares
#[tracing::instrument(name = "time_split_witness_rep3", skip_all)]
pub fn split_witness_rep3<P: Pairing>(
    r1cs: R1CS<P>,
    witness: Witness<P::ScalarField>,
    compression: Compression,
) -> color_eyre::Result<[CompressedRep3SharedWitness<P::ScalarField>; 3]> {
    let mut rng = rand::thread_rng();
    // create witness shares
    let shares =
        CompressedRep3SharedWitness::share_rep3(witness, r1cs.num_inputs, &mut rng, compression);
    Ok(shares)
}

/// Split the witness into shamir shares
#[tracing::instrument(name = "time_split_witness_shamir", skip_all)]
pub fn split_witness_shamir<P: Pairing>(
    r1cs: R1CS<P>,
    witness: Witness<P::ScalarField>,
    threshold: usize,
    num_parties: usize,
) -> color_eyre::Result<Vec<ShamirSharedWitness<P::ScalarField>>> {
    let mut rng = rand::thread_rng();
    // create witness shares
    let shares = ShamirSharedWitness::<P::ScalarField>::share_shamir(
        witness,
        r1cs.num_inputs,
        threshold,
        num_parties,
        &mut rng,
    );
    Ok(shares)
}

/// Translate the REP3 shared witness into a shamir shared witness
#[tracing::instrument(name = "time_translate_witness", skip_all)]
pub fn translate_witness<P>(
    witness: CompressedRep3SharedWitness<P::ScalarField>,
    net: Rep3MpcNet,
) -> color_eyre::Result<(ShamirSharedWitness<P::ScalarField>, ShamirMpcNet)>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    let witness = SharedWitness::from(witness);
    // init MPC protocol
    let threshold = 1;
    let num_pairs = witness.witness.len();
    let preprocessing =
        ShamirPreprocessing::<P::ScalarField, _>::new(threshold, net.to_shamir_net(), num_pairs)
            .context("while shamir preprocessing")?;
    let mut protocol = ShamirProtocol::from(preprocessing);
    // Translate witness to shamir shares
    let translated_witness = protocol
        .translate_primefield_addshare_vec(witness.witness)
        .context("while translating witness")?;
    let shamir_witness_share: ShamirSharedWitness<P::ScalarField> = SharedWitness {
        public_inputs: witness.public_inputs,
        witness: translated_witness,
    };

    let net = protocol.get_network();
    Ok((shamir_witness_share, net))
}

/// Invoke the MPC witness generation process. It will return a [SharedWitness] if successful.
/// It executes several steps:
/// 1. Parse the circuit file.
/// 2. Compile the circuit to MPC VM bytecode.
/// 3. Set up a network connection to the MPC network.
/// 4. Execute the bytecode on the MPC VM to generate the witness.
pub fn generate_witness_rep3<P>(
    circuit: CoCircomCompilerParsed<P::ScalarField>,
    input: Rep3SharedInput<P::ScalarField>,
    net: Rep3MpcNet,
    config: VMConfig,
) -> color_eyre::Result<(Rep3SharedWitness<P::ScalarField>, Rep3MpcNet)>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    if !input.maybe_shared_inputs.is_empty() {
        bail!("still unmerged elements left");
    }

    // init MPC protocol
    let rep3_vm = circuit
        .to_rep3_vm_with_network(net, config)
        .context("while constructing MPC VM")?;

    // execute witness generation in MPC
    let (witness_share, mpc_net) = rep3_vm
        .run_and_get_network(input)
        .context("while running witness generation")?;

    Ok((witness_share.into_shared_witness(), mpc_net))
}

fn parse_field<F>(val: &serde_json::Value) -> eyre::Result<F>
where
    F: std::str::FromStr + PrimeField,
{
    let s = val.as_str().ok_or_else(|| {
        eyre::eyre!(
            "expected input to be a field element string, got \"{}\"",
            val
        )
    })?;
    let (is_negative, stripped) = if let Some(stripped) = s.strip_prefix('-') {
        (true, stripped)
    } else {
        (false, s)
    };
    let positive_value = if let Some(stripped) = stripped.strip_prefix("0x") {
        let mut big_int = BigUint::from_str_radix(stripped, 16)
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?;
        let modulus = BigUint::try_from(F::MODULUS).expect("can convert mod to biguint");
        if big_int >= modulus {
            tracing::warn!("val {} >= mod", big_int);
            // snarkjs also does this
            big_int %= modulus;
        }
        let big_int: F::BigInt = big_int
            .try_into()
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?;
        F::from(big_int)
    } else {
        stripped
            .parse::<F>()
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?
    };
    if is_negative {
        Ok(-positive_value)
    } else {
        Ok(positive_value)
    }
}

fn parse_array<F: PrimeField>(val: &serde_json::Value) -> eyre::Result<Vec<Option<F>>> {
    let json_arr = val.as_array().expect("is an array");
    let mut field_elements = vec![];
    for ele in json_arr {
        if ele.is_array() {
            field_elements.extend(parse_array::<F>(ele)?);
        } else if ele.is_boolean() {
            field_elements.push(Some(parse_boolean(ele)?));
        } else if ele.as_str().is_some_and(|e| e == "?") {
            field_elements.push(None);
        } else {
            field_elements.push(Some(parse_field(ele)?));
        }
    }
    Ok(field_elements)
}

fn parse_boolean<F: PrimeField>(val: &serde_json::Value) -> eyre::Result<F> {
    let bool = val
        .as_bool()
        .with_context(|| format!("expected input to be a bool, got {val}"))?;
    if bool {
        Ok(F::ONE)
    } else {
        Ok(F::ZERO)
    }
}
