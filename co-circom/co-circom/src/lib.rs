//! # Example:
//!
//! ```no_run
#![doc = include_str!("../examples/co_circom_party0.rs")]
//! ```

#![warn(missing_docs)]

use std::{marker::PhantomData, sync::Arc};

use co_circom_types::{CompressedRep3SharedWitness, SharedWitness};
use co_groth16::{CircomReduction, ConstraintMatrices, ProvingKey};
use color_eyre::eyre::{self, Context};
use mpc_core::protocols::{
    bridges::network::RepToShamirNetwork,
    shamir::{ShamirPreprocessing, ShamirProtocol},
};

pub use ark_bls12_381::Bls12_381;
pub use ark_bn254::Bn254;
pub use ark_ec::pairing::Pairing;
pub use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
pub use circom_mpc_vm::{mpc_vm::VMConfig, types::CoCircomCompilerParsed};
pub use circom_types::{
    groth16::{
        CircomGroth16Proof, JsonVerificationKey as Groth16JsonVerificationKey, ZKey as Groth16ZKey,
    },
    plonk::{JsonVerificationKey as PlonkJsonVerificationKey, PlonkProof, ZKey as PlonkZKey},
    traits::{CheckElement, CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
    Witness, R1CS,
};
pub use co_circom_types::{
    Compression, Input, Rep3SharedInput, Rep3SharedWitness, ShamirSharedWitness,
};
pub use co_groth16::{Groth16, Rep3CoGroth16, ShamirCoGroth16};
pub use co_plonk::{Plonk, Rep3CoPlonk, ShamirCoPlonk};
pub use mpc_core::protocols::{
    rep3::{network::Rep3MpcNet, uncompress_shared_witness, PartyID},
    shamir::network::ShamirMpcNet,
};
pub use mpc_net::config::{Address, NetworkConfig, NetworkParty, ParseAddressError};
pub use serde_json::Number;
pub use serde_json::Value;

/// State with a shamir shared witness
pub struct ShamirSharedWitnessState<P>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    net: ShamirMpcNet,
    threshold: usize,
    /// The shared witness
    pub witness: ShamirSharedWitness<P::ScalarField>,
}

impl<P> ShamirSharedWitnessState<P>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Create a new [ShamirSharedWitnessState]
    pub fn new(
        net: ShamirMpcNet,
        threshold: usize,
        witness: ShamirSharedWitness<P::ScalarField>,
    ) -> Self {
        Self {
            net,
            threshold,
            witness,
        }
    }

    /// Create a Groth16 poof and return the public inputs
    pub fn prove_groth16(
        self,
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
    ) -> eyre::Result<(CircomGroth16Proof<P>, Vec<P::ScalarField>)> {
        let public_inputs = self.witness.public_inputs[1..].to_vec();
        let (proof, _net) = ShamirCoGroth16::prove::<CircomReduction>(
            self.net,
            self.threshold,
            pkey,
            matrices,
            self.witness,
        )?;
        Ok((proof.into(), public_inputs))
    }

    /// Create a Plonk poof and return the public inputs
    pub fn prove_plonk(
        self,
        zkey: Arc<PlonkZKey<P>>,
    ) -> eyre::Result<(PlonkProof<P>, Vec<P::ScalarField>)> {
        let public_inputs = self.witness.public_inputs[1..].to_vec();
        let (proof, _net) = ShamirCoPlonk::prove(self.net, self.threshold, zkey, self.witness)?;
        Ok((proof, public_inputs))
    }
}

/// State with a rep3 shared witness
pub struct Rep3SharedWitnessState<P>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    net: Rep3MpcNet,
    /// The shared witness
    pub witness: CompressedRep3SharedWitness<P::ScalarField>,
}

impl<P> Rep3SharedWitnessState<P>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Create a new [Rep3SharedWitnessState]
    pub fn new(
        net: Rep3MpcNet,
        witness: impl Into<CompressedRep3SharedWitness<P::ScalarField>>,
    ) -> Self {
        Self {
            net,
            witness: witness.into(),
        }
    }

    /// Translate the rep3 shared witness into a shamir shared witness
    pub fn translate(self) -> eyre::Result<ShamirSharedWitnessState<P>> {
        let (witness, net) = translate_witness::<P>(self.witness, self.net)?;
        Ok(ShamirSharedWitnessState {
            witness,
            threshold: 1,
            net,
        })
    }

    /// Create a Groth16 poof and return the public inputs
    pub fn prove_groth16(
        mut self,
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
    ) -> eyre::Result<(CircomGroth16Proof<P>, Vec<P::ScalarField>)> {
        let witness = uncompress_shared_witness(self.witness, &mut self.net)?;
        let public_inputs = witness.public_inputs[1..].to_vec();
        let (proof, _net) =
            Rep3CoGroth16::prove::<CircomReduction>(self.net, pkey, matrices, witness)?;
        Ok((proof.into(), public_inputs))
    }

    /// Create a Plonk poof and return the public inputs
    pub fn prove_plonk(
        mut self,
        zkey: Arc<PlonkZKey<P>>,
    ) -> eyre::Result<(PlonkProof<P>, Vec<P::ScalarField>)> {
        let witness = uncompress_shared_witness(self.witness, &mut self.net)?;
        let public_inputs = witness.public_inputs[1..].to_vec();
        let (proof, _net) = Rep3CoPlonk::prove(self.net, zkey, witness)?;
        Ok((proof, public_inputs))
    }
}

/// Initial state for the type-state pattern
pub struct CoCircomRep3<P> {
    net: Rep3MpcNet,
    phantom: PhantomData<P>,
}

impl<P> CoCircomRep3<P>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Create a new initial state
    pub fn new(net: Rep3MpcNet) -> Self {
        Self {
            net,
            phantom: PhantomData,
        }
    }

    /// Perform the witness generation advance to the next state
    pub fn generate_witness(
        self,
        circuit: CoCircomCompilerParsed<P::ScalarField>,
        shared_input: Rep3SharedInput<P::ScalarField>,
        config: VMConfig,
    ) -> eyre::Result<Rep3SharedWitnessState<P>> {
        let (witness, net) = generate_witness_rep3::<P>(circuit, shared_input, self.net, config)?;
        Ok(Rep3SharedWitnessState {
            net,
            witness: witness.into(),
        })
    }
}

/// Split the input into REP3 shares
pub fn split_input<P: Pairing>(
    input: Input,
    public_inputs: &[String],
) -> color_eyre::Result<[Rep3SharedInput<P::ScalarField>; 3]> {
    co_circom_types::split_input(input, public_inputs)
}

/// Merge multiple REP3 shared inputs into one
pub fn merge_input_shares<P: Pairing>(
    inputs: Vec<Rep3SharedInput<P::ScalarField>>,
) -> color_eyre::Result<Rep3SharedInput<P::ScalarField>> {
    co_circom_types::merge_input_shares(inputs)
}

/// Split the witness into REP3 shares
pub fn split_witness_rep3<P: Pairing>(
    r1cs: &R1CS<P>,
    witness: Witness<P::ScalarField>,
    compression: Compression,
) -> [CompressedRep3SharedWitness<P::ScalarField>; 3] {
    let mut rng = rand::thread_rng();
    // create witness shares
    CompressedRep3SharedWitness::share_rep3(witness, r1cs.num_inputs, &mut rng, compression)
}

/// Split the witness into shamir shares
pub fn split_witness_shamir<P: Pairing>(
    r1cs: &R1CS<P>,
    witness: Witness<P::ScalarField>,
    threshold: usize,
    num_parties: usize,
) -> Vec<ShamirSharedWitness<P::ScalarField>> {
    let mut rng = rand::thread_rng();
    // create witness shares
    ShamirSharedWitness::<P::ScalarField>::share_shamir(
        witness,
        r1cs.num_inputs,
        threshold,
        num_parties,
        &mut rng,
    )
}

/// Translate the REP3 shared witness into a shamir shared witness
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
        eyre::bail!("still unmerged elements left");
    }

    // init MPC protocol
    let rep3_vm = circuit
        .to_rep3_vm_with_network(net, config)
        .context("while constructing MPC VM")?;

    // execute witness generation in MPC
    let (witness_share, mpc_net) = rep3_vm
        .run_and_return_network(input)
        .context("while running witness generation")?;

    Ok((witness_share.into_shared_witness(), mpc_net))
}
