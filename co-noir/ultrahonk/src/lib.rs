#![warn(clippy::iter_over_hash_type)]

pub(crate) mod decider;
pub(crate) mod keccak_hash;
pub(crate) mod oink;
pub mod prelude;
pub(crate) mod prover;
pub(crate) mod sponge_hasher;
mod transcript;
pub(crate) mod types;
pub(crate) mod verifier;

use acir::{native_types::WitnessStack, FieldElement};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_builder::{
    prelude::{AcirFormat, ProverCrs},
    HonkProofResult,
};
use noirc_artifacts::program::ProgramArtifact;
use std::{io, path::Path};

pub const NUM_ALPHAS: usize = decider::relations::NUM_SUBRELATIONS - 1;
/// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
/// AZTEC TODO(<https://github.com/AztecProtocol/barretenberg/issues/1046>): Remove the need for const sized proofs
pub const CONST_PROOF_SIZE_LOG_N: usize = 28;
// For ZK Flavors: the number of the commitments required by Libra and SmallSubgroupIPA.
pub const NUM_LIBRA_COMMITMENTS: usize = 3;
pub const NUM_LIBRA_EVALUATIONS: usize = 4;

pub struct Utils {}

impl Utils {
    pub fn get_program_artifact_from_file(path: impl AsRef<Path>) -> io::Result<ProgramArtifact> {
        let program = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str::<ProgramArtifact>(&program)?)
    }

    fn read_witness_stack_from_file(
        path: impl AsRef<Path>,
    ) -> io::Result<WitnessStack<FieldElement>> {
        let witness_stack = std::fs::read(path)?;
        WitnessStack::try_from(witness_stack.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn get_constraint_system_from_artifact(
        program_artifact: &ProgramArtifact,
        honk_recusion: bool,
    ) -> AcirFormat<ark_bn254::Fr> {
        let circuit = program_artifact.bytecode.functions[0].to_owned();
        AcirFormat::circuit_serde_to_acir_format(circuit, honk_recusion)
    }

    pub fn get_constraint_system_from_file(
        path: impl AsRef<Path>,
        honk_recusion: bool,
    ) -> io::Result<AcirFormat<ark_bn254::Fr>> {
        let program_artifact = Self::get_program_artifact_from_file(path)?;
        Ok(Self::get_constraint_system_from_artifact(
            &program_artifact,
            honk_recusion,
        ))
    }

    pub fn get_witness_from_file(path: impl AsRef<Path>) -> io::Result<Vec<ark_bn254::Fr>> {
        let mut witness_stack = Self::read_witness_stack_from_file(path)?;
        let witness_map = witness_stack
            .pop()
            .expect("Witness should be present")
            .witness;
        let witness = AcirFormat::witness_map_to_witness_vector(witness_map);
        Ok(witness)
    }

    pub fn get_msb32(inp: u32) -> u32 {
        co_builder::prelude::Utils::get_msb32(inp)
    }

    pub fn round_up_power_2(inp: usize) -> usize {
        co_builder::prelude::Utils::round_up_power_2(inp)
    }

    pub fn get_msb64(inp: u64) -> u32 {
        co_builder::prelude::Utils::get_msb64(inp)
    }

    fn batch_invert<F: PrimeField>(coeffs: &mut [F]) {
        co_builder::prelude::Utils::batch_invert(coeffs);
    }

    pub fn commit<P: Pairing>(
        poly: &[P::ScalarField],
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<P::G1> {
        co_builder::prelude::Utils::commit(poly, crs)
    }

    pub fn msm<P: Pairing>(poly: &[P::ScalarField], crs: &[P::G1Affine]) -> HonkProofResult<P::G1> {
        co_builder::prelude::Utils::msm::<P>(poly, crs)
    }
}
