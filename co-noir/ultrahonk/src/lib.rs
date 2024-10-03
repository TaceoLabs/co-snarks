pub(crate) mod decider;
pub(crate) mod honk_curve;
pub(crate) mod oink;
#[allow(unused)] // TODO remove this at a later point
pub(crate) mod parse;
pub(crate) mod poseidon2;
pub mod prelude;
pub(crate) mod prover;
pub(crate) mod sponge_hasher;
mod transcript;
pub(crate) mod types;
pub(crate) mod verifier;

use acir::{native_types::WitnessStack, FieldElement};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::PrimeField;
use eyre::Error;
use noirc_artifacts::program::ProgramArtifact;
use num_bigint::BigUint;
use num_traits::Num;
use prelude::AcirFormat;
use prover::{HonkProofError, HonkProofResult};
use std::{io, path::Path};
use types::ProverCrs;

pub const NUM_ALPHAS: usize = decider::relations::NUM_SUBRELATIONS - 1;
/// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
/// TODO(<https://github.com/AztecProtocol/barretenberg/issues/1046>): Remove the need for const sized proofs
pub const CONST_PROOF_SIZE_LOG_N: usize = 28;
pub const N_MAX: usize = 1 << 25;

pub struct Utils {}

impl Utils {
    pub(crate) fn field_from_hex_string<F: PrimeField>(str: &str) -> Result<F, Error> {
        let tmp = match str.strip_prefix("0x") {
            Some(t) => BigUint::from_str_radix(t, 16),
            None => BigUint::from_str_radix(str, 16),
        };

        Ok(tmp?.into())
    }

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

    // from http://supertech.csail.mit.edu/papers/debruijn.pdf
    pub fn get_msb32(inp: u32) -> u8 {
        const MULTIPLY_DE_BRUIJNI_BIT_POSIITION: [u8; 32] = [
            0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24,
            7, 19, 27, 23, 6, 26, 5, 4, 31,
        ];

        let mut v = inp | (inp >> 1);
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;

        MULTIPLY_DE_BRUIJNI_BIT_POSIITION[((v.wrapping_mul(0x07C4ACDD)) >> 27) as usize]
    }

    pub fn round_up_power_2(inp: usize) -> usize {
        let lower_bound = 1usize << Self::get_msb64(inp as u64);
        if lower_bound == inp || lower_bound == 1 {
            inp
        } else {
            lower_bound * 2
        }
    }

    pub fn get_msb64(inp: u64) -> u8 {
        const DE_BRUIJNI_SEQUENCE: [u8; 64] = [
            0, 47, 1, 56, 48, 27, 2, 60, 57, 49, 41, 37, 28, 16, 3, 61, 54, 58, 35, 52, 50, 42, 21,
            44, 38, 32, 29, 23, 17, 11, 4, 62, 46, 55, 26, 59, 40, 36, 15, 53, 34, 51, 20, 43, 31,
            22, 10, 45, 25, 39, 14, 33, 19, 30, 9, 24, 13, 18, 8, 12, 7, 6, 5, 63,
        ];

        let mut t = inp | (inp >> 1);
        t |= t >> 2;
        t |= t >> 4;
        t |= t >> 8;
        t |= t >> 16;
        t |= t >> 32;

        DE_BRUIJNI_SEQUENCE[((t.wrapping_mul(0x03F79D71B4CB0A89)) >> 58) as usize]
    }

    fn batch_invert<F: PrimeField>(coeffs: &mut [F]) {
        ark_ff::batch_inversion(coeffs);
    }

    pub fn commit<P: Pairing>(
        poly: &[P::ScalarField],
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<P::G1> {
        Self::commit_inner::<P>(poly, crs.monomials.as_slice())
    }

    pub fn commit_inner<P: Pairing>(
        poly: &[P::ScalarField],
        crs: &[P::G1Affine],
    ) -> HonkProofResult<P::G1> {
        if poly.len() > crs.len() {
            return Err(HonkProofError::CrsTooSmall);
        }
        Ok(P::G1::msm_unchecked(crs, poly))
    }
}
