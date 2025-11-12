use ark_ec::pairing::Pairing;
use co_acvm::PlainAcvmSolver;
use co_noir_common::{
    crs::ProverCrs, honk_proof::HonkProofResult, keys::verification_key::VerifyingKey,
};
use std::sync::Arc;

use crate::prelude::UltraCircuitBuilder;

pub trait VerifyingKeyTrait<P: Pairing> {
    fn create(
        circuit: UltraCircuitBuilder<P::G1>,
        prover_crs: Arc<ProverCrs<P::G1>>,
        verifier_crs: P::G2Affine,
        driver: &mut PlainAcvmSolver<P::ScalarField>,
    ) -> HonkProofResult<Self>
    where
        Self: std::marker::Sized;
}

impl<P: Pairing> VerifyingKeyTrait<P> for VerifyingKey<P> {
    fn create(
        circuit: UltraCircuitBuilder<P::G1>,
        prover_crs: Arc<ProverCrs<P::G1>>,
        verifier_crs: P::G2Affine,
        driver: &mut PlainAcvmSolver<P::ScalarField>,
    ) -> HonkProofResult<Self> {
        let (_, vk) = circuit.create_keys(prover_crs, verifier_crs, driver)?;
        Ok(vk)
    }
}
