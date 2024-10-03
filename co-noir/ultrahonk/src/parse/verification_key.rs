use super::builder::{GenericUltraCircuitBuilder, UltraCircuitBuilder, UltraCircuitVariable};
use crate::{
    prelude::CrsParser,
    prover::HonkProofResult,
    types::{Crs, PrecomputedEntities, ProverCrs, ProvingKey, VerifyingKey},
    Utils,
};
use ark_ec::pairing::Pairing;
use eyre::Result;

impl<P: Pairing> VerifyingKey<P> {
    pub fn create(circuit: UltraCircuitBuilder<P>, crs: Crs<P>) -> HonkProofResult<Self> {
        let (_, vk) = circuit.create_keys(crs)?;
        Ok(vk)
    }

    pub fn get_crs<S: UltraCircuitVariable<P::ScalarField>>(
        circuit: &GenericUltraCircuitBuilder<P, S>,
        path_g1: &str,
        path_g2: &str,
    ) -> Result<Crs<P>> {
        tracing::info!("Getting crs");
        ProvingKey::get_crs(circuit, path_g1, path_g2)
    }

    pub fn get_verifier_crs<S: UltraCircuitVariable<P::ScalarField>>(
        path_g2: &str,
    ) -> Result<P::G2Affine> {
        tracing::info!("Getting verifier crs");
        CrsParser::<P>::get_crs_g2(path_g2)
    }
}
