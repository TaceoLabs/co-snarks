//! This module implements the verification of a Groth16 proof on the [`Groth16`] type.
//!
//! We use [arkworks Groth16 implementation](https://docs.rs/ark-groth16/latest/ark_groth16/struct.Groth16.html#method.verify_proof)
//! for verification.

use crate::groth16::Groth16;
use ark_ec::pairing::Pairing;
use ark_groth16::Proof;
use ark_groth16::VerifyingKey;
use circom_types::groth16::{proof::Groth16Proof, verification_key::JsonVerificationKey};
use circom_types::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use mpc_core::traits::FFTPostProcessing;

use ark_groth16::Groth16 as ArkworksGroth16;

impl<P: Pairing> Groth16<P>
where
    P::ScalarField: CircomArkworksPrimeFieldBridge,
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: FFTPostProcessing,
{
    /// Verify a Groth16 proof.
    /// This method is a wrapper arkworks Groth16 and does not use MPC.
    pub fn verify(
        vk: &JsonVerificationKey<P>,
        proof: &Groth16Proof<P>,
        public_inputs: &[P::ScalarField],
    ) -> Result<bool, ark_relations::r1cs::SynthesisError> {
        let vk = VerifyingKey::<P> {
            alpha_g1: vk.alpha_1,
            beta_g2: vk.beta_2,
            gamma_g2: vk.gamma_2,
            delta_g2: vk.delta_2,
            gamma_abc_g1: vk.ic.clone(),
        };
        let proof = Proof {
            a: proof.pi_a,
            b: proof.pi_b,
            c: proof.pi_c,
        };

        let vk = ark_groth16::prepare_verifying_key(&vk);
        ArkworksGroth16::<P>::verify_proof(&vk, &proof, public_inputs)
    }
}
