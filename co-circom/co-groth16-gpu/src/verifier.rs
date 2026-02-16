//! This module implements the verification of a Groth16 proof on the [`Groth16`] type.
//!
//! We use [arkworks Groth16 implementation](https://docs.rs/ark-groth16/latest/ark_groth16/struct.Groth16.html#method.verify_proof)
//! for verification.

use crate::groth16::Groth16;
use ark_ec::pairing::Pairing;
use ark_groth16::Proof;
use ark_groth16::VerifyingKey;

use ark_groth16::Groth16 as ArkworksGroth16;
use co_circom_types::VerificationError;

impl<P: Pairing> Groth16<P> {
    /// Verify a Groth16 proof.
    /// This method is a wrapper arkworks Groth16 and does not use MPC.
    pub fn verify(
        vk: &VerifyingKey<P>,
        proof: &Proof<P>,
        public_inputs: &[P::ScalarField],
    ) -> Result<(), VerificationError> {
        let vk = ark_groth16::prepare_verifying_key(vk);
        let proof_valid = ArkworksGroth16::<P>::verify_proof(&vk, proof, public_inputs)
            .map_err(eyre::Report::from)?;
        if proof_valid {
            Ok(())
        } else {
            Err(VerificationError::InvalidProof)
        }
    }
}
