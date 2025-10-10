use super::types::VerifierMemory;
use crate::{
    oink::oink_prover::Oink, plain_prover_flavour::PlainProverFlavour,
    ultra_verifier::HonkVerifyResult,
};
use ark_ec::pairing::Pairing;
use co_builder::prelude::VerifyingKey;
use co_builder::{
    polynomials::polynomial_flavours::WitnessEntitiesFlavour, prover_flavour::Flavour,
};
use co_noir_common::mpc::plain::PlainUltraHonkDriver;
use co_noir_common::transcript::{Transcript, TranscriptHasher};
use co_noir_common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType};

pub(crate) struct OinkVerifier<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, PlainUltraHonkDriver, P>,
    L: PlainProverFlavour,
> {
    memory: VerifierMemory<P, L>,
    pub public_inputs: Vec<P::ScalarField>,
    phantom_hasher: std::marker::PhantomData<(H, L)>,
}

impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, PlainUltraHonkDriver, P>,
    L: PlainProverFlavour,
> Default for OinkVerifier<P, H, L>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, PlainUltraHonkDriver, C>,
    L: PlainProverFlavour,
> OinkVerifier<C, H, L>
{
    pub(crate) fn new() -> Self {
        Self {
            memory: VerifierMemory::default(),
            public_inputs: Default::default(),
            phantom_hasher: Default::default(),
        }
    }

    fn execute_preamble_round<P: Pairing<G1 = C>>(
        &mut self,
        verifying_key: &VerifyingKey<P, L>,
        transcript: &mut Transcript<TranscriptFieldType, H, PlainUltraHonkDriver, C>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("executing (verifying) preamble round");

        let circuit_size = verifying_key.circuit_size as u64;
        let public_input_size = verifying_key.num_public_inputs as u64;
        let pub_inputs_offset = verifying_key.pub_inputs_offset as u64;

        transcript.add_u64_to_hash_buffer("circuit_size".to_string(), circuit_size);
        transcript.add_u64_to_hash_buffer("public_input_size".to_string(), public_input_size);
        transcript.add_u64_to_hash_buffer("pub_inputs_offset".to_string(), pub_inputs_offset);

        self.public_inputs = Vec::with_capacity(public_input_size as usize);

        for i in 0..public_input_size {
            let public_input =
                transcript.receive_fr_from_prover::<C>(format!("public_input_{i}"))?;
            self.public_inputs.push(public_input);
        }

        Ok(())
    }

    fn execute_wire_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H, PlainUltraHonkDriver, C>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("executing (verifying) wire commitments round");

        *self.memory.witness_commitments.w_l_mut() =
            transcript.receive_point_from_prover::<C>("W_L".to_string())?;
        *self.memory.witness_commitments.w_r_mut() =
            transcript.receive_point_from_prover::<C>("W_R".to_string())?;
        *self.memory.witness_commitments.w_o_mut() =
            transcript.receive_point_from_prover::<C>("W_O".to_string())?;

        if L::FLAVOUR == Flavour::Mega {
            *self.memory.witness_commitments.ecc_op_wire_1_mut() =
                transcript.receive_point_from_prover::<C>("ecc_op_wire_1".to_string())?;
            *self.memory.witness_commitments.ecc_op_wire_2_mut() =
                transcript.receive_point_from_prover::<C>("ecc_op_wire_2".to_string())?;
            *self.memory.witness_commitments.ecc_op_wire_3_mut() =
                transcript.receive_point_from_prover::<C>("ecc_op_wire_3".to_string())?;
            *self.memory.witness_commitments.ecc_op_wire_4_mut() =
                transcript.receive_point_from_prover::<C>("ecc_op_wire_4".to_string())?;
            *self.memory.witness_commitments.calldata_mut() =
                transcript.receive_point_from_prover::<C>("calldata".to_string())?;
            *self.memory.witness_commitments.calldata_read_counts_mut() =
                transcript.receive_point_from_prover::<C>("calldata_read_counts".to_string())?;
            *self.memory.witness_commitments.calldata_read_tags_mut() =
                transcript.receive_point_from_prover::<C>("calldata_read_tags".to_string())?;
            *self.memory.witness_commitments.secondary_calldata_mut() =
                transcript.receive_point_from_prover::<C>("secondary_calldata".to_string())?;
            *self
                .memory
                .witness_commitments
                .secondary_calldata_read_counts_mut() = transcript
                .receive_point_from_prover::<C>("secondary_calldata_read_counts".to_string())?;
            *self
                .memory
                .witness_commitments
                .secondary_calldata_read_tags_mut() = transcript
                .receive_point_from_prover::<C>("secondary_calldata_read_tags".to_string())?;
            *self.memory.witness_commitments.return_data_mut() =
                transcript.receive_point_from_prover::<C>("return_data".to_string())?;
            *self
                .memory
                .witness_commitments
                .return_data_read_counts_mut() =
                transcript.receive_point_from_prover::<C>("return_data_read_counts".to_string())?;
            *self.memory.witness_commitments.return_data_read_tags_mut() =
                transcript.receive_point_from_prover::<C>("return_data_read_tags".to_string())?;
        }
        Ok(())
    }

    fn execute_sorted_list_accumulator_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H, PlainUltraHonkDriver, C>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("executing (verifying) sorted list accumulator round");

        let challs = transcript.get_challenges::<C>(&[
            "eta".to_string(),
            "eta_two".to_string(),
            "eta_three".to_string(),
        ]);
        self.memory.challenges.eta_1 = challs[0];
        self.memory.challenges.eta_2 = challs[1];
        self.memory.challenges.eta_3 = challs[2];

        *self.memory.witness_commitments.lookup_read_counts_mut() =
            transcript.receive_point_from_prover::<C>("lookup_read_counts".to_string())?;

        *self.memory.witness_commitments.lookup_read_tags_mut() =
            transcript.receive_point_from_prover::<C>("lookup_read_tags".to_string())?;

        *self.memory.witness_commitments.w_4_mut() =
            transcript.receive_point_from_prover::<C>("w_4".to_string())?;

        Ok(())
    }

    fn execute_log_derivative_inverse_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H, PlainUltraHonkDriver, C>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("executing (verifying) log derivative inverse round");

        let challs = transcript.get_challenges::<C>(&["beta".to_string(), "gamma".to_string()]);
        self.memory.challenges.beta = challs[0];
        self.memory.challenges.gamma = challs[1];

        *self.memory.witness_commitments.lookup_inverses_mut() =
            transcript.receive_point_from_prover::<C>("lookup_inverses".to_string())?;

        // If Goblin (i.e. using DataBus) receive commitments to log-deriv inverses polynomials
        if L::FLAVOUR == Flavour::Mega {
            *self.memory.witness_commitments.calldata_inverses_mut() =
                transcript.receive_point_from_prover::<C>("calldata_inverses".to_string())?;
            *self
                .memory
                .witness_commitments
                .secondary_calldata_inverses_mut() = transcript
                .receive_point_from_prover::<C>("secondary_calldata_inverses".to_string())?;
            *self.memory.witness_commitments.return_data_inverses_mut() =
                transcript.receive_point_from_prover::<C>("return_data_inverses".to_string())?;
        }
        Ok(())
    }

    fn execute_grand_product_computation_round<P: Pairing<G1 = C>>(
        &mut self,
        verifying_key: &VerifyingKey<P, L>,
        transcript: &mut Transcript<TranscriptFieldType, H, PlainUltraHonkDriver, C>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("executing (verifying) grand product computation round");
        self.memory.public_input_delta = Oink::<C, H, L>::compute_public_input_delta(
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            &self.public_inputs,
            verifying_key.circuit_size,
            verifying_key.pub_inputs_offset,
        );
        *self.memory.witness_commitments.z_perm_mut() =
            transcript.receive_point_from_prover::<C>("z_perm".to_string())?;
        Ok(())
    }

    pub(crate) fn verify<P: Pairing<G1 = C>>(
        mut self,
        verifying_key: &VerifyingKey<P, L>,
        transcript: &mut Transcript<TranscriptFieldType, H, PlainUltraHonkDriver, C>,
    ) -> HonkVerifyResult<VerifierMemory<C, L>> {
        tracing::trace!("Oink verify");
        self.execute_preamble_round(verifying_key, transcript)?;
        self.execute_wire_commitments_round(transcript)?;
        self.execute_sorted_list_accumulator_round(transcript)?;
        self.execute_log_derivative_inverse_round(transcript)?;
        self.execute_grand_product_computation_round(verifying_key, transcript)?;
        Oink::<C, H, L>::generate_alphas_round(&mut self.memory.challenges.alphas, transcript);
        Ok(self.memory)
    }
}
