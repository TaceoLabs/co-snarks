use crate::oink::{oink_prover::Oink, types::VerifierMemory};
use crate::ultra_verifier::HonkVerifyResult;
use ark_ec::pairing::Pairing;
use co_noir_common::keys::verification_key::VerifyingKey;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    transcript::{Transcript, TranscriptHasher},
};

pub(crate) struct OinkVerifier<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> {
    memory: VerifierMemory<P>,
    pub public_inputs: Vec<P::ScalarField>,
    phantom_hasher: std::marker::PhantomData<H>,
    domain_separator: String,
}

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> Default
    for OinkVerifier<P, H>
{
    fn default() -> Self {
        Self::new("".to_string())
    }
}

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    OinkVerifier<C, H>
{
    pub(crate) fn new(domain_separator: String) -> Self {
        Self {
            memory: VerifierMemory::default(),
            public_inputs: Default::default(),
            phantom_hasher: Default::default(),
            domain_separator,
        }
    }

    fn execute_preamble_round<P: Pairing<G1 = C, G1Affine = C::Affine>>(
        &mut self,
        verifying_key: &VerifyingKey<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("executing preamble round");

        let public_input_size = verifying_key.inner_vk.num_public_inputs;

        let vk_hash =
            verifying_key.hash_with_origin_tagging::<H, C>(&self.domain_separator, transcript);
        transcript.add_fr_to_hash_buffer::<C>(self.domain_separator.clone() + "vk_hash", vk_hash);

        self.public_inputs = Vec::with_capacity(public_input_size as usize);

        for i in 0..public_input_size {
            let public_input =
                transcript.receive_fr_from_prover::<C>(format!("public_input_{i}"))?;
            self.public_inputs.push(public_input);
        }

        Ok(())
    }

    fn commit_to_wires(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("executing (verifying) wire commitments round");

        *self.memory.witness_commitments.w_l_mut() =
            transcript.receive_point_from_prover::<C>("W_L".to_string())?;
        *self.memory.witness_commitments.w_r_mut() =
            transcript.receive_point_from_prover::<C>("W_R".to_string())?;
        *self.memory.witness_commitments.w_o_mut() =
            transcript.receive_point_from_prover::<C>("W_O".to_string())?;

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    fn commit_to_lookup_counts_and_w4(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("executing (verifying) lookup counts and w4 commitments round");

        let eta = transcript.get_challenge::<C>("eta".to_string());
        self.memory.challenges.eta_1 = eta;
        self.memory.challenges.eta_2 = eta * eta;
        self.memory.challenges.eta_3 = eta * eta * eta;

        *self.memory.witness_commitments.lookup_read_counts_mut() =
            transcript.receive_point_from_prover::<C>("lookup_read_counts".to_string())?;

        *self.memory.witness_commitments.lookup_read_tags_mut() =
            transcript.receive_point_from_prover::<C>("lookup_read_tags".to_string())?;

        *self.memory.witness_commitments.w_4_mut() =
            transcript.receive_point_from_prover::<C>("w_4".to_string())?;

        Ok(())
    }

    fn commit_to_logderiv_inverses(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("reading log derivative inverse round");

        let challs = transcript.get_challenges::<C>(&["beta".to_string(), "gamma".to_string()]);
        self.memory.challenges.beta = challs[0];
        self.memory.challenges.gamma = challs[1];

        *self.memory.witness_commitments.lookup_inverses_mut() =
            transcript.receive_point_from_prover::<C>("lookup_inverses".to_string())?;

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    fn commit_to_z_perm<P: Pairing<G1 = C>>(
        &mut self,
        verifying_key: &VerifyingKey<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<()> {
        tracing::trace!("reading grand product computation round");
        self.memory.public_input_delta = Oink::<C, H>::compute_public_input_delta(
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            &self.public_inputs,
            verifying_key.inner_vk.pub_inputs_offset,
        );
        *self.memory.witness_commitments.z_perm_mut() =
            transcript.receive_point_from_prover::<C>("z_perm".to_string())?;
        Ok(())
    }

    pub(crate) fn verify<P: Pairing<G1 = C, G1Affine = C::Affine>>(
        mut self,
        verifying_key: &VerifyingKey<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<VerifierMemory<C>> {
        tracing::trace!("Oink verify");

        self.execute_preamble_round(verifying_key, transcript)?;
        self.commit_to_wires(transcript)?;
        self.commit_to_lookup_counts_and_w4(transcript)?;
        self.commit_to_logderiv_inverses(transcript)?;
        self.commit_to_z_perm(verifying_key, transcript)?;

        Oink::<C, H>::generate_alphas_round(&mut self.memory.challenges.alphas, transcript);
        Ok(self.memory)
    }
}
