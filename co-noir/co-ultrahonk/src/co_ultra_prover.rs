use crate::{
    CONST_PROOF_SIZE_LOG_N, co_decider::co_decider_prover::CoDecider,
    co_decider::types::ProverMemory, co_oink::co_oink_prover::CoOink, key::proving_key::ProvingKey,
};
use co_builder::prelude::PAIRING_POINT_ACCUMULATOR_SIZE;
use co_noir_common::{
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    mpc::{
        NoirUltraHonkProver, plain::PlainUltraHonkDriver, rep3::Rep3UltraHonkDriver,
        shamir::ShamirUltraHonkDriver,
    },
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    shamir::{ShamirPreprocessing, ShamirState},
};
use mpc_net::Network;
use noir_types::HonkProof;
use std::marker::PhantomData;
use ultrahonk::prelude::VerifyingKeyBarretenberg;

pub type Rep3CoUltraHonk<P, H> = CoUltraHonk<Rep3UltraHonkDriver, P, H>;
pub type ShamirCoUltraHonk<P, H> = CoUltraHonk<ShamirUltraHonkDriver, P, H>;

pub struct CoUltraHonk<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> {
    phantom_data: PhantomData<(P, H, T)>,
}

impl<
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> CoUltraHonk<T, C, H>
{
    fn generate_gate_challenges(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        virtual_log_n: usize,
    ) -> Vec<C::ScalarField> {
        tracing::trace!("generate gate challenges");

        transcript
            .get_powers_of_challenge::<C>("Sumcheck:gate_challenge".to_string(), virtual_log_n)
    }

    pub fn prove_inner<N: Network>(
        net: &N,
        state: &mut T::State,
        mut proving_key: ProvingKey<T, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> HonkProofResult<HonkProof<H::DataType>> {
        tracing::trace!("CoUltraHonk prove");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        let oink = CoOink::new(net, state, has_zk);
        let oink_result = oink.prove(&mut proving_key, &mut transcript, crs, verifying_key)?;

        let circuit_size = proving_key.circuit_size;
        let log_dyadic_circuit_size = proving_key.circuit_size.next_power_of_two().ilog2() as usize;
        let virtual_log_n = if H::USE_PADDING {
            CONST_PROOF_SIZE_LOG_N
        } else {
            log_dyadic_circuit_size
        };

        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        memory.gate_challenges = Self::generate_gate_challenges(&mut transcript, virtual_log_n);

        let decider = CoDecider::new(net, state, memory, has_zk);
        decider.prove(circuit_size, crs, transcript, virtual_log_n)
    }
}

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    Rep3CoUltraHonk<C, H>
{
    #[expect(clippy::type_complexity)]
    pub fn prove<N: Network>(
        net: &N,
        proving_key: ProvingKey<Rep3UltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        let mut state = Rep3State::new(net, A2BType::default())?;
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(net, &mut state, proving_key, crs, has_zk, verifying_key)?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs))
    }
}

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    ShamirCoUltraHonk<C, H>
{
    #[expect(clippy::type_complexity)]
    pub fn prove<N: Network>(
        net: &N,
        num_parties: usize,
        threshold: usize,
        proving_key: ProvingKey<ShamirUltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        // init MPC protocol
        let num_pairs = if num_parties == 3 {
            0 // Precomputation is done on the fly since it requires no communication
        } else {
            proving_key.ultrahonk_num_randomness(has_zk)
        };
        let preprocessing = ShamirPreprocessing::new(num_parties, threshold, num_pairs, net)?;
        let mut state = ShamirState::from(preprocessing);
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(net, &mut state, proving_key, crs, has_zk, verifying_key)?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs))
    }
}

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    CoUltraHonk<PlainUltraHonkDriver, C, H>
{
    #[expect(clippy::type_complexity)]
    pub fn prove(
        proving_key: ProvingKey<PlainUltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(&(), &mut (), proving_key, crs, has_zk, verifying_key)?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }
}
