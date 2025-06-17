use crate::{
    CONST_PROOF_SIZE_LOG_N,
    co_decider::{prover::CoDecider, types::ProverMemory},
    co_oink::prover::CoOink,
    key::proving_key::ProvingKey,
    mpc::NoirUltraHonkProver,
    prelude::{PlainUltraHonkDriver, Rep3UltraHonkDriver, ShamirUltraHonkDriver},
};
use ark_ec::pairing::Pairing;
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, PAIRING_POINT_ACCUMULATOR_SIZE, ProverCrs},
};
use mpc_core::protocols::{
    rep3::Rep3State,
    shamir::{ShamirPreprocessing, ShamirState},
};
use mpc_net::Network;
use std::marker::PhantomData;
use ultrahonk::prelude::{
    HonkProof, Transcript, TranscriptFieldType, TranscriptHasher, ZeroKnowledge,
};

pub type Rep3CoUltraHonk<P, H> = CoUltraHonk<Rep3UltraHonkDriver, P, H>;
pub type ShamirCoUltraHonk<P, H> = CoUltraHonk<ShamirUltraHonkDriver, P, H>;

pub struct CoUltraHonk<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> {
    phantom_data0: PhantomData<P>,
    phantom_data1: PhantomData<H>,
    phantom_data2: PhantomData<T>,
}

impl<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> CoUltraHonk<T, P, H>
{
    fn generate_gate_challenges(
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> Vec<P::ScalarField> {
        tracing::trace!("generate gate challenges");

        let mut gate_challenges: Vec<<P as Pairing>::ScalarField> =
            Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);

        for idx in 0..CONST_PROOF_SIZE_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{idx}"));
            gate_challenges.push(chall);
        }
        gate_challenges
    }

    pub fn prove_inner<N: Network>(
        net: &N,
        state: &mut T::State,
        mut proving_key: ProvingKey<T, P>,
        crs: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("CoUltraHonk prove");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        let oink = CoOink::new(net, state, has_zk);
        let oink_result = oink.prove(&mut proving_key, &mut transcript, crs)?;

        let circuit_size = proving_key.circuit_size;

        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        memory.relation_parameters.gate_challenges =
            Self::generate_gate_challenges(&mut transcript);

        let decider = CoDecider::new(net, state, memory, has_zk);
        decider.prove(circuit_size, crs, transcript)
    }
}

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    Rep3CoUltraHonk<P, H>
{
    pub fn prove<N: Network>(
        net: &N,
        proving_key: ProvingKey<Rep3UltraHonkDriver, P>,
        crs: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<(HonkProof<TranscriptFieldType>, Vec<TranscriptFieldType>)> {
        let mut state = Rep3State::new(net)?;
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(net, &mut state, proving_key, crs, has_zk)?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs))
    }
}

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    ShamirCoUltraHonk<P, H>
{
    pub fn prove<N: Network>(
        net: &N,
        num_parties: usize,
        threshold: usize,
        proving_key: ProvingKey<ShamirUltraHonkDriver, P>,
        crs: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<(HonkProof<TranscriptFieldType>, Vec<TranscriptFieldType>)> {
        // init MPC protocol
        let num_pairs = if num_parties == 3 {
            0 // Precomputation is done on the fly since it requires no communication
        } else {
            proving_key.ultrahonk_num_randomness(has_zk)
        };
        let preprocessing = ShamirPreprocessing::new(num_parties, threshold, num_pairs, net)?;
        let mut state = ShamirState::from(preprocessing);
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(net, &mut state, proving_key, crs, has_zk)?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs))
    }
}

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    CoUltraHonk<PlainUltraHonkDriver, P, H>
{
    pub fn prove(
        proving_key: ProvingKey<PlainUltraHonkDriver, P>,
        crs: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<(HonkProof<TranscriptFieldType>, Vec<TranscriptFieldType>)> {
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(&(), &mut (), proving_key, crs, has_zk)?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }
}
