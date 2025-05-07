use crate::{
    co_decider::{prover::CoDecider, types::ProverMemory},
    co_oink::prover::CoOink,
    key::proving_key::ProvingKey,
    mpc::NoirUltraHonkProver,
    prelude::{PlainUltraHonkDriver, Rep3UltraHonkDriver, ShamirUltraHonkDriver},
    CONST_PROOF_SIZE_LOG_N,
};
use ark_ec::pairing::Pairing;
use co_builder::{
    prelude::{HonkCurve, ProverCrs, PAIRING_POINT_ACCUMULATOR_SIZE},
    HonkProofResult,
};
use mpc_core::protocols::{
    rep3::network::{IoContext, Rep3Network},
    shamir::{network::ShamirNetwork, ShamirPreprocessing, ShamirProtocol},
};
use std::{marker::PhantomData, time::Instant};
use ultrahonk::prelude::{
    HonkProof, Transcript, TranscriptFieldType, TranscriptHasher, ZeroKnowledge,
};

pub type Rep3CoUltraHonk<N, P, H> = CoUltraHonk<Rep3UltraHonkDriver<N>, P, H>;
pub type ShamirCoUltraHonk<N, P, H> =
    CoUltraHonk<ShamirUltraHonkDriver<<P as Pairing>::ScalarField, N>, P, H>;

pub struct CoUltraHonk<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> {
    pub(crate) driver: T,
    phantom_data: PhantomData<P>,
    phantom_hasher: PhantomData<H>,
}

impl<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
    > CoUltraHonk<T, P, H>
{
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
        }
    }

    fn generate_gate_challenges(
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> Vec<P::ScalarField> {
        tracing::trace!("generate gate challenges");

        let mut gate_challenges: Vec<<P as Pairing>::ScalarField> =
            Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);

        for idx in 0..CONST_PROOF_SIZE_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{}", idx));
            gate_challenges.push(chall);
        }
        gate_challenges
    }

    pub fn prove_inner(
        mut self,
        mut proving_key: ProvingKey<T, P>,
        crs: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkProofResult<(HonkProof<TranscriptFieldType>, T)> {
        tracing::trace!("CoUltraHonk prove");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        let oink = CoOink::new(&mut self.driver, has_zk);
        let start = Instant::now();
        let oink_result = oink.prove(&mut proving_key, &mut transcript, crs)?;
        let duration_ms = start.elapsed().as_micros() as f64 / 1000.;
        tracing::info!("Oink::prove took {duration_ms} ms");

        let circuit_size = proving_key.circuit_size;

        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        memory.relation_parameters.gate_challenges =
            Self::generate_gate_challenges(&mut transcript);

        let decider = CoDecider::new(self.driver, memory, has_zk);
        let start = Instant::now();
        let result = decider.prove(circuit_size, crs, transcript);
        let duration_ms = start.elapsed().as_micros() as f64 / 1000.;
        tracing::info!("Decider::prove took {duration_ms} ms");
        result
    }
}

impl<
        P: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
        N: Rep3Network,
    > Rep3CoUltraHonk<N, P, H>
{
    pub fn prove(
        net: N,
        proving_key: ProvingKey<Rep3UltraHonkDriver<N>, P>,
        crs: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<(HonkProof<TranscriptFieldType>, Vec<TranscriptFieldType>, N)> {
        let mut io_context0 = IoContext::init(net)?;
        let io_context1 = io_context0.fork()?;
        let prover = Self {
            driver: Rep3UltraHonkDriver::new(io_context0, io_context1),
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
        };
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let (proof, driver) = prover.prove_inner(proving_key, crs, has_zk)?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs, driver.into_network()))
    }
}

impl<
        P: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
        N: ShamirNetwork,
    > ShamirCoUltraHonk<N, P, H>
{
    pub fn prove(
        net: N,
        threshold: usize,
        proving_key: ProvingKey<ShamirUltraHonkDriver<<P as Pairing>::ScalarField, N>, P>,
        crs: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<(HonkProof<TranscriptFieldType>, Vec<TranscriptFieldType>, N)> {
        // init MPC protocol
        let num_pairs = if net.get_num_parties() == 3 {
            0 // Precomputation is done on the fly since it requires no communication
        } else {
            proving_key.ultrahonk_num_randomness(has_zk)
        };
        let preprocessing = ShamirPreprocessing::new(threshold, net, num_pairs)?;
        let mut protocol0 = ShamirProtocol::from(preprocessing);
        let protocol1 = protocol0.fork_with_pairs(0)?;
        let driver = ShamirUltraHonkDriver::new(protocol0, protocol1);
        let prover = Self {
            driver,
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
        };
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let (proof, driver) = prover.prove_inner(proving_key, crs, has_zk)?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs, driver.into_network()))
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
        let prover = Self {
            driver: PlainUltraHonkDriver,
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
        };
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let (proof, _) = prover.prove_inner(proving_key, crs, has_zk)?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }
}
