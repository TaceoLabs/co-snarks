use crate::{co_oink::prover::CoOink, types::ProvingKey};
use mpc_core::traits::{MSMProvider, PrimeFieldMpcProtocol};
use std::marker::PhantomData;
use ultrahonk::prelude::{
    HonkCurve, HonkProof, HonkProofResult, TranscriptFieldType, TranscriptType,
    POSEIDON2_BN254_T4_PARAMS,
};

pub struct CoUltraHonk<T, P: HonkCurve<TranscriptFieldType>>
where
    T: PrimeFieldMpcProtocol<P::ScalarField> + MSMProvider<P::G1>,
{
    pub(crate) driver: T,
    phantom_data: PhantomData<P>,
}

impl<T, P: HonkCurve<TranscriptFieldType>> CoUltraHonk<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField> + MSMProvider<P::G1>,
{
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
        }
    }

    pub fn prove(
        &mut self,
        proving_key: ProvingKey<T, P>,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("CoUltraHonk prove");

        let mut transcript = TranscriptType::new(&POSEIDON2_BN254_T4_PARAMS);

        let oink = CoOink::new(&mut self.driver);
        let oink_result = oink.prove(&proving_key, &mut transcript)?;

        let cicruit_size = proving_key.circuit_size;
        let crs = proving_key.crs;

        todo!("prove");
    }
}
