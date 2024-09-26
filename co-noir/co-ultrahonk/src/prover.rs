use crate::types::ProvingKey;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::marker::PhantomData;
use ultrahonk::prelude::{
    HonkCurve, HonkProof, HonkProofResult, TranscriptFieldType, TranscriptType,
    POSEIDON2_BN254_T4_PARAMS,
};

pub struct CoUltraHonk<T, P: HonkCurve<TranscriptFieldType>>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) driver: T,
    phantom_data: PhantomData<P>,
}

impl<T, P: HonkCurve<TranscriptFieldType>> CoUltraHonk<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
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
        tracing::trace!("UltraHonk prove");

        let mut transcript = TranscriptType::new(&POSEIDON2_BN254_T4_PARAMS);

        todo!("prove");
    }
}
