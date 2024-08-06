use ark_ec::pairing::Pairing;
use mpc_core::traits::{
    FFTPostProcessing, FFTProvider, MSMProvider, MontgomeryField, MpcToMontgomery,
    PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};

use crate::{
    round1::{Round1Challenges, Round1Proof},
    types::WirePolyOutput,
    Domains, PlonkProofResult, Round,
};

impl<T, P: Pairing> Round<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>
        + MpcToMontgomery<P::ScalarField>,
    P::ScalarField: FFTPostProcessing + MontgomeryField,
{
    pub(super) fn round2(
        driver: &mut T,
        domains: Domains<P>,
        challenges: Round1Challenges<T, P>,
        proof: Round1Proof<P>,
        wire_polys: WirePolyOutput<T, P>,
    ) -> PlonkProofResult<Self> {
        todo!()
    }
}
