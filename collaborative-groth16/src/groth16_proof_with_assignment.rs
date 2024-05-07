// TODO move this file

use crate::groth16::CollaborativeGroth16;
use ark_ec::pairing::Pairing;
use ark_groth16::{Proof, ProvingKey};
use ark_relations::r1cs::Result as R1CSResult;
use mpc_core::traits::{EcMpcProtocol, FFTProvider, PrimeFieldMpcProtocol};

type FieldShare<'a, T, P> =
    <T as PrimeFieldMpcProtocol<'a, <P as Pairing>::ScalarField>>::FieldShare;
type FieldShareSlice<'a, T, P> =
    <T as PrimeFieldMpcProtocol<'a, <P as Pairing>::ScalarField>>::FieldShareSlice;

impl<T, P: Pairing> CollaborativeGroth16<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<'a, P::ScalarField>
        + EcMpcProtocol<'a, P::G1>
        + EcMpcProtocol<'a, P::G2>
        + FFTProvider<'a, P::ScalarField>,
{
    pub fn create_proof_with_assignment(
        pk: &ProvingKey<P>,
        r: FieldShare<'_, T, P>,
        s: FieldShare<'_, T, P>,
        h: FieldShareSlice<'_, T, P>,
        input_assignment: &[P::ScalarField],
        aux_assignment: FieldShareSlice<'_, T, P>,
    ) -> R1CSResult<Proof<P>> {
        todo!()
    }
}
