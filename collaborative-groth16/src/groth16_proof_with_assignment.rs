// TODO move this file

use crate::groth16::CollaborativeGroth16;
use ark_ec::pairing::Pairing;
use ark_groth16::{Proof, ProvingKey};
use ark_relations::r1cs::Result as R1CSResult;
use ark_std::{end_timer, start_timer};
use mpc_core::traits::{EcMpcProtocol, FFTProvider, MSMProvider, PrimeFieldMpcProtocol};

type FieldShare<'a, T, P> =
    <T as PrimeFieldMpcProtocol<'a, <P as Pairing>::ScalarField>>::FieldShare;
type FieldShareSlice<'a, T, P> =
    <T as PrimeFieldMpcProtocol<'a, <P as Pairing>::ScalarField>>::FieldShareSlice;

impl<T, P: Pairing> CollaborativeGroth16<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<'a, P::ScalarField>
        + EcMpcProtocol<'a, P::G1>
        + EcMpcProtocol<'a, P::G2>
        + FFTProvider<'a, P::ScalarField>
        + MSMProvider<'a, P::G1>,
{
    pub fn create_proof_with_assignment(
        &mut self,
        pk: &ProvingKey<P>,
        r: FieldShare<'_, T, P>,
        s: FieldShare<'_, T, P>,
        h: FieldShareSlice<'_, T, P>,
        input_assignment: &[P::ScalarField],
        aux_assignment: FieldShareSlice<'_, T, P>,
    ) -> R1CSResult<Proof<P>> {
        let c_acc_time = start_timer!(|| "Compute C");
        let h_acc = self.driver.msm_public_points(&pk.h_query, h);

        // Compute C
        let l_aux_acc = self.driver.msm_public_points(&pk.l_query, aux_assignment);

        // let r_s_delta_g1 = pk
        //     .delta_g1
        //     .into_group()
        //     .mul_bigint(&r.into_bigint())
        //     .mul_bigint(&s.into_bigint());

        end_timer!(c_acc_time);
        todo!()
    }
}
