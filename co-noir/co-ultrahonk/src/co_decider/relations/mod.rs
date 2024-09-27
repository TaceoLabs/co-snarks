pub(crate) mod poseidon2_external_relation;

use super::{co_sumcheck::round::SumcheckRoundOutput, univariates::SharedUnivariate};
use ark_ec::pairing::Pairing;
use mpc_core::traits::PrimeFieldMpcProtocol;
use poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc};
use ultrahonk::prelude::Univariate;

// TODO calculate once relations are here
pub(crate) const NUM_SUBRELATIONS: usize = 26;

// pub(crate) const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
//     + UltraPermutationRelation::NUM_RELATIONS
//     + DeltaRangeConstraintRelation::NUM_RELATIONS
//     + EllipticRelation::NUM_RELATIONS
//     + AuxiliaryRelation::NUM_RELATIONS
//     + LogDerivLookupRelation::NUM_RELATIONS
//     + Poseidon2ExternalRelation::NUM_RELATIONS
//     + Poseidon2InternalRelation::NUM_RELATIONS;

pub(crate) struct AllRelationAcc<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<T, P>,
}

impl<T, P: Pairing> Default for AllRelationAcc<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn default() -> Self {
        Self {
            r_pos_ext: Default::default(),
        }
    }
}

impl<T, P: Pairing> AllRelationAcc<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) fn scale(
        &mut self,
        driver: &mut T,
        first_scalar: P::ScalarField,
        elements: &[P::ScalarField],
    ) {
        assert!(elements.len() == NUM_SUBRELATIONS - 1);
        // self.r_arith.scale(driver, &[first_scalar, elements[0]]);
        // self.r_perm.scale(driver, &elements[1..3]);
        // self.r_delta.scale(driver, &elements[3..7]);
        // self.r_elliptic.scale(driver, &elements[7..9]);
        // self.r_aux.scale(driver, &elements[9..15]);
        // self.r_lookup.scale(driver, &elements[15..17]);
        self.r_pos_ext.scale(driver, &elements[17..21]);
        // self.r_pos_int.scale(driver, &elements[21..]);
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        driver: &mut T,
        result: &mut SharedUnivariate<T, P, SIZE>,
        extended_random_poly: &Univariate<P::ScalarField, SIZE>,
        partial_evaluation_result: &P::ScalarField,
    ) {
        // self.r_arith.extend_and_batch_univariates(
        //     driver,
        //     result,
        //     extended_random_poly,
        //     partial_evaluation_result,
        // );
        // self.r_perm.extend_and_batch_univariates(
        //     driver,
        //     result,
        //     extended_random_poly,
        //     partial_evaluation_result,
        // );
        // self.r_delta.extend_and_batch_univariates(
        //     driver,
        //     result,
        //     extended_random_poly,
        //     partial_evaluation_result,
        // );
        // self.r_elliptic.extend_and_batch_univariates(
        //     driver,
        //     result,
        //     extended_random_poly,
        //     partial_evaluation_result,
        // );
        // self.r_aux.extend_and_batch_univariates(
        //     driver,
        //     result,
        //     extended_random_poly,
        //     partial_evaluation_result,
        // );
        // self.r_lookup.extend_and_batch_univariates(
        //     driver,
        //     result,
        //     extended_random_poly,
        //     partial_evaluation_result,
        // );
        self.r_pos_ext.extend_and_batch_univariates(
            driver,
            result,
            extended_random_poly,
            partial_evaluation_result,
        );
        // self.r_pos_int.extend_and_batch_univariates(
        //     driver,
        //     result,
        //     extended_random_poly,
        //     partial_evaluation_result,
        // );
    }
}
