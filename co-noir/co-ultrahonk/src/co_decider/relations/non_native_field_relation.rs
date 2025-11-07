use super::{ProverUnivariatesBatch, Relation};
use crate::co_decider::{
    relations::fold_accumulator, types::MAX_PARTIAL_RELATION_LENGTH, univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::Zero;
use co_noir_common::types::RelationParameters;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    mpc::NoirUltraHonkProver,
};
use itertools::Itertools as _;
use mpc_net::Network;
use num_bigint::BigUint;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct NonNativeFieldRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 6>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for NonNativeFieldRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> NonNativeFieldRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == NonNativeFieldRelation::NUM_RELATIONS);
        self.r0.scale_inplace(elements[0]);
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut SharedUnivariate<T, P, SIZE>,
        extended_random_poly: &Univariate<P::ScalarField, SIZE>,
        partial_evaluation_result: &P::ScalarField,
    ) {
        self.r0.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

pub(crate) struct NonNativeFieldRelation {}

impl NonNativeFieldRelation {
    pub(crate) const NUM_RELATIONS: usize = 1;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 5;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P>
    for NonNativeFieldRelation
{
    type Acc = NonNativeFieldRelationAcc<T, P>;

    fn can_skip(entity: &super::ProverUnivariates<T, P>) -> bool {
        entity.precomputed.q_nnf().is_zero()
    }

    fn add_entites(
        entity: &super::ProverUnivariates<T, P>,
        batch: &mut ProverUnivariatesBatch<T, P>,
    ) {
        batch.add_w_l(entity);
        batch.add_w_r(entity);
        batch.add_w_o(entity);
        batch.add_w_4(entity);

        batch.add_shifted_w_l(entity);
        batch.add_shifted_w_r(entity);
        batch.add_shifted_w_o(entity);
        batch.add_shifted_w_4(entity);

        batch.add_q_r(entity);
        batch.add_q_o(entity);
        batch.add_q_4(entity);
        batch.add_q_m(entity);
        batch.add_q_nnf(entity);
    }

    /**
     * @brief Non-native field arithmetic relation
     * @details Adds contributions for identities associated with non-native field arithmetic:
     *  * Bigfield product evaluation (3 in total)
     *  * Bigfield limb accumulation (2 in total)
     *
     * Multiple selectors are used to 'switch' nnf gates on/off according to the following pattern:
     *
     * | gate type                    | q_nnf | q_2 | q_3 | q_4 | q_m |
     * | ---------------------------- | ----- | --- | --- | --- | --- |
     * | Bigfield Limb Accumulation 1 | 1     | 0   | 1   | 1   | 0   |
     * | Bigfield Limb Accumulation 2 | 1     | 0   | 1   | 0   | 1   |
     * | Bigfield Product 1           | 1     | 1   | 1   | 0   | 0   |
     * | Bigfield Product 2           | 1     | 1   | 0   | 1   | 0   |
     * | Bigfield Product 3           | 1     | 1   | 0   | 0   | 1   |
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the Totaly extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<N: Network>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P>,
        _relation_parameters: &RelationParameters<<P>::ScalarField>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let w_3 = input.witness.w_o();
        let w_4 = input.witness.w_4();
        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();

        let q_2 = input.precomputed.q_r();
        let q_3 = input.precomputed.q_o();
        let q_4 = input.precomputed.q_4();
        let q_m = input.precomputed.q_m();
        let q_nnf = input.precomputed.q_nnf();

        let limb_size = P::ScalarField::from(BigUint::one() << 68);
        let sublimb_shift = P::ScalarField::from(1u64 << 14);

        let capacity = w_1.len() + w_2.len() + w_3.len() + w_4.len() + w_1_shift.len();
        let mut lhs = Vec::with_capacity(capacity);
        let mut rhs = Vec::with_capacity(capacity);
        lhs.extend(w_1);
        lhs.extend(w_2);
        lhs.extend(w_4);
        lhs.extend(w_3);
        lhs.extend(w_1_shift);

        rhs.extend(w_2_shift);
        rhs.extend(w_1_shift);
        rhs.extend(w_1);
        rhs.extend(w_2);
        rhs.extend(w_2_shift);

        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 5).collect_vec();
        debug_assert_eq!(mul.len(), 5);

        // Non native field arithmetic gate 2
        let mut limb_subproduct = T::add_many(mul[0], mul[1]);
        let mut non_native_field_gate_2 = T::sub_many(&T::add_many(mul[2], mul[3]), w_3_shift);

        T::scale_many_in_place(&mut non_native_field_gate_2, limb_size);
        T::sub_assign_many(&mut non_native_field_gate_2, w_4_shift);
        T::add_assign_many(&mut non_native_field_gate_2, &limb_subproduct);
        T::mul_assign_with_public_many(&mut non_native_field_gate_2, q_4);

        T::scale_many_in_place(&mut limb_subproduct, limb_size);
        T::add_assign_many(&mut limb_subproduct, mul[4]);

        let mut non_native_field_gate_1 = limb_subproduct.clone();
        T::sub_assign_many(&mut non_native_field_gate_1, w_3);
        T::sub_assign_many(&mut non_native_field_gate_1, w_4);
        T::mul_assign_with_public_many(&mut non_native_field_gate_1, q_3);

        let mut non_native_field_gate_3 = limb_subproduct;
        T::add_assign_many(&mut non_native_field_gate_3, w_4);
        T::sub_assign_many(&mut non_native_field_gate_3, w_3_shift);
        T::sub_assign_many(&mut non_native_field_gate_3, w_4_shift);
        T::mul_assign_with_public_many(&mut non_native_field_gate_3, q_m);

        let mut non_native_field_identity = non_native_field_gate_1; //+ non_native_field_gate_2 + non_native_field_gate_3;
        T::add_assign_many(&mut non_native_field_identity, &non_native_field_gate_2);
        T::add_assign_many(&mut non_native_field_identity, &non_native_field_gate_3);
        T::mul_assign_with_public_many(&mut non_native_field_identity, q_2);

        // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * q_4
        let mut limb_accumulator_1 = T::scale_many(w_2_shift, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_1, w_1_shift);
        T::scale_many_in_place(&mut limb_accumulator_1, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_1, w_3);
        T::scale_many_in_place(&mut limb_accumulator_1, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_1, w_2);
        T::scale_many_in_place(&mut limb_accumulator_1, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_1, w_1);
        T::sub_assign_many(&mut limb_accumulator_1, w_4);
        T::mul_assign_with_public_many(&mut limb_accumulator_1, q_4);

        // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * q_m
        let mut limb_accumulator_2 = T::scale_many(w_3_shift, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_2, w_2_shift);
        T::scale_many_in_place(&mut limb_accumulator_2, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_2, w_1_shift);
        T::scale_many_in_place(&mut limb_accumulator_2, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_2, w_4);
        T::scale_many_in_place(&mut limb_accumulator_2, sublimb_shift);
        T::add_assign_many(&mut limb_accumulator_2, w_3);
        T::sub_assign_many(&mut limb_accumulator_2, w_4_shift);
        T::mul_assign_with_public_many(&mut limb_accumulator_2, q_m);

        let mut limb_accumulator_identity = T::add_many(&limb_accumulator_1, &limb_accumulator_2);
        T::mul_assign_with_public_many(&mut limb_accumulator_identity, q_3);

        let mut nnf_identity = T::add_many(&non_native_field_identity, &limb_accumulator_identity);
        T::mul_assign_with_public_many(&mut nnf_identity, q_nnf);
        T::mul_assign_with_public_many(&mut nnf_identity, scaling_factors);

        fold_accumulator!(univariate_accumulator.r0, nnf_identity);
        Ok(())
    }
}
