use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct TranslatorOpCodeConstraintRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 5>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> TranslatorOpCodeConstraintRelationAcc<T, P> {
    pub(crate) fn scale(
        &mut self,
        current_scalar: &mut P::ScalarField,
        challenge: &P::ScalarField,
    ) {
        self.r0.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
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
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default
    for TranslatorOpCodeConstraintRelationAcc<T, P>
{
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
        }
    }
}

pub(crate) struct TranslatorOpCodeConstraintRelation {}

impl TranslatorOpCodeConstraintRelation {
    pub(crate) const NUM_RELATIONS: usize = 1;
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, TranslatorFlavour>
    for TranslatorOpCodeConstraintRelation
{
    type Acc = TranslatorOpCodeConstraintRelationAcc<T, P>;
    type VerifyAcc = ();

    fn can_skip(
        _entity: &crate::co_decider::types::ProverUnivariates<T, P, TranslatorFlavour>,
    ) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, TranslatorFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, TranslatorFlavour>,
    ) {
        batch.add_op(entity);
    }

    /**
     * @brief Expression for enforcing the value of the Opcode to be {0,3,4,8} (nop, eq and reset, mul or add)
     * @details This relation enforces the opcode to be one of described values. Since we don't care about even
     * values in the opcode wire and usually just set them to zero, we don't use a lagrange polynomial to specify
     * the relation to be enforced just at odd indices, which brings the degree down by 1.
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, TranslatorFlavour>,
        _relation_parameters: &RelationParameters<P::ScalarField>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate TranslatorOpCodeConstraintRelation");
        let op = input.witness.op();

        let minus_three = -P::ScalarField::from(3u64);
        let minus_four = -P::ScalarField::from(4u64);
        let minus_eight = -P::ScalarField::from(8u64);

        let op_minus_three = T::add_scalar(op, minus_three, state.id());
        let op_minus_four = T::add_scalar(op, minus_four, state.id());
        let op_minus_eight = T::add_scalar(op, minus_eight, state.id());
        let capacity = op.len() * 2;
        let mut lhs = Vec::with_capacity(capacity);
        let mut rhs = Vec::with_capacity(capacity);
        lhs.extend(op_minus_three);
        rhs.extend(op);
        lhs.extend(op_minus_four);
        rhs.extend(op_minus_eight);
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);

        let mut lhs = Vec::with_capacity(capacity);
        let mut rhs = Vec::with_capacity(capacity);
        lhs.extend(mul[0]);
        rhs.extend(mul[1]);
        let mut tmp = T::mul_many(&lhs, &rhs, net, state)?;
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);

        Ok(())
    }
}
