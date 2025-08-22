use crate::decider::relations::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::decider::{types::RelationParameters, univariate::Univariate};
use ark_ff::{PrimeField, Zero};
use co_builder::flavours::translator_flavour::TranslatorFlavour;

#[derive(Clone, Debug, Default)]
pub(crate) struct TranslatorOpCodeConstraintRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 5>,
}

impl<F: PrimeField> TranslatorOpCodeConstraintRelationAcc<F> {
    pub(crate) fn scale(&mut self, current_scalar: &mut F, challenge: &F) {
        self.r0 *= *current_scalar;
        *current_scalar *= challenge;
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    ) {
        self.r0.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
    }
}

#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct TranslatorOpCodeConstraintRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
}

pub(crate) struct TranslatorOpCodeConstraintRelation {}

impl TranslatorOpCodeConstraintRelation {
    pub(crate) const NUM_RELATIONS: usize = 1;
}

impl<F: PrimeField> Relation<F, TranslatorFlavour> for TranslatorOpCodeConstraintRelation {
    type Acc = TranslatorOpCodeConstraintRelationAcc<F>;
    type VerifyAcc = TranslatorOpCodeConstraintRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>) -> bool {
        input.witness.op().is_zero()
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
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, TranslatorFlavour, SIZE>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate TranslatorOpCodeConstraintRelation");
        let op = input.witness.op();

        let minus_three = -F::from(3u64);
        let minus_four = -F::from(4u64);
        let minus_eight = -F::from(8u64);

        let mut tmp_1 = (op.to_owned() + &minus_three) * op;
        tmp_1 *= op.to_owned() + &minus_four;
        tmp_1 *= op.to_owned() + &minus_eight;
        tmp_1 *= *scaling_factor;

        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp_1.evaluations[i];
        }
    }
}
