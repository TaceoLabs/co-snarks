use super::Relation;
use crate::decider::types::ProverUnivariatesSized;
use crate::{
    decider::{
        types::{ClaimedEvaluations, RelationParameters},
        univariate::Univariate,
    },
    plain_prover_flavour::PlainProverFlavour,
};
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, WitnessEntitiesFlavour,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusData {
    BusIdx0,
    BusIdx1,
    BusIdx2,
}

impl From<usize> for BusData {
    fn from(idx: usize) -> Self {
        match idx {
            0 => BusData::BusIdx0,
            1 => BusData::BusIdx1,
            2 => BusData::BusIdx2,
            _ => panic!("Invalid bus index: {idx}"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DataBusLookupRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 5>,
    pub(crate) r1: Univariate<F, 5>,
    pub(crate) r2: Univariate<F, 5>,
    pub(crate) r3: Univariate<F, 5>,
    pub(crate) r4: Univariate<F, 5>,
    pub(crate) r5: Univariate<F, 5>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DataBusLookupRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
    pub(crate) r2: F,
    pub(crate) r3: F,
    pub(crate) r4: F,
    pub(crate) r5: F,
}

impl<F: PrimeField> DataBusLookupRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == DataBusLookupRelation::NUM_RELATIONS);

        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
        *result += self.r2 * running_challenge[2];
        *result += self.r3 * running_challenge[3];
        *result += self.r4 * running_challenge[4];
        *result += self.r5 * running_challenge[5];
    }
}

impl<F: PrimeField> DataBusLookupRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == DataBusLookupRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
        self.r4 *= elements[4];
        self.r5 *= elements[5];
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
        self.r1.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r2.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r3.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
        self.r4.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            true,
        );
        self.r5.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
    }
}

pub(crate) struct DataBusLookupRelation {}
impl DataBusLookupRelation {
    pub(crate) const NUM_RELATIONS: usize = 6;
    const NUM_BUS_COLUMNS: usize = 3; // calldata, return data

    fn values<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        bus_idx: BusData,
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> &Univariate<F, SIZE> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata(),
            BusData::BusIdx1 => input.witness.secondary_calldata(),
            BusData::BusIdx2 => input.witness.return_data(),
        }
    }
    fn selector<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        bus_idx: BusData,
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> &Univariate<F, SIZE> {
        match bus_idx {
            BusData::BusIdx0 => input.precomputed.q_l(),
            BusData::BusIdx1 => input.precomputed.q_r(),
            BusData::BusIdx2 => input.precomputed.q_o(),
        }
    }
    fn inverses<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        bus_idx: BusData,
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> &Univariate<F, SIZE> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_inverses(),
            BusData::BusIdx1 => input.witness.secondary_calldata_inverses(),
            BusData::BusIdx2 => input.witness.return_data_inverses(),
        }
    }
    fn read_counts<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        bus_idx: BusData,
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> &Univariate<F, SIZE> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_read_counts(),
            BusData::BusIdx1 => input.witness.secondary_calldata_read_counts(),
            BusData::BusIdx2 => input.witness.return_data_read_counts(),
        }
    }
    fn read_tags<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        bus_idx: BusData,
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> &Univariate<F, SIZE> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_read_tags(),
            BusData::BusIdx1 => input.witness.secondary_calldata_read_tags(),
            BusData::BusIdx2 => input.witness.return_data_read_tags(),
        }
    }

    fn compute_inverse_exists<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        bus_idx: BusData,
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> Univariate<F, SIZE> {
        let is_read_gate = DataBusLookupRelation::get_read_selector(bus_idx, input);
        let read_tag = DataBusLookupRelation::read_tags(bus_idx, input);
        is_read_gate.to_owned() + read_tag - (is_read_gate * read_tag)
    }

    fn get_read_selector<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        bus_idx: BusData,
        input: &ProverUnivariatesSized<F, L, SIZE>,
    ) -> Univariate<F, SIZE> {
        let q_busread = input.precomputed.q_busread();
        let column_selector = DataBusLookupRelation::selector(bus_idx, input);
        q_busread.to_owned() * column_selector
    }

    fn compute_write_term<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        bus_idx: BusData,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        params: &RelationParameters<F, L>,
    ) -> Univariate<F, SIZE> {
        let id = input.precomputed.databus_id();
        let value = DataBusLookupRelation::values(bus_idx, input);
        let gamma = params.gamma;
        let beta = params.beta;

        // value_i + idx_i * beta + gamma
        id.to_owned() * beta + value + &gamma
    }

    fn compute_read_term<F: PrimeField, L: PlainProverFlavour, const SIZE: usize>(
        input: &ProverUnivariatesSized<F, L, SIZE>,
        params: &RelationParameters<F, L>,
    ) -> Univariate<F, SIZE> {
        // Bus value stored in w_l, index into bus column stored in w_r
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let gamma = params.gamma;
        let beta = params.beta;

        // value + index * beta + gamma
        w_2.to_owned() * beta + w_1 + &gamma
    }

    fn values_verifier<F: PrimeField, L: PlainProverFlavour>(
        bus_idx: BusData,
        input: &ClaimedEvaluations<F, L>,
    ) -> F {
        match bus_idx {
            BusData::BusIdx0 => *input.witness.calldata(),
            BusData::BusIdx1 => *input.witness.secondary_calldata(),
            BusData::BusIdx2 => *input.witness.return_data(),
        }
    }
    fn selector_verifier<F: PrimeField, L: PlainProverFlavour>(
        bus_idx: BusData,
        input: &ClaimedEvaluations<F, L>,
    ) -> F {
        match bus_idx {
            BusData::BusIdx0 => *input.precomputed.q_l(),
            BusData::BusIdx1 => *input.precomputed.q_r(),
            BusData::BusIdx2 => *input.precomputed.q_o(),
        }
    }
    fn inverses_verifier<F: PrimeField, L: PlainProverFlavour>(
        bus_idx: BusData,
        input: &ClaimedEvaluations<F, L>,
    ) -> F {
        match bus_idx {
            BusData::BusIdx0 => *input.witness.calldata_inverses(),
            BusData::BusIdx1 => *input.witness.secondary_calldata_inverses(),
            BusData::BusIdx2 => *input.witness.return_data_inverses(),
        }
    }
    fn read_counts_verifier<F: PrimeField, L: PlainProverFlavour>(
        bus_idx: BusData,
        input: &ClaimedEvaluations<F, L>,
    ) -> F {
        match bus_idx {
            BusData::BusIdx0 => *input.witness.calldata_read_counts(),
            BusData::BusIdx1 => *input.witness.secondary_calldata_read_counts(),
            BusData::BusIdx2 => *input.witness.return_data_read_counts(),
        }
    }
    fn read_tags_verifier<F: PrimeField, L: PlainProverFlavour>(
        bus_idx: BusData,
        input: &ClaimedEvaluations<F, L>,
    ) -> F {
        match bus_idx {
            BusData::BusIdx0 => *input.witness.calldata_read_tags(),
            BusData::BusIdx1 => *input.witness.secondary_calldata_read_tags(),
            BusData::BusIdx2 => *input.witness.return_data_read_tags(),
        }
    }

    fn compute_inverse_exists_verifier<F: PrimeField, L: PlainProverFlavour>(
        bus_idx: BusData,
        input: &ClaimedEvaluations<F, L>,
    ) -> F {
        let is_read_gate = DataBusLookupRelation::get_read_selector_verifier(bus_idx, input);
        let read_tag = DataBusLookupRelation::read_tags_verifier(bus_idx, input);
        is_read_gate + read_tag - (is_read_gate * read_tag)
    }

    fn get_read_selector_verifier<F: PrimeField, L: PlainProverFlavour>(
        bus_idx: BusData,
        input: &ClaimedEvaluations<F, L>,
    ) -> F {
        let q_busread = input.precomputed.q_busread();
        let column_selector = DataBusLookupRelation::selector_verifier(bus_idx, input);
        (*q_busread) * column_selector
    }

    fn compute_write_term_verifier<F: PrimeField, L: PlainProverFlavour>(
        bus_idx: BusData,
        input: &ClaimedEvaluations<F, L>,
        params: &RelationParameters<F, L>,
    ) -> F {
        let id = input.precomputed.databus_id();
        let value = DataBusLookupRelation::values_verifier(bus_idx, input);
        let gamma = params.gamma;
        let beta = params.beta;

        // value_i + idx_i * beta + gamma
        value + *id * beta + gamma
    }

    fn compute_read_term_verifier<F: PrimeField, L: PlainProverFlavour>(
        input: &ClaimedEvaluations<F, L>,
        params: &RelationParameters<F, L>,
    ) -> F {
        // Bus value stored in w_l, index into bus column stored in w_r
        let w_1 = *input.witness.w_l();
        let w_2 = *input.witness.w_r();
        let gamma = params.gamma;
        let beta = params.beta;

        // value + index * beta + gamma
        w_2 * beta + w_1 + gamma
    }

    fn accumulate_subrelation_contributions<
        F: PrimeField,
        L: PlainProverFlavour,
        const SIZE: usize,
    >(
        univariate_accumulator: &mut DataBusLookupRelationAcc<F>,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        params: &RelationParameters<F, L>,
        scaling_factor: &F,
        bus_idx: BusData,
    ) {
        let inverses = Self::inverses(bus_idx, input); // Degree 1
        let read_counts_m = Self::read_counts(bus_idx, input); // Degree 1
        let read_term = Self::compute_read_term(input, params); // Degree 1 (2)
        let write_term = Self::compute_write_term(bus_idx, input, params); // Degree 1 (2)
        let inverse_exists = Self::compute_inverse_exists(bus_idx, input); // Degree 2
        let read_selector = Self::get_read_selector(bus_idx, input); // Degree 2

        // Determine which pair of subrelations to update based on which bus column is being read
        let subrel_idx_1: u32 = 2u32 * (bus_idx as u32);
        let subrel_idx_2: u32 = 2u32 * (bus_idx as u32) + 1u32;

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value
        // is 0 if !inverse_exists. Degree 3 (5)
        let tmp = (read_term.clone() * &write_term * inverses - inverse_exists) * scaling_factor;
        match subrel_idx_1 {
            0 => {
                for i in 0..univariate_accumulator.r0.evaluations.len() {
                    univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
                }
            }
            2 => {
                for i in 0..univariate_accumulator.r2.evaluations.len() {
                    univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i];
                }
            }
            4 => {
                for i in 0..univariate_accumulator.r4.evaluations.len() {
                    univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i];
                }
            }
            _ => panic!("unexpected subrel_idx_1"),
        }

        // Establish validity of the read. Note: no scaling factor here since this constraint is enforced across the
        // entire trace, not on a per-row basis.
        let mut tmp = read_selector * write_term;
        tmp -= read_counts_m.to_owned() * read_term;
        tmp *= inverses;
        match subrel_idx_2 {
            1 => {
                for i in 0..univariate_accumulator.r1.evaluations.len() {
                    univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
                }
            }
            3 => {
                for i in 0..univariate_accumulator.r3.evaluations.len() {
                    univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i];
                }
            }
            5 => {
                for i in 0..univariate_accumulator.r5.evaluations.len() {
                    univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i];
                }
            }
            _ => panic!("unexpected subrel_idx_2"),
        } // Deg 4 (5)
    }

    fn verify_accumulate_subrelation_contributions<F: PrimeField, L: PlainProverFlavour>(
        univariate_accumulator: &mut DataBusLookupRelationEvals<F>,
        input: &ClaimedEvaluations<F, L>,
        params: &RelationParameters<F, L>,
        scaling_factor: &F,
        bus_idx: BusData,
    ) {
        let inverses = Self::inverses_verifier(bus_idx, input); // Degree 1
        let read_counts_m = Self::read_counts_verifier(bus_idx, input); // Degree 1
        let read_term = Self::compute_read_term_verifier(input, params); // Degree 1 (2)
        let write_term = Self::compute_write_term_verifier(bus_idx, input, params); // Degree 1 (2)
        let inverse_exists = Self::compute_inverse_exists_verifier(bus_idx, input); // Degree 2
        let read_selector = Self::get_read_selector_verifier(bus_idx, input); // Degree 2

        // Determine which pair of subrelations to update based on which bus column is being read
        let subrel_idx_1: u32 = 2u32 * (bus_idx as u32);
        let subrel_idx_2: u32 = 2u32 * (bus_idx as u32) + 1u32;

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value
        // is 0 if !inverse_exists. Degree 3 (5)
        let tmp = (read_term * write_term * inverses - inverse_exists) * scaling_factor;
        match subrel_idx_1 {
            0 => {
                univariate_accumulator.r0 += tmp;
            }
            2 => {
                univariate_accumulator.r2 += tmp;
            }
            4 => {
                univariate_accumulator.r4 += tmp;
            }
            _ => panic!("unexpected subrel_idx_1"),
        }

        // Establish validity of the read. Note: no scaling factor here since this constraint is enforced across the
        // entire trace, not on a per-row basis.
        let mut tmp = read_selector * write_term;
        tmp -= read_counts_m.to_owned() * read_term;
        tmp *= inverses;
        match subrel_idx_2 {
            1 => {
                univariate_accumulator.r1 += tmp;
            }
            3 => {
                univariate_accumulator.r3 += tmp;
            }
            5 => {
                univariate_accumulator.r5 += tmp;
            }
            _ => panic!("unexpected subrel_idx_2"),
        } // Deg 4 (5)
    }
}

impl<F: PrimeField, L: PlainProverFlavour> Relation<F, L> for DataBusLookupRelation {
    type Acc = DataBusLookupRelationAcc<F>;
    type VerifyAcc = DataBusLookupRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip<const SIZE: usize>(input: &ProverUnivariatesSized<F, L, SIZE>) -> bool {
        // Ensure the input does not contain a read gate or data that is being read
        <Self as Relation<F, L>>::check_skippable();
        input.precomputed.q_busread().is_zero()
            && input.witness.calldata_read_counts().is_zero()
            && input.witness.secondary_calldata_read_counts().is_zero()
            && input.witness.return_data_read_counts().is_zero()
    }

    /**
     * @brief Expression for the generalized permutation sort gate.
     * @details The relation is defined as C(in(X)...) =
     *    q_delta_range * \sum{ i = [0, 3]} \alpha^i D_i(D_i - 1)(D_i - 2)(D_i - 3)
     *      where
     *      D_0 = w_2 - w_1
     *      D_1 = w_3 - w_2
     *      D_2 = w_4 - w_3
     *      D_3 = w_1_shift - w_4
     *
     * @param evals transformed to `evals + C(in(X)...)*scaling_factor`
     * @param in an std::array containing the fully extended Univariate edges.
     * @param parameters contains beta, gamma, and public_input_delta, ....
     * @param scaling_factor optional term to scale the evaluation before adding to evals.
     */
    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesSized<F, L, SIZE>,
        _relation_parameters: &RelationParameters<F, L>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate DataBusLookupRelation");
        // Accumulate the subrelation contributions for each column of the databus
        for bus_idx in 0..Self::NUM_BUS_COLUMNS {
            DataBusLookupRelation::accumulate_subrelation_contributions::<F, L, SIZE>(
                univariate_accumulator,
                input,
                _relation_parameters,
                scaling_factor,
                BusData::from(bus_idx),
            );
        }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F, L>,
        relation_parameters: &RelationParameters<F, L>,
        scaling_factor: &F,
    ) {
        tracing::trace!("Accumulate DataBusLookupRelation");
        // Accumulate the subrelation contributions for each column of the databus
        for bus_idx in 0..Self::NUM_BUS_COLUMNS {
            DataBusLookupRelation::verify_accumulate_subrelation_contributions::<F, L>(
                univariate_accumulator,
                input,
                relation_parameters,
                scaling_factor,
                BusData::from(bus_idx),
            );
        }
    }
}
