use super::Relation;
use crate::co_decider::relations::fold_accumulator;
use crate::co_decider::types::ProverUnivariatesBatch;
use crate::co_decider::types::RelationParameters;
use crate::co_decider::univariates::SharedUnivariate;
use crate::mpc::NoirUltraHonkProver;
use crate::mpc_prover_flavour::MPCProverFlavour;
use ark_ec::CurveGroup;
use co_builder::HonkProofResult;
use co_builder::TranscriptFieldType;
use co_builder::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, WitnessEntitiesFlavour,
};
use co_builder::prelude::HonkCurve;
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;
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

#[derive(Clone, Debug)]
pub(crate) struct DataBusLookupRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 5>,
    pub(crate) r1: SharedUnivariate<T, P, 5>,
    pub(crate) r2: SharedUnivariate<T, P, 5>,
    pub(crate) r3: SharedUnivariate<T, P, 5>,
    pub(crate) r4: SharedUnivariate<T, P, 5>,
    pub(crate) r5: SharedUnivariate<T, P, 5>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for DataBusLookupRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
            r2: SharedUnivariate::default(),
            r3: SharedUnivariate::default(),
            r4: SharedUnivariate::default(),
            r5: SharedUnivariate::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> DataBusLookupRelationAcc<T, P> {
    pub(crate) fn scale(&mut self, elements: &[P::ScalarField]) {
        assert!(elements.len() == DataBusLookupRelation::NUM_RELATIONS);
        self.r0.scale_inplace(elements[0]);
        self.r1.scale_inplace(elements[1]);
        self.r2.scale_inplace(elements[2]);
        self.r3.scale_inplace(elements[3]);
        self.r4.scale_inplace(elements[4]);
        self.r5.scale_inplace(elements[5]);
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
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 6;
    const NUM_BUS_COLUMNS: usize = 3; // calldata, return data

    fn values<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, L: MPCProverFlavour>(
        bus_idx: BusData,
        input: &ProverUnivariatesBatch<T, P, L>,
    ) -> &Vec<T::ArithmeticShare> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata(),
            BusData::BusIdx1 => input.witness.secondary_calldata(),
            BusData::BusIdx2 => input.witness.return_data(),
        }
    }
    fn selector<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        bus_idx: BusData,
        input: &ProverUnivariatesBatch<T, P, L>,
    ) -> &Vec<P::ScalarField> {
        match bus_idx {
            BusData::BusIdx0 => input.precomputed.q_l(),
            BusData::BusIdx1 => input.precomputed.q_r(),
            BusData::BusIdx2 => input.precomputed.q_o(),
        }
    }
    fn inverses<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        bus_idx: BusData,
        input: &ProverUnivariatesBatch<T, P, L>,
    ) -> &Vec<T::ArithmeticShare> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_inverses(),
            BusData::BusIdx1 => input.witness.secondary_calldata_inverses(),
            BusData::BusIdx2 => input.witness.return_data_inverses(),
        }
    }
    fn read_counts<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        bus_idx: BusData,
        input: &ProverUnivariatesBatch<T, P, L>,
    ) -> &Vec<T::ArithmeticShare> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_read_counts(),
            BusData::BusIdx1 => input.witness.secondary_calldata_read_counts(),
            BusData::BusIdx2 => input.witness.return_data_read_counts(),
        }
    }
    fn read_tags<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        bus_idx: BusData,
        input: &ProverUnivariatesBatch<T, P, L>,
    ) -> &Vec<T::ArithmeticShare> {
        match bus_idx {
            BusData::BusIdx0 => input.witness.calldata_read_tags(),
            BusData::BusIdx1 => input.witness.secondary_calldata_read_tags(),
            BusData::BusIdx2 => input.witness.return_data_read_tags(),
        }
    }

    fn compute_inverse_exists<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        state: &mut T::State,
        bus_idx: BusData,
        input: &ProverUnivariatesBatch<T, P, L>,
    ) -> Vec<T::ArithmeticShare> {
        let is_read_gate = DataBusLookupRelation::get_read_selector(bus_idx, input);
        let read_tag = DataBusLookupRelation::read_tags(bus_idx, input);
        let add = T::add_with_public_many(&is_read_gate, read_tag, state.id());
        let mul = T::mul_with_public_many(&is_read_gate, read_tag);
        T::sub_many(&add, &mul)
    }

    fn get_read_selector<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        bus_idx: BusData,
        input: &ProverUnivariatesBatch<T, P, L>,
    ) -> Vec<P::ScalarField> {
        let q_busread = input.precomputed.q_busread();
        let column_selector = DataBusLookupRelation::selector(bus_idx, input);
        q_busread
            .iter()
            .zip_eq(column_selector.iter())
            .map(|(a, b)| *a * *b)
            .collect()
    }

    fn compute_write_term<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        state: &mut T::State,
        bus_idx: BusData,
        input: &ProverUnivariatesBatch<T, P, L>,
        params: &RelationParameters<P::ScalarField, L>,
    ) -> Vec<T::ArithmeticShare> {
        let id = input.precomputed.databus_id();
        let value = DataBusLookupRelation::values(bus_idx, input);
        let gamma = params.gamma;
        let beta = params.beta;
        let mut tmp = Vec::with_capacity(id.len());
        for val in id.iter().cloned() {
            tmp.push(val * beta + gamma);
        }
        // value_i + idx_i * beta + gamma
        T::add_with_public_many(&tmp, value, state.id())
    }

    fn compute_read_term<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        L: MPCProverFlavour,
    >(
        state: &mut T::State,
        input: &ProverUnivariatesBatch<T, P, L>,
        params: &RelationParameters<P::ScalarField, L>,
    ) -> Vec<T::ArithmeticShare> {
        // Bus value stored in w_l, index into bus column stored in w_r
        let w_1 = input.witness.w_l();
        let w_2 = input.witness.w_r();
        let gamma = params.gamma;
        let beta = params.beta;
        let mut tmp = Vec::with_capacity(w_2.len());
        for val in w_2.iter().cloned() {
            tmp.push(T::add_with_public(
                gamma,
                T::mul_with_public(beta, val),
                state.id(),
            ));
        }
        // value + index * beta + gamma
        T::add_many(&tmp, w_1)
    }

    fn accumulate_subrelation_contributions<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
        L: MPCProverFlavour,
        const SIZE: usize,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut DataBusLookupRelationAcc<T, P>,
        input: &ProverUnivariatesBatch<T, P, L>,
        params: &RelationParameters<P::ScalarField, L>,
        scaling_factors: &[P::ScalarField],
        bus_idx: BusData,
    ) -> HonkProofResult<()> {
        let inverses = Self::inverses(bus_idx, input); // Degree 1
        let read_counts_m = Self::read_counts(bus_idx, input); // Degree 1
        let read_term = Self::compute_read_term(state, input, params); // Degree 1 (2)
        let write_term = Self::compute_write_term(state, bus_idx, input, params); // Degree 1 (2)
        let inverse_exists = Self::compute_inverse_exists(state, bus_idx, input); // Degree 2
        let read_selector = Self::get_read_selector(bus_idx, input); // Degree 2

        // Determine which pair of subrelations to update based on which bus column is being read
        let subrel_idx_1: u32 = 2u32 * (bus_idx as u32);
        let subrel_idx_2: u32 = 2u32 * (bus_idx as u32) + 1u32;
        let mut lhs = Vec::with_capacity(read_term.len() + read_counts_m.len());
        let mut rhs = Vec::with_capacity(write_term.len() + read_term.len());
        lhs.extend(read_term.clone());
        lhs.extend(read_counts_m);
        rhs.extend(write_term.clone());
        rhs.extend(read_term);
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);

        // Establish the correctness of the polynomial of inverses I. Note: inverses is computed so that the value
        // is 0 if !inverse_exists. Degree 3 (5)
        let mul_2 = T::mul_many(mul[0], inverses, net, state)?; //TACEO TODO: combine this mul into the mul above by writing a custom multiplication function
        let tmp = T::sub_many(&mul_2, &inverse_exists)
            .into_iter()
            .zip_eq(scaling_factors)
            .map(|(a, b)| T::mul_with_public(*b, a))
            .collect_vec();

        match subrel_idx_1 {
            0 => {
                fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);
            }
            2 => {
                fold_accumulator!(univariate_accumulator.r2, tmp, SIZE);
            }
            4 => {
                fold_accumulator!(univariate_accumulator.r4, tmp, SIZE);
            }
            _ => panic!("unexpected subrel_idx_1"),
        }

        // Establish validity of the read. Note: no scaling factor here since this constraint is enforced across the
        // entire trace, not on a per-row basis.
        let mut tmp = write_term
            .into_iter()
            .zip_eq(read_selector.iter())
            .map(|(a, b)| T::mul_with_public(*b, a))
            .collect_vec();
        T::sub_assign_many(&mut tmp, mul[1]);
        tmp = T::mul_many(&tmp, inverses, net, state)?;
        match subrel_idx_2 {
            1 => {
                fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);
            }
            3 => {
                fold_accumulator!(univariate_accumulator.r3, tmp, SIZE);
            }
            5 => {
                fold_accumulator!(univariate_accumulator.r5, tmp, SIZE);
            }
            _ => panic!("unexpected subrel_idx_2"),
        } // Deg 4 (5)
        Ok(())
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, L: MPCProverFlavour>
    Relation<T, P, L> for DataBusLookupRelation
{
    type Acc = DataBusLookupRelationAcc<T, P>;

    fn can_skip(_entity: &super::ProverUnivariates<T, P, L>) -> bool {
        // Ensure the input does not contain a read gate or data that is being read
        false
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
    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &super::ProverUnivariatesBatch<T, P, L>,
        _relation_parameters: &RelationParameters<<P>::ScalarField, L>,
        scaling_factors: &[<P>::ScalarField],
    ) -> HonkProofResult<()> {
        tracing::trace!("Accumulate DataBusLookupRelation");
        // Accumulate the subrelation contributions for each column of the databus
        // TODO this can be parallelized
        for bus_idx in 0..Self::NUM_BUS_COLUMNS {
            DataBusLookupRelation::accumulate_subrelation_contributions::<T, P, N, L, SIZE>(
                net,
                state,
                univariate_accumulator,
                input,
                _relation_parameters,
                scaling_factors,
                BusData::from(bus_idx),
            )?;
        }
        Ok(())
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, L>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, L>,
    ) {
        batch.add_w_l(entity);
        batch.add_w_r(entity);
        batch.add_shifted_w_o(entity);
        batch.add_shifted_w_4(entity);

        batch.add_calldata(entity);
        batch.add_secondary_calldata(entity);
        batch.add_return_data(entity);

        batch.add_q_l(entity);
        batch.add_q_r(entity);
        batch.add_q_o(entity);

        batch.add_calldata_inverses(entity);
        batch.add_secondary_calldata_inverses(entity);
        batch.add_return_data_inverses(entity);

        batch.add_calldata_read_counts(entity);
        batch.add_secondary_calldata_read_counts(entity);
        batch.add_return_data_read_counts(entity);

        batch.add_calldata_read_tags(entity);
        batch.add_secondary_calldata_read_tags(entity);
        batch.add_return_data_read_tags(entity);

        batch.add_q_busread(entity);
        batch.add_databus_id(entity);
    }
}
