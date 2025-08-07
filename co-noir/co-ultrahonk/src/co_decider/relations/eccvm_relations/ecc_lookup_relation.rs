use crate::co_decider::{
    relations::{Relation, fold_accumulator},
    types::{ProverUnivariatesBatch, RelationParameters},
    univariates::SharedUnivariate,
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::{HonkProofResult, flavours::eccvm_flavour::ECCVMFlavour, prelude::HonkCurve};
use common::{mpc::NoirUltraHonkProver, transcript::TranscriptFieldType};
use itertools::Itertools;
use mpc_core::MpcState;
use mpc_net::Network;
use ultrahonk::prelude::Univariate;

#[derive(Clone, Debug)]
pub(crate) struct EccLookupRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r0: SharedUnivariate<T, P, 9>,
    pub(crate) r1: SharedUnivariate<T, P, 9>,
}
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for EccLookupRelationAcc<T, P> {
    fn default() -> Self {
        Self {
            r0: SharedUnivariate::default(),
            r1: SharedUnivariate::default(),
        }
    }
}

pub(crate) struct EccLookupRelation {}
impl EccLookupRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const READ_TERMS: usize = 4;
    pub(crate) const WRITE_TERMS: usize = 2;
    pub(crate) const CRAND_PAIRS_FACTOR: usize = 19;

    pub(crate) fn compute_read_term<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        const SIZE: usize,
    >(
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        relation_parameters: &RelationParameters<<P>::ScalarField, ECCVMFlavour>,
        read_index: usize,
        id: <T::State as MpcState>::PartyID,
    ) -> Vec<T::ArithmeticShare> {
        assert!(
            read_index < Self::READ_TERMS,
            "READ_INDEX must be less than 4"
        );

        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        let beta_sqr = beta * beta;
        let beta_cube = beta_sqr * beta;

        let msm_pc = input.witness.msm_pc();
        let msm_count = input.witness.msm_count();
        let msm_slice1 = input.witness.msm_slice1();
        let msm_slice2 = input.witness.msm_slice2();
        let msm_slice3 = input.witness.msm_slice3();
        let msm_slice4 = input.witness.msm_slice4();
        let msm_x1 = input.witness.msm_x1();
        let msm_x2 = input.witness.msm_x2();
        let msm_x3 = input.witness.msm_x3();
        let msm_x4 = input.witness.msm_x4();
        let msm_y1 = input.witness.msm_y1();
        let msm_y2 = input.witness.msm_y2();
        let msm_y3 = input.witness.msm_y3();
        let msm_y4 = input.witness.msm_y4();

        let mut current_pc = T::add_many(
            &msm_count
                .iter()
                .map(|a| T::mul_with_public(P::ScalarField::from(-1), *a))
                .collect_vec(),
            msm_pc,
        );

        match read_index {
            0 => {
                T::add_scalar_in_place(&mut current_pc, gamma, id);
                T::add_many(
                    &T::add_many(
                        &T::add_many(
                            &current_pc,
                            &msm_slice1
                                .iter()
                                .map(|a| T::mul_with_public(beta, *a))
                                .collect_vec(),
                        ),
                        &msm_x1
                            .iter()
                            .map(|a| T::mul_with_public(beta_sqr, *a))
                            .collect_vec(),
                    ),
                    &msm_y1
                        .iter()
                        .map(|a| T::mul_with_public(beta_cube, *a))
                        .collect_vec(),
                )
            }
            1 => {
                T::add_scalar_in_place(&mut current_pc, P::ScalarField::from(-1) + gamma, id);
                T::add_many(
                    &T::add_many(
                        &T::add_many(
                            &current_pc,
                            &msm_slice2
                                .iter()
                                .map(|a| T::mul_with_public(beta, *a))
                                .collect_vec(),
                        ),
                        &msm_x2
                            .iter()
                            .map(|a| T::mul_with_public(beta_sqr, *a))
                            .collect_vec(),
                    ),
                    &msm_y2
                        .iter()
                        .map(|a| T::mul_with_public(beta_cube, *a))
                        .collect_vec(),
                )
            }
            2 => {
                T::add_scalar_in_place(&mut current_pc, P::ScalarField::from(-2) + gamma, id);
                T::add_many(
                    &T::add_many(
                        &T::add_many(
                            &current_pc,
                            &msm_slice3
                                .iter()
                                .map(|a| T::mul_with_public(beta, *a))
                                .collect_vec(),
                        ),
                        &msm_x3
                            .iter()
                            .map(|a| T::mul_with_public(beta_sqr, *a))
                            .collect_vec(),
                    ),
                    &msm_y3
                        .iter()
                        .map(|a| T::mul_with_public(beta_cube, *a))
                        .collect_vec(),
                )
            }
            3 => {
                T::add_scalar_in_place(&mut current_pc, P::ScalarField::from(-3) + gamma, id);
                T::add_many(
                    &T::add_many(
                        &T::add_many(
                            &current_pc,
                            &msm_slice4
                                .iter()
                                .map(|a| T::mul_with_public(beta, *a))
                                .collect_vec(),
                        ),
                        &msm_x4
                            .iter()
                            .map(|a| T::mul_with_public(beta_sqr, *a))
                            .collect_vec(),
                    ),
                    &msm_y4
                        .iter()
                        .map(|a| T::mul_with_public(beta_cube, *a))
                        .collect_vec(),
                )
            }
            _ => unreachable!(),
        }
    }
    pub(crate) fn compute_write_term<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        const SIZE: usize,
    >(
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        relation_parameters: &RelationParameters<<P>::ScalarField, ECCVMFlavour>,
        write_index: usize,
        id: <T::State as MpcState>::PartyID,
    ) -> Vec<T::ArithmeticShare> {
        assert!(
            write_index < Self::WRITE_TERMS,
            "WRITE_INDEX must be less than 2"
        );

        let precompute_pc = input.witness.precompute_pc();
        let tx = input.witness.precompute_tx();
        let ty = input.witness.precompute_ty();
        let precompute_round = input.witness.precompute_round();
        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        let beta_sqr = beta * beta;
        let beta_cube = beta_sqr * beta;

        match write_index {
            0 => {
                let mut positive_slice_value = precompute_round.to_owned(); //-*precompute_round + P::ScalarField::from(15);
                T::scale_many_in_place(&mut positive_slice_value, -P::ScalarField::one());
                T::add_scalar_in_place(&mut positive_slice_value, P::ScalarField::from(15), id);
                T::scale_many_in_place(&mut positive_slice_value, beta);
                T::add_assign_many(&mut positive_slice_value, precompute_pc);
                T::add_assign_many(&mut positive_slice_value, &T::scale_many(tx, beta_sqr));
                T::add_scalar_in_place(&mut positive_slice_value, gamma, id);
                T::add_assign_many(&mut positive_slice_value, &T::scale_many(ty, beta_cube));
                positive_slice_value
            } // degree 1
            1 => {
                let mut tmp = precompute_pc.to_owned();
                T::add_scalar_in_place(&mut tmp, gamma, id);
                T::add_assign_many(&mut tmp, &T::scale_many(precompute_round, beta));
                T::add_assign_many(&mut tmp, &T::scale_many(tx, beta_sqr));
                T::add_assign_many(&mut tmp, &T::scale_many(ty, -beta_cube));
                tmp
            } // degree 1
            _ => unreachable!(),
        }
    }

    pub(crate) fn lookup_read_counts<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        const SIZE: usize,
    >(
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        index: usize,
    ) -> &[T::ArithmeticShare] {
        match index {
            0 => input.witness.lookup_read_counts_0(),
            1 => input.witness.lookup_read_counts_1(),
            _ => unreachable!(),
        }
    }

    pub(crate) fn compute_read_term_predicate<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        const SIZE: usize,
    >(
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        read_index: usize,
    ) -> &[T::ArithmeticShare] {
        match read_index {
            0 => input.witness.msm_add1(),
            1 => input.witness.msm_add2(),
            2 => input.witness.msm_add3(),
            3 => input.witness.msm_add4(),
            _ => unreachable!(),
        }
    }

    pub(crate) fn compute_write_term_predicate<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        const SIZE: usize,
    >(
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        write_index: usize,
    ) -> &[T::ArithmeticShare] {
        match write_index {
            0 => input.witness.precompute_select(),
            1 => input.witness.precompute_select(),
            _ => unreachable!(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> EccLookupRelationAcc<T, P> {
    pub(crate) fn scale(
        &mut self,
        current_scalar: &mut P::ScalarField,
        challenge: &P::ScalarField,
    ) {
        self.r0.scale_inplace(*current_scalar);
        *current_scalar *= challenge;
        self.r1.scale_inplace(*current_scalar);
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
        self.r1.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
    }
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> Relation<T, P, ECCVMFlavour>
    for EccLookupRelation
{
    type Acc = EccLookupRelationAcc<T, P>;

    fn can_skip(_entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>) -> bool {
        false
    }

    fn add_entities(
        entity: &crate::co_decider::types::ProverUnivariates<T, P, ECCVMFlavour>,
        batch: &mut crate::co_decider::types::ProverUnivariatesBatch<T, P, ECCVMFlavour>,
    ) {
        batch.add_msm_pc(entity);
        batch.add_msm_count(entity);
        batch.add_msm_slice1(entity);
        batch.add_msm_slice2(entity);
        batch.add_msm_slice3(entity);
        batch.add_msm_slice4(entity);
        batch.add_msm_x1(entity);
        batch.add_msm_x2(entity);
        batch.add_msm_x3(entity);
        batch.add_msm_x4(entity);
        batch.add_msm_y1(entity);
        batch.add_msm_y2(entity);
        batch.add_msm_y3(entity);
        batch.add_msm_y4(entity);
        batch.add_precompute_pc(entity);
        batch.add_precompute_tx(entity);
        batch.add_precompute_ty(entity);
        batch.add_precompute_round(entity);
        batch.add_lookup_read_counts_0(entity);
        batch.add_lookup_read_counts_1(entity);
        batch.add_msm_add1(entity);
        batch.add_msm_add2(entity);
        batch.add_msm_add3(entity);
        batch.add_msm_add4(entity);
        batch.add_precompute_select(entity);
        batch.add_lookup_inverses(entity);
        batch.add_msm_add(entity);
        batch.add_msm_skew(entity);
    }

    fn accumulate<N: Network, const SIZE: usize>(
        net: &N,
        state: &mut T::State,
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariatesBatch<T, P, ECCVMFlavour>,
        relation_parameters: &RelationParameters<<P>::ScalarField, ECCVMFlavour>,
        scaling_factors: &[P::ScalarField],
    ) -> HonkProofResult<()> {
        const NUM_TOTAL_TERMS: usize =
            EccLookupRelation::READ_TERMS + EccLookupRelation::WRITE_TERMS;
        let id = state.id();
        let mut lookup_inverses = input.witness.lookup_inverses().to_owned(); // Degree 1

        let mut lookup_terms = Vec::with_capacity(NUM_TOTAL_TERMS);

        for i in 0..EccLookupRelation::READ_TERMS {
            lookup_terms.push(Self::compute_read_term::<T, P, SIZE>(
                input,
                relation_parameters,
                i,
                id,
            ))
        }

        for i in 0..EccLookupRelation::WRITE_TERMS {
            lookup_terms.push(Self::compute_write_term::<T, P, SIZE>(
                input,
                relation_parameters,
                i,
                id,
            ))
        }

        let mut lhs = Vec::with_capacity(lookup_terms[0].len() * 3);
        let mut rhs = Vec::with_capacity(lhs.len());
        lhs.extend(lookup_terms[0].to_owned());
        rhs.extend(lookup_terms[1].to_owned());
        lhs.extend(lookup_terms[2].to_owned());
        rhs.extend(lookup_terms[3].to_owned());
        lhs.extend(lookup_terms[4].to_owned());
        rhs.extend(lookup_terms[5].to_owned());
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 3).collect_vec();
        debug_assert_eq!(mul.len(), 3);
        let x0x1 = mul[0];
        let x2x3 = mul[1];
        let x4x5 = mul[2];
        let mut lhs = Vec::with_capacity(x0x1.len() * 2);
        let mut rhs = Vec::with_capacity(lhs.len());
        lhs.extend(x0x1.to_owned());
        rhs.extend(lookup_terms[2].to_owned());
        lhs.extend(x0x1.to_owned());
        rhs.extend(x2x3.to_owned());
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);
        let x0x1x2 = mul[0];
        let x0x1x2x3 = mul[1];
        let mut lhs = Vec::with_capacity(x0x1x2x3.len() * 2);
        let mut rhs = Vec::with_capacity(lhs.len());
        lhs.extend(x0x1x2x3.to_owned());
        rhs.extend(lookup_terms[4].to_owned());
        lhs.extend(x0x1x2x3.to_owned());
        rhs.extend(x4x5.to_owned());
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);
        let x0x1x2x3x4 = mul[0];
        let x0x1x2x3x4x5 = mul[1];

        let mut denominator_accumulator = lookup_terms.clone();
        denominator_accumulator[1] = x0x1.to_vec();
        denominator_accumulator[2] = x0x1x2.to_vec();
        denominator_accumulator[3] = x0x1x2x3.to_vec();
        denominator_accumulator[4] = x0x1x2x3x4.to_vec();
        denominator_accumulator[5] = x0x1x2x3x4x5.to_vec();

        let mut lhs = Vec::with_capacity(
            denominator_accumulator[NUM_TOTAL_TERMS - 1].len()
                + input.witness.precompute_select().len(),
        );
        let mut rhs = Vec::with_capacity(lhs.len());

        // let inverse_exists = {
        let row_has_write = input.witness.precompute_select();
        let row_has_read = T::add_many(input.witness.msm_add(), input.witness.msm_skew());
        lhs.extend(row_has_write.to_owned());
        rhs.extend(row_has_read.clone());

        lhs.extend(denominator_accumulator[NUM_TOTAL_TERMS - 1].clone());
        rhs.extend(lookup_inverses.clone());
        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);
        let mut tmp = mul[0].to_owned();
        T::scale_many_in_place(&mut tmp, P::ScalarField::from(-1));

        let inverse_exists = T::add_many(&tmp, &T::add_many(row_has_write, &row_has_read));

        // Note: the lookup_inverses are computed so that the value is 0 if !inverse_exists
        let mut tmp = T::sub_many(mul[1], &inverse_exists);
        T::mul_assign_with_public_many(&mut tmp, scaling_factors);

        fold_accumulator!(univariate_accumulator.r0, tmp, SIZE);

        // After this algo, total degree of denominator_accumulator = NUM_TOTAL_TERMS
        for i in 0..NUM_TOTAL_TERMS - 1 {
            // TACEO TODO: Is there a better way?
            let (new_denominator, new_lookup_inverses) = {
                let lhs = [
                    &denominator_accumulator[NUM_TOTAL_TERMS - 2 - i][..],
                    &lookup_terms[NUM_TOTAL_TERMS - 1 - i][..],
                ]
                .concat();
                let rhs = [&lookup_inverses[..], &lookup_inverses[..]].concat();
                let mul = T::mul_many(&lhs, &rhs, net, state)?;
                let chunks = mul.chunks_exact(mul.len() / 2).collect_vec();
                debug_assert_eq!(chunks.len(), 2);
                (chunks[0].to_vec(), chunks[1].to_vec())
            };
            denominator_accumulator[NUM_TOTAL_TERMS - 1 - i] = new_denominator;
            lookup_inverses = new_lookup_inverses;
        }
        denominator_accumulator[0] = lookup_inverses;

        // Each predicate is degree-1
        // Degree of relation at this point = NUM_TOTAL_TERMS + 1
        // let mut tmp = Univariate::default();
        let mut lhs = Vec::with_capacity(
            (Self::READ_TERMS + Self::WRITE_TERMS) * denominator_accumulator[0].len(),
        );
        let mut rhs = Vec::with_capacity(
            (Self::READ_TERMS + Self::WRITE_TERMS) * denominator_accumulator[0].len(),
        );
        for (i, denominator) in denominator_accumulator
            .iter()
            .enumerate()
            .take(Self::READ_TERMS)
        {
            lhs.extend(Self::compute_read_term_predicate::<T, P, SIZE>(input, i).to_owned());
            rhs.extend(denominator.to_owned());
        }
        for i in 0..Self::WRITE_TERMS {
            lhs.extend(Self::compute_write_term_predicate::<T, P, SIZE>(input, i));
            rhs.extend(Self::lookup_read_counts::<T, P, SIZE>(input, i));
        }

        let mul = T::mul_many(&lhs, &rhs, net, state)?;
        let mul = mul
            .chunks_exact(mul.len() / (Self::READ_TERMS + Self::WRITE_TERMS))
            .collect_vec();
        debug_assert_eq!(mul.len(), Self::READ_TERMS + Self::WRITE_TERMS);
        let mut tmp = T::add_many(mul[0], mul[1]);
        for el in mul.iter().take(Self::READ_TERMS).skip(2) {
            T::add_assign_many(&mut tmp, el);
        }
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);

        let lhs = denominator_accumulator[Self::READ_TERMS..]
            .concat()
            .into_iter();
        let rhs = mul[Self::READ_TERMS..].concat().into_iter();
        let mul = T::mul_many(&lhs.collect_vec(), &rhs.collect_vec(), net, state)?;
        let mul = mul
            .chunks_exact(mul.len() / Self::WRITE_TERMS)
            .collect_vec();
        debug_assert_eq!(mul.len(), Self::WRITE_TERMS);
        let mut tmp = T::add_many(mul[0], mul[1]);
        T::scale_many_in_place(&mut tmp, P::ScalarField::from(-1));
        for el in mul.iter().skip(2) {
            T::add_assign_many(&mut tmp, el);
        }
        fold_accumulator!(univariate_accumulator.r1, tmp, SIZE);
        Ok(())
    }
}
