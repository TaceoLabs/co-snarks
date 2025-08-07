use crate::{decider::relations::Relation, prelude::Univariate};
use ark_ff::PrimeField;
use co_builder::{
    flavours::eccvm_flavour::ECCVMFlavour, polynomials::polynomial_flavours::WitnessEntitiesFlavour,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct EccLookupRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 9>,
    pub(crate) r1: Univariate<F, 9>,
}
#[derive(Clone, Debug, Default)]
#[expect(dead_code)]
pub(crate) struct EccLookupRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
}

pub(crate) struct EccLookupRelation {}
impl EccLookupRelation {
    pub(crate) const NUM_RELATIONS: usize = 2;
    pub(crate) const READ_TERMS: usize = 4;
    pub(crate) const WRITE_TERMS: usize = 2;

    pub(crate) fn compute_read_term<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F>,
        read_index: usize,
    ) -> Univariate<F, SIZE> {
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

        let current_pc = msm_count.to_owned() * F::from(-1) + msm_pc;

        match read_index {
            0 => {
                current_pc.clone()
                    + &gamma
                    + msm_slice1.to_owned() * beta
                    + msm_x1.to_owned() * beta_sqr
                    + msm_y1.to_owned() * beta_cube
            }
            1 => {
                (current_pc.clone() + &F::from(-1))
                    + &gamma
                    + msm_slice2.to_owned() * beta
                    + msm_x2.to_owned() * beta_sqr
                    + msm_y2.to_owned() * beta_cube
            }
            2 => {
                (current_pc.clone() + &F::from(-2))
                    + &gamma
                    + msm_slice3.to_owned() * beta
                    + msm_x3.to_owned() * beta_sqr
                    + msm_y3.to_owned() * beta_cube
            }
            3 => {
                (current_pc + &F::from(-3))
                    + &gamma
                    + msm_slice4.to_owned() * beta
                    + msm_x4.to_owned() * beta_sqr
                    + msm_y4.to_owned() * beta_cube
            }
            _ => unreachable!(),
        }
    }
    pub(crate) fn compute_write_term<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F>,
        write_index: usize,
    ) -> Univariate<F, SIZE> {
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
                let positive_slice_value = -precompute_round.to_owned() + &F::from(15);
                positive_slice_value * beta
                    + tx.to_owned() * beta_sqr
                    + ty.to_owned() * beta_cube
                    + precompute_pc
                    + &gamma
            } // degree 1
            1 => {
                precompute_pc.to_owned()
                    + &gamma
                    + precompute_round.to_owned() * beta
                    + tx.to_owned() * beta_sqr
                    - ty.to_owned() * beta_cube
            } // degree 1
            _ => unreachable!(),
        }
    }
    pub(crate) fn compute_inverse_exists<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
    ) -> Univariate<F, SIZE> {
        let row_has_write = input.witness.precompute_select();
        let row_has_read = input.witness.msm_add().to_owned() + input.witness.msm_skew();
        (row_has_write.to_owned() * F::from(-1) * row_has_read.clone())
            + row_has_write
            + row_has_read
    }
    pub(crate) fn lookup_read_counts<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        index: usize,
    ) -> &Univariate<F, SIZE> {
        match index {
            0 => input.witness.lookup_read_counts_0(),
            1 => input.witness.lookup_read_counts_1(),
            _ => unreachable!(),
        }
    }

    pub(crate) fn compute_read_term_predicate<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        read_index: usize,
    ) -> &Univariate<F, SIZE> {
        match read_index {
            0 => input.witness.msm_add1(),
            1 => input.witness.msm_add2(),
            2 => input.witness.msm_add3(),
            3 => input.witness.msm_add4(),
            _ => unreachable!(),
        }
    }

    pub(crate) fn compute_write_term_predicate<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        write_index: usize,
    ) -> &Univariate<F, SIZE> {
        match write_index {
            0 => input.witness.precompute_select(),
            1 => input.witness.precompute_select(), // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/750) Is this a bug?
            _ => unreachable!(),
        }
    }
}

impl<F: PrimeField> EccLookupRelationAcc<F> {
    pub(crate) fn scale(&mut self, current_scalar: &mut F, challenge: &F) {
        self.r0 *= *current_scalar;
        *current_scalar *= challenge;
        self.r1 *= *current_scalar;
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
        self.r1.extend_and_batch_univariates(
            result,
            extended_random_poly,
            partial_evaluation_result,
            false,
        );
    }
}

impl<F: PrimeField> Relation<F, ECCVMFlavour> for EccLookupRelation {
    type Acc = EccLookupRelationAcc<F>;

    type VerifyAcc = EccLookupRelationEvals<F>;

    const SKIPPABLE: bool = false;

    fn skip<const SIZE: usize>(
        _input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
    ) -> bool {
        false
    }

    fn accumulate<const SIZE: usize>(
        univariate_accumulator: &mut Self::Acc,
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F>,
        scaling_factor: &F,
    ) {
        const NUM_TOTAL_TERMS: usize =
            EccLookupRelation::READ_TERMS + EccLookupRelation::WRITE_TERMS;
        let mut lookup_inverses = input.witness.lookup_inverses().to_owned(); // Degree 1

        let mut lookup_terms = vec![Univariate::default(); NUM_TOTAL_TERMS];

        for (i, term) in lookup_terms.iter_mut().take(Self::READ_TERMS).enumerate() {
            *term = Self::compute_read_term::<F, SIZE>(input, relation_parameters, i);
        }

        for (i, term) in lookup_terms
            .iter_mut()
            .skip(Self::READ_TERMS)
            .take(Self::WRITE_TERMS)
            .enumerate()
        {
            *term = Self::compute_write_term::<F, SIZE>(input, relation_parameters, i);
        }

        let mut denominator_accumulator = lookup_terms.clone();

        for i in 0..NUM_TOTAL_TERMS - 1 {
            let tmp = denominator_accumulator[i].clone();
            denominator_accumulator[i + 1] *= tmp;
        }

        let inverse_exists = Self::compute_inverse_exists(input); // Degree 2

        // Note: the lookup_inverses are computed so that the value is 0 if !inverse_exists
        let tmp = (denominator_accumulator[NUM_TOTAL_TERMS - 1].clone() * &lookup_inverses
            - inverse_exists.clone())
            * scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        // After this algo, total degree of denominator_accumulator = NUM_TOTAL_TERMS
        for i in 0..NUM_TOTAL_TERMS - 1 {
            denominator_accumulator[NUM_TOTAL_TERMS - 1 - i] =
                denominator_accumulator[NUM_TOTAL_TERMS - 2 - i].clone() * lookup_inverses.clone();
            lookup_inverses = lookup_terms[NUM_TOTAL_TERMS - 1 - i].clone() * &lookup_inverses;
        }
        denominator_accumulator[0] = lookup_inverses;

        // Each predicate is degree-1
        // Degree of relation at this point = NUM_TOTAL_TERMS + 1
        let mut tmp = Univariate::default();
        for (i, denominator) in denominator_accumulator
            .iter()
            .enumerate()
            .take(Self::READ_TERMS)
        {
            tmp += Self::compute_read_term_predicate::<F, SIZE>(input, i).to_owned() * denominator;
        }
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }

        // Each predicate is degree-1, `lookup_read_counts` is degree-1
        // Degree of relation = NUM_TOTAL_TERMS + 2
        tmp = Univariate::default();
        for i in 0..Self::WRITE_TERMS {
            let p = Self::compute_write_term_predicate::<F, SIZE>(input, i);
            let lookup_read_count = Self::lookup_read_counts::<F, SIZE>(input, i);
            tmp -= p.to_owned()
                * (denominator_accumulator[i + Self::READ_TERMS].clone() * lookup_read_count);
        }
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }
}
