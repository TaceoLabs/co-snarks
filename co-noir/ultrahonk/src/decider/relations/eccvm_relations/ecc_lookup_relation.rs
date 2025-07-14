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
pub(crate) struct EccLookupRelationEvals<F: PrimeField> {
    pub(crate) r0: F,
    pub(crate) r1: F,
}

pub(crate) struct EccLookupRelation {}
impl EccLookupRelation {
    pub(crate) const NUM_RELATIONS: usize = 19;
    pub(crate) const READ_TERMS: usize = 4;
    pub(crate) const WRITE_TERMS: usize = 2;

    pub(crate) fn compute_read_term<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
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

        let read_term1 = current_pc.clone()
            + &gamma
            + msm_slice1.to_owned() * beta
            + msm_x1.to_owned() * beta_sqr
            + msm_y1.to_owned() * beta_cube;

        let read_term2 = (current_pc.clone() + &F::from(-1))
            + &gamma
            + msm_slice2.to_owned() * beta
            + msm_x2.to_owned() * beta_sqr
            + msm_y2.to_owned() * beta_cube;

        let read_term3 = (current_pc.clone() + &F::from(-2))
            + &gamma
            + msm_slice3.to_owned() * beta
            + msm_x3.to_owned() * beta_sqr
            + msm_y3.to_owned() * beta_cube;

        let read_term4 = (current_pc + &F::from(-3))
            + &gamma
            + msm_slice4.to_owned() * beta
            + msm_x4.to_owned() * beta_sqr
            + msm_y4.to_owned() * beta_cube;

        match read_index {
            0 => read_term1,
            1 => read_term2,
            2 => read_term3,
            3 => read_term4,
            _ => unreachable!(),
        }
    }
    pub(crate) fn compute_write_term<F: PrimeField, const SIZE: usize>(
        input: &crate::decider::types::ProverUnivariatesSized<F, ECCVMFlavour, SIZE>,
        relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
        write_index: usize,
    ) -> Univariate<F, SIZE> {
        assert!(
            write_index < Self::WRITE_TERMS,
            "WRITE_INDEX must be less than 2"
        );

        let precompute_pc = input.witness.msm_pc();
        let tx = input.witness.msm_x1(); // Assuming tx corresponds to msm_x1
        let ty = input.witness.msm_y1(); // Assuming ty corresponds to msm_y1
        let precompute_round = input.witness.msm_slice1(); // Assuming precompute_round corresponds to msm_slice1
        let gamma = relation_parameters.gamma;
        let beta = relation_parameters.beta;
        let beta_sqr = beta * beta;
        let beta_cube = beta_sqr * beta;

        let negative_term = precompute_pc.to_owned()
            + &gamma
            + precompute_round.to_owned() * beta
            + tx.to_owned() * beta_sqr
            - ty.to_owned() * beta_cube;

        let positive_slice_value = -precompute_round.to_owned() + &F::from(15);
        let positive_term = positive_slice_value * beta
            + tx.to_owned() * beta_sqr
            + ty.to_owned() * beta_cube
            + precompute_pc
            + &gamma;

        match write_index {
            0 => positive_term, // degree 1
            1 => negative_term, // degree 1
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
            1 => input.witness.precompute_select(), // TODO: Verify if this is correct
            _ => unreachable!(),
        }
    }
}

impl<F: PrimeField> EccLookupRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == EccLookupRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
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
            true,
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
        relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
        scaling_factor: &F,
    ) {
        const NUM_TOTAL_TERMS: usize =
            EccLookupRelation::READ_TERMS + EccLookupRelation::WRITE_TERMS;
        let mut lookup_inverses = input.witness.lookup_inverses().clone(); // Degree 1

        let mut lookup_terms = Vec::with_capacity(NUM_TOTAL_TERMS);

        for (i, term) in lookup_terms.iter_mut().take(Self::READ_TERMS).enumerate() {
            *term = Self::compute_read_term::<_, _>(input, relation_parameters, i);
        }

        for i in 0..Self::WRITE_TERMS {
            lookup_terms[i + Self::READ_TERMS] =
                Self::compute_write_term::<_, _>(input, relation_parameters, i);
        }

        let mut denominator_accumulator = lookup_terms.clone();

        for i in 0..NUM_TOTAL_TERMS {
            let tmp = denominator_accumulator[i].clone();
            denominator_accumulator[i + 1] *= tmp;
        }

        let inverse_exists = Self::compute_inverse_exists(input); // Degree 2

        // Note: the lookup_inverses are computed so that the value is 0 if !inverse_exists
        let tmp = (denominator_accumulator[NUM_TOTAL_TERMS - 1].clone()
            * input.witness.lookup_inverses().clone()
            - inverse_exists.clone())
            * scaling_factor;
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        // After this algo, total degree of denominator_accumulator = NUM_TOTAL_TERMS
        for i in 0..NUM_TOTAL_TERMS - 1 {
            denominator_accumulator[NUM_TOTAL_TERMS - 1 - i] =
                denominator_accumulator[NUM_TOTAL_TERMS - 2 - i].clone() * lookup_inverses.clone();

            lookup_inverses =
                lookup_inverses.clone() * lookup_terms[NUM_TOTAL_TERMS - 1 - i].clone();
        }
        denominator_accumulator[0] = lookup_inverses;

        // Each predicate is degree-1
        // Degree of relation at this point = NUM_TOTAL_TERMS + 1
        let mut tmp = Univariate {
            evaluations: [F::zero(); SIZE],
        };
        for (i, denuminator) in denominator_accumulator
            .iter()
            .enumerate()
            .take(Self::READ_TERMS)
        {
            tmp += Self::compute_read_term_predicate::<_, _>(input, i).to_owned() * denuminator;
        }
        for i in 0..univariate_accumulator.r0.evaluations.len() {
            univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i];
        }

        // Each predicate is degree-1, `lookup_read_counts` is degree-1
        // Degree of relation = NUM_TOTAL_TERMS + 2
        tmp = Univariate {
            evaluations: [F::zero(); SIZE],
        };
        for i in 0..Self::WRITE_TERMS {
            let p = Self::compute_write_term_predicate::<_, _>(input, i);
            let lookup_read_count = Self::lookup_read_counts::<_, _>(input, i);
            tmp -= p.to_owned()
                * (denominator_accumulator[i + Self::READ_TERMS].clone() * lookup_read_count);
        }
        for i in 0..univariate_accumulator.r1.evaluations.len() {
            univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i];
        }
    }

    fn verify_accumulate(
        _univariate_accumulator: &mut Self::VerifyAcc,
        _input: &crate::prelude::ClaimedEvaluations<F, ECCVMFlavour>,
        _relation_parameters: &crate::prelude::RelationParameters<F, ECCVMFlavour>,
        _scaling_factor: &F,
    ) {
        todo!()
    }
}
