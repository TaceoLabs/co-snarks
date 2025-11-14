use super::Relation;
use crate::honk_verifier::verifier_relations::VerifyAccGetter;
use crate::impl_relation_evals;
use crate::prelude::GenericUltraCircuitBuilder;
use crate::types::field_ct::FieldCT;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::types::RelationParameters;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use mpc_core::gadgets::poseidon2::POSEIDON2_BN254_T4_PARAMS;
use num_bigint::BigUint;

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2InternalRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
}

impl_relation_evals!(Poseidon2InternalRelationEvals, r0, r1, r2, r3);
pub(crate) struct Poseidon2InternalRelation;

impl Poseidon2InternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
}

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for Poseidon2InternalRelation {
    type VerifyAcc = Poseidon2InternalRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_l = input.witness.w_l().to_owned();
        let w_r = input.witness.w_r().to_owned();
        let w_o = input.witness.w_o().to_owned();
        let w_4 = input.witness.w_4().to_owned();
        let w_l_shift = input.shifted_witness.w_l().to_owned();
        let w_r_shift = input.shifted_witness.w_r().to_owned();
        let w_o_shift = input.shifted_witness.w_o().to_owned();
        let w_4_shift = input.shifted_witness.w_4().to_owned();
        let q_l = input.precomputed.q_l().to_owned();
        let q_poseidon2_internal = input.precomputed.q_poseidon2_internal().to_owned();

        // add round constants
        let s1 = w_l.add(&q_l, builder, driver);

        // apply s-box round
        // 0xThemis TODO again can we do something better for x^5?
        let u1 = s1.multiply(&s1, builder, driver)?;
        let u1 = u1.multiply(&u1, builder, driver)?;
        let u1 = u1.multiply(&s1, builder, driver)?;

        let q_pos_by_scaling = q_poseidon2_internal.multiply(scaling_factor, builder, driver)?;

        let partial_sum = w_r.add(&w_o, builder, driver).add(&w_4, builder, driver);
        let scaled_u1 = u1.multiply(&q_pos_by_scaling, builder, driver)?;

        // TACEO TODO this poseidon instance is very hardcoded to the bn254 curve
        let internal_matrix_diag_0 = FieldCT::from(C::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[0],
        )));
        let internal_matrix_diag_1 = FieldCT::from(C::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[1],
        )));
        let internal_matrix_diag_2 = FieldCT::from(C::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[2],
        )));
        let internal_matrix_diag_3 = FieldCT::from(C::ScalarField::from(BigUint::from(
            POSEIDON2_BN254_T4_PARAMS.mat_internal_diag_m_1[3],
        )));

        let mut barycentric_term = scaled_u1.multiply(&internal_matrix_diag_0, builder, driver)?;
        let monomial_term = partial_sum.sub(&w_l_shift, builder, driver);
        barycentric_term.add_assign(
            &monomial_term.multiply(&q_pos_by_scaling, builder, driver)?,
            builder,
            driver,
        );
        accumulator
            .r0
            .add_assign(&barycentric_term, builder, driver);

        ///////////////////////////////////////////////////////////////////////
        let v2_m = w_r
            .multiply(&internal_matrix_diag_1, builder, driver)?
            .add(&partial_sum, builder, driver)
            .sub(&w_r_shift, builder, driver);
        let barycentric_term = v2_m
            .multiply(&q_pos_by_scaling, builder, driver)?
            .add(&scaled_u1, builder, driver);
        accumulator
            .r1
            .add_assign(&barycentric_term, builder, driver);

        ///////////////////////////////////////////////////////////////////////
        let v3_m = w_o
            .multiply(&internal_matrix_diag_2, builder, driver)?
            .add(&partial_sum, builder, driver)
            .sub(&w_o_shift, builder, driver);
        let barycentric_term = v3_m
            .multiply(&q_pos_by_scaling, builder, driver)?
            .add(&scaled_u1, builder, driver);
        accumulator
            .r2
            .add_assign(&barycentric_term, builder, driver);

        ///////////////////////////////////////////////////////////////////////
        let v4_m = w_4
            .multiply(&internal_matrix_diag_3, builder, driver)?
            .add(&partial_sum, builder, driver)
            .sub(&w_4_shift, builder, driver);
        let barycentric_term = v4_m
            .multiply(&q_pos_by_scaling, builder, driver)?
            .add(&scaled_u1, builder, driver);
        accumulator
            .r3
            .add_assign(&barycentric_term, builder, driver);

        ///////////////////////////////////////////////////////////////////////
        Ok(())
    }
}
