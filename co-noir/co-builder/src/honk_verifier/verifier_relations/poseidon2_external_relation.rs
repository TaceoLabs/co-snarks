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

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2ExternalRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
}

impl_relation_evals!(Poseidon2ExternalRelationEvals, r0, r1, r2, r3);

pub(crate) struct Poseidon2ExternalRelation;

impl Poseidon2ExternalRelation {
    pub(crate) const NUM_RELATIONS: usize = 4;
}

impl<C: HonkCurve<TranscriptFieldType>> Relation<C> for Poseidon2ExternalRelation {
    type VerifyAcc = Poseidon2ExternalRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let w_1 = input.witness.w_l().to_owned();
        let w_2 = input.witness.w_r().to_owned();
        let w_3 = input.witness.w_o().to_owned();
        let w_4 = input.witness.w_4().to_owned();
        let w_1_shift = input.shifted_witness.w_l().to_owned();
        let w_2_shift = input.shifted_witness.w_r().to_owned();
        let w_3_shift = input.shifted_witness.w_o().to_owned();
        let w_4_shift = input.shifted_witness.w_4().to_owned();
        let c_1 = input.precomputed.q_l().to_owned();
        let c_2 = input.precomputed.q_r().to_owned();
        let c_3 = input.precomputed.q_o().to_owned();
        let c_4 = input.precomputed.q_4().to_owned();
        let q_poseidon2_external = input.precomputed.q_poseidon2_external().to_owned();

        let sbox = |x: &FieldCT<C::ScalarField>,
                    builder: &mut GenericUltraCircuitBuilder<C, T>,
                    driver: &mut T|
         -> HonkProofResult<FieldCT<C::ScalarField>> {
            let x2 = x.multiply(x, builder, driver)?;
            let x4 = x2.multiply(&x2, builder, driver)?;
            let result = x4.multiply(x, builder, driver)?;
            Ok(result)
        };

        // add round constants which are loaded in selectors
        // TACEO TODO: Batch somehow
        let u1 = sbox(&w_1.add(&c_1, builder, driver), builder, driver)?;
        let u2 = sbox(&w_2.add(&c_2, builder, driver), builder, driver)?;
        let u3 = sbox(&w_3.add(&c_3, builder, driver), builder, driver)?;
        let u4 = sbox(&w_4.add(&c_4, builder, driver), builder, driver)?;

        // matrix mul v = M_E * u with 14 additions
        let t0 = u1.add(&u2, builder, driver); // u_1 + u_2
        let t1 = u3.add(&u4, builder, driver); // u_3 + u_4
        let t2 = u2.add(&u2, builder, driver).add(&t1, builder, driver); // 2u_2 + u_3 + u_4
        let t3 = u4.add(&u4, builder, driver).add(&t0, builder, driver); // u_1 + u_2 + 2u_4

        let mut v4 = t1.add(&t1, builder, driver);
        v4 = v4.add(&v4, builder, driver).add(&t3, builder, driver); // u_1 + u_2 + 4u_3 + 8u_4

        let mut v2 = t0.add(&t0, builder, driver);
        v2 = v2.add(&v2, builder, driver).add(&t2, builder, driver); // 4u_1 + 6u_2 + u_3 + u_4

        let v1 = t3.add(&v2, builder, driver); // 5u_1 + 7u_2 + u_3 + 3u_4
        let v3 = t2.add(&v4, builder, driver); // u_1 + 3u_2 + 5u_3 + 7u_4

        let q_pos_by_scaling = q_poseidon2_external.multiply(scaling_factor, builder, driver)?;
        let tmp =
            q_pos_by_scaling.multiply(&v1.sub(&w_1_shift, builder, driver), builder, driver)?;
        accumulator.r0.add_assign(&tmp, builder, driver);

        ///////////////////////////////////////////////////////////////////////
        let tmp =
            q_pos_by_scaling.multiply(&v2.sub(&w_2_shift, builder, driver), builder, driver)?;
        accumulator.r1.add_assign(&tmp, builder, driver);

        ///////////////////////////////////////////////////////////////////////
        let tmp =
            q_pos_by_scaling.multiply(&v3.sub(&w_3_shift, builder, driver), builder, driver)?;
        accumulator.r2.add_assign(&tmp, builder, driver);

        //////////////////////////////////////////////////////////////////////
        let tmp =
            q_pos_by_scaling.multiply(&v4.sub(&w_4_shift, builder, driver), builder, driver)?;
        accumulator.r3.add_assign(&tmp, builder, driver);

        Ok(())
    }
}
