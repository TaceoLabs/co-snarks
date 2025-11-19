use super::Relation;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_ultrahonk::co_decider::types::RelationParameters;
use co_ultrahonk::types::AllEntities;

use crate::impl_relation_evals;
use crate::verifier_relations::VerifyAccGetter;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::{
    flavours::mega_flavour::MegaFlavour, mega_builder::MegaCircuitBuilder,
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour, types::field_ct::FieldCT,
};
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofResult, TranscriptFieldType};

#[derive(Clone, Debug)]
pub(crate) struct Poseidon2ExternalRelationEvals<F: PrimeField> {
    pub(crate) r0: FieldCT<F>,
    pub(crate) r1: FieldCT<F>,
    pub(crate) r2: FieldCT<F>,
    pub(crate) r3: FieldCT<F>,
}

impl_relation_evals!(Poseidon2ExternalRelationEvals, r0, r1, r2, r3);

pub(crate) struct Poseidon2ExternalRelation;

impl<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>> Relation<C>
    for Poseidon2ExternalRelation
{
    type VerifyAcc = Poseidon2ExternalRelationEvals<C::ScalarField>;

    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        accumulator: &mut Self::VerifyAcc,
        input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>, MegaFlavour>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        scaling_factor: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
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
        let q_r = input.precomputed.q_r().to_owned();
        let q_o = input.precomputed.q_o().to_owned();
        let q_4 = input.precomputed.q_4().to_owned();
        let q_poseidon2_external = input.precomputed.q_poseidon2_external().to_owned();

        // add round constants which are loaded in selectors
        let s1 = q_l.add(&w_l, builder, driver);
        let s2 = q_r.add(&w_r, builder, driver);
        let s3 = q_o.add(&w_o, builder, driver);
        let s4 = q_4.add(&w_4, builder, driver);

        let s = vec![s1, s2, s3, s4];
        // apply s-box round
        // 0xThemis TODO better mul depth for x^5?
        let u = FieldCT::multiply_many(&s, &s, builder, driver)?;
        let u = FieldCT::multiply_many(&u, &u, builder, driver)?;
        let u = FieldCT::multiply_many(&u, &s, builder, driver)?;

        // matrix mul v = M_E * u with 14 additions
        let t0 = u[0].add(&u[1], builder, driver); // u_1 + u_2
        let t1 = u[2].add(&u[3], builder, driver); // u_3 + u_4
        let t2 = u[1].add(&u[1], builder, driver).add(&t1, builder, driver); // 2u_2 + u_3 + u_4
        let t3 = u[3].add(&u[3], builder, driver).add(&t0, builder, driver); // u_1 + u_2 + 2u_4

        let mut v4 = t1.add(&t1, builder, driver);
        v4 = v4.add(&v4, builder, driver).add(&t3, builder, driver); // u_1 + u_2 + 4u_3 + 8u_4

        let mut v2 = t0.add(&t0, builder, driver);
        v2 = v2.add(&v2, builder, driver).add(&t2, builder, driver); // 4u_1 + 6u_2 + u_3 + u_4

        let v1 = t3.add(&v2, builder, driver); // 5u_1 + 7u_2 + u_3 + 3u_4
        let v3 = t2.add(&v4, builder, driver); // u_1 + 3u_2 + 5u_3 + 7u_4

        let q_pos_by_scaling = q_poseidon2_external.multiply(scaling_factor, builder, driver)?;
        let tmp =
            v1.sub(&w_l_shift, builder, driver)
                .multiply(&q_pos_by_scaling, builder, driver)?;

        accumulator.r0 = accumulator.r0.add(&tmp, builder, driver);

        ///////////////////////////////////////////////////////////////////////

        let tmp =
            v2.sub(&w_r_shift, builder, driver)
                .multiply(&q_pos_by_scaling, builder, driver)?;
        accumulator.r1 = accumulator.r1.add(&tmp, builder, driver);

        ///////////////////////////////////////////////////////////////////////
        let tmp =
            v3.sub(&w_o_shift, builder, driver)
                .multiply(&q_pos_by_scaling, builder, driver)?;
        accumulator.r2 = accumulator.r2.add(&tmp, builder, driver);

        //////////////////////////////////////////////////////////////////////
        let tmp =
            v4.sub(&w_4_shift, builder, driver)
                .multiply(&q_pos_by_scaling, builder, driver)?;
        accumulator.r3 = accumulator.r3.add(&tmp, builder, driver);

        Ok(())
    }
}
