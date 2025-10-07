use crate::co_decider::co_sumcheck::co_sumcheck_round::SumcheckRound;
use crate::co_decider::relations::Relation;
use crate::{
    co_decider::{
        relations::eccvm_relations::{
            ecc_bools_relation::{EccBoolsRelation, EccBoolsRelationAcc},
            ecc_lookup_relation::{EccLookupRelation, EccLookupRelationAcc},
            ecc_msm_relation::{EccMsmRelation, EccMsmRelationAcc},
            ecc_point_table_relation::{EccPointTableRelation, EccPointTableRelationAcc},
            ecc_set_relation::{EccSetRelation, EccSetRelationAcc},
            ecc_transcript_relation::{EccTranscriptRelation, EccTranscriptRelationAcc},
            ecc_wnaf_relation::{EccWnafRelation, EccWnafRelationAcc},
        },
        univariates::SharedUnivariate,
    },
    prelude::MPCProverFlavour,
    types_batch::{AllEntitiesBatchRelationsTrait, Public, Shared, SumCheckDataForRelation},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::{
    flavours::eccvm_flavour::ECCVMFlavour, prelude::HonkCurve, prover_flavour::ProverFlavour,
};
use common::{mpc::NoirUltraHonkProver, transcript::TranscriptFieldType};
use ultrahonk::prelude::Univariate;

pub struct AllRelationAccECCVM<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r_ecc_transcript: EccTranscriptRelationAcc<T, P>,
    pub(crate) r_ecc_point_table: EccPointTableRelationAcc<T, P>,
    pub(crate) r_ecc_wnaf: EccWnafRelationAcc<T, P>,
    pub(crate) r_ecc_msm: EccMsmRelationAcc<T, P>,
    pub(crate) r_ecc_set: EccSetRelationAcc<T, P>,
    pub(crate) r_ecc_lookup: EccLookupRelationAcc<T, P>,
    pub(crate) r_ecc_bools: EccBoolsRelationAcc<T, P>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for AllRelationAccECCVM<T, P> {
    fn default() -> Self {
        Self {
            r_ecc_transcript: EccTranscriptRelationAcc::default(),
            r_ecc_point_table: EccPointTableRelationAcc::default(),
            r_ecc_wnaf: EccWnafRelationAcc::default(),
            r_ecc_msm: EccMsmRelationAcc::default(),
            r_ecc_set: EccSetRelationAcc::default(),
            r_ecc_lookup: EccLookupRelationAcc::default(),
            r_ecc_bools: EccBoolsRelationAcc::default(),
        }
    }
}

pub struct AllEntitiesBatchRelationsECCVM<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
{
    pub(crate) ecc_transcript: SumCheckDataForRelation<T, P, ECCVMFlavour>,
    pub(crate) ecc_point_table: SumCheckDataForRelation<T, P, ECCVMFlavour>,
    pub(crate) ecc_wnaf: SumCheckDataForRelation<T, P, ECCVMFlavour>,
    pub(crate) ecc_msm: SumCheckDataForRelation<T, P, ECCVMFlavour>,
    pub(crate) ecc_set: SumCheckDataForRelation<T, P, ECCVMFlavour>,
    pub(crate) ecc_lookup: SumCheckDataForRelation<T, P, ECCVMFlavour>,
    pub(crate) ecc_bools: SumCheckDataForRelation<T, P, ECCVMFlavour>,
}

fn extend_and_batch_univariates_template<
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    const SIZE: usize,
>(
    acc: &AllRelationAccECCVM<T, P>,
    result: &mut SharedUnivariate<T, P, SIZE>,
    extended_random_poly: &Univariate<P::ScalarField, SIZE>,
    partial_evaluation_result: &P::ScalarField,
) {
    tracing::trace!("Prove::Extend and batch univariates");
    acc.r_ecc_transcript.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_point_table.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_wnaf.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_msm.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_set.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_lookup.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_ecc_bools.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
}

impl MPCProverFlavour for ECCVMFlavour {
    type AllRelationAcc<T: common::mpc::NoirUltraHonkProver<P>, P: ark_ec::CurveGroup> =
        AllRelationAccECCVM<T, P>;
    type AllRelationEvaluations<T: NoirUltraHonkProver<P>, P: CurveGroup> = (); // No evaluations needed

    type AllRelationAccHalfShared<T: common::mpc::NoirUltraHonkProver<P>, P: ark_ec::CurveGroup> =
        AllRelationAccECCVM<T, P>;

    type SumcheckRoundOutput<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { ECCVMFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type SumcheckRoundOutputZK<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { ECCVMFlavour::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>;

    type SumcheckRoundOutputPublic<F: PrimeField> =
        Univariate<F, { ECCVMFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type SumcheckRoundOutputZKPublic<F: PrimeField> =
        Univariate<F, { ECCVMFlavour::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>;

    type ProverUnivariateShared<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { ECCVMFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

    type ProverUnivariatePublic<P: CurveGroup> =
        Univariate<P::ScalarField, { ECCVMFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

    type AllEntitiesBatchRelations<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> =
        AllEntitiesBatchRelationsECCVM<T, P>;

    const NUM_SUBRELATIONS: usize = EccTranscriptRelation::NUM_RELATIONS
        + EccPointTableRelation::NUM_RELATIONS
        + EccWnafRelation::NUM_RELATIONS
        + EccMsmRelation::NUM_RELATIONS
        + EccSetRelation::NUM_RELATIONS
        + EccLookupRelation::NUM_RELATIONS
        + EccBoolsRelation::NUM_RELATIONS;

    const CRAND_PAIRS_FACTOR: usize = EccTranscriptRelation::CRAND_PAIRS_FACTOR
        + EccPointTableRelation::CRAND_PAIRS_FACTOR
        + EccWnafRelation::CRAND_PAIRS_FACTOR
        + EccMsmRelation::CRAND_PAIRS_FACTOR
        + EccSetRelation::CRAND_PAIRS_FACTOR
        + EccLookupRelation::CRAND_PAIRS_FACTOR
        + EccBoolsRelation::CRAND_PAIRS_FACTOR;

    fn scale<T: common::mpc::NoirUltraHonkProver<P>, P: ark_ec::CurveGroup>(
        acc: &mut Self::AllRelationAcc<T, P>,
        first_scalar: P::ScalarField,
        elements: &[P::ScalarField],
    ) {
        tracing::trace!("Prove::Scale");
        assert!(elements.len() == 1);
        let elements = &elements[0];
        let mut current_scalar = first_scalar;
        acc.r_ecc_transcript.scale(&mut current_scalar, elements);
        acc.r_ecc_point_table.scale(&mut current_scalar, elements);
        acc.r_ecc_wnaf.scale(&mut current_scalar, elements);
        acc.r_ecc_msm.scale(&mut current_scalar, elements);
        acc.r_ecc_set.scale(&mut current_scalar, elements);
        acc.r_ecc_lookup.scale(&mut current_scalar, elements);
        acc.r_ecc_bools.scale(&mut current_scalar, elements);
    }

    fn extend_and_batch_univariates<
        T: common::mpc::NoirUltraHonkProver<P>,
        P: ark_ec::CurveGroup,
    >(
        acc: &Self::AllRelationAcc<T, P>,
        result: &mut Self::SumcheckRoundOutput<T, P>,
        extended_random_poly: &Self::SumcheckRoundOutputPublic<P::ScalarField>,
        partial_evaluation_result: &P::ScalarField,
    ) {
        extend_and_batch_univariates_template(
            acc,
            result,
            extended_random_poly,
            partial_evaluation_result,
        )
    }

    fn extend_and_batch_univariates_zk<
        T: common::mpc::NoirUltraHonkProver<P>,
        P: ark_ec::CurveGroup,
    >(
        acc: &Self::AllRelationAcc<T, P>,
        result: &mut Self::SumcheckRoundOutputZK<T, P>,
        extended_random_poly: &Self::SumcheckRoundOutputZKPublic<P::ScalarField>,
        partial_evaluation_result: &P::ScalarField,
    ) {
        extend_and_batch_univariates_template(
            acc,
            result,
            extended_random_poly,
            partial_evaluation_result,
        )
    }

    fn accumulate_relation_univariates_batch<
        P: co_builder::prelude::HonkCurve<co_builder::TranscriptFieldType>,
        T: common::mpc::NoirUltraHonkProver<P>,
        N: mpc_net::Network,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulators: &mut Self::AllRelationAccHalfShared<T, P>,
        sum_check_data: &Self::AllEntitiesBatchRelations<T, P>,
        relation_parameters: &crate::co_decider::types::RelationParameters<P::ScalarField>,
    ) -> co_builder::HonkProofResult<()> {
        tracing::trace!("Accumulate relations");
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EccTranscriptRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_ecc_transcript,
            relation_parameters,
            &sum_check_data.ecc_transcript,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EccPointTableRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_ecc_point_table,
            relation_parameters,
            &sum_check_data.ecc_point_table,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EccWnafRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_ecc_wnaf,
            relation_parameters,
            &sum_check_data.ecc_wnaf,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EccMsmRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_ecc_msm,
            relation_parameters,
            &sum_check_data.ecc_msm,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EccSetRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_ecc_set,
            relation_parameters,
            &sum_check_data.ecc_set,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EccLookupRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_ecc_lookup,
            relation_parameters,
            &sum_check_data.ecc_lookup,
        )?;
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EccBoolsRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_ecc_bools,
            relation_parameters,
            &sum_check_data.ecc_bools,
        )?;
        Ok(())
    }

    fn get_alpha_challenges<
        F: ark_ff::PrimeField,
        H: common::transcript::TranscriptHasher<F>,
        P: co_builder::prelude::HonkCurve<F>,
    >(
        _transcript: &mut common::transcript::Transcript<F, H>,
        _alphas: &mut Vec<P::ScalarField>,
    ) {
        panic!(
            "This is used in the Oink Prover and thus should not be called with the ECCVM flavour"
        );
    }

    fn reshare<
        T: common::mpc::NoirUltraHonkProver<P>,
        P: ark_ec::CurveGroup,
        N: mpc_net::Network,
    >(
        acc: Self::AllRelationAccHalfShared<T, P>,
        _net: &N,
        _state: &mut T::State,
    ) -> co_builder::HonkProofResult<Self::AllRelationAcc<T, P>> {
        Ok(AllRelationAccECCVM {
            r_ecc_transcript: acc.r_ecc_transcript,
            r_ecc_point_table: acc.r_ecc_point_table,
            r_ecc_wnaf: acc.r_ecc_wnaf,
            r_ecc_msm: acc.r_ecc_msm,
            r_ecc_set: acc.r_ecc_set,
            r_ecc_lookup: acc.r_ecc_lookup,
            r_ecc_bools: acc.r_ecc_bools,
        })
    }
}

impl<T, P> AllEntitiesBatchRelationsTrait<T, P, ECCVMFlavour>
    for AllEntitiesBatchRelationsECCVM<T, P>
where
    P: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<P>,
{
    fn new() -> Self {
        Self {
            ecc_transcript: SumCheckDataForRelation::new(),
            ecc_point_table: SumCheckDataForRelation::new(),
            ecc_wnaf: SumCheckDataForRelation::new(),
            ecc_msm: SumCheckDataForRelation::new(),
            ecc_set: SumCheckDataForRelation::new(),
            ecc_lookup: SumCheckDataForRelation::new(),
            ecc_bools: SumCheckDataForRelation::new(),
        }
    }

    fn fold_and_filter(
        &mut self,
        entity: crate::types::AllEntities<
            Shared<T, P, ECCVMFlavour>,
            Public<P, ECCVMFlavour>,
            ECCVMFlavour,
        >,
        scaling_factor: P::ScalarField,
    ) {
        // 0xThemis TODO - for all (?) accumulator we don't need all 7 elements. Can we remove
        // somehow skip those to decrease work even further?
        // e.g. UltraArith only has
        //
        // pub(crate) r0: SharedUnivariate<T, P, 6>,
        // pub(crate) r1: SharedUnivariate<T, P, 5>,
        //
        // Can we somehow only add 5/6 elements?

        EccBoolsRelation::add_edge(&entity, scaling_factor, &mut self.ecc_bools);
        EccLookupRelation::add_edge(&entity, scaling_factor, &mut self.ecc_lookup);
        EccMsmRelation::add_edge(&entity, scaling_factor, &mut self.ecc_msm);
        EccSetRelation::add_edge(&entity, scaling_factor, &mut self.ecc_set);
        EccWnafRelation::add_edge(&entity, scaling_factor, &mut self.ecc_wnaf);
        EccPointTableRelation::add_edge(&entity, scaling_factor, &mut self.ecc_point_table);
        EccTranscriptRelation::add_edge(&entity, scaling_factor, &mut self.ecc_transcript);
    }
}
