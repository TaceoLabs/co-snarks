use crate::co_decider::relations::Relation;
use crate::types_batch::{AllEntitiesBatchRelationsTrait, Public, Shared, SumCheckDataForRelation};
use crate::{
    co_decider::{
        co_sumcheck::co_sumcheck_round::SumcheckRound,
        relations::{
            auxiliary_relation::{AuxiliaryRelation, AuxiliaryRelationAcc},
            databus_lookup_relation::{DataBusLookupRelation, DataBusLookupRelationAcc},
            delta_range_constraint_relation::{
                DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
            },
            ecc_op_queue_relation::{EccOpQueueRelation, EccOpQueueRelationAcc},
            elliptic_relation::{EllipticRelation, EllipticRelationAcc},
            logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationAcc},
            permutation_relation::{UltraPermutationRelation, UltraPermutationRelationAcc},
            poseidon2_external_relation::{
                Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc,
            },
            poseidon2_internal_relation::{
                Poseidon2InternalRelation, Poseidon2InternalRelationAcc,
            },
            ultra_arithmetic_relation::{
                UltraArithmeticRelation, UltraArithmeticRelationAcc,
                UltraArithmeticRelationAccHalfShared,
            },
        },
        univariates::SharedUnivariate,
    },
    mpc_prover_flavour::MPCProverFlavour,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::TranscriptFieldType;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::prelude::HonkCurve;
use co_builder::prover_flavour::ProverFlavour;
use common::mpc::NoirUltraHonkProver;
use mpc_net::Network;
use std::array;
use ultrahonk::prelude::Univariate;

pub struct AllRelationAccMega<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<T, P>,
    pub(crate) r_perm: UltraPermutationRelationAcc<T, P>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<T, P>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<T, P>,
    pub(crate) r_elliptic: EllipticRelationAcc<T, P>,
    pub(crate) r_aux: AuxiliaryRelationAcc<T, P>,
    pub(crate) r_ecc_op_queue: EccOpQueueRelationAcc<T, P>,
    pub(crate) r_databus: DataBusLookupRelationAcc<T, P>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<T, P>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<T, P>,
}

pub struct AllRelationAccHalfSharedMega<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r_arith: UltraArithmeticRelationAccHalfShared<T, P>,
    pub(crate) r_perm: UltraPermutationRelationAcc<T, P>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<T, P>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<T, P>,
    pub(crate) r_elliptic: EllipticRelationAcc<T, P>,
    pub(crate) r_aux: AuxiliaryRelationAcc<T, P>,
    pub(crate) r_ecc_op_queue: EccOpQueueRelationAcc<T, P>,
    pub(crate) r_databus: DataBusLookupRelationAcc<T, P>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<T, P>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<T, P>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for AllRelationAccHalfSharedMega<T, P> {
    fn default() -> Self {
        AllRelationAccHalfSharedMega {
            r_arith: UltraArithmeticRelationAccHalfShared::default(),
            r_perm: UltraPermutationRelationAcc::default(),
            r_lookup: LogDerivLookupRelationAcc::default(),
            r_delta: DeltaRangeConstraintRelationAcc::default(),
            r_elliptic: EllipticRelationAcc::default(),
            r_aux: AuxiliaryRelationAcc::default(),
            r_ecc_op_queue: EccOpQueueRelationAcc::default(),
            r_databus: DataBusLookupRelationAcc::default(),
            r_pos_ext: Poseidon2ExternalRelationAcc::default(),
            r_pos_int: Poseidon2InternalRelationAcc::default(),
        }
    }
}

pub struct AllEntitiesBatchRelationsMega<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
{
    pub(crate) ultra_arith: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) ultra_perm: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) delta_range: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) elliptic: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) auxiliary: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) log_lookup: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) ecc_op_queue: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) databus: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) poseidon_ext: SumCheckDataForRelation<T, P, MegaFlavour>,
    pub(crate) poseidon_int: SumCheckDataForRelation<T, P, MegaFlavour>,
}

fn extend_and_batch_univariates_template<
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    const SIZE: usize,
>(
    acc: &AllRelationAccMega<T, P>,
    result: &mut SharedUnivariate<T, P, SIZE>,
    extended_random_poly: &Univariate<P::ScalarField, SIZE>,
    partial_evaluation_result: &P::ScalarField,
) {
    acc.r_arith.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_perm.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_lookup.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_delta.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_elliptic.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_aux
        .extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result);
    acc.r_ecc_op_queue.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_databus.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_pos_ext.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
    acc.r_pos_int.extend_and_batch_univariates(
        result,
        extended_random_poly,
        partial_evaluation_result,
    );
}

impl MPCProverFlavour for MegaFlavour {
    type AllRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> = AllRelationAccMega<T, P>;

    type AllRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        AllRelationAccHalfSharedMega<T, P>;

    type SumcheckRoundOutput<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { Self::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type SumcheckRoundOutputZK<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { Self::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>;

    type SumcheckRoundOutputPublic<F: PrimeField> =
        Univariate<F, { Self::BATCHED_RELATION_PARTIAL_LENGTH }>;

    type SumcheckRoundOutputZKPublic<F: PrimeField> =
        Univariate<F, { Self::BATCHED_RELATION_PARTIAL_LENGTH_ZK }>;

    type ProverUnivariateShared<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        SharedUnivariate<T, P, { Self::MAX_PARTIAL_RELATION_LENGTH }>;

    type ProverUnivariatePublic<P: CurveGroup> =
        Univariate<P::ScalarField, { Self::MAX_PARTIAL_RELATION_LENGTH }>;

    type Alphas<F: PrimeField> = MegaAlphas<F>;

    type AllEntitiesBatchRelations<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> =
        AllEntitiesBatchRelationsMega<T, P>;

    const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
        + UltraPermutationRelation::NUM_RELATIONS
        + DeltaRangeConstraintRelation::NUM_RELATIONS
        + EllipticRelation::NUM_RELATIONS
        + AuxiliaryRelation::NUM_RELATIONS
        + LogDerivLookupRelation::NUM_RELATIONS
        + EccOpQueueRelation::NUM_RELATIONS
        + DataBusLookupRelation::NUM_RELATIONS
        + Poseidon2ExternalRelation::NUM_RELATIONS
        + Poseidon2InternalRelation::NUM_RELATIONS;

    const CRAND_PAIRS_FACTOR: usize = AuxiliaryRelation::CRAND_PAIRS_FACTOR
        + DeltaRangeConstraintRelation::CRAND_PAIRS_FACTOR
        + EllipticRelation::CRAND_PAIRS_FACTOR
        + LogDerivLookupRelation::CRAND_PAIRS_FACTOR
        + UltraPermutationRelation::CRAND_PAIRS_FACTOR
        + Poseidon2ExternalRelation::CRAND_PAIRS_FACTOR
        + Poseidon2InternalRelation::CRAND_PAIRS_FACTOR
        + UltraArithmeticRelation::CRAND_PAIRS_FACTOR
        // + EccOpQueueRelation::CRAND_PAIRS_FACTOR=0
        + DataBusLookupRelation::CRAND_PAIRS_FACTOR;

    fn scale<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        acc: &mut Self::AllRelationAcc<T, P>,
        first_scalar: P::ScalarField,
        elements: &Self::Alphas<P::ScalarField>,
    ) {
        tracing::trace!("Prove::Scale");
        assert!(elements.0.len() == Self::NUM_SUBRELATIONS - 1);
        acc.r_arith.scale(&[first_scalar, elements.0[0]]);
        acc.r_perm.scale(&elements.0[1..3]);
        acc.r_lookup.scale(&elements.0[3..5]);
        acc.r_delta.scale(&elements.0[5..9]);
        acc.r_elliptic.scale(&elements.0[9..11]);
        acc.r_aux.scale(&elements.0[11..17]);
        acc.r_ecc_op_queue.scale(&elements.0[17..25]);
        acc.r_databus.scale(&elements.0[25..31]);
        acc.r_pos_ext.scale(&elements.0[31..35]);
        acc.r_pos_int.scale(&elements.0[35..]);
    }

    fn extend_and_batch_univariates<T: NoirUltraHonkProver<P>, P: CurveGroup>(
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

    fn extend_and_batch_univariates_zk<T: NoirUltraHonkProver<P>, P: CurveGroup>(
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
        T: NoirUltraHonkProver<P>,
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulators: &mut Self::AllRelationAccHalfShared<T, P>,
        sum_check_data: &Self::AllEntitiesBatchRelations<T, P>,
        relation_parameters: &crate::co_decider::types::RelationParameters<P::ScalarField, Self>,
    ) -> co_builder::HonkProofResult<()> {
        tracing::trace!("Accumulate relations");
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            UltraArithmeticRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_arith,
            relation_parameters,
            &sum_check_data.ultra_arith,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            UltraPermutationRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_perm,
            relation_parameters,
            &sum_check_data.ultra_perm,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            DeltaRangeConstraintRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_delta,
            relation_parameters,
            &sum_check_data.delta_range,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EllipticRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_elliptic,
            relation_parameters,
            &sum_check_data.elliptic,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            AuxiliaryRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_aux,
            relation_parameters,
            &sum_check_data.auxiliary,
        )?;

        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            LogDerivLookupRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_lookup,
            relation_parameters,
            &sum_check_data.log_lookup,
        )?;
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            EccOpQueueRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_ecc_op_queue,
            relation_parameters,
            &sum_check_data.ecc_op_queue,
        )?;
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            DataBusLookupRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_databus,
            relation_parameters,
            &sum_check_data.databus,
        )?;
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            Poseidon2ExternalRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_pos_ext,
            relation_parameters,
            &sum_check_data.poseidon_ext,
        )?;
        SumcheckRound::accumulate_one_relation_univariates_batch::<
            _,
            _,
            _,
            Self,
            Poseidon2InternalRelation,
            { Self::MAX_PARTIAL_RELATION_LENGTH },
        >(
            net,
            state,
            &mut univariate_accumulators.r_pos_int,
            relation_parameters,
            &sum_check_data.poseidon_int,
        )?;
        Ok(())
    }

    fn get_alpha_challenges<
        F: ark_ff::PrimeField,
        H: common::transcript::TranscriptHasher<F>,
        P: co_builder::prelude::HonkCurve<F>,
    >(
        transcript: &mut common::transcript::Transcript<F, H>,
        alphas: &mut Self::Alphas<P::ScalarField>,
    ) {
        let args: [String; Self::NUM_ALPHAS] = array::from_fn(|i| format!("alpha_{i}"));
        alphas
            .0
            .copy_from_slice(&transcript.get_challenges::<P>(&args));
    }

    fn reshare<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        acc: Self::AllRelationAccHalfShared<T, P>,
        net: &N,
        state: &mut T::State,
    ) -> co_builder::HonkProofResult<Self::AllRelationAcc<T, P>> {
        let r_arith_r0 = T::reshare(acc.r_arith.r0.evaluations.to_vec(), net, state)?;
        Ok(AllRelationAccMega {
            r_arith: UltraArithmeticRelationAcc {
                r0: SharedUnivariate::from_vec(r_arith_r0),
                r1: acc.r_arith.r1,
            },
            r_perm: acc.r_perm,
            r_lookup: acc.r_lookup,
            r_delta: acc.r_delta,
            r_elliptic: acc.r_elliptic,
            r_aux: acc.r_aux,
            r_ecc_op_queue: acc.r_ecc_op_queue,
            r_databus: acc.r_databus,
            r_pos_ext: acc.r_pos_ext,
            r_pos_int: acc.r_pos_int,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MegaAlphas<F: PrimeField>([F; MegaFlavour::NUM_ALPHAS]);

impl<F: PrimeField + Default> Default for MegaAlphas<F> {
    fn default() -> Self {
        Self(std::array::from_fn(|_| F::default()))
    }
}

impl<T, P> AllEntitiesBatchRelationsTrait<T, P, MegaFlavour> for AllEntitiesBatchRelationsMega<T, P>
where
    P: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<P>,
{
    fn new() -> Self {
        Self {
            ultra_arith: SumCheckDataForRelation::new(),
            ultra_perm: SumCheckDataForRelation::new(),
            delta_range: SumCheckDataForRelation::new(),
            log_lookup: SumCheckDataForRelation::new(),
            elliptic: SumCheckDataForRelation::new(),
            auxiliary: SumCheckDataForRelation::new(),
            ecc_op_queue: SumCheckDataForRelation::new(),
            databus: SumCheckDataForRelation::new(),
            poseidon_ext: SumCheckDataForRelation::new(),
            poseidon_int: SumCheckDataForRelation::new(),
        }
    }

    fn fold_and_filter(
        &mut self,
        entity: crate::types::AllEntities<
            Shared<T, P, MegaFlavour>,
            Public<P, MegaFlavour>,
            MegaFlavour,
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

        UltraArithmeticRelation::add_edge(&entity, scaling_factor, &mut self.ultra_arith);
        UltraPermutationRelation::add_edge(&entity, scaling_factor, &mut self.ultra_perm);
        DeltaRangeConstraintRelation::add_edge(&entity, scaling_factor, &mut self.delta_range);

        EllipticRelation::add_edge(&entity, scaling_factor, &mut self.elliptic);
        AuxiliaryRelation::add_edge(&entity, scaling_factor, &mut self.auxiliary);
        LogDerivLookupRelation::add_edge(&entity, scaling_factor, &mut self.log_lookup);

        EccOpQueueRelation::add_edge(&entity, scaling_factor, &mut self.ecc_op_queue);
        DataBusLookupRelation::add_edge(&entity, scaling_factor, &mut self.databus);

        Poseidon2ExternalRelation::add_edge(&entity, scaling_factor, &mut self.poseidon_ext);
        Poseidon2InternalRelation::add_edge(&entity, scaling_factor, &mut self.poseidon_int);
    }
}
