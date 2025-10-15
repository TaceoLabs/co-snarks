use crate::co_decider::relations::Relation;
use crate::co_decider::relations::auxiliary_relation::AuxiliaryRelationAccType;
use crate::co_decider::relations::logderiv_lookup_relation::LogDerivLookupRelationAccType;
use crate::co_decider::relations::permutation_relation::UltraPermutationRelationAccType;
use crate::types_batch::{AllEntitiesBatchRelationsTrait, Public, Shared, SumCheckDataForRelation};
use crate::{
    co_decider::{
        co_sumcheck::co_sumcheck_round::SumcheckRound,
        relations::{
            auxiliary_relation::AuxiliaryRelation,
            delta_range_constraint_relation::{
                DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
            },
            elliptic_relation::{EllipticRelation, EllipticRelationAcc},
            logderiv_lookup_relation::LogDerivLookupRelation,
            permutation_relation::UltraPermutationRelation,
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
use ark_ff::AdditiveGroup;
use ark_ff::PrimeField;
use co_builder::flavours::ultra_flavour::UltraFlavour;
use co_builder::prover_flavour::ProverFlavour;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofResult, TranscriptFieldType};
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::transcript_mpc::TranscriptRef;
use mpc_net::Network;
use std::array;
use ultrahonk::prelude::{TranscriptHasher, Univariate};

pub struct AllRelationAccUltra<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<T, P>,
    pub(crate) r_perm: UltraPermutationRelationAccType<T, P>,
    pub(crate) r_lookup: LogDerivLookupRelationAccType<T, P>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<T, P>,
    pub(crate) r_elliptic: EllipticRelationAcc<T, P>,
    pub(crate) r_aux: AuxiliaryRelationAccType<T, P>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<T, P>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<T, P>,
}

pub struct AllRelationAccHalfSharedUltra<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) r_arith: UltraArithmeticRelationAccHalfShared<T, P>,
    pub(crate) r_perm: UltraPermutationRelationAccType<T, P>,
    pub(crate) r_lookup: LogDerivLookupRelationAccType<T, P>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<T, P>,
    pub(crate) r_elliptic: EllipticRelationAcc<T, P>,
    pub(crate) r_aux: AuxiliaryRelationAccType<T, P>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<T, P>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<T, P>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for AllRelationAccHalfSharedUltra<T, P> {
    fn default() -> Self {
        AllRelationAccHalfSharedUltra {
            r_arith: UltraArithmeticRelationAccHalfShared::default(),
            r_perm: UltraPermutationRelationAccType::default(),
            r_lookup: LogDerivLookupRelationAccType::default(),
            r_delta: DeltaRangeConstraintRelationAcc::default(),
            r_elliptic: EllipticRelationAcc::default(),
            r_aux: AuxiliaryRelationAccType::default(),
            r_pos_ext: Poseidon2ExternalRelationAcc::default(),
            r_pos_int: Poseidon2InternalRelationAcc::default(),
        }
    }
}

#[derive(Default)]
pub struct AllEntitiesBatchRelationsUltra<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
{
    pub(crate) ultra_arith: SumCheckDataForRelation<T, P, UltraFlavour>,
    pub(crate) ultra_perm: SumCheckDataForRelation<T, P, UltraFlavour>,
    pub(crate) delta_range: SumCheckDataForRelation<T, P, UltraFlavour>,
    pub(crate) elliptic: SumCheckDataForRelation<T, P, UltraFlavour>,
    pub(crate) auxiliary: SumCheckDataForRelation<T, P, UltraFlavour>,
    pub(crate) log_lookup: SumCheckDataForRelation<T, P, UltraFlavour>,
    pub(crate) poseidon_ext: SumCheckDataForRelation<T, P, UltraFlavour>,
    pub(crate) poseidon_int: SumCheckDataForRelation<T, P, UltraFlavour>,
}

fn extend_and_batch_univariates_template<
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    const SIZE: usize,
>(
    acc: &AllRelationAccUltra<T, P>,
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

impl MPCProverFlavour for UltraFlavour {
    type AllRelationAcc<T: NoirUltraHonkProver<P>, P: CurveGroup> = AllRelationAccUltra<T, P>;
    type AllRelationEvaluations<T: NoirUltraHonkProver<P>, P: CurveGroup> = ();

    type AllRelationAccHalfShared<T: NoirUltraHonkProver<P>, P: CurveGroup> =
        AllRelationAccHalfSharedUltra<T, P>;

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

    type AllEntitiesBatchRelations<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> =
        AllEntitiesBatchRelationsUltra<T, P>;

    const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS
        + UltraPermutationRelation::NUM_RELATIONS
        + DeltaRangeConstraintRelation::NUM_RELATIONS
        + EllipticRelation::NUM_RELATIONS
        + AuxiliaryRelation::NUM_RELATIONS
        + LogDerivLookupRelation::NUM_RELATIONS
        + Poseidon2ExternalRelation::NUM_RELATIONS
        + Poseidon2InternalRelation::NUM_RELATIONS;

    const CRAND_PAIRS_FACTOR: usize = AuxiliaryRelation::CRAND_PAIRS_FACTOR
        + DeltaRangeConstraintRelation::CRAND_PAIRS_FACTOR
        + EllipticRelation::CRAND_PAIRS_FACTOR
        + LogDerivLookupRelation::CRAND_PAIRS_FACTOR
        + UltraPermutationRelation::CRAND_PAIRS_FACTOR
        + Poseidon2ExternalRelation::CRAND_PAIRS_FACTOR
        + Poseidon2InternalRelation::CRAND_PAIRS_FACTOR
        + UltraArithmeticRelation::CRAND_PAIRS_FACTOR;

    fn scale<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        acc: &mut Self::AllRelationAcc<T, P>,
        first_scalar: P::ScalarField,
        elements: &[P::ScalarField],
    ) {
        tracing::trace!("Prove::Scale");
        assert!(elements.len() == Self::NUM_SUBRELATIONS - 1);
        acc.r_arith.scale(&[first_scalar, elements[0]]);
        acc.r_perm.scale(&elements[1..3]);
        acc.r_lookup.scale(&elements[3..5]);
        acc.r_delta.scale(&elements[5..9]);
        acc.r_elliptic.scale(&elements[9..11]);
        acc.r_aux.scale(&elements[11..17]);
        acc.r_pos_ext.scale(&elements[17..21]);
        acc.r_pos_int.scale(&elements[21..]);
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
        );
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
        );
    }

    fn accumulate_relation_univariates_batch<
        P: HonkCurve<TranscriptFieldType>,
        T: NoirUltraHonkProver<P>,
        N: Network,
    >(
        net: &N,
        state: &mut T::State,
        univariate_accumulators: &mut Self::AllRelationAccHalfShared<T, P>,
        sum_check_data: &Self::AllEntitiesBatchRelations<T, P>,
        relation_parameters: &crate::co_decider::types::RelationParameters<P::ScalarField>,
    ) -> HonkProofResult<()> {
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
        T: NoirUltraHonkProver<P>,
        H: TranscriptHasher<TranscriptFieldType, T, P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        transcript: &mut TranscriptRef<TranscriptFieldType, T, P, H>,
        alphas: &mut Vec<P::ScalarField>,
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<()> {
        let args: [String; Self::NUM_ALPHAS] = array::from_fn(|i| format!("alpha_{i}"));
        alphas.resize(Self::NUM_ALPHAS, P::ScalarField::ZERO);
        match transcript {
            TranscriptRef::Plain(transcript) => {
                alphas.copy_from_slice(&transcript.get_challenges::<P>(&args))
            }
            TranscriptRef::Rep3(transcript_rep3) => {
                alphas.copy_from_slice(&transcript_rep3.get_challenges(&args, net, state)?)
            }
        };
        Ok(())
    }

    fn reshare<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        acc: Self::AllRelationAccHalfShared<T, P>,
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<Self::AllRelationAcc<T, P>> {
        let r_arith_r0 = T::reshare(acc.r_arith.r0.evaluations.to_vec(), net, state)?;
        Ok(AllRelationAccUltra {
            r_arith: UltraArithmeticRelationAcc {
                r0: SharedUnivariate::from_vec(r_arith_r0),
                r1: acc.r_arith.r1,
            },
            r_perm: acc.r_perm,
            r_lookup: acc.r_lookup,
            r_delta: acc.r_delta,
            r_elliptic: acc.r_elliptic,
            r_aux: acc.r_aux,
            r_pos_ext: acc.r_pos_ext,
            r_pos_int: acc.r_pos_int,
        })
    }
}

impl<T, P> AllEntitiesBatchRelationsTrait<T, P, UltraFlavour>
    for AllEntitiesBatchRelationsUltra<T, P>
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
            poseidon_ext: SumCheckDataForRelation::new(),
            poseidon_int: SumCheckDataForRelation::new(),
        }
    }

    fn fold_and_filter(
        &mut self,
        entity: crate::types::AllEntities<
            Shared<T, P, UltraFlavour>,
            Public<P, UltraFlavour>,
            UltraFlavour,
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

        Poseidon2ExternalRelation::add_edge(&entity, scaling_factor, &mut self.poseidon_ext);
        Poseidon2InternalRelation::add_edge(&entity, scaling_factor, &mut self.poseidon_int);
    }
}
