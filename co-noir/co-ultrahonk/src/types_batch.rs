use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use itertools::izip;
use ultrahonk::prelude::{
    PrecomputedEntitiesBatch, ShiftedWitnessEntitiesBatch, Univariate, WitnessEntitiesBatch,
};

use crate::{
    co_decider::{types::MAX_PARTIAL_RELATION_LENGTH, univariates::SharedUnivariate},
    mpc::NoirUltraHonkProver,
    types::AllEntities,
};

type Shared<T, P> = SharedUnivariate<T, P, MAX_PARTIAL_RELATION_LENGTH>;
type Public<P> = Univariate<<P as Pairing>::ScalarField, MAX_PARTIAL_RELATION_LENGTH>;

#[derive(Default)]
pub(crate) struct AllEntitiesBatch<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    pub(crate) witness: WitnessEntitiesBatch<T::ArithmeticShare>,
    pub(crate) precomputed: PrecomputedEntitiesBatch<P::ScalarField>,
    pub(crate) shifted_witness: ShiftedWitnessEntitiesBatch<T::ArithmeticShare>,
}

#[derive(Default)]
pub(crate) struct SumCheckDataForRelation<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    pub(crate) all_entites: AllEntitiesBatch<T, P>,
    pub(crate) scaling_factors: Vec<P::ScalarField>,
}

#[derive(Default)]
pub(crate) struct AllEntitiesBatchRelations<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    pub(crate) ultra_arith: SumCheckDataForRelation<T, P>,
    pub(crate) delta_range: SumCheckDataForRelation<T, P>,
    pub(crate) elliptic: SumCheckDataForRelation<T, P>,
    pub(crate) auxiliary: SumCheckDataForRelation<T, P>,
    pub(crate) poseidon_ext: SumCheckDataForRelation<T, P>,
    pub(crate) poseidon_int: SumCheckDataForRelation<T, P>,
    // NOT SKIPABLE
    pub(crate) not_skippable: SumCheckDataForRelation<T, P>,
}

impl<T, P> SumCheckDataForRelation<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    // FRANCO TODO nicer new
    fn new() -> Self {
        Self {
            all_entites: AllEntitiesBatch::reserve_round_size(4),
            scaling_factors: vec![],
        }
    }
}

impl<T, P> AllEntitiesBatchRelations<T, P>
where
    P: Pairing,
    T: NoirUltraHonkProver<P>,
{
    pub fn new() -> Self {
        Self {
            ultra_arith: SumCheckDataForRelation::new(),
            delta_range: SumCheckDataForRelation::new(),
            elliptic: SumCheckDataForRelation::new(),
            auxiliary: SumCheckDataForRelation::new(),
            poseidon_ext: SumCheckDataForRelation::new(),
            poseidon_int: SumCheckDataForRelation::new(),
            not_skippable: SumCheckDataForRelation::new(),
        }
    }

    pub fn fold_and_filter(
        &mut self,
        entity: AllEntities<Shared<T, P>, Public<P>>,
        scaling_factor: P::ScalarField,
    ) {
        let scaling_factors = vec![scaling_factor; MAX_PARTIAL_RELATION_LENGTH];
        // check if we can skip arith
        if !entity.precomputed.q_arith().is_zero() {
            self.ultra_arith.all_entites.add(entity.clone());
            self.ultra_arith
                .scaling_factors
                .extend(scaling_factors.clone());
        }

        // check if we can skip delta range
        if !entity.precomputed.q_delta_range().is_zero() {
            self.delta_range.all_entites.add(entity.clone());
            self.delta_range
                .scaling_factors
                .extend(scaling_factors.clone());
        }

        // check if we can skip elliptic
        if !entity.precomputed.q_elliptic().is_zero() {
            self.elliptic.all_entites.add(entity.clone());
            self.elliptic
                .scaling_factors
                .extend(scaling_factors.clone());
        }

        // check if we can skip aux
        if !entity.precomputed.q_aux().is_zero() {
            self.auxiliary.all_entites.add(entity.clone());
            self.auxiliary
                .scaling_factors
                .extend(scaling_factors.clone());
        }

        // check if we can skip poseidon external
        if !entity.precomputed.q_poseidon2_external().is_zero() {
            self.poseidon_ext.all_entites.add(entity.clone());
            self.poseidon_ext
                .scaling_factors
                .extend(scaling_factors.clone());
        }

        // check if we can skip poseidon internal
        if !entity.precomputed.q_poseidon2_internal().is_zero() {
            self.poseidon_int.all_entites.add(entity.clone());
            self.poseidon_int
                .scaling_factors
                .extend(scaling_factors.clone());
        }

        // NOT SKIPABLE LogDeriveLookupRelation
        // NOT SKIPPABLE UltraPermutationRelation
        self.not_skippable.all_entites.add(entity);
        self.not_skippable.scaling_factors.extend(scaling_factors);
    }
}

impl<T, P> AllEntitiesBatch<T, P>
where
    P: Pairing,
    T: NoirUltraHonkProver<P>,
{
    pub fn reserve_round_size(round_size: usize) -> Self {
        let round_size = round_size / 2;
        let witness = WitnessEntitiesBatch::<T::ArithmeticShare>::with_capacity(round_size);
        let precomputed = PrecomputedEntitiesBatch::<P::ScalarField>::with_capacity(round_size);
        let shifted_witness =
            ShiftedWitnessEntitiesBatch::<T::ArithmeticShare>::with_capacity(round_size);
        Self {
            witness,
            precomputed,
            shifted_witness,
        }
    }

    pub fn add(&mut self, entity: AllEntities<Shared<T, P>, Public<P>>) {
        for (src, des) in izip!(entity.witness.into_iter(), self.witness.iter_mut()) {
            des.extend(src.evaluations);
        }

        for (src, des) in izip!(entity.precomputed.into_iter(), self.precomputed.iter_mut()) {
            des.extend(src.evaluations);
        }

        for (src, des) in izip!(
            entity.shifted_witness.into_iter(),
            self.shifted_witness.iter_mut()
        ) {
            des.extend(src.evaluations);
        }
    }
}
