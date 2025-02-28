use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use co_builder::prelude::PrecomputedEntities;
use itertools::izip;
use ultrahonk::prelude::{ShiftedWitnessEntities, Univariate, WitnessEntities};

pub(crate) type WitnessEntitiesBatch<T> = WitnessEntities<Vec<T>>;
pub(crate) type PrecomputedEntitiesBatch<T> = PrecomputedEntities<Vec<T>>;
pub(crate) type ShiftedWitnessEntitiesBatch<T> = ShiftedWitnessEntities<Vec<T>>;

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
    pub(crate) can_skip: bool,
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
    fn new() -> Self {
        Self {
            can_skip: true,
            all_entites: AllEntitiesBatch::new(),
            scaling_factors: vec![],
        }
    }

    fn add(
        &mut self,
        entity: &AllEntities<Shared<T, P>, Public<P>>,
        scaling_factor: P::ScalarField,
    ) {
        let scaling_factors = vec![scaling_factor; MAX_PARTIAL_RELATION_LENGTH];
        self.can_skip = false;
        self.all_entites.add(entity.clone());
        self.scaling_factors.extend(scaling_factors);
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
        // FRANCO TODO - for all (?) accumulator we don't need all 7 elements. Can we remove
        // somehow skip those to decrease work even further?
        // e.g. UltraArith only has
        //
        // pub(crate) r0: SharedUnivariate<T, P, 6>,
        // pub(crate) r1: SharedUnivariate<T, P, 5>,
        //
        // Can we somehow only add 5/6 elements?
        // check if we can skip arith
        if !entity.precomputed.q_arith().is_zero() {
            self.ultra_arith.add(&entity, scaling_factor)
        }

        // check if we can skip delta range
        if !entity.precomputed.q_delta_range().is_zero() {
            self.delta_range.add(&entity, scaling_factor)
        }

        // check if we can skip elliptic
        if !entity.precomputed.q_elliptic().is_zero() {
            self.elliptic.add(&entity, scaling_factor)
        }

        // check if we can skip aux
        if !entity.precomputed.q_aux().is_zero() {
            self.auxiliary.add(&entity, scaling_factor)
        }

        // check if we can skip poseidon external
        if !entity.precomputed.q_poseidon2_external().is_zero() {
            self.poseidon_ext.add(&entity, scaling_factor)
        }

        // check if we can skip poseidon internal
        if !entity.precomputed.q_poseidon2_internal().is_zero() {
            self.poseidon_int.add(&entity, scaling_factor)
        }

        // NOT SKIPABLE LogDeriveLookupRelation
        // NOT SKIPPABLE UltraPermutationRelation
        self.not_skippable.add(&entity, scaling_factor);
    }
}

impl<T, P> AllEntitiesBatch<T, P>
where
    P: Pairing,
    T: NoirUltraHonkProver<P>,
{
    pub fn new() -> Self {
        // rather arbitary size of 1024 capacity - we dont want to reserver full round size
        // as this would hit the RAM quite hard, but 1024 should always be fine and smaller
        // circuits won't need to move the vecs in memory around
        let witness = WitnessEntitiesBatch::<T::ArithmeticShare>::with_capacity(1024);
        let precomputed = PrecomputedEntitiesBatch::<P::ScalarField>::with_capacity(1024);
        let shifted_witness =
            ShiftedWitnessEntitiesBatch::<T::ArithmeticShare>::with_capacity(1024);
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
