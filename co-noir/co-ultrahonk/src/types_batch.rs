use ark_ec::pairing::Pairing;
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

pub(crate) struct AllEntitiesBatch<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    pub(crate) witness: WitnessEntitiesBatch<T::ArithmeticShare>,
    pub(crate) precomputed: PrecomputedEntitiesBatch<P::ScalarField>,
    pub(crate) shifted_witness: ShiftedWitnessEntitiesBatch<T::ArithmeticShare>,
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

    pub fn fold(mut self, entity: AllEntities<Shared<T, P>, Public<P>>) -> Self {
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

        self
    }
}
