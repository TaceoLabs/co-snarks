use crate::types::{ShiftedWitnessEntities, WitnessEntities};
use co_builder::prelude::PrecomputedEntities;

pub type WitnessEntitiesBatch<T> = WitnessEntities<Vec<T>>;
pub type PrecomputedEntitiesBatch<T> = PrecomputedEntities<Vec<T>>;
pub type ShiftedWitnessEntitiesBatch<T> = ShiftedWitnessEntities<Vec<T>>;

impl<T: Default> WitnessEntitiesBatch<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elements: std::array::from_fn(|_| Vec::with_capacity(capacity)),
        }
    }

    pub fn add(&mut self, witness_entity: WitnessEntities<T>) {
        for (src, dst) in witness_entity.into_iter().zip(self.iter_mut()) {
            dst.push(src);
        }
    }
}

impl<T: Default> ShiftedWitnessEntitiesBatch<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elements: std::array::from_fn(|_| Vec::with_capacity(capacity)),
        }
    }

    pub fn add(&mut self, shifted_witness_entities: ShiftedWitnessEntities<T>) {
        for (src, dst) in shifted_witness_entities.into_iter().zip(self.iter_mut()) {
            dst.push(src);
        }
    }
}
