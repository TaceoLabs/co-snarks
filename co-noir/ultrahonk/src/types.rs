use co_noir_common::polynomials::entities::{
    PRECOMPUTED_ENTITIES_SIZE, PrecomputedEntities, SHIFTED_WITNESS_ENTITIES_SIZE,
    ShiftedWitnessEntities, WITNESS_ENTITIES_SIZE, WitnessEntities,
};

#[derive(Default, Debug)]
pub(crate) struct AllEntities<T: Default> {
    pub(crate) witness: WitnessEntities<T>,
    pub(crate) precomputed: PrecomputedEntities<T>,
    pub(crate) shifted_witness: ShiftedWitnessEntities<T>,
}

impl<T: Default> AllEntities<T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed
            .iter()
            .chain(self.witness.iter())
            .chain(self.shifted_witness.iter())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.precomputed
            .iter_mut()
            .chain(self.witness.iter_mut())
            .chain(self.shifted_witness.iter_mut())
    }
}

impl<T: Default + Clone> AllEntities<Vec<T>> {
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }
}
impl<T: Default> IntoIterator for AllEntities<T> {
    type Item = T;
    type IntoIter = std::iter::Chain<
        std::iter::Chain<
            std::array::IntoIter<T, PRECOMPUTED_ENTITIES_SIZE>,
            std::array::IntoIter<T, WITNESS_ENTITIES_SIZE>,
        >,
        std::array::IntoIter<T, SHIFTED_WITNESS_ENTITIES_SIZE>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.precomputed
            .into_iter()
            .chain(self.witness)
            .chain(self.shifted_witness)
    }
}
