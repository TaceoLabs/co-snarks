use co_builder::prelude::{Polynomial, PrecomputedEntities, ProverWitnessEntities};
use serde::{Deserialize, Serialize};
use ultrahonk::prelude::{ShiftedTableEntities, ShiftedWitnessEntities, WitnessEntities};

// This is what we get from the proving key, we shift at a later point
#[derive(Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Polynomials<Shared: Default, Public: Default>
where
    Polynomial<Shared>: Serialize + for<'a> Deserialize<'a>,
    Polynomial<Public>: Serialize + for<'a> Deserialize<'a>,
{
    pub witness: ProverWitnessEntities<Polynomial<Shared>>,
    pub precomputed: PrecomputedEntities<Polynomial<Public>>,
}

impl<Shared: Clone + Default, Public: Clone + Default> Polynomials<Shared, Public>
where
    Polynomial<Shared>: Serialize + for<'a> Deserialize<'a>,
    Polynomial<Public>: Serialize + for<'a> Deserialize<'a>,
{
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .witness
            .get_wires_mut()
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));
        polynomials
            .witness
            .lookup_read_counts_and_tags_mut()
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));
        polynomials.precomputed.iter_mut().for_each(|el| {
            el.resize(circuit_size, Default::default());
        });

        polynomials
    }
}

#[derive(Default)]
pub(crate) struct AllEntities<Shared: Default, Public: Default> {
    pub(crate) witness: WitnessEntities<Shared>,
    pub(crate) precomputed: PrecomputedEntities<Public>,
    pub(crate) shifted_witness: ShiftedWitnessEntities<Shared>,
    pub(crate) shifted_tables: ShiftedTableEntities<Public>,
}

impl<Shared: Default, Public: Default> AllEntities<Shared, Public> {
    pub(crate) fn public_iter(&self) -> impl Iterator<Item = &Public> {
        self.precomputed.iter().chain(self.shifted_tables.iter())
    }

    pub(crate) fn shared_iter(&self) -> impl Iterator<Item = &Shared> {
        self.witness.iter().chain(self.shifted_witness.iter())
    }

    pub(crate) fn into_shared_iter(self) -> impl Iterator<Item = Shared> {
        self.witness.into_iter().chain(self.shifted_witness)
    }

    pub(crate) fn public_iter_mut(&mut self) -> impl Iterator<Item = &mut Public> {
        self.precomputed
            .iter_mut()
            .chain(self.shifted_tables.iter_mut())
    }

    pub(crate) fn shared_iter_mut(&mut self) -> impl Iterator<Item = &mut Shared> {
        self.witness
            .iter_mut()
            .chain(self.shifted_witness.iter_mut())
    }
}

impl<Shared: Default + Clone, Public: Default + Clone> AllEntities<Vec<Shared>, Vec<Public>> {
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .shared_iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));
        polynomials
            .public_iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }
}

impl<T: Default> AllEntities<T, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed
            .iter()
            .chain(self.witness.iter())
            .chain(self.shifted_tables.iter())
            .chain(self.shifted_witness.iter())
    }
}
