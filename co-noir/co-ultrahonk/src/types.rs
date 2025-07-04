use crate::mpc_prover_flavour::MPCProverFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::Polynomial;
use co_builder::prover_flavour::ProverFlavour;
use serde::{Deserialize, Serialize};

// This is what we get from the proving key, we shift at a later point
// #[derive(Default, Serialize, Deserialize)]
// #[serde(bound = "")]
// #[derive(Default)]
pub struct Polynomials<
    Shared: Default + Sync,
    Public: Default + Clone + std::marker::Sync,
    L: ProverFlavour,
> where
    Polynomial<Shared>: Serialize + for<'a> Deserialize<'a>,
    Polynomial<Public>: Serialize + for<'a> Deserialize<'a>,
{
    pub witness: L::ProverWitnessEntities<Polynomial<Shared>>,
    pub precomputed: L::PrecomputedEntities<Polynomial<Public>>,
}

impl<Shared: Default + Sync, Public: Default + Clone + std::marker::Sync, L: MPCProverFlavour>
    Default for Polynomials<Shared, Public, L>
where
    Polynomial<Shared>: Serialize + for<'a> Deserialize<'a>,
    Polynomial<Public>: Serialize + for<'a> Deserialize<'a>,
{
    fn default() -> Self {
        Self {
            witness: L::ProverWitnessEntities::default(),
            precomputed: L::PrecomputedEntities::default(),
        }
    }
}

impl<
    Shared: Clone + Default + Sync,
    Public: Clone + Default + std::marker::Sync,
    L: MPCProverFlavour,
> Polynomials<Shared, Public, L>
where
    Polynomial<Shared>: Serialize + for<'a> Deserialize<'a>,
    Polynomial<Public>: Serialize + for<'a> Deserialize<'a>,
{
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .witness
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));
        polynomials.precomputed.iter_mut().for_each(|el| {
            el.resize(circuit_size, Default::default());
        });

        polynomials
    }
}

#[derive(Default, Clone)]
pub(crate) struct AllEntities<
    Shared: Default + std::marker::Sync,
    Public: Default + Clone + std::marker::Sync,
    L: MPCProverFlavour,
> {
    pub(crate) witness: L::WitnessEntities<Shared>,
    pub(crate) precomputed: L::PrecomputedEntities<Public>,
    pub(crate) shifted_witness: L::ShiftedWitnessEntities<Shared>,
}

impl<
    Shared: Default + std::marker::Sync,
    Public: Default + Clone + std::marker::Sync,
    L: MPCProverFlavour,
> AllEntities<Shared, Public, L>
{
    pub(crate) fn public_iter(&self) -> impl Iterator<Item = &Public> {
        self.precomputed.iter()
    }

    pub(crate) fn shared_iter(&self) -> impl Iterator<Item = &Shared> {
        self.witness.iter().chain(self.shifted_witness.iter())
    }

    //This is not needed I think
    // pub(crate) fn into_shared_iter(self) -> impl Iterator<Item = Shared> {
    //     self.witness.into_iter().chain(self.shifted_witness)
    // }

    pub(crate) fn public_iter_mut(&mut self) -> impl Iterator<Item = &mut Public> {
        self.precomputed.iter_mut()
    }

    pub(crate) fn shared_iter_mut(&mut self) -> impl Iterator<Item = &mut Shared> {
        self.witness
            .iter_mut()
            .chain(self.shifted_witness.iter_mut())
    }
}

impl<
    Shared: Default + Clone + std::marker::Sync,
    Public: Default + Clone + std::marker::Sync,
    L: MPCProverFlavour,
> AllEntities<Vec<Shared>, Vec<Public>, L>
{
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

impl<T: Default + Clone + std::marker::Sync, L: MPCProverFlavour> AllEntities<T, T, L> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed
            .iter()
            .chain(self.witness.iter())
            .chain(self.shifted_witness.iter())
    }
}
