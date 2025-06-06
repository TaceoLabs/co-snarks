use super::polynomial::Polynomial;
use crate::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use crate::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use crate::prover_flavour::ProverFlavour;
use ark_ff::PrimeField;
// use serde::{Deserialize, Serialize};

// This is what we get from the proving key, we shift at a later point
#[derive(Default)]
pub struct Polynomials<F: PrimeField, L: ProverFlavour> {
    pub witness: L::ProverWitnessEntities<Polynomial<F>>,
    pub precomputed: L::PrecomputedEntities<Polynomial<F>>,
}

impl<F: PrimeField, L: ProverFlavour> Polynomials<F, L> {
    pub fn new(circuit_size: usize) -> Self {
        let mut polynomials = Self::default();
        // Shifting is done at a later point
        polynomials
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));

        polynomials
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Polynomial<F>> {
        self.witness.iter_mut().chain(self.precomputed.iter_mut())
    }
}

pub struct ProverWitnessEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}

#[derive(Clone)]
pub struct PrecomputedEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}

pub struct WitnessEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}
pub struct ShiftedWitnessEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}

impl<T: Default, const SIZE: usize> Default for ProverWitnessEntities<T, SIZE> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}
impl<T: Default, const SIZE: usize> Default for PrecomputedEntities<T, SIZE> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}
impl<T: Default, const SIZE: usize> Default for WitnessEntities<T, SIZE> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}
impl<T: Default, const SIZE: usize> Default for ShiftedWitnessEntities<T, SIZE> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}

impl<T: Default, const SIZE: usize> PrecomputedEntities<T, SIZE> {}
