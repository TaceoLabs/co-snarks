use crate::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use crate::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use crate::prover_flavour::ProverFlavour;
use ark_ff::PrimeField;
use co_noir_common::polynomials::polynomial::Polynomial;
use serde::Deserializer;
use serde::de;
use serde::de::SeqAccess;
use serde::de::Visitor;
use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::marker::PhantomData;

// This is what we get from the proving key, we shift at a later point
#[derive(Default, Debug)]
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

    pub fn increase_polynomial_size(&mut self, circuit_size: usize) {
        self.witness
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));
        self.precomputed
            .iter_mut()
            .for_each(|el| el.resize(circuit_size, Default::default()));
    }
}
#[derive(Debug)]
pub struct ProverWitnessEntities<T: Default, const SIZE: usize> {
    pub elements: [T; SIZE],
}

#[derive(Clone, Debug)]
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

impl<'de, T, const SIZE: usize> Deserialize<'de> for PrecomputedEntities<T, SIZE>
where
    T: Deserialize<'de> + Default + Clone + Copy,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<T, const SIZE: usize> {
            marker: PhantomData<T>,
        }

        impl<'de, T, const SIZE: usize> Visitor<'de> for ArrayVisitor<T, SIZE>
        where
            T: Deserialize<'de> + Default + Clone + Copy,
        {
            type Value = PrecomputedEntities<T, SIZE>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an array of length {SIZE}")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::with_capacity(SIZE);
                for i in 0..SIZE {
                    match seq.next_element()? {
                        Some(value) => vec.push(value),
                        None => return Err(de::Error::invalid_length(i, &self)),
                    }
                }
                // Ensure there are no extra elements
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(SIZE + 1, &self));
                }
                let elements: [T; SIZE] = vec.try_into().unwrap_or_else(|_| {
                    // This should never panic due to the above checks
                    [T::default(); SIZE]
                });
                Ok(PrecomputedEntities { elements })
            }
        }

        deserializer.deserialize_tuple(
            SIZE,
            ArrayVisitor::<T, SIZE> {
                marker: PhantomData,
            },
        )
    }
}
impl<T, const SIZE: usize> Serialize for PrecomputedEntities<T, SIZE>
where
    T: Serialize + Default + Clone + Copy,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let elements = &self.elements;
        let mut seq = serializer.serialize_tuple(SIZE)?;
        for element in elements.iter() {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

impl<'de, T, const SIZE: usize> Deserialize<'de> for ProverWitnessEntities<T, SIZE>
where
    T: Deserialize<'de> + Default + Clone + Copy,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<T, const SIZE: usize> {
            marker: PhantomData<T>,
        }

        impl<'de, T, const SIZE: usize> Visitor<'de> for ArrayVisitor<T, SIZE>
        where
            T: Deserialize<'de> + Default + Clone + Copy,
        {
            type Value = ProverWitnessEntities<T, SIZE>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an array of length {SIZE}")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::with_capacity(SIZE);
                for i in 0..SIZE {
                    match seq.next_element()? {
                        Some(value) => vec.push(value),
                        None => return Err(de::Error::invalid_length(i, &self)),
                    }
                }
                // Ensure there are no extra elements
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(SIZE + 1, &self));
                }
                let elements: [T; SIZE] = vec.try_into().unwrap_or_else(|_| {
                    // This should never panic due to the above checks
                    [T::default(); SIZE]
                });
                Ok(ProverWitnessEntities { elements })
            }
        }

        deserializer.deserialize_tuple(
            SIZE,
            ArrayVisitor::<T, SIZE> {
                marker: PhantomData,
            },
        )
    }
}
impl<T, const SIZE: usize> Serialize for ProverWitnessEntities<T, SIZE>
where
    T: Serialize + Default + Clone + Copy,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let elements = &self.elements;
        let mut seq = serializer.serialize_tuple(SIZE)?;
        for element in elements.iter() {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}
