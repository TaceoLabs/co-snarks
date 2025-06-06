use crate::mpc::NoirUltraHonkProver;
use crate::mpc_prover_flavour::MPCProverFlavour;
use ark_ec::pairing::Pairing;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::Polynomial;
use co_builder::prover_flavour::Flavour;
use co_builder::prover_flavour::ProverFlavour;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};

// This is what we get from the proving key, we shift at a later point
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

    pub(crate) fn into_shared_iter(self) -> impl Iterator<Item = Shared> {
        self.witness
            .into_iter()
            .chain(self.shifted_witness.into_iter())
    }

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

pub(crate) fn ark_se_polynomials<T, P, L, S>(
    polys: &Polynomials<T::ArithmeticShare, P::ScalarField, L>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
    L: MPCProverFlavour,
    S: serde::Serializer,
{
    // Serialize the polynomials using the provided serializer
    let mut seq = s.serialize_seq(Some(
        L::PROVER_WITNESS_ENTITIES_SIZE + L::PRECOMPUTED_ENTITIES_SIZE,
    ))?;
    for poly in polys.witness.iter() {
        seq.serialize_element(&poly)?;
    }
    for poly in polys.precomputed.iter() {
        seq.serialize_element(&poly)?;
    }
    seq.end()
}

pub(crate) fn ark_de_polynomials<'de, T, P, L, D>(
    deserializer: D,
) -> Result<Polynomials<T::ArithmeticShare, P::ScalarField, L>, D::Error>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
    L: MPCProverFlavour,
    D: serde::de::Deserializer<'de>,
{
    struct PolyVisitor<T, P, L>
    where
        T: NoirUltraHonkProver<P>,
        P: Pairing,
        L: MPCProverFlavour,
    {
        _marker: std::marker::PhantomData<(T, P, L)>,
    }

    impl<'de, T, P, L> Visitor<'de> for PolyVisitor<T, P, L>
    where
        T: NoirUltraHonkProver<P>,
        P: Pairing,
        L: MPCProverFlavour,
    {
        type Value = Polynomials<T::ArithmeticShare, P::ScalarField, L>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a sequence of witness and precomputed polynomials")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if L::FLAVOUR != Flavour::Ultra && L::FLAVOUR != Flavour::Mega {
                return Err(serde::de::Error::custom(
                    "ProvingKey deserialization only supported for Ultra and Mega flavour",
                ));
            }
            let mut witness_polys = Vec::with_capacity(L::PROVER_WITNESS_ENTITIES_SIZE);
            let mut precomputed_polys = Vec::with_capacity(L::PRECOMPUTED_ENTITIES_SIZE);

            for _ in 0..L::PROVER_WITNESS_ENTITIES_SIZE {
                let poly: Polynomial<T::ArithmeticShare> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::custom("Expected more witness polynomials"))?;
                witness_polys.push(poly);
            }

            for _ in 0..L::PRECOMPUTED_ENTITIES_SIZE {
                let poly: Polynomial<P::ScalarField> = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::custom("Expected more precomputed polynomials")
                })?;
                precomputed_polys.push(poly);
            }

            Ok(Polynomials {
                witness: L::prover_witness_entity_from_vec(witness_polys),
                precomputed: L::precomputed_entity_from_vec(precomputed_polys),
            })
        }
    }

    deserializer.deserialize_seq(PolyVisitor::<T, P, L> {
        _marker: std::marker::PhantomData,
    })
}
