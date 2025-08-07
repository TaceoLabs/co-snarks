use std::{array, collections::BTreeMap};

use ark_ff::PrimeField;
use mpc_core::protocols::{
    rep3::{self, Rep3PrimeFieldShare},
    shamir::{self, ShamirPrimeFieldShare},
};
use serde::{Deserialize, Serialize};

/// A REP3 shared input type
pub type Rep3SharedInput<F> = BTreeMap<String, Rep3Type<F>>;

/// A REP3 shared witness type
pub type Rep3SharedWitness<F> = Vec<Rep3Type<F>>;

/// A shamir shared witness type
pub type ShamirSharedWitness<F> = Vec<ShamirType<F>>;

#[derive(Clone, Debug)]
pub enum PubPrivate<F> {
    Public(F),
    Private(F),
}

impl<F> PubPrivate<F> {
    pub fn into_inner(self) -> F {
        match self {
            PubPrivate::Public(inner) => inner,
            PubPrivate::Private(inner) => inner,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Rep3Type<F: PrimeField> {
    Public(
        #[serde(
            serialize_with = "mpc_core::serde_compat::ark_se",
            deserialize_with = "mpc_core::serde_compat::ark_de"
        )]
        F,
    ),
    Shared(
        #[serde(
            serialize_with = "mpc_core::serde_compat::ark_se",
            deserialize_with = "mpc_core::serde_compat::ark_de"
        )]
        Rep3PrimeFieldShare<F>,
    ),
}

impl<F: PrimeField> From<F> for Rep3Type<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<Rep3PrimeFieldShare<F>> for Rep3Type<F> {
    fn from(value: Rep3PrimeFieldShare<F>) -> Self {
        Self::Shared(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShamirType<F: PrimeField> {
    Public(
        #[serde(
            serialize_with = "mpc_core::serde_compat::ark_se",
            deserialize_with = "mpc_core::serde_compat::ark_de"
        )]
        F,
    ),
    Shared(
        #[serde(
            serialize_with = "mpc_core::serde_compat::ark_se",
            deserialize_with = "mpc_core::serde_compat::ark_de"
        )]
        ShamirPrimeFieldShare<F>,
    ),
}

impl<F: PrimeField> From<F> for ShamirType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<ShamirPrimeFieldShare<F>> for ShamirType<F> {
    fn from(value: ShamirPrimeFieldShare<F>) -> Self {
        Self::Shared(value)
    }
}

/// Split input into REP3 shares
pub fn split_input_rep3<F: PrimeField>(
    initial_witness: BTreeMap<String, PubPrivate<F>>,
) -> [Rep3SharedInput<F>; 3] {
    let mut rng = rand::thread_rng();
    let mut witnesses = array::from_fn(|_| BTreeMap::default());
    for (witness, v) in initial_witness.into_iter() {
        match v {
            PubPrivate::Public(v) => {
                for w in witnesses.iter_mut() {
                    w.insert(witness.to_owned(), Rep3Type::Public(v));
                }
            }
            PubPrivate::Private(v) => {
                let shares = rep3::share_field_element(v, &mut rng);
                for (w, share) in witnesses.iter_mut().zip(shares) {
                    w.insert(witness.clone(), Rep3Type::Shared(share));
                }
            }
        }
    }

    witnesses
}

/// Split a witness into REP3 shares
pub fn split_witness_rep3<F: PrimeField>(witness: Vec<PubPrivate<F>>) -> [Rep3SharedWitness<F>; 3] {
    let mut rng = rand::thread_rng();
    let mut res = array::from_fn(|_| Vec::with_capacity(witness.len()));

    for witness in witness {
        match witness {
            PubPrivate::Public(f) => {
                for r in res.iter_mut() {
                    r.push(Rep3Type::from(f));
                }
            }
            PubPrivate::Private(f) => {
                let shares = rep3::share_field_element(f, &mut rng);
                for (r, share) in res.iter_mut().zip(shares) {
                    r.push(Rep3Type::from(share));
                }
            }
        }
    }
    res
}

/// Split a witness into shamir shares
pub fn split_witness_shamir<F: PrimeField>(
    witness: Vec<PubPrivate<F>>,
    degree: usize,
    num_parties: usize,
) -> Vec<ShamirSharedWitness<F>> {
    let mut rng = rand::thread_rng();
    let mut res = (0..num_parties)
        .map(|_| Vec::with_capacity(witness.len()))
        .collect::<Vec<_>>();

    for witness in witness {
        match witness {
            PubPrivate::Public(f) => {
                for r in res.iter_mut() {
                    r.push(ShamirType::from(f));
                }
            }
            PubPrivate::Private(f) => {
                let shares = shamir::share_field_element(f, degree, num_parties, &mut rng);
                for (r, share) in res.iter_mut().zip(shares) {
                    r.push(ShamirType::from(share));
                }
            }
        }
    }
    res
}
