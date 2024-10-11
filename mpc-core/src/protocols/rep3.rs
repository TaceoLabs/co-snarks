//! # REP3
//!
//! This module implements the rep3 share and combine operations

pub mod arithmetic;
pub mod binary;
pub mod conversion;
mod detail;
pub mod id;
pub mod lut;
pub mod network;
pub mod pointshare;
pub mod poly;
pub mod rngs;

use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;

use ark_ff::{One, PrimeField};
use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng, SeedableRng};

pub use arithmetic::types::Rep3PrimeFieldShare;
pub use binary::types::Rep3BigUintShare;
pub use pointshare::Rep3PointShare;
use serde::{Deserialize, Serialize};

pub(crate) type IoResult<T> = std::io::Result<T>;

/// A type representing the different states a share can have. Either full replicated share, only an additive share, or both variants in compressed form.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Rep3ShareVecType<F: PrimeField, U>
where
    U: Rng + SeedableRng + CryptoRng,
    U::Seed: Serialize + for<'a> Deserialize<'a> + Clone + std::fmt::Debug,
{
    /// A fully expanded replicated share.
    Replicated(
        #[serde(
            serialize_with = "super::serde_compat::ark_se",
            deserialize_with = "super::serde_compat::ark_de"
        )]
        Vec<Rep3PrimeFieldShare<F>>,
    ),
    /// A compressed replicated share.
    SeededReplicated(ReplicatedSeedType<Vec<F>, U>),
    /// A fully expanded additive share.
    Additive(
        #[serde(
            serialize_with = "super::serde_compat::ark_se",
            deserialize_with = "super::serde_compat::ark_de"
        )]
        Vec<F>,
    ),
    /// A compressed additive share.
    SeededAdditive(SeededType<Vec<F>, U>),
}

/// A type that represents a compressed additive share. It can either be a seed (with length) or the actual share.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]

pub enum SeededType<
    T: Clone + CanonicalSerialize + CanonicalDeserialize,
    U: Rng + SeedableRng + CryptoRng,
> where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// The actual additive share
    Shares(
        #[serde(
            serialize_with = "super::serde_compat::ark_se",
            deserialize_with = "super::serde_compat::ark_de"
        )]
        T,
    ),
    /// A compressed additive share
    Seed(U::Seed, usize, PhantomData<U>),
}

impl<T: Clone + CanonicalSerialize + CanonicalDeserialize, U: Rng + SeedableRng + CryptoRng> Clone
    for SeededType<T, U>
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    fn clone(&self) -> Self {
        match self {
            SeededType::Shares(val) => SeededType::Shares(val.clone()),
            SeededType::Seed(seed, len, _) => SeededType::Seed(seed.clone(), *len, PhantomData),
        }
    }
}

impl<F: PrimeField, U: Rng + SeedableRng + CryptoRng> SeededType<Vec<F>, U>
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// Expands the compressed share.
    pub fn expand_vec(self) -> Vec<F> {
        match self {
            SeededType::Shares(val) => val,
            SeededType::Seed(seed, len, _) => {
                let mut rng = U::from_seed(seed);
                let mut shares = Vec::with_capacity(len);
                for _ in 0..len {
                    shares.push(F::rand(&mut rng));
                }
                shares
            }
        }
    }

    /// Returns the length of the share
    pub fn length(&self) -> usize {
        match self {
            SeededType::Shares(val) => val.len(),
            SeededType::Seed(_, len, _) => *len,
        }
    }
}

impl<F: PrimeField, U: Rng + SeedableRng + CryptoRng> SeededType<F, U>
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// Expands the compressed share.
    pub fn expand(self) -> F {
        match self {
            SeededType::Shares(val) => val,
            SeededType::Seed(seed, len, _) => {
                assert_eq!(len, 1);
                let mut rng = U::from_seed(seed);
                F::rand(&mut rng)
            }
        }
    }
}

/// A type that represents a compressed replicated share. It consists of two compressed additive shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ReplicatedSeedType<
    T: Clone + CanonicalSerialize + CanonicalDeserialize,
    U: Rng + SeedableRng + CryptoRng,
> where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// The first compressed additive share
    pub a: SeededType<T, U>,
    /// The second compressed additive share
    pub b: SeededType<T, U>,
}

impl<F: PrimeField, U: Rng + SeedableRng + CryptoRng> ReplicatedSeedType<F, U>
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// Expands the compressed share.
    pub fn expand(self) -> Rep3PrimeFieldShare<F> {
        let a = self.a.expand();
        let b = self.b.expand();
        Rep3PrimeFieldShare::new(a, b)
    }
}

impl<F: PrimeField, U: Rng + SeedableRng + CryptoRng> ReplicatedSeedType<Vec<F>, U>
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// Expands the compressed share.
    pub fn expand_vec(self) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
        let a = self.a.expand_vec();
        let b = self.b.expand_vec();
        if a.len() != b.len() {
            return Err(eyre::eyre!("Lengths of shares do not match"));
        }
        Ok(a.into_iter()
            .zip(b)
            .map(|(a, b)| Rep3PrimeFieldShare::new(a, b))
            .collect())
    }

    /// Returns the length of the share
    pub fn length(&self) -> eyre::Result<usize> {
        let a = self.a.length();
        let b = self.b.length();
        if a != b {
            return Err(eyre::eyre!("Lengths of shares do not match"));
        }
        Ok(a)
    }
}

/// Secret shares a field element using replicated secret sharing and the provided random number generator. The field element is split into three additive shares, where each party holds two. The outputs are of type [Rep3PrimeFieldShare].
pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
    val: F,
    rng: &mut R,
) -> [Rep3PrimeFieldShare<F>; 3] {
    let a = F::rand(rng);
    let b = F::rand(rng);
    let c = val - a - b;
    let share1 = Rep3PrimeFieldShare::new(a, c);
    let share2 = Rep3PrimeFieldShare::new(b, a);
    let share3 = Rep3PrimeFieldShare::new(c, b);
    [share1, share2, share3]
}

/// Secret shares a field element using additive secret sharing and the provided random number generator. The field element is split into three additive shares. The outputs are of type [F].
pub fn share_field_element_additive<F: PrimeField, R: Rng + CryptoRng>(
    val: F,
    rng: &mut R,
) -> [F; 3] {
    let a = F::rand(rng);
    let b = F::rand(rng);
    let c = val - a - b;
    [a, b, c]
}

/// Secret shares a field element using replicated secret sharing, whereas only one additive share is stored while the others are compressed as seeds derived form the provided random number generator. The outputs are of type [Rep3ShareType].
pub fn share_field_element_seeded<
    F: PrimeField,
    R: Rng + CryptoRng,
    U: Rng + SeedableRng + CryptoRng,
>(
    val: F,
    rng: &mut R,
) -> [ReplicatedSeedType<F, U>; 3]
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Standard: Distribution<U::Seed>,
{
    let seed_b = rng.gen::<U::Seed>();
    let seed_c = rng.gen::<U::Seed>();

    let mut rng_b = U::from_seed(seed_b.to_owned());
    let mut rng_c = U::from_seed(seed_c.to_owned());

    let b = F::rand(&mut rng_b);
    let c = F::rand(&mut rng_c);
    let a = val - b - c;

    let a = SeededType::Shares(a);
    let b = SeededType::Seed(seed_b, 1, PhantomData);
    let c = SeededType::Seed(seed_c, 1, PhantomData);

    let share1 = ReplicatedSeedType {
        a: a.to_owned(),
        b: c.to_owned(),
    };
    let share2 = ReplicatedSeedType {
        a: b.to_owned(),
        b: a,
    };
    let share3 = ReplicatedSeedType { a: c, b };
    [share1, share2, share3]
}

/// Secret shares a field element using additive secret sharing, whereas only one additive share is stored while the others are compressed as seeds derived form the provided random number generator. The outputs are of type [SeededType].
pub fn share_field_element_additive_seeded<
    F: PrimeField,
    R: Rng + CryptoRng,
    U: Rng + SeedableRng + CryptoRng,
>(
    val: F,
    rng: &mut R,
) -> [SeededType<F, U>; 3]
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Standard: Distribution<U::Seed>,
{
    let seed_b = rng.gen::<U::Seed>();
    let seed_c = rng.gen::<U::Seed>();

    let mut rng_b = U::from_seed(seed_b.to_owned());
    let mut rng_c = U::from_seed(seed_c.to_owned());

    let b = F::rand(&mut rng_b);
    let c = F::rand(&mut rng_c);
    let a = val - b - c;

    let a = SeededType::Shares(a);
    let b = SeededType::Seed(seed_b, 1, PhantomData);
    let c = SeededType::Seed(seed_c, 1, PhantomData);

    [a, b, c]
}

/// Secret shares a vector of field element using replicated secret sharing and the provided random number generator. The field elements are split into three additive shares each, where each party holds two. The outputs are of type [Rep3PrimeFieldShareVec].
pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
    vals: &[F],
    rng: &mut R,
) -> [Vec<Rep3PrimeFieldShare<F>>; 3] {
    let mut shares1 = Vec::with_capacity(vals.len());
    let mut shares2 = Vec::with_capacity(vals.len());
    let mut shares3 = Vec::with_capacity(vals.len());
    for val in vals {
        let [share1, share2, share3] = share_field_element(*val, rng);
        shares1.push(share1);
        shares2.push(share2);
        shares3.push(share3);
    }
    [shares1, shares2, shares3]
}

/// Secret shares a vector of field element using additive secret sharing and the provided random number generator. The field elements are split into three additive shares each. The outputs are of type [Rep3PrimeFieldShareVec].
pub fn share_field_elements_additive<F: PrimeField, R: Rng + CryptoRng>(
    vals: &[F],
    rng: &mut R,
) -> [Vec<F>; 3] {
    let mut shares1 = Vec::with_capacity(vals.len());
    let mut shares2 = Vec::with_capacity(vals.len());
    let mut shares3 = Vec::with_capacity(vals.len());
    for val in vals {
        let [share1, share2, share3] = share_field_element_additive(*val, rng);
        shares1.push(share1);
        shares2.push(share2);
        shares3.push(share3);
    }
    [shares1, shares2, shares3]
}

/// Secret shares a vector of field element using replicated secret sharing, whereas only one additive share is stored while the others are compressed as seeds derived form the provided random number generator. The outputs are of type [ReplicatedSeedType].
pub fn share_field_elements_seeded<
    F: PrimeField,
    R: Rng + CryptoRng,
    U: Rng + SeedableRng + CryptoRng,
>(
    vals: &[F],
    rng: &mut R,
) -> [ReplicatedSeedType<Vec<F>, U>; 3]
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Standard: Distribution<U::Seed>,
{
    let len = vals.len();
    let seed_b = rng.gen::<U::Seed>();
    let seed_c = rng.gen::<U::Seed>();

    let mut rng_b = U::from_seed(seed_b.to_owned());
    let mut rng_c = U::from_seed(seed_c.to_owned());

    let b = SeededType::Seed(seed_b, len, PhantomData);
    let c = SeededType::Seed(seed_c, len, PhantomData);

    let mut a = Vec::with_capacity(vals.len());
    for val in vals {
        let b_ = F::rand(&mut rng_b);
        let c_ = F::rand(&mut rng_c);
        let a_ = *val - b_ - c_;
        a.push(a_);
    }

    let a = SeededType::Shares(a);

    let share1 = ReplicatedSeedType {
        a: a.to_owned(),
        b: c.to_owned(),
    };
    let share2 = ReplicatedSeedType {
        a: b.to_owned(),
        b: a,
    };
    let share3 = ReplicatedSeedType { a: c, b };
    [share1, share2, share3]
}

/// Secret shares a vector of field element using additive secret sharing, whereas only one additive share is stored while the others are compressed as seeds derived form the provided random number generator. The outputs are of type [SeededType].
pub fn share_field_elements_additive_seeded<
    F: PrimeField,
    R: Rng + CryptoRng,
    U: Rng + SeedableRng + CryptoRng,
>(
    vals: &[F],
    rng: &mut R,
) -> [SeededType<Vec<F>, U>; 3]
where
    U::Seed: std::fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Standard: Distribution<U::Seed>,
{
    let len = vals.len();
    let seed_b = rng.gen::<U::Seed>();
    let seed_c = rng.gen::<U::Seed>();

    let mut rng_b = U::from_seed(seed_b.to_owned());
    let mut rng_c = U::from_seed(seed_c.to_owned());

    let b = SeededType::Seed(seed_b, len, PhantomData);
    let c = SeededType::Seed(seed_c, len, PhantomData);

    let mut a = Vec::with_capacity(vals.len());
    for val in vals {
        let b_ = F::rand(&mut rng_b);
        let c_ = F::rand(&mut rng_c);
        let a_ = *val - b_ - c_;
        a.push(a_);
    }

    let a = SeededType::Shares(a);

    [a, b, c]
}

/// Secret shares a field element using replicated secret sharing and the provided random number generator. The field element is split into three binary shares, where each party holds two. The outputs are of type [Rep3BigUintShare].
pub fn share_biguint<F: PrimeField, R: Rng + CryptoRng>(
    val: F,
    rng: &mut R,
) -> [Rep3BigUintShare<F>; 3] {
    let val: BigUint = val.into();
    let limbsize = F::MODULUS_BIT_SIZE.div_ceil(8);
    let mask = (BigUint::from(1u32) << F::MODULUS_BIT_SIZE) - BigUint::one();
    let a = BigUint::new((0..limbsize).map(|_| rng.gen()).collect()) & &mask;
    let b = BigUint::new((0..limbsize).map(|_| rng.gen()).collect()) & mask;

    let c = val ^ &a ^ &b;
    let share1 = Rep3BigUintShare::new(a.to_owned(), c.to_owned());
    let share2 = Rep3BigUintShare::new(b.to_owned(), a);
    let share3 = Rep3BigUintShare::new(c, b);
    [share1, share2, share3]
}

/// Secret shares a curve point using replicated secret sharing and the provided random number generator. The point is split into three additive shares, where each party holds two. The outputs are of type [Rep3PointShare].
pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
    val: C,
    rng: &mut R,
) -> [Rep3PointShare<C>; 3] {
    let a = C::rand(rng);
    let b = C::rand(rng);
    let c = val - a - b;
    let share1 = Rep3PointShare::new(a, c);
    let share2 = Rep3PointShare::new(b, a);
    let share3 = Rep3PointShare::new(c, b);
    [share1, share2, share3]
}

//TODO RENAME ME TO COMBINE_ARITHMETIC_SHARE
/// Reconstructs a field element from its arithmetic replicated shares.
pub fn combine_field_element<F: PrimeField>(
    share1: Rep3PrimeFieldShare<F>,
    share2: Rep3PrimeFieldShare<F>,
    share3: Rep3PrimeFieldShare<F>,
) -> F {
    share1.a + share2.a + share3.a
}

/// Reconstructs a vector of field elements from its arithmetic replicated shares.
/// # Panics
/// Panics if the provided `Vec` sizes do not match.
pub fn combine_field_elements<F: PrimeField>(
    share1: Vec<Rep3PrimeFieldShare<F>>,
    share2: Vec<Rep3PrimeFieldShare<F>>,
    share3: Vec<Rep3PrimeFieldShare<F>>,
) -> Vec<F> {
    assert_eq!(share1.len(), share2.len());
    assert_eq!(share2.len(), share3.len());

    itertools::multizip((share1.into_iter(), share2.into_iter(), share3.into_iter()))
        .map(|(x1, x2, x3)| x1.a + x2.a + x3.a)
        .collect::<Vec<_>>()
}

/// Reconstructs a value (represented as [BigUint]) from its binary replicated shares. Since binary operations can lead to results >= p, the result is not guaranteed to be a valid field element.
pub fn combine_binary_element<F: PrimeField>(
    share1: Rep3BigUintShare<F>,
    share2: Rep3BigUintShare<F>,
    share3: Rep3BigUintShare<F>,
) -> BigUint {
    share1.a ^ share2.a ^ share3.a
}

/// Reconstructs a curve point from its arithmetic replicated shares.
pub fn combine_curve_point<C: CurveGroup>(
    share1: Rep3PointShare<C>,
    share2: Rep3PointShare<C>,
    share3: Rep3PointShare<C>,
) -> C {
    share1.a + share2.a + share3.a
}
