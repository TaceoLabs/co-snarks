#![warn(missing_docs)]
//! This crate collects all functionality that is shared between the SNARKs supported by co-circom. At the moment
//! this is [Groth16](https://eprint.iacr.org/2016/260.pdf) and [PLONK](https://eprint.iacr.org/2019/953.pdf).

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circom_types::Witness;
use mpc_core::protocols::{
    rep3::{self, Rep3PrimeFieldShare, Rep3ShareVecType},
    shamir::{self, ShamirPrimeFieldShare},
};
use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod serde_compat;

/// This type represents the serialized version of a Rep3 witness. Its share can be either additive or replicated, and in both cases also compressed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SerializeableSharedRep3Witness<F: PrimeField, U: Rng + SeedableRng + CryptoRng>
where
    U::Seed: Serialize + for<'a> Deserialize<'a> + Clone + std::fmt::Debug,
{
    /// The public inputs (which are the outputs of the circom circuit).
    /// This also includes the constant 1 at position 0.
    #[serde(
        serialize_with = "crate::serde_compat::ark_se",
        deserialize_with = "crate::serde_compat::ark_de"
    )]
    pub public_inputs: Vec<F>,
    /// The secret-shared witness elements.
    pub witness: Rep3ShareVecType<F, U>,
}

impl<F: PrimeField, U: Rng + SeedableRng + CryptoRng> SerializeableSharedRep3Witness<F, U>
where
    U::Seed: Serialize + for<'a> Deserialize<'a> + Clone + std::fmt::Debug,
{
    /// Transforms a shared witness into a serializable version.
    pub fn from_shared_witness(inp: SharedWitness<F, Rep3PrimeFieldShare<F>>) -> Self {
        Self {
            public_inputs: inp.public_inputs,
            witness: Rep3ShareVecType::Replicated(inp.witness),
        }
    }
}

//TODO THE SECRETSHARED TRAIT IS REALLY BAD. WE DO WANT SOMETHING ELSE!
/// A shared witness in the circom ecosystem.
#[derive(Debug, Serialize, Deserialize)]
pub struct SharedWitness<F: PrimeField, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    #[serde(
        serialize_with = "crate::serde_compat::ark_se",
        deserialize_with = "crate::serde_compat::ark_de"
    )]
    /// The public inputs (which are the outputs of the circom circuit).
    /// This also includes the constant 1 at position 0.
    pub public_inputs: Vec<F>,
    #[serde(
        serialize_with = "crate::serde_compat::ark_se",
        deserialize_with = "crate::serde_compat::ark_de"
    )]
    /// The secret-shared witness elements.
    pub witness: Vec<S>,
}

/// This type represents the serialized version of a Rep3 witness. Its share can be either additive or replicated, and in both cases also compressed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SerializeableSharedRep3Input<F: PrimeField, U: Rng + SeedableRng + CryptoRng>
where
    U::Seed: Serialize + for<'a> Deserialize<'a> + Clone + std::fmt::Debug,
{
    #[serde(
        serialize_with = "crate::serde_compat::ark_se",
        deserialize_with = "crate::serde_compat::ark_de"
    )]
    /// A map from variable names to the public field elements.
    /// This is a BTreeMap because it implements Canonical(De)Serialize.
    pub public_inputs: BTreeMap<String, Vec<F>>,
    /// A map from variable names to the share of the field element.
    /// This is a BTreeMap because it implements Canonical(De)Serialize.
    pub shared_inputs: BTreeMap<String, Rep3ShareVecType<F, U>>,
}

impl<F: PrimeField, U: Rng + SeedableRng + CryptoRng> Default for SerializeableSharedRep3Input<F, U>
where
    U::Seed: Serialize + for<'a> Deserialize<'a> + Clone + std::fmt::Debug,
{
    fn default() -> Self {
        Self {
            public_inputs: BTreeMap::new(),
            shared_inputs: BTreeMap::new(),
        }
    }
}

impl<F: PrimeField, U: Rng + SeedableRng + CryptoRng> SerializeableSharedRep3Input<F, U>
where
    U::Seed: Serialize + for<'a> Deserialize<'a> + Clone + std::fmt::Debug,
    Standard: Distribution<U::Seed>,
{
    /// Shares a given input into a [Rep3ShareVecType] type.
    pub fn share_rep3<R: Rng + CryptoRng>(
        input: &[F],
        rng: &mut R,
        seeded: bool,
        additive: bool,
    ) -> [Rep3ShareVecType<F, U>; 3] {
        let (share1, share2, share3) = match (seeded, additive) {
            (true, true) => {
                let [share1, share2, share3] =
                    rep3::share_field_elements_additive_seeded::<_, _, U>(input, rng);
                let share1 = Rep3ShareVecType::SeededAdditive(share1);
                let share2 = Rep3ShareVecType::SeededAdditive(share2);
                let share3 = Rep3ShareVecType::SeededAdditive(share3);
                (share1, share2, share3)
            }
            (true, false) => {
                let [share1, share2, share3] =
                    rep3::share_field_elements_seeded::<_, _, U>(input, rng);
                let share1 = Rep3ShareVecType::SeededReplicated(share1);
                let share2 = Rep3ShareVecType::SeededReplicated(share2);
                let share3 = Rep3ShareVecType::SeededReplicated(share3);
                (share1, share2, share3)
            }
            (false, true) => {
                let [share1, share2, share3] = rep3::share_field_elements_additive(input, rng);
                let share1 = Rep3ShareVecType::Additive(share1);
                let share2 = Rep3ShareVecType::Additive(share2);
                let share3 = Rep3ShareVecType::Additive(share3);
                (share1, share2, share3)
            }
            (false, false) => {
                let [share1, share2, share3] = rep3::share_field_elements(input, rng);
                let share1 = Rep3ShareVecType::Replicated(share1);
                let share2 = Rep3ShareVecType::Replicated(share2);
                let share3 = Rep3ShareVecType::Replicated(share3);
                (share1, share2, share3)
            }
        };
        [share1, share2, share3]
    }

    /// Merges two [SerializeableSharedRep3Input]s into one, performing basic sanity checks.
    pub fn merge(self, other: Self) -> eyre::Result<Self> {
        let mut shared_inputs = self.shared_inputs;
        let public_inputs = self.public_inputs;
        for (key, value) in other.shared_inputs {
            if shared_inputs.contains_key(&key) {
                eyre::bail!("Input with name {} present in multiple input shares", key);
            }
            if public_inputs.contains_key(&key) || other.public_inputs.contains_key(&key) {
                eyre::bail!(
                    "Input name is once in shared inputs and once in public inputs: \"{key}\""
                );
            }
            shared_inputs.insert(key, value);
        }
        for (key, value) in other.public_inputs {
            if !public_inputs.contains_key(&key) {
                eyre::bail!("Public input \"{key}\" must be present in all files");
            }
            if public_inputs.get(&key).expect("is there we checked") != &value {
                eyre::bail!("Public input \"{key}\" must be same in all files");
            }
        }

        Ok(Self {
            shared_inputs,
            public_inputs,
        })
    }
}

/// A shared input for a collaborative circom witness extension.
#[derive(Debug, Serialize, Deserialize)]
pub struct SharedInput<F: PrimeField, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    #[serde(
        serialize_with = "crate::serde_compat::ark_se",
        deserialize_with = "crate::serde_compat::ark_de"
    )]
    /// A map from variable names to the public field elements.
    /// This is a BTreeMap because it implements Canonical(De)Serialize.
    pub public_inputs: BTreeMap<String, Vec<F>>,
    #[serde(
        serialize_with = "crate::serde_compat::ark_se",
        deserialize_with = "crate::serde_compat::ark_de"
    )]
    /// A map from variable names to the share of the field element.
    /// This is a BTreeMap because it implements Canonical(De)Serialize.
    pub shared_inputs: BTreeMap<String, Vec<S>>,
}

/// We manually implement Clone here since it was not derived correctly and it added bounds on T, P which are not needed
impl<F: PrimeField, S> Clone for SharedWitness<F, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    fn clone(&self) -> Self {
        Self {
            public_inputs: self.public_inputs.clone(),
            witness: self.witness.clone(),
        }
    }
}

/// We manually implement Clone here since it was not derived correctly and it added bounds on T, P which are not needed
impl<F: PrimeField, S> Clone for SharedInput<F, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    fn clone(&self) -> Self {
        Self {
            public_inputs: self.public_inputs.clone(),
            shared_inputs: self.shared_inputs.clone(),
        }
    }
}

impl<F: PrimeField, S> Default for SharedInput<F, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    fn default() -> Self {
        Self {
            public_inputs: BTreeMap::new(),
            shared_inputs: BTreeMap::new(),
        }
    }
}

impl<F: PrimeField, S> SharedInput<F, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    /// Adds a public input with a given name to the [SharedInput].
    pub fn add_public_input(&mut self, key: String, elements: Vec<F>) {
        self.public_inputs.insert(key, elements);
    }

    /// Adds a shared input with a given name to the [SharedInput].
    pub fn add_shared_input(&mut self, key: String, elements: Vec<S>) {
        self.shared_inputs.insert(key, elements);
    }

    /// Merges two [SharedInput]s into one, performing basic sanity checks.
    pub fn merge(self, other: Self) -> eyre::Result<Self> {
        let mut shared_inputs = self.shared_inputs;
        let public_inputs = self.public_inputs;
        for (key, value) in other.shared_inputs {
            if shared_inputs.contains_key(&key) {
                eyre::bail!("Input with name {} present in multiple input shares", key);
            }
            if public_inputs.contains_key(&key) || other.public_inputs.contains_key(&key) {
                eyre::bail!(
                    "Input name is once in shared inputs and once in public inputs: \"{key}\""
                );
            }
            shared_inputs.insert(key, value);
        }
        for (key, value) in other.public_inputs {
            if !public_inputs.contains_key(&key) {
                eyre::bail!("Public input \"{key}\" must be present in all files");
            }
            if public_inputs.get(&key).expect("is there we checked") != &value {
                eyre::bail!("Public input \"{key}\" must be same in all files");
            }
        }

        Ok(Self {
            shared_inputs,
            public_inputs,
        })
    }
}

impl<F: PrimeField, U: Rng + SeedableRng + CryptoRng> SerializeableSharedRep3Witness<F, U>
where
    U::Seed: Serialize + for<'a> Deserialize<'a> + Clone + std::fmt::Debug,

    Standard: Distribution<U::Seed>,
{
    /// Shares a given witness and public input vector using the Rep3 protocol.
    pub fn share_rep3<R: Rng + CryptoRng>(
        witness: Witness<F>,
        num_pub_inputs: usize,
        rng: &mut R,
        seeded: bool,
        additive: bool,
    ) -> [Self; 3] {
        let public_inputs = &witness.values[..num_pub_inputs];
        let witness = &witness.values[num_pub_inputs..];

        let [share1, share2, share3] =
            SerializeableSharedRep3Input::share_rep3(witness, rng, seeded, additive);

        let witness1 = Self {
            public_inputs: public_inputs.to_vec(),
            witness: share1,
        };
        let witness2 = Self {
            public_inputs: public_inputs.to_vec(),
            witness: share2,
        };
        let witness3 = Self {
            public_inputs: public_inputs.to_vec(),
            witness: share3,
        };
        [witness1, witness2, witness3]
    }
}

impl<F: PrimeField> SharedWitness<F, Rep3PrimeFieldShare<F>> {
    /// Shares a given witness and public input vector using the rep3 protocol.
    pub fn share_rep3<R: Rng + CryptoRng>(
        witness: Witness<F>,
        num_pub_inputs: usize,
        rng: &mut R,
    ) -> [Self; 3] {
        let public_inputs = &witness.values[..num_pub_inputs];
        let witness = &witness.values[num_pub_inputs..];
        let [share1, share2, share3] = rep3::share_field_elements(witness, rng);
        let witness1 = Self {
            public_inputs: public_inputs.to_vec(),
            witness: share1,
        };
        let witness2 = Self {
            public_inputs: public_inputs.to_vec(),
            witness: share2,
        };
        let witness3 = Self {
            public_inputs: public_inputs.to_vec(),
            witness: share3,
        };
        [witness1, witness2, witness3]
    }
}

impl<F: PrimeField> SharedWitness<F, ShamirPrimeFieldShare<F>> {
    /// Shares a given witness and public input vector using the Shamir protocol.
    pub fn share_shamir<R: Rng + CryptoRng>(
        witness: Witness<F>,
        num_pub_inputs: usize,
        degree: usize,
        num_parties: usize,
        rng: &mut R,
    ) -> Vec<Self> {
        let public_inputs = &witness.values[..num_pub_inputs];
        let witness = &witness.values[num_pub_inputs..];
        let shares = shamir::share_field_elements(witness, degree, num_parties, rng);
        shares
            .into_iter()
            .map(|share| Self {
                public_inputs: public_inputs.to_vec(),
                witness: share,
            })
            .collect()
    }
}

/// Gathers utility methods for proving coSNARKs.
pub mod utils {
    use ark_ff::{FftField, LegendreSymbol, PrimeField};
    use num_traits::ToPrimitive;

    /// Computes the roots of unity over the provided prime field. This method
    /// is equivalent with [circom's implementation](https://github.com/iden3/ffjavascript/blob/337b881579107ab74d5b2094dbe1910e33da4484/src/wasm_field1.js).
    ///
    /// We calculate smallest quadratic non residue q (by checking q^((p-1)/2)=-1 mod p). We also calculate smallest t s.t. p-1=2^s*t, s is the two adicity.
    /// We use g=q^t (this is a 2^s-th root of unity) as (some kind of) generator and compute another domain by repeatedly squaring g, should get to 1 in the s+1-th step.
    /// Then if log2(\text{domain_size}) equals s we take q^2 as root of unity. Else we take the log2(\text{domain_size}) + 1-th element of the domain created above.
    pub fn roots_of_unity<F: PrimeField + FftField>() -> (F, Vec<F>) {
        let mut roots = vec![F::zero(); F::TWO_ADICITY.to_usize().unwrap() + 1];
        let mut q = F::one();
        while q.legendre() != LegendreSymbol::QuadraticNonResidue {
            q += F::one();
        }
        let z = q.pow(F::TRACE);
        roots[0] = z;
        for i in 1..roots.len() {
            roots[i] = roots[i - 1].square();
        }
        roots.reverse();
        (q, roots)
    }
}
