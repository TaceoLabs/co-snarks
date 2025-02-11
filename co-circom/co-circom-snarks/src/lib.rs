#![warn(missing_docs)]
//! This crate collects all functionality that is shared between the SNARKs supported by co-circom. At the moment
//! this is [Groth16](https://eprint.iacr.org/2016/260.pdf) and [PLONK](https://eprint.iacr.org/2019/953.pdf).

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circom_types::Witness;
use mpc_core::protocols::{
    rep3::{
        self,
        network::{Rep3MpcNet, Rep3Network},
        Rep3PrimeFieldShare, Rep3ShareVecType,
    },
    shamir::{self, ShamirPrimeFieldShare},
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;

/// A REP3 shared input type
pub type Rep3SharedInput<F> = SharedInput<F, Rep3PrimeFieldShare<F>>;

/// A REP3 shared witness type
pub type Rep3SharedWitness<F> = SharedWitness<F, Rep3PrimeFieldShare<F>>;

/// A shamir shared witness type
pub type ShamirSharedWitness<F> = SharedWitness<F, ShamirPrimeFieldShare<F>>;

/// Compression levels for [`CompressedRep3SharedWitness`] shares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Compression {
    #[default]
    /// No compression
    None,
    /// Additive half shares, only half the size but need to be replicated before proof generation.
    HalfShares,
    /// Only share as seeds, need to be expanded before use.
    SeededShares,
    /// Combination of additive and seeded shares
    SeededHalfShares,
}

/// This type represents the serialized version of a Rep3 witness. Its share can be either additive or replicated, and in both cases also compressed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CompressedRep3SharedWitness<F: PrimeField> {
    /// The public inputs (which are the outputs of the circom circuit).
    /// This also includes the constant 1 at position 0.
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub public_inputs: Vec<F>,
    /// The secret-shared witness elements.
    pub witness: Rep3ShareVecType<F>,
}

impl<F: PrimeField> From<Rep3SharedWitness<F>> for CompressedRep3SharedWitness<F> {
    fn from(value: Rep3SharedWitness<F>) -> Self {
        Self {
            public_inputs: value.public_inputs,
            witness: Rep3ShareVecType::Replicated(value.witness),
        }
    }
}

impl<F: PrimeField> From<CompressedRep3SharedWitness<F>> for SharedWitness<F, F> {
    fn from(value: CompressedRep3SharedWitness<F>) -> Self {
        let public_inputs = value.public_inputs;
        let witness = value.witness;
        let witness = match witness {
            Rep3ShareVecType::Replicated(vec) => vec.into_iter().map(|x| x.a).collect::<Vec<_>>(),
            Rep3ShareVecType::SeededReplicated(replicated_seed_type) => {
                replicated_seed_type.a.expand_vec()
            }
            Rep3ShareVecType::Additive(vec) => vec,
            Rep3ShareVecType::SeededAdditive(seeded_type) => seeded_type.expand_vec(),
        };

        SharedWitness {
            public_inputs,
            witness,
        }
    }
}

fn reshare_vec<F: PrimeField>(
    vec: Vec<F>,
    mpc_net: &mut Rep3MpcNet,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let b: Vec<F> = mpc_net.reshare_many(&vec)?;

    if vec.len() != b.len() {
        return Err(eyre::eyre!("reshare_vec: vec and b have different lengths"));
    }

    let shares = vec
        .into_iter()
        .zip(b)
        .map(|(a, b)| Rep3PrimeFieldShare { a, b })
        .collect();

    Ok(shares)
}

impl<F: PrimeField> CompressedRep3SharedWitness<F> {
    /// Uncompress into [`Rep3SharedWitness`].
    pub fn uncompress(self, mpc_net: &mut Rep3MpcNet) -> eyre::Result<Rep3SharedWitness<F>> {
        let public_inputs = self.public_inputs;
        let witness = self.witness;
        let witness = match witness {
            Rep3ShareVecType::Replicated(vec) => vec,
            Rep3ShareVecType::SeededReplicated(replicated_seed_type) => {
                replicated_seed_type.expand_vec()?
            }
            Rep3ShareVecType::Additive(vec) => reshare_vec(vec, mpc_net)?,
            Rep3ShareVecType::SeededAdditive(seeded_type) => {
                reshare_vec(seeded_type.expand_vec(), mpc_net)?
            }
        };

        Ok(SharedWitness {
            public_inputs,
            witness,
        })
    }
}

/// A shared witness in the circom ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedWitness<F: PrimeField, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    /// The public inputs (which are the outputs of the circom circuit).
    /// This also includes the constant 1 at position 0.
    pub public_inputs: Vec<F>,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    /// The secret-shared witness elements.
    pub witness: Vec<S>,
}

impl<F: PrimeField, S> SharedWitness<F, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    /// Get the public inputs needed for verification (does not include constant 1 at position 0)
    pub fn public_inputs_for_verify(&self) -> Vec<F> {
        self.public_inputs[1..].to_vec()
    }
}

/// A shared input for a collaborative circom witness extension.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedInput<F: PrimeField, S>
where
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    /// A map from variable names to the public field elements.
    /// This is a BTreeMap because it implements Canonical(De)Serialize.
    pub public_inputs: BTreeMap<String, Vec<F>>,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    /// A map from variable names to the share of the field element.
    /// This is a BTreeMap because it implements Canonical(De)Serialize.
    pub shared_inputs: BTreeMap<String, Vec<S>>,
    /// A map from variable names to vecs with maybe unknown elements that need to be merged.
    /// This is a BTreeMap because it implements Canonical(De)Serialize.
    pub maybe_shared_inputs: BTreeMap<String, Vec<Option<S>>>,
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
        let maybe_shared_inputs = self.maybe_shared_inputs;

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

        let mut merged_maybe_shared_inputs = BTreeMap::new();
        if maybe_shared_inputs.len() != other.maybe_shared_inputs.len() {
            eyre::bail!("Both inputs must have the same number of unmerged entries");
        }
        for ((k1, v1), (k2, v2)) in maybe_shared_inputs
            .into_iter()
            .zip(other.maybe_shared_inputs.into_iter())
        {
            if k1 != k2 {
                eyre::bail!("Both inputs must have the same keys for unmerged elements");
            }

            let merged = v1
                .into_iter()
                .zip(v2.into_iter())
                .map(|(a, b)| match (a, b) {
                    (None, None) => Ok(None),
                    (a @ Some(_), None) | (None, a @ Some(_)) => Ok(a),
                    _ => Err(eyre::eyre!("Input {} present in both unmerged inputs", k1)),
                })
                .collect::<Result<Vec<_>, eyre::Report>>()?;
            if let Some(merged) = merged.iter().cloned().collect::<Option<Vec<_>>>() {
                shared_inputs.insert(k1.clone(), merged);
            } else {
                merged_maybe_shared_inputs.insert(k1.clone(), merged);
            }
        }

        Ok(Self {
            shared_inputs,
            public_inputs,
            maybe_shared_inputs: merged_maybe_shared_inputs,
        })
    }
}

impl<F: PrimeField> SharedInput<F, Rep3PrimeFieldShare<F>> {
    /// Shares a given input.
    pub fn share_rep3<R: Rng + CryptoRng>(
        input: &[F],
        rng: &mut R,
    ) -> [Vec<Rep3PrimeFieldShare<F>>; 3] {
        rep3::share_field_elements(input, rng)
    }

    /// Shares a given input with unknown elements
    pub fn maybe_share_rep3<R: Rng + CryptoRng>(
        input: &[Option<F>],
        rng: &mut R,
    ) -> [Vec<Option<Rep3PrimeFieldShare<F>>>; 3] {
        rep3::share_maybe_field_elements(input, rng)
    }
}

impl<F: PrimeField> CompressedRep3SharedWitness<F> {
    /// Shares a given witness and public input vector using the Rep3 protocol.
    pub fn share_rep3<R: Rng + CryptoRng>(
        witness: Witness<F>,
        num_pub_inputs: usize,
        rng: &mut R,
        compression: Compression,
    ) -> [Self; 3] {
        let public_inputs = &witness.values[..num_pub_inputs];
        let witness = &witness.values[num_pub_inputs..];

        let [share1, share2, share3] = match compression {
            Compression::SeededHalfShares => {
                let [share1, share2, share3] =
                    rep3::share_field_elements_additive_seeded(witness, rng);
                let share1 = Rep3ShareVecType::SeededAdditive(share1);
                let share2 = Rep3ShareVecType::SeededAdditive(share2);
                let share3 = Rep3ShareVecType::SeededAdditive(share3);
                [share1, share2, share3]
            }
            Compression::SeededShares => {
                let [share1, share2, share3] = rep3::share_field_elements_seeded(witness, rng);
                let share1 = Rep3ShareVecType::SeededReplicated(share1);
                let share2 = Rep3ShareVecType::SeededReplicated(share2);
                let share3 = Rep3ShareVecType::SeededReplicated(share3);
                [share1, share2, share3]
            }
            Compression::HalfShares => {
                let [share1, share2, share3] = rep3::share_field_elements_additive(witness, rng);
                let share1 = Rep3ShareVecType::Additive(share1);
                let share2 = Rep3ShareVecType::Additive(share2);
                let share3 = Rep3ShareVecType::Additive(share3);
                [share1, share2, share3]
            }
            Compression::None => {
                let [share1, share2, share3] = rep3::share_field_elements(witness, rng);
                let share1 = Rep3ShareVecType::Replicated(share1);
                let share2 = Rep3ShareVecType::Replicated(share2);
                let share3 = Rep3ShareVecType::Replicated(share3);
                [share1, share2, share3]
            }
        };

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

/// The error type for the verification of a Circom proof.
///
/// If the verification failed because the proof is Invalid, the method
/// will return the [VerificationError::InvalidProof] variant. If the
/// underlying implementation encounters an error, the method
/// will wrap that error in the [VerificationError::Malformed] variant.
#[derive(Debug)]
pub enum VerificationError {
    /// Indicates that the proof verification failed
    InvalidProof,
    /// Wraps an underlying error (e.g., malformed verification key)
    Malformed(eyre::Report),
}

impl From<eyre::Report> for VerificationError {
    fn from(error: eyre::Report) -> Self {
        VerificationError::Malformed(error)
    }
}

impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            VerificationError::Malformed(source) => Some(source.as_ref()),
            VerificationError::InvalidProof => None,
        }
    }
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidProof => writeln!(f, "proof is invalid"),
            VerificationError::Malformed(error) => writeln!(f, "cannot verify proof: {error}"),
        }
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
