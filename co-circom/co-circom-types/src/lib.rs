#![warn(missing_docs)]
//! This crate collects all functionality that is shared between the SNARKs supported by co-circom. At the moment
//! this is [Groth16](https://eprint.iacr.org/2016/260.pdf) and [PLONK](https://eprint.iacr.org/2019/953.pdf).

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circom_types::Witness;
use core::panic;
use eyre::{Context, ContextCompat};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3ShareVecType};
use mpc_core::protocols::shamir::{self, ShamirPrimeFieldShare};
use mpc_core::serde_compat::{ark_de, ark_se};
use num_bigint::BigUint;
use num_traits::Num;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;

/// A REP3 shared input type
pub type Rep3SharedInput<F> = BTreeMap<String, Rep3InputType<F>>;

/// A batched REP3 shared input type. Should be used with the batched witness extension
pub type BatchedRep3SharedInput<F> = BTreeMap<String, Vec<Rep3InputType<F>>>;

/// A shorthand type for batched witnesses. Produced by the batched witness extension
pub type BatchedWitness<P, S> = SharedWitness<Vec<P>, Vec<S>>;

/// A REP3 shared witness type
pub type Rep3SharedWitness<F> = SharedWitness<F, Rep3PrimeFieldShare<F>>;

/// A shamir shared witness type
pub type ShamirSharedWitness<F> = SharedWitness<F, ShamirPrimeFieldShare<F>>;

/// A REP3 input type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Rep3InputType<F: PrimeField> {
    /// The public variant
    Public(
        #[serde(
            serialize_with = "mpc_core::serde_compat::ark_se",
            deserialize_with = "mpc_core::serde_compat::ark_de"
        )]
        F,
    ),
    /// The shared variant
    Shared(
        #[serde(
            serialize_with = "mpc_core::serde_compat::ark_se",
            deserialize_with = "mpc_core::serde_compat::ark_de"
        )]
        Rep3PrimeFieldShare<F>,
    ),
}

impl<F: PrimeField> Rep3InputType<F> {
    /// Returns true if the input is public
    pub fn is_public(&self) -> bool {
        matches!(self, Rep3InputType::Public(_))
    }

    /// Returns the public input or None
    pub fn as_public(&self) -> Option<F> {
        match self {
            Rep3InputType::Public(value) => Some(*value),
            Rep3InputType::Shared(_) => None,
        }
    }

    /// Returns the shared input or None
    pub fn as_shared(&self) -> Option<Rep3PrimeFieldShare<F>> {
        match self {
            Rep3InputType::Public(_) => None,
            Rep3InputType::Shared(share) => Some(*share),
        }
    }
}

impl<F: PrimeField> From<F> for Rep3InputType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<Rep3PrimeFieldShare<F>> for Rep3InputType<F> {
    fn from(value: Rep3PrimeFieldShare<F>) -> Self {
        Self::Shared(value)
    }
}

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
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
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

/// A shared witness in the circom ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedWitness<P, S>
where
    P: CanonicalSerialize + CanonicalDeserialize + Clone,
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    /// The public inputs (which are the outputs of the circom circuit).
    /// This also includes the constant 1 at position 0.
    pub public_inputs: Vec<P>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    /// The secret-shared witness elements.
    pub witness: Vec<S>,
}

impl<P, S> BatchedWitness<P, S>
where
    P: CanonicalSerialize + CanonicalDeserialize + Clone,
    S: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    /// Transforms the [BatchedWitness] to a vec of ordinary [SharedWitness] instances.
    pub fn unbatch(self) -> Vec<SharedWitness<P, S>> {
        if self.public_inputs.is_empty() {
            panic!("trying to unbatch an empty shared witness");
        }
        let batch_size = self.public_inputs[0].len();
        let mut public_inputs = vec![Vec::with_capacity(self.public_inputs.len()); batch_size];
        let mut witnesses = vec![Vec::with_capacity(self.witness.len()); batch_size];

        for batched_public_input in self.public_inputs.into_iter() {
            assert_eq!(
                batched_public_input.len(),
                batch_size,
                "batch size not consistent in batched witness"
            );
            for (idx, public_input) in batched_public_input.into_iter().enumerate() {
                public_inputs[idx].push(public_input);
            }
        }

        for batched_witness in self.witness.into_iter() {
            assert_eq!(
                batched_witness.len(),
                batch_size,
                "batch size not consistent in batched witness"
            );
            for (idx, witness) in batched_witness.into_iter().enumerate() {
                witnesses[idx].push(witness);
            }
        }
        public_inputs
            .into_iter()
            .zip(witnesses)
            .map(|(public_inputs, witness)| SharedWitness {
                public_inputs,
                witness,
            })
            .collect()
    }
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

/// A JSON map of input names and values
pub type Input = serde_json::Map<String, serde_json::Value>;

/// Splits the input into REP3 shares
pub fn split_input<F: PrimeField>(
    input: Input,
    public_inputs: &[String],
) -> eyre::Result<[Rep3SharedInput<F>; 3]> {
    // create input shares
    let mut shares = [
        Rep3SharedInput::<F>::default(),
        Rep3SharedInput::<F>::default(),
        Rep3SharedInput::<F>::default(),
    ];

    let mut rng = rand::thread_rng();
    for (name, val) in input {
        let parsed_vals = if val.is_array() {
            parse_array::<F>(&val)?
                .into_iter()
                .enumerate()
                .filter_map(|(idx, field)| field.map(|field| (format!("{name}[{idx}]"), field)))
                .collect::<BTreeMap<_, _>>()
        } else if val.is_boolean() {
            BTreeMap::from([(name.clone(), parse_boolean::<F>(&val)?)])
        } else {
            BTreeMap::from([(name.clone(), parse_field::<F>(&val)?)])
        };

        if public_inputs.contains(&name) {
            for (k, v) in parsed_vals.into_iter() {
                shares[0].insert(k.clone(), Rep3InputType::Public(v));
                shares[1].insert(k.clone(), Rep3InputType::Public(v));
                shares[2].insert(k.clone(), Rep3InputType::Public(v));
            }
        } else {
            for (k, v) in parsed_vals.into_iter() {
                let [share0, share1, share2] = rep3::share_field_element(v, &mut rng);
                shares[0].insert(k.clone(), Rep3InputType::Shared(share0));
                shares[1].insert(k.clone(), Rep3InputType::Shared(share1));
                shares[2].insert(k.clone(), Rep3InputType::Shared(share2));
            }
        }
    }
    Ok(shares)
}

/// Merge multiple REP3 input shares
pub fn merge_input_shares<F: PrimeField>(
    input_shares: Vec<Rep3SharedInput<F>>,
    public_inputs: &[String],
) -> eyre::Result<Rep3SharedInput<F>> {
    let mut result = BTreeMap::new();
    for input_share in input_shares.into_iter() {
        for (name, share) in input_share.into_iter() {
            // some input name have a trailing [\d+], remove for public inputs check
            let orig_name = name.split('[').next().unwrap_or(&name).to_owned();
            if public_inputs.contains(&orig_name) {
                if result.get(&name).is_some_and(|v| *v != share) {
                    eyre::bail!("Public entry '{name}' not the same in all inputs");
                }
            } else if result.contains_key(&name) {
                eyre::bail!("Duplicate entry '{name}' found in input shares");
            }
            result.insert(name, share);
        }
    }
    Ok(result)
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

fn parse_field<F>(val: &serde_json::Value) -> eyre::Result<F>
where
    F: std::str::FromStr + PrimeField,
{
    let s = val.as_str().ok_or_else(|| {
        eyre::eyre!(
            "expected input to be a field element string, got \"{}\"",
            val
        )
    })?;
    let (is_negative, stripped) = if let Some(stripped) = s.strip_prefix('-') {
        (true, stripped)
    } else {
        (false, s)
    };
    let positive_value = if let Some(stripped) = stripped.strip_prefix("0x") {
        let mut big_int = BigUint::from_str_radix(stripped, 16)
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?;
        let modulus = BigUint::try_from(F::MODULUS).expect("can convert mod to biguint");
        if big_int >= modulus {
            tracing::warn!("val {} >= mod", big_int);
            // snarkjs also does this
            big_int %= modulus;
        }
        let big_int: F::BigInt = big_int
            .try_into()
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?;
        F::from(big_int)
    } else {
        stripped
            .parse::<F>()
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?
    };
    if is_negative {
        Ok(-positive_value)
    } else {
        Ok(positive_value)
    }
}

fn parse_array<F: PrimeField>(val: &serde_json::Value) -> eyre::Result<Vec<Option<F>>> {
    let json_arr = val.as_array().expect("is an array");
    let mut field_elements = vec![];
    for ele in json_arr {
        if ele.is_array() {
            field_elements.extend(parse_array::<F>(ele)?);
        } else if ele.is_boolean() {
            field_elements.push(Some(parse_boolean(ele)?));
        } else if ele.as_str().is_some_and(|e| e == "?") {
            field_elements.push(None);
        } else {
            field_elements.push(Some(parse_field(ele)?));
        }
    }
    Ok(field_elements)
}

fn parse_boolean<F: PrimeField>(val: &serde_json::Value) -> eyre::Result<F> {
    let bool = val
        .as_bool()
        .with_context(|| format!("expected input to be a bool, got {val}"))?;
    if bool { Ok(F::ONE) } else { Ok(F::ZERO) }
}
