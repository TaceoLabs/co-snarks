//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.

#![warn(missing_docs)]
use ark_ec::pairing::Pairing;
use circom_types::plonk::PlonkProof;
use circom_types::plonk::ZKey;
use circom_types::traits::CircomArkworksPairingBridge;
use circom_types::traits::CircomArkworksPrimeFieldBridge;
use co_circom_types::Rep3SharedWitness;
use co_circom_types::ShamirSharedWitness;
use co_circom_types::SharedWitness;
use eyre::Context;
use mpc::CircomPlonkProver;
use mpc::plain::PlainPlonkDriver;
use mpc::rep3::Rep3PlonkDriver;
use mpc::shamir::ShamirPlonkDriver;
use mpc_core::protocols::rep3::Rep3State;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::shamir::ShamirPreprocessing;
use mpc_core::protocols::shamir::ShamirState;
use mpc_net::Network;
use round1::Round1;
use std::marker::PhantomData;
use std::sync::Arc;

/// This module contains the Plonk prover trait
pub mod mpc;
mod plonk;
mod round1;
mod round2;
mod round3;
mod round4;
mod round5;
pub(crate) mod types;

type PlonkProofResult<T> = std::result::Result<T, PlonkProofError>;

/// The plain [`Plonk`] type.
///
/// This type is actually the [`CoPlonk`] type initialized with
/// the [`PlainPlonkDriver`], a single party (you) MPC protocol (i.e., your everyday PLONK).
/// You can use this instance to create a proof, but we recommend against it for a real use-case.
/// The co-PLONK prover uses some MPC optimizations (for the product check), which are not optimal
/// for a plain run.
///
/// More interesting is the [`Plonk::verify`] method. You can verify any circom PLONK proof, be it
/// from snarkjs or one created by this project.
pub type Plonk<P> = CoPlonk<P, PlainPlonkDriver>;
/// A type alias for a [CoPlonk] protocol using replicated secret sharing.
pub type Rep3CoPlonk<P> = CoPlonk<P, Rep3PlonkDriver>;
/// A type alias for a [CoPlonk] protocol using shamir secret sharing.
pub type ShamirCoPlonk<P> = CoPlonk<P, ShamirPlonkDriver>;

/// The errors that may arise during the computation of a co-PLONK proof.
#[derive(Debug, thiserror::Error)]
pub enum PlonkProofError {
    /// Invalid domain size
    #[error("Invalid domain size {0}. Must be power of two")]
    InvalidDomainSize(usize),
    /// Indicates that the witness is too small for the provided circuit.
    #[error("Cannot index into witness {0}")]
    CorruptedWitness(usize),
    /// Indicates that the domain size from the zkey is corrupted.
    #[error("Cannot create domain, Polynomial degree too large")]
    PolynomialDegreeTooLarge,
    /// An [eyre::Report].
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

/// A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.
pub struct CoPlonk<P: Pairing, T: CircomPlonkProver<P>> {
    phantom_data: PhantomData<(P, T)>,
}

impl<P, T> CoPlonk<P, T>
where
    T: CircomPlonkProver<P>,
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
{
    /// Execute the PLONK prover using the internal MPC driver.
    fn prove_inner<N: Network + 'static>(
        nets: &[N; 8],
        state: &mut T::State,
        zkey: Arc<ZKey<P>>,
        witness: SharedWitness<P::ScalarField, T::ArithmeticShare>,
    ) -> PlonkProofResult<PlonkProof<P>> {
        tracing::debug!("starting PLONK prove!");
        tracing::debug!(
            "we have {} constraints and {} addition constraints",
            zkey.n_constraints,
            zkey.n_additions
        );
        tracing::debug!("the domain size is {}", zkey.domain_size);
        tracing::debug!(
            "we have {} n_vars and {} public inputs",
            zkey.n_vars,
            zkey.n_public
        );
        let state = Round1::<P, T, N>::init_round(nets, state, zkey.as_ref(), witness)?;
        tracing::debug!("init round done..");
        let state = state.round1()?;
        tracing::debug!("round 1 done..");
        let state = state.round2()?;
        tracing::debug!("round 2 done..");
        let state = state.round3()?;
        tracing::debug!("round 3 done..");
        let state = state.round4()?;
        tracing::debug!("round 4 done..");
        let result = state.round5();
        tracing::debug!("round 5 done! We are done!");
        result
    }
}

mod plonk_utils {
    use ark_ec::pairing::Pairing;
    use circom_types::plonk::ZKey;
    use mpc_core::MpcState;
    use rayon::prelude::*;

    use crate::mpc::CircomPlonkProver;
    use crate::types::{Domains, PlonkWitness};
    use crate::{PlonkProofError, PlonkProofResult};
    use ark_ff::Field;
    use num_traits::One;
    use num_traits::Zero;

    macro_rules! rayon_join3 {
        ($f0: expr, $f1: expr, $f2: expr) => {{
            let (r0, (r1, r2)) = rayon::join($f0, || rayon::join($f1, $f2));
            (r0, r1, r2)
        }};
    }

    macro_rules! rayon_join4 {
        ($f0: expr, $f1: expr, $f2: expr, $f3: expr) => {{
            let (r0, (r1, (r2, r3))) =
                rayon::join($f0, || rayon::join($f1, || rayon::join($f2, $f3)));
            (r0, r1, r2, r3)
        }};
    }

    macro_rules! rayon_join5 {
        ($f0: expr, $f1: expr, $f2: expr, $f3: expr, $f4: expr) => {{
            let (r0, (r1, (r2, (r3, r4)))) = rayon::join($f0, || {
                rayon::join($f1, || rayon::join($f2, || rayon::join($f3, $f4)))
            });
            (r0, r1, r2, r3, r4)
        }};
    }

    macro_rules! rayon_join8 {
        ($f0: expr, $f1: expr, $f2: expr, $f3: expr, $f4: expr, $f5: expr, $f6: expr, $f7: expr) => {{
            let (r0, (r1, (r2, (r3, (r4, (r5, (r6, r7))))))) = rayon::join($f0, || {
                rayon::join($f1, || {
                    rayon::join($f2, || {
                        rayon::join($f3, || {
                            rayon::join($f4, || rayon::join($f5, || rayon::join($f6, $f7)))
                        })
                    })
                })
            });
            (r0, r1, r2, r3, r4, r5, r6, r7)
        }};
    }

    pub(crate) use rayon_join3;
    pub(crate) use rayon_join4;
    pub(crate) use rayon_join5;
    pub(crate) use rayon_join8;

    pub(crate) fn get_witness<P: Pairing, T: CircomPlonkProver<P>>(
        id: <T::State as MpcState>::PartyID,
        witness: &PlonkWitness<P, T>,
        zkey: &ZKey<P>,
        index: usize,
    ) -> PlonkProofResult<T::ArithmeticShare> {
        tracing::trace!("get witness on {index}");
        let result = if index <= zkey.n_public {
            tracing::trace!("indexing public input!");
            T::promote_to_trivial_share(id, witness.public_inputs[index])
        } else if index < zkey.n_vars - zkey.n_additions {
            tracing::trace!("indexing private input!");
            witness.witness[index - zkey.n_public - 1]
        } else if index < zkey.n_vars {
            tracing::trace!("indexing additions!");
            witness.addition_witness[index + zkey.n_additions - zkey.n_vars].to_owned()
        } else {
            tracing::warn!("Witness corrupted with invalid Index {index}");
            return Err(PlonkProofError::CorruptedWitness(index));
        };
        Ok(result)
    }

    // For convenience coeff is given in reverse order
    pub(crate) fn blind_coefficients<P: Pairing, T: CircomPlonkProver<P>>(
        poly: &mut Vec<T::ArithmeticShare>,
        coeff_rev: &[T::ArithmeticShare],
    ) {
        poly.par_iter_mut()
            .zip(coeff_rev.par_iter().rev())
            .with_min_len(512)
            .for_each(|(p, c)| {
                *p = T::sub(*p, *c);
            });
        // Extend
        poly.reserve(coeff_rev.len());
        for c in coeff_rev.iter().rev().cloned() {
            poly.push(c);
        }
    }

    pub(crate) fn calculate_lagrange_evaluations<P: Pairing>(
        power: usize,
        n_public: usize,
        xi: &P::ScalarField,
        domains: &Domains<P::ScalarField>,
    ) -> (Vec<P::ScalarField>, P::ScalarField) {
        let mut xin = *xi;
        let mut domain_size = 1;
        for _ in 0..power {
            xin.square_in_place();
            domain_size *= 2;
        }
        let zh = xin - P::ScalarField::one();
        let l_length = usize::max(1, n_public);
        let mut l = Vec::with_capacity(l_length);
        let root_of_unity = domains.root_of_unity_pow;

        let n = P::ScalarField::from(domain_size as u64);
        let mut w = P::ScalarField::one();
        for _ in 0..l_length {
            l.push((w * zh) / (n * (*xi - w)));
            w *= root_of_unity;
        }
        (l, xin)
    }

    pub(crate) fn calculate_pi<P: Pairing>(
        public_inputs: &[P::ScalarField],
        l: &[P::ScalarField],
    ) -> P::ScalarField {
        let mut pi = P::ScalarField::zero();
        for (val, l) in public_inputs.iter().zip(l) {
            pi -= *l * val;
        }
        pi
    }
}

impl<P: Pairing> Rep3CoPlonk<P> {
    /// Create a [`PlonkProof`]
    pub fn prove<N: Network + 'static>(
        nets: &[N; 8],
        zkey: Arc<ZKey<P>>,
        witness: Rep3SharedWitness<P::ScalarField>,
    ) -> eyre::Result<PlonkProof<P>>
    where
        P: Pairing + CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        let mut state = Rep3State::new(&nets[0], A2BType::default())?;
        // execute prover in MPC
        Self::prove_inner(nets, &mut state, zkey, witness).context("while prove inner")
    }
}

impl<P: Pairing> ShamirCoPlonk<P> {
    /// Create a [`PlonkProof`]
    pub fn prove<N: Network + 'static>(
        nets: &[N; 8],
        num_parties: usize,
        threshold: usize,
        zkey: Arc<ZKey<P>>,
        witness: ShamirSharedWitness<P::ScalarField>,
    ) -> eyre::Result<PlonkProof<P>>
    where
        P: Pairing + CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        let domain_size = zkey.domain_size;
        // TODO check and explain numbers
        let num_pairs = domain_size * 222 + 15;
        let preprocessing = ShamirPreprocessing::new(num_parties, threshold, num_pairs, &nets[0])?;
        let mut state = ShamirState::from(preprocessing);
        // execute prover in MPC
        Self::prove_inner(nets, &mut state, zkey, witness).context("while prove inner")
    }
}

impl<P: Pairing> Plonk<P>
where
    P: CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// *Locally* create a `Plonk` proof. This is just the [`CoPlonk`] prover
    /// initialized with the [`PlainPlonkDriver`].
    ///
    /// DOES NOT PERFORM ANY MPC. For a plain prover checkout the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/).
    pub fn plain_prove(
        zkey: Arc<ZKey<P>>,
        private_witness: SharedWitness<P::ScalarField, P::ScalarField>,
    ) -> eyre::Result<PlonkProof<P>> {
        Self::prove_inner(&[(); 8], &mut (), zkey, private_witness).context("while prove inner")
    }
}

#[cfg(test)]
mod tests {
    use super::Plonk;
    use ark_bn254::Bn254;
    use circom_types::Witness;
    use circom_types::groth16::JsonPublicInput;
    use circom_types::plonk::{JsonVerificationKey, ZKey};
    use circom_types::traits::CheckElement;
    use co_circom_types::SharedWitness;
    use std::sync::Arc;
    use std::{fs::File, io::BufReader};

    #[test]
    pub fn test_multiplier2_bn254() -> eyre::Result<()> {
        for check in [CheckElement::Yes, CheckElement::No] {
            let zkey_file = "../../test_vectors/Plonk/bn254/multiplier2/circuit.zkey";
            let witness_file = "../../test_vectors/Plonk/bn254/multiplier2/witness.wtns";
            let zkey = Arc::new(ZKey::<Bn254>::from_reader(File::open(zkey_file)?, check)?);
            let witness = Witness::<ark_bn254::Fr>::from_reader(File::open(witness_file)?)?;

            let witness = SharedWitness {
                public_inputs: witness.values[..=zkey.n_public].to_vec(),
                witness: witness.values[zkey.n_public + 1..].to_vec(),
            };

            let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(
                File::open("../../test_vectors/Plonk/bn254/multiplier2/verification_key.json")
                    .unwrap(),
            )
            .unwrap();

            let public_input: JsonPublicInput<ark_bn254::Fr> = serde_json::from_reader(
                File::open("../../test_vectors/Plonk/bn254/multiplier2/public.json").unwrap(),
            )
            .unwrap();
            let proof = Plonk::<Bn254>::plain_prove(zkey, witness).unwrap();
            Plonk::<Bn254>::verify(&vk, &proof, &public_input.values).unwrap();
        }
        Ok(())
    }

    #[test]
    pub fn test_poseidon_bn254() {
        for check in [CheckElement::Yes, CheckElement::No] {
            let mut reader = BufReader::new(
                File::open("../../test_vectors/Plonk/bn254/poseidon/circuit.zkey").unwrap(),
            );
            let zkey = Arc::new(ZKey::<Bn254>::from_reader(&mut reader, check).unwrap());
            let witness_file =
                File::open("../../test_vectors/Plonk/bn254/poseidon/witness.wtns").unwrap();
            let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
            let public_input = witness.values[..=zkey.n_public].to_vec();
            let witness = SharedWitness {
                public_inputs: public_input.clone(),
                witness: witness.values[zkey.n_public + 1..].to_vec(),
            };

            let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(
                File::open("../../test_vectors/Plonk/bn254/poseidon/verification_key.json")
                    .unwrap(),
            )
            .unwrap();

            let public_inputs: JsonPublicInput<ark_bn254::Fr> = serde_json::from_reader(
                File::open("../../test_vectors/Plonk/bn254/poseidon/public.json").unwrap(),
            )
            .unwrap();

            let proof = Plonk::<Bn254>::plain_prove(zkey, witness).unwrap();

            let mut proof_bytes = vec![];
            serde_json::to_writer(&mut proof_bytes, &proof).unwrap();
            let proof = serde_json::from_reader(proof_bytes.as_slice()).unwrap();
            Plonk::<Bn254>::verify(&vk, &proof, &public_inputs.values).unwrap();
        }
    }
}
