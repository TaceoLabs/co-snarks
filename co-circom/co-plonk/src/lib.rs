//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.

#![warn(missing_docs)]
use ark_ec::pairing::Pairing;
use circom_types::plonk::PlonkProof;
use circom_types::plonk::ZKey;
use circom_types::traits::CircomArkworksPairingBridge;
use circom_types::traits::CircomArkworksPrimeFieldBridge;
use co_circom_snarks::Rep3SharedWitness;
use co_circom_snarks::ShamirSharedWitness;
use co_circom_snarks::SharedWitness;
use eyre::Context;
use mpc::rep3::Rep3PlonkDriver;
use mpc::shamir::ShamirPlonkDriver;
use mpc::CircomPlonkProver;
use mpc_core::protocols::rep3::Rep3State;
use mpc_core::protocols::shamir::ShamirPreprocessing;
use mpc_core::protocols::shamir::ShamirProtocol;
use mpc_engine::{MpcEngine, Network};
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

pub use plonk::Plonk;

type PlonkProofResult<T> = std::result::Result<T, PlonkProofError>;

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
    phantom_data0: PhantomData<P>,
    phantom_data1: PhantomData<T>,
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
        engine: &MpcEngine<N>,
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
        let state = Round1::<P, T, N>::init_round(engine, state, zkey.as_ref(), witness)?;
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
    use rayon::prelude::*;

    use crate::mpc::CircomPlonkProver;
    use crate::types::{Domains, PlonkWitness};
    use crate::{PlonkProofError, PlonkProofResult};
    use ark_ff::Field;
    use num_traits::One;
    use num_traits::Zero;

    pub(crate) fn get_witness<P: Pairing, T: CircomPlonkProver<P>>(
        party_id: usize,
        witness: &PlonkWitness<P, T>,
        zkey: &ZKey<P>,
        index: usize,
    ) -> PlonkProofResult<T::ArithmeticShare> {
        tracing::trace!("get witness on {index}");
        let result = if index <= zkey.n_public {
            tracing::trace!("indexing public input!");
            T::promote_to_trivial_share(party_id, witness.public_inputs[index])
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
        engine: &MpcEngine<N>,
        zkey: Arc<ZKey<P>>,
        witness: Rep3SharedWitness<P::ScalarField>,
    ) -> eyre::Result<PlonkProof<P>>
    where
        P: Pairing + CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        let mut state = engine.install_net(|net| Rep3State::new(net))?;
        // execute prover in MPC
        Self::prove_inner(engine, &mut state, zkey, witness).context("while prove inner")
    }
}

impl<P: Pairing> ShamirCoPlonk<P> {
    /// Create a [`PlonkProof`]
    pub fn prove<N: Network + 'static>(
        engine: &MpcEngine<N>,
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
        let preprocessing = engine
            .install_net(|net| ShamirPreprocessing::new(num_parties, threshold, num_pairs, net))?;
        let mut protocol = ShamirProtocol::from(preprocessing);
        // execute prover in MPC
        Self::prove_inner(engine, &mut protocol, zkey, witness).context("while prove inner")
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
    pub fn plain_prove<N: Network + 'static>(
        engine: &MpcEngine<N>,
        zkey: Arc<ZKey<P>>,
        private_witness: SharedWitness<P::ScalarField, P::ScalarField>,
    ) -> eyre::Result<PlonkProof<P>> {
        Self::prove_inner(engine, &mut (), zkey, private_witness).context("while prove inner")
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use circom_types::groth16::JsonPublicInput;
    use circom_types::plonk::{JsonVerificationKey, ZKey};
    use circom_types::Witness;
    use co_circom_snarks::SharedWitness;
    use mpc_engine::{DummyNetwork, MpcEngine, NUM_THREADS_CPU, NUM_THREADS_NET};
    use std::sync::Arc;
    use std::{fs::File, io::BufReader};

    use circom_types::traits::CheckElement;

    use crate::plonk::Plonk;

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

            let nets = DummyNetwork::networks(8);
            let engine = MpcEngine::new(0, NUM_THREADS_NET, NUM_THREADS_CPU, nets);
            let proof = Plonk::<Bn254>::plain_prove(&engine, zkey, witness).unwrap();
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

            let nets = DummyNetwork::networks(8);
            let engine = MpcEngine::new(0, NUM_THREADS_NET, NUM_THREADS_CPU, nets);
            let proof = Plonk::<Bn254>::plain_prove(&engine, zkey, witness).unwrap();

            let mut proof_bytes = vec![];
            serde_json::to_writer(&mut proof_bytes, &proof).unwrap();
            let proof = serde_json::from_reader(proof_bytes.as_slice()).unwrap();
            Plonk::<Bn254>::verify(&vk, &proof, &public_inputs.values).unwrap();
        }
    }
}
