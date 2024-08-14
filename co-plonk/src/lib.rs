//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.

#![warn(missing_docs)]
use ark_ec::pairing::Pairing;
use circom_types::plonk::PlonkProof;
use circom_types::plonk::ZKey;
use circom_types::traits::CircomArkworksPairingBridge;
use circom_types::traits::CircomArkworksPrimeFieldBridge;
use co_circom_snarks::SharedWitness;
use mpc_core::traits::FFTPostProcessing;
use mpc_core::traits::{FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol};
use round1::Round1;
use std::io;
use std::marker::PhantomData;

mod plonk;
mod round1;
mod round2;
mod round3;
mod round4;
mod round5;
pub(crate) mod types;

pub use plonk::Plonk;

type FieldShare<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShare;
type FieldShareVec<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShareVec;

type PlonkProofResult<T> = std::result::Result<T, PlonkProofError>;

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
    /// An [io::Error]. Communication to another party failed.
    #[error(transparent)]
    IOError(#[from] io::Error),
}

/// A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.
pub struct CoPlonk<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: FFTPostProcessing,
{
    pub(crate) driver: T,
    phantom_data: PhantomData<P>,
}

impl<T, P> CoPlonk<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: FFTPostProcessing + CircomArkworksPrimeFieldBridge,
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
{
    /// Creates a new [CoPlonk] protocol with a given MPC driver.
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
        }
    }

    /// Execute the PLONK prover using the internal MPC driver.
    pub fn prove(
        self,
        zkey: &ZKey<P>,
        witness: SharedWitness<T, P>,
    ) -> PlonkProofResult<PlonkProof<P>> {
        let state = Round1::init_round(self.driver, zkey, witness)?;
        let state = state.round1()?;
        let state = state.round2()?;
        let state = state.round3()?;
        let state = state.round4()?;
        state.round5()
    }
}

mod plonk_utils {
    use ark_ec::pairing::Pairing;
    use circom_types::plonk::ZKey;
    use mpc_core::traits::{FieldShareVecTrait, PrimeFieldMpcProtocol};

    use crate::types::{Domains, PlonkWitness};
    use crate::{FieldShare, FieldShareVec, PlonkProofError, PlonkProofResult};
    use ark_ff::Field;
    use num_traits::One;
    use num_traits::Zero;

    pub(crate) fn get_witness<T, P: Pairing>(
        driver: &mut T,
        witness: &PlonkWitness<T, P>,
        zkey: &ZKey<P>,
        index: usize,
    ) -> PlonkProofResult<FieldShare<T, P>>
    where
        T: PrimeFieldMpcProtocol<P::ScalarField>,
    {
        let result = if index <= zkey.n_public {
            driver.promote_to_trivial_share(witness.public_inputs[index])
        } else if index < zkey.n_vars - zkey.n_additions {
            witness.witness.index(index - zkey.n_public - 1)
        } else if index < zkey.n_vars {
            witness.addition_witness[index + zkey.n_additions - zkey.n_vars].to_owned()
        } else {
            return Err(PlonkProofError::CorruptedWitness(index));
        };
        Ok(result)
    }

    // For convenience coeff is given in reverse order
    pub(crate) fn blind_coefficients<T, P: Pairing>(
        driver: &mut T,
        poly: &FieldShareVec<T, P>,
        coeff_rev: &[FieldShare<T, P>],
    ) -> Vec<FieldShare<T, P>>
    where
        T: PrimeFieldMpcProtocol<P::ScalarField>,
    {
        let mut res = poly.clone().into_iter().collect::<Vec<_>>();
        for (p, c) in res.iter_mut().zip(coeff_rev.iter().rev()) {
            *p = driver.sub(p, c);
        }
        // Extend
        res.reserve(coeff_rev.len());
        for c in coeff_rev.iter().rev().cloned() {
            res.push(c);
        }
        res
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

#[cfg(test)]
pub mod tests {
    use ark_bn254::Bn254;
    use circom_types::groth16::JsonPublicInput;
    use circom_types::plonk::{JsonVerificationKey, ZKey};
    use circom_types::Witness;
    use co_circom_snarks::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;
    use std::{fs::File, io::BufReader};

    use crate::plonk::Plonk;

    #[test]
    pub fn test_multiplier2_bn254() -> eyre::Result<()> {
        let zkey_file = "../test_vectors/Plonk/bn254/multiplierAdd2/multiplier2.zkey";
        let witness_file = "../test_vectors/Plonk/bn254/multiplierAdd2/multiplier2_wtns.wtns";
        let zkey = ZKey::<Bn254>::from_reader(File::open(zkey_file)?)?;
        let witness = Witness::<ark_bn254::Fr>::from_reader(File::open(witness_file)?)?;
        let driver = PlainDriver::<ark_bn254::Fr>::default();

        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: witness.values[..=zkey.n_public].to_vec(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };

        let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/verification_key.json").unwrap(),
        )
        .unwrap();

        let public_input: JsonPublicInput<ark_bn254::Fr> = serde_json::from_reader(
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/public.json").unwrap(),
        )
        .unwrap();

        let plonk = Plonk::<Bn254>::new(driver);
        let proof = plonk.prove(&zkey, witness).unwrap();
        let result = Plonk::<Bn254>::verify(&vk, &proof, &public_input.values).unwrap();
        assert!(result);
        Ok(())
    }

    #[test]
    pub fn test_poseidon_bn254() {
        let driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut reader = BufReader::new(
            File::open("../test_vectors/Plonk/bn254/poseidon/poseidon.zkey").unwrap(),
        );
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file = File::open("../test_vectors/Plonk/bn254/poseidon/witness.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let public_input = witness.values[..=zkey.n_public].to_vec();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: public_input.clone(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };

        let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(
            File::open("../test_vectors/Plonk/bn254/poseidon/verification_key.json").unwrap(),
        )
        .unwrap();

        let public_inputs: JsonPublicInput<ark_bn254::Fr> = serde_json::from_reader(
            File::open("../test_vectors/Plonk/bn254/poseidon/public.json").unwrap(),
        )
        .unwrap();

        let plonk = Plonk::<Bn254>::new(driver);
        let proof = plonk.prove(&zkey, witness).unwrap();

        let mut proof_bytes = vec![];
        serde_json::to_writer(&mut proof_bytes, &proof).unwrap();
        let proof = serde_json::from_reader(proof_bytes.as_slice()).unwrap();
        let result = Plonk::<Bn254>::verify(&vk, &proof, &public_inputs.values).unwrap();
        assert!(result)
    }
}
