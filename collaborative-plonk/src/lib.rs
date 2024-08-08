//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.
use ark_ec::pairing::Pairing;
use ark_ff::FftField;
use ark_ff::LegendreSymbol;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use circom_types::plonk::PlonkProof;
use circom_types::plonk::ZKey;
use circom_types::traits::CircomArkworksPairingBridge;
use circom_types::traits::CircomArkworksPrimeFieldBridge;
use collaborative_groth16::groth16::SharedWitness;
use mpc_core::traits::FFTPostProcessing;
use mpc_core::traits::{FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol};
use num_traits::ToPrimitive;
use round1::Round1;
use std::io;
use std::marker::PhantomData;

pub mod plonk;
mod round1;
mod round2;
mod round3;
mod round4;
mod round5;
pub(crate) mod types;

type FieldShare<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShare;
type FieldShareVec<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShareVec;

type PlonkProofResult<T> = std::result::Result<T, PlonkProofError>;

#[derive(Debug, thiserror::Error)]
pub enum PlonkProofError {
    #[error("Cannot index into witness {0}")]
    CorruptedWitness(usize),
    #[error("Cannot create domain, Polynomial degree too large")]
    PolynomialDegreeTooLarge,
    #[error(transparent)]
    IOError(#[from] io::Error),
}

pub(crate) struct Domains<F: PrimeField> {
    domain: GeneralEvaluationDomain<F>,
    extended_domain: GeneralEvaluationDomain<F>,
    roots_of_unity: Vec<F>,
}

//TODO WE COPIED THIS FROM GROTH16 - WE WANT A COMMON PLACE
fn roots_of_unity<F: PrimeField + FftField>() -> Vec<F> {
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
    roots
}

impl<F: PrimeField> Domains<F> {
    fn new(domain_size: usize) -> PlonkProofResult<Self> {
        let domain = GeneralEvaluationDomain::<F>::new(domain_size)
            .ok_or(PlonkProofError::PolynomialDegreeTooLarge)?;
        let extended_domain = GeneralEvaluationDomain::<F>::new(domain_size * 4)
            .ok_or(PlonkProofError::PolynomialDegreeTooLarge)?;

        Ok(Self {
            domain,
            extended_domain,
            roots_of_unity: roots_of_unity(),
        })
    }
}

pub(crate) struct PlonkWitness<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    public_inputs: Vec<P::ScalarField>,
    witness: FieldShareVec<T, P>,
    addition_witness: Vec<FieldShare<T, P>>,
}

pub(crate) struct PlonkData<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    witness: PlonkWitness<T, P>,
    zkey: ZKey<P>,
}

impl<T, P: Pairing> PlonkWitness<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(shared_witness: SharedWitness<T, P>, n_additions: usize) -> Self {
        //we need the leading zero for round1
        Self {
            public_inputs: shared_witness.public_inputs,
            witness: shared_witness.witness,
            addition_witness: Vec::with_capacity(n_additions),
        }
    }
}

/// A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.
pub struct CollaborativePlonk<T, P: Pairing>
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

impl<T, P> CollaborativePlonk<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing + CircomArkworksPrimeFieldBridge,
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
{
    /// Creates a new [CollaborativePlonk] protocol with a given MPC driver.
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
        }
    }

    pub fn prove(
        self,
        zkey: ZKey<P>,
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

pub mod plonk_utils {
    use ark_ec::pairing::Pairing;
    use circom_types::plonk::ZKey;
    use mpc_core::traits::FieldShareVecTrait;
    use mpc_core::traits::PrimeFieldMpcProtocol;

    use crate::{FieldShare, FieldShareVec, PlonkProofError, PlonkProofResult, PlonkWitness};
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
        root_of_unitys: &[P::ScalarField],
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
        let root_of_unity = root_of_unitys[power];

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
    use std::{fs::File, io::BufReader};

    use ark_bn254::Bn254;
    use circom_types::{
        groth16::{public_input::JsonPublicInput, witness::Witness},
        plonk::{JsonVerificationKey, ZKey},
        r1cs::R1CS,
    };
    use collaborative_groth16::{circuit::Circuit, groth16::SharedWitness};
    use mpc_core::protocols::plain::PlainDriver;
    use num_traits::Zero;

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
        let proof = plonk.prove(zkey, witness).unwrap();
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
        let r1cs = R1CS::<Bn254>::from_reader(
            File::open("../test_vectors/Plonk/bn254/poseidon/poseidon.r1cs").unwrap(),
        )
        .unwrap();
        let circuit = Circuit::new(r1cs, witness);
        let public_inputs = circuit.public_inputs();
        let mut public_input = vec![ark_bn254::Fr::zero()];
        public_input.extend(public_inputs);
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: public_input,
            witness: circuit.witnesses(),
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
        let proof = plonk.prove(zkey, witness).unwrap();
        let result = Plonk::<Bn254>::verify(&vk, &proof, &public_inputs.values).unwrap();
        assert!(result)
    }
}
