//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.
use ark_ec::pairing::Pairing;
use ark_ff::FftField;
use ark_ff::LegendreSymbol;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use circom_types::plonk::JsonVerificationKey;
use circom_types::plonk::PlonkProof;
use circom_types::plonk::ZKey;
use circom_types::traits::CircomArkworksPairingBridge;
use circom_types::traits::CircomArkworksPrimeFieldBridge;
use collaborative_groth16::groth16::SharedWitness;
use mpc_core::traits::{FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol};
use num_traits::ToPrimitive;
use num_traits::Zero;
use round1::Round1;
use std::io;
use std::marker::PhantomData;

mod round1;
mod round2;
mod round3;
mod round4;
mod round5;
pub(crate) mod types;
mod verifiy;

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

pub(crate) struct Domains<P: Pairing> {
    domain: GeneralEvaluationDomain<P::ScalarField>,
    extended_domain: GeneralEvaluationDomain<P::ScalarField>,
    roots_of_unity: Vec<P::ScalarField>,
    phantom_data: PhantomData<P>,
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

impl<P: Pairing> Domains<P> {
    fn new(domain_size: usize) -> PlonkProofResult<Self> {
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(domain_size)
            .ok_or(PlonkProofError::PolynomialDegreeTooLarge)?;
        let extended_domain = GeneralEvaluationDomain::<P::ScalarField>::new(domain_size * 4)
            .ok_or(PlonkProofError::PolynomialDegreeTooLarge)?;

        Ok(Self {
            domain,
            extended_domain,
            roots_of_unity: roots_of_unity(),
            phantom_data: PhantomData,
        })
    }
}

pub(crate) struct PlonkWitness<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    shared_witness: SharedWitness<T, P>,
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
    fn new(mut shared_witness: SharedWitness<T, P>, n_additions: usize) -> Self {
        shared_witness.public_inputs[0] = P::ScalarField::zero();
        Self {
            shared_witness,
            addition_witness: Vec::with_capacity(n_additions),
        }
    }
}

/// A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.
pub struct CollaborativePlonk<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    pub(crate) driver: T,
    phantom_data: PhantomData<P>,
}

impl<T, P> CollaborativePlonk<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
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
    use circom_types::{
        plonk::{JsonVerificationKey, PlonkProof, ZKey},
        traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
    };
    use mpc_core::traits::PrimeFieldMpcProtocol;

    use crate::{
        roots_of_unity, verifiy::Plonk, FieldShare, FieldShareVec, PlonkProofError,
        PlonkProofResult, PlonkWitness,
    };

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
            driver.promote_to_trivial_share(witness.shared_witness.public_inputs[index])
        } else if index < zkey.n_vars - zkey.n_additions {
            //subtract public values and the leading 0 in witness
            T::index_sharevec(&witness.shared_witness.witness, index - zkey.n_public - 1)
        } else if index < zkey.n_vars {
            witness.addition_witness[index + zkey.n_additions - zkey.n_vars].to_owned()
        } else {
            //TODO make this as an error
            return Err(PlonkProofError::CorruptedWitness(index));
        };
        Ok(result)
    }

    pub(crate) fn blind_coefficients<T, P: Pairing>(
        driver: &mut T,
        poly: &FieldShareVec<T, P>,
        coeff: &[FieldShare<T, P>],
    ) -> Vec<FieldShare<T, P>>
    where
        T: PrimeFieldMpcProtocol<P::ScalarField>,
    {
        let mut res = poly.clone().into_iter().collect::<Vec<_>>();
        for (p, c) in res.iter_mut().zip(coeff.iter()) {
            *p = driver.sub(p, c);
        }
        res.extend_from_slice(coeff);
        res
    }
}

#[cfg(test)]
pub mod tests {
    use std::{fs::File, io::BufReader};

    use ark_bn254::Bn254;
    use circom_types::{
        groth16::witness::Witness,
        plonk::{JsonVerificationKey, ZKey},
    };
    use collaborative_groth16::groth16::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;
    use num_traits::Zero;

    use crate::{plonk_utils, verifiy::Plonk, CollaborativePlonk};

    #[test]
    pub fn test_multiplier2_bn254() {
        let driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut reader = BufReader::new(
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/multiplier2.zkey").unwrap(),
        );
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file =
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/multiplier2_wtns.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let value1 = witness.values[1];
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: vec![ark_bn254::Fr::zero(), witness.values[1]],
            witness: vec![witness.values[2], witness.values[3]],
        };

        let vk: JsonVerificationKey<Bn254> = serde_json::from_reader(
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/verification_key.json").unwrap(),
        )
        .unwrap();

        let plonk_prover = CollaborativePlonk::new(driver);
        let proof = plonk_prover.prove(zkey, witness).unwrap();
        let result = Plonk::<Bn254>::verify(&vk, &proof, &[value1]).unwrap();
        assert!(result)
    }
}
