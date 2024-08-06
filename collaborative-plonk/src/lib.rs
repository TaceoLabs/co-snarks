//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.

use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_groth16::data_structures;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use circom_types::groth16::public_input;
use circom_types::plonk::ZKey;
use circom_types::traits::CircomArkworksPairingBridge;
use circom_types::traits::CircomArkworksPrimeFieldBridge;
use collaborative_groth16::groth16::CollaborativeGroth16;
use collaborative_groth16::groth16::SharedWitness;
use mpc_core::traits::MontgomeryField;
use mpc_core::traits::MpcToMontgomery;
use mpc_core::traits::{
    EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};
use num_traits::One;
use num_traits::Zero;
use round1::Round1Challenges;
use round1::Round1Proof;
use sha3::Digest;
use sha3::Keccak256;
use std::io;
use std::marker::PhantomData;
use std::ops::MulAssign;
use types::WirePolyOutput;

mod round1;
mod round2;
pub(crate) mod types;

type FieldShare<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShare;
type FieldShareVec<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShareVec;
type PointShare<T, C> = <T as EcMpcProtocol<C>>::PointShare;

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
    constraint_domain: GeneralEvaluationDomain<P::ScalarField>,
    constraint_domain4: GeneralEvaluationDomain<P::ScalarField>,
    constraint_domain16: GeneralEvaluationDomain<P::ScalarField>,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Domains<P> {
    fn new(zkey: &ZKey<P>) -> PlonkProofResult<Self> {
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(zkey.n_constraints)
            .ok_or(PlonkProofError::PolynomialDegreeTooLarge)?;
        let domain2 = GeneralEvaluationDomain::<P::ScalarField>::new(zkey.n_constraints * 4)
            .ok_or(PlonkProofError::PolynomialDegreeTooLarge)?;
        let domain3 = GeneralEvaluationDomain::<P::ScalarField>::new(zkey.n_constraints * 16)
            .ok_or(PlonkProofError::PolynomialDegreeTooLarge)?;
        Ok(Self {
            constraint_domain: domain1,
            constraint_domain4: domain2,
            constraint_domain16: domain3,
            phantom_data: PhantomData,
        })
    }
}

pub(crate) struct PlonkWitness<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    shared_witness: SharedWitness<T, P>,
    addition_witness: FieldShareVec<T, P>,
}

pub(crate) struct PlonkData<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    witness: PlonkWitness<T, P>,
    zkey: ZKey<P>,
}

impl<T, P: Pairing> From<SharedWitness<T, P>> for PlonkWitness<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn from(mut shared_witness: SharedWitness<T, P>) -> Self {
        shared_witness.public_inputs[0] = P::ScalarField::zero();
        Self {
            shared_witness,
            addition_witness: vec![].into(),
        }
    }
}

enum Round<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    Init {
        zkey: ZKey<P>,
        witness: SharedWitness<T, P>,
        public_inputs: Vec<P::ScalarField>,
    },
    Round1 {
        domains: Domains<P>,
        challenges: Round1Challenges<T, P>,
        data: PlonkData<T, P>,
    },
    Round2 {
        domains: Domains<P>,
        challenges: Round1Challenges<T, P>,
        proof: Round1Proof<P>,
        wire_polys: WirePolyOutput<T, P>,
        data: PlonkData<T, P>,
    },
    Round3,
    Round4,
    Round5,
    Round6,
    Finished,
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
    pub(crate) state: Round<T, P>,
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
    pub fn new(
        driver: T,
        public_inputs: Vec<P::ScalarField>,
        zkey: ZKey<P>,
        witness: SharedWitness<T, P>,
    ) -> Self {
        Self {
            driver,
            state: Round::Init {
                zkey,
                witness,
                public_inputs,
            },
            phantom_data: PhantomData,
        }
    }

    pub fn proof(self) {}

    pub(crate) fn next_round(&mut self) {}
}

impl<T, P: Pairing> Round<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>
        + MpcToMontgomery<P::ScalarField>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing + MontgomeryField,
{
    fn next_round(self, driver: &mut T) -> PlonkProofResult<Self> {
        match self {
            Round::Init {
                zkey,
                public_inputs,
                witness,
            } => Self::init_round(driver, zkey, public_inputs, witness),
            Round::Round1 {
                domains,
                challenges,
                data,
            } => Self::round1(driver, domains, challenges, data),
            Round::Round2 {
                domains,
                challenges,
                proof,
                wire_polys,
                data,
            } => Self::round2(driver, domains, challenges, proof, wire_polys, data),
            Round::Round3 => todo!(),
            Round::Round4 => todo!(),
            Round::Round5 => todo!(),
            Round::Round6 => todo!(),
            Round::Finished => todo!(),
        }
    }

    fn calculate_additions(
        driver: &mut T,
        witness: &mut PlonkWitness<T, P>,
        zkey: &ZKey<P>,
    ) -> PlonkProofResult<()> {
        let mut additions = Vec::with_capacity(zkey.n_additions);
        for addition in zkey.additions.iter() {
            let witness1 = Self::get_witness(
                driver,
                witness,
                zkey,
                addition.signal_id1.try_into().expect("u32 fits into usize"),
            )?;
            let witness2 = Self::get_witness(
                driver,
                witness,
                zkey,
                addition.signal_id2.try_into().expect("u32 fits into usize"),
            )?;

            let f1 = driver.mul_with_public(&addition.factor1, &witness1);
            let f2 = driver.mul_with_public(&addition.factor2, &witness2);
            let result = driver.add(&f1, &f2);
            additions.push(result);
        }
        witness.addition_witness = additions.into();
        Ok(())
    }

    fn init_round(
        driver: &mut T,
        zkey: ZKey<P>,
        public_input: Vec<P::ScalarField>,
        private_witness: SharedWitness<T, P>,
    ) -> PlonkProofResult<Self> {
        //TODO calculate additions
        //set first element to zero as it is not used
        let mut plonk_witness = PlonkWitness::from(private_witness);
        Self::calculate_additions(driver, &mut plonk_witness, &zkey);

        Ok(Round::Round1 {
            domains: Domains::new(&zkey)?,
            challenges: Round1Challenges::random(driver)?,
            data: PlonkData {
                witness: plonk_witness,
                zkey,
            },
        })
    }

    // TODO check if this is correct
    fn get_witness(
        driver: &mut T,
        witness: &PlonkWitness<T, P>,
        zkey: &ZKey<P>,
        index: usize,
    ) -> PlonkProofResult<FieldShare<T, P>> {
        let result = if index <= zkey.n_public {
            driver.promote_to_trivial_share(witness.shared_witness.public_inputs[index])
        } else if index <= zkey.n_vars - zkey.n_additions {
            //subtract public values and the leading 0 in witness
            T::index_sharevec(&witness.shared_witness.witness, index - zkey.n_public - 1)
        } else if index < zkey.n_vars {
            T::index_sharevec(
                &witness.addition_witness,
                index - zkey.n_vars + zkey.n_additions,
            )
        } else {
            //TODO make this as an error
            return Err(PlonkProofError::CorruptedWitness(index));
        };
        Ok(result)
    }

    fn blind_coefficients(
        driver: &mut T,
        poly: &FieldShareVec<T, P>,
        coeff: &[FieldShare<T, P>],
    ) -> Vec<FieldShare<T, P>> {
        let mut res = poly.clone().into_iter().collect::<Vec<_>>();
        for (p, c) in res.iter_mut().zip(coeff.iter()) {
            *p = driver.sub(p, c);
        }
        res.extend_from_slice(coeff);
        res
    }
}
