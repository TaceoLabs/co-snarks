use crate::{
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, ProverCrs, Serialize, Utils},
};
use mpc_net::Network;

pub mod co_shplemini;
pub mod keccak_hash;
pub mod mpc;
pub mod shared_polynomial;
pub mod shplemini;
pub mod sponge_hasher;
pub mod transcript;

const NUM_SMALL_IPA_EVALUATIONS: usize = 4;
// ECCVM constants:
pub const CONST_ECCVM_LOG_N: usize = 16;
pub const ECCVM_FIXED_SIZE: usize = 1usize << CONST_ECCVM_LOG_N;
pub const NUM_TRANSLATION_OPENING_CLAIMS: usize = NUM_SMALL_IPA_EVALUATIONS + 1;
pub const NUM_OPENING_CLAIMS: usize = NUM_TRANSLATION_OPENING_CLAIMS + 1;
pub const NUM_LIMB_BITS_IN_FIELD_SIMULATION: usize = 68;
pub const NUM_SCALAR_BITS: usize = 128; // The length of scalars handled by the ECCVVM
pub const NUM_WNAF_DIGIT_BITS: usize = 4; // Scalars are decompose into base 16 in wNAF form
pub const NUM_WNAF_DIGITS_PER_SCALAR: usize = NUM_SCALAR_BITS / NUM_WNAF_DIGIT_BITS; // 32
pub const WNAF_MASK: u64 = (1 << NUM_WNAF_DIGIT_BITS) - 1;
pub const POINT_TABLE_SIZE: usize = 1 << (NUM_WNAF_DIGIT_BITS);
pub const WNAF_DIGITS_PER_ROW: usize = 4;
pub const ADDITIONS_PER_ROW: usize = 4;
pub const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

// Translator constants:
pub const CONST_TRANSLATOR_LOG_N: usize = 18;
pub const NUM_BINARY_LIMBS: usize = 4;
pub const NUM_Z_LIMBS: usize = 2;
pub const NUM_MICRO_LIMBS: usize = 6;
pub const NUM_RELATION_WIDE_LIMBS: usize = 2;
pub const NUM_LAST_LIMB_BITS: usize = 50;
pub const NUM_QUOTIENT_BITS: usize = 256;
pub const NUM_Z_BITS: usize = 128;
pub const MICRO_LIMB_BITS: usize = 14;

pub fn compute_opening_proof<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
>(
    opening_claim: shplemini::ShpleminiOpeningClaim<P::ScalarField>,
    transcript: &mut Transcript<TranscriptFieldType, H>,
    crs: &ProverCrs<P>,
) -> HonkProofResult<()> {
    let mut quotient = opening_claim.polynomial;
    let pair = opening_claim.opening_pair;
    quotient[0] -= pair.evaluation;
    // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
    quotient.factor_roots(&pair.challenge);
    let quotient_commitment = Utils::commit(&quotient.coefficients, crs)?;
    // AZTEC TODO(#479): compute_opening_proof
    // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
    // pthreads) or even the work queue itself
    transcript.send_point_to_verifier::<P>("KZG:W".to_string(), quotient_commitment.into());
    Ok(())
}

pub fn compute_co_opening_proof<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
>(
    net: &N,
    state: &mut T::State,
    opening_claim: co_shplemini::ShpleminiOpeningClaim<T, P>,
    transcript: &mut Transcript<TranscriptFieldType, H>,
    crs: &ProverCrs<P>,
) -> HonkProofResult<()> {
    let mut quotient = opening_claim.polynomial;
    let pair = opening_claim.opening_pair;

    quotient[0] = T::sub(quotient[0], pair.evaluation);
    // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
    quotient.factor_roots(&pair.challenge);
    let quotient_commitment = CoUtils::commit::<T, P>(&quotient.coefficients, crs);
    // AZTEC TODO(#479): for now we compute the KZG commitment directly to unify the KZG and IPA interfaces but in the
    // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
    // pthreads) or even the work queue itself
    let quotient_commitment = T::open_point(quotient_commitment, net, state)?;
    transcript.send_point_to_verifier::<P>("KZG:W".to_string(), quotient_commitment.into());
    Ok(())
}

pub struct CoUtils {}

impl CoUtils {
    pub fn commit<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        poly: &[T::ArithmeticShare],
        crs: &ProverCrs<P>,
    ) -> T::PointShare {
        Self::msm::<T, P>(poly, &crs.monomials)
    }

    pub fn msm<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        poly: &[T::ArithmeticShare],
        crs: &[P::Affine],
    ) -> T::PointShare {
        let len = poly.len();
        T::msm_public_points(&crs[..len], poly)
    }

    pub fn batch_invert<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        poly: &mut [T::ArithmeticShare],
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<()> {
        T::inv_many_in_place(poly, net, state)
    }

    pub fn batch_invert_leaking_zeros<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        poly: &mut [T::ArithmeticShare],
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<()> {
        T::inv_many_in_place_leaking_zeros(poly, net, state)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HonkProof<F: PrimeField> {
    proof: Vec<F>,
}

impl<F: PrimeField> HonkProof<F> {
    pub fn new(proof: Vec<F>) -> Self {
        Self { proof }
    }

    pub fn inner(self) -> Vec<F> {
        self.proof
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        Serialize::to_buffer(&self.proof, false)
    }

    pub fn from_buffer(buf: &[u8]) -> HonkProofResult<Self> {
        let res = Serialize::from_buffer(buf, false)?;
        Ok(Self::new(res))
    }

    pub fn separate_proof_and_public_inputs(self, num_public_inputs: usize) -> (Self, Vec<F>) {
        let (public_inputs, proof) = self.proof.split_at(num_public_inputs);
        (Self::new(proof.to_vec()), public_inputs.to_vec())
    }

    pub fn insert_public_inputs(self, public_inputs: Vec<F>) -> Self {
        let mut proof = public_inputs;
        proof.extend(self.proof.to_owned());
        Self::new(proof)
    }
}
