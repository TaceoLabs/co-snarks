use crate::{
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, NUM_MASKED_ROWS, Polynomial, ProverCrs, Serialize, Utils},
};
use itertools::izip;
use mpc_net::Network;

pub mod co_shplemini;
pub mod keccak_hash;
pub mod mpc;
pub mod shared_polynomial;
pub mod shplemini;
pub mod sponge_hasher;
pub mod transcript;

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

    pub fn mask_polynomial<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        net: &N,
        state: &mut T::State,
        polynomial: &mut Polynomial<T::ArithmeticShare>,
    ) -> HonkProofResult<()> {
        tracing::trace!("mask polynomial");

        let virtual_size = polynomial.coefficients.len();
        assert!(
            virtual_size >= NUM_MASKED_ROWS as usize,
            "Insufficient space for masking"
        );
        for i in (virtual_size - NUM_MASKED_ROWS as usize..virtual_size).rev() {
            polynomial.coefficients[i] = T::rand(net, state)?;
        }

        Ok(())
    }
    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    pub fn array_prod_mul<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        net: &N,
        state: &mut T::State,
        inp: &[T::ArithmeticShare],
    ) -> eyre::Result<Vec<T::ArithmeticShare>> {
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let len = inp.len();

        let r = (0..=len)
            .map(|_| T::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let r_inv = T::inv_many(&r, net, state)?;
        let r_inv0 = vec![r_inv[0]; len];

        let mut unblind = T::mul_many(&r_inv0, &r[1..], net, state)?;

        let mul = T::mul_many(&r[..len], inp, net, state)?;
        let mut open = T::mul_open_many(&mul, &r_inv[1..], net, state)?;

        for i in 1..open.len() {
            open[i] = open[i] * open[i - 1];
        }

        for (unblind, open) in unblind.iter_mut().zip(open.iter()) {
            *unblind = T::mul_with_public(*open, *unblind);
        }
        Ok(unblind)
    }
    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    //TODO FLORIN TEST AND CLEAN THIS UP
    pub fn array_prod_mul_many<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        net: &N,
        state: &mut T::State,
        inp: Vec<Vec<T::ArithmeticShare>>,
    ) -> eyre::Result<Vec<Vec<T::ArithmeticShare>>> {
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let vector_size = inp.len();
        let len = inp[0].len();
        debug_assert!(
            inp.iter().all(|v| v.len() == len),
            "All input slices must have the same length"
        );

        let r = (0..=vector_size * (len + 1))
            .map(|_| T::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let r_inv = T::inv_many(&r, net, state)?;
        let mut r_invs = Vec::with_capacity(vector_size * len);
        let mut r_chunks = Vec::with_capacity(vector_size * len);
        let mut mul_r = Vec::with_capacity(vector_size * len);
        let mut r_invs_mul = Vec::with_capacity(vector_size * len);
        for (r_, r_inv_) in izip!(r.chunks(len), r_inv.chunks(len)) {
            r_invs.extend(vec![r_inv_[0]; len]);
            r_chunks.extend(r_[1..].to_vec());
            mul_r.extend(r_[..len].to_vec());
            r_invs_mul.extend(r_inv_[1..].to_vec());
        }

        let mut unblind = T::mul_many(&r_invs, &r_chunks, net, state)?;

        // Flatten inp (Vec<&[T::ArithmeticShare]>) into one contiguous vector
        let flat_inp = inp.concat();
        let mul = T::mul_many(&mul_r, &flat_inp, net, state)?;
        let mut open = T::mul_open_many(&mul, &r_invs_mul, net, state)?;

        for open_ in open.chunks_mut(len) {
            for i in 1..open_.len() {
                open_[i] *= open_[i - 1];
            }
        }

        for (unblind, open) in unblind.iter_mut().zip(open.iter()) {
            *unblind = T::mul_with_public(*open, *unblind);
        }
        Ok(unblind.chunks(len).map(|c| c.to_vec()).collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HonkProof<F: PrimeField> {
    proof: Vec<F>,
}

impl<F: PrimeField> HonkProof<F> {
    pub(crate) fn new(proof: Vec<F>) -> Self {
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
