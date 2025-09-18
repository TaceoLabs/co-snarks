use crate::{
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
};
use ark_ec::CurveGroup;
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, ProverCrs, Utils},
};
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
}
