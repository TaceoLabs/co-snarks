use crate::barycentric::Barycentric;
use crate::{
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
};
use ark_ec::CurveGroup;
use ark_ff::{One, Zero};
use co_builder::prelude::{NUM_MASKED_ROWS, Polynomial};
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, ProverCrs, Utils},
};
use itertools::izip;
use mpc_net::Network;

pub mod barycentric;
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

    pub fn batch_invert_or_zero_many<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        poly: &mut [T::ArithmeticShare],
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<()> {
        T::inverse_or_zero_many_in_place(net, state, poly)
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
            // polynomial.coefficients[i] = T::rand(net, state)?; // TODO FLORIN
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
    // Batched version of the above, multiplies every inner array separately
    pub fn array_prod_inner_mul_many<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        net: &N,
        state: &mut T::State,
        inp: &[Vec<T::ArithmeticShare>],
    ) -> eyre::Result<Vec<Vec<T::ArithmeticShare>>> {
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let depth = inp.len();
        let width = inp[0].len();
        debug_assert!(
            inp.iter().all(|v| v.len() == width),
            "All input slices must have the same length"
        );

        let r = (0..(width + 1) * depth)
            .map(|_| T::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let r_inv = T::inv_many(&r, net, state)?;
        let mut r_inv0s = Vec::with_capacity(depth * width);
        let mut r_chunks = Vec::with_capacity(depth * width);
        let mut mul_r = Vec::with_capacity(depth * width);
        let mut r_invs_mul = Vec::with_capacity(depth * width);

        for (r_, r_inv_) in izip!(r.chunks(width + 1), r_inv.chunks(width + 1)) {
            r_inv0s.extend(vec![r_inv_[0]; width]);
            r_chunks.extend(r_[1..].to_vec());
            mul_r.extend(r_[..width].to_vec());
            r_invs_mul.extend(r_inv_[1..].to_vec());
        }

        let mut unblind = T::mul_many(&r_inv0s, &r_chunks, net, state)?;

        let input = inp.iter().flatten().cloned().collect::<Vec<_>>();

        let mul = T::mul_many(&mul_r, &input, net, state)?;
        let mut open = T::mul_open_many(&mul, &r_invs_mul, net, state)?;

        for open_ in open.chunks_mut(width) {
            for i in 1..open_.len() {
                open_[i] *= open_[i - 1];
            }
        }

        for (unblind, open) in unblind.iter_mut().zip(open.iter()) {
            *unblind = T::mul_with_public(*open, *unblind);
        }

        let mut out = Vec::with_capacity(depth);
        for chunk in unblind.chunks(width) {
            out.push(chunk.to_vec());
        }

        Ok(out)
    }

    pub fn evaluate<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        evaluations: &[T::ArithmeticShare],
        u: P::ScalarField,
    ) -> T::ArithmeticShare {
        if u == P::ScalarField::zero() {
            return evaluations[0];
        }
        let size = evaluations.len();

        let mut full_numerator_value = P::ScalarField::one();
        for i in 0..size {
            full_numerator_value *= u - P::ScalarField::from(i as u64);
        }

        let big_domain = Barycentric::construct_big_domain(evaluations.len(), size);
        let lagrange_denominators = Barycentric::construct_lagrange_denominators(size, &big_domain);

        let mut denominator_inverses = vec![P::ScalarField::zero(); size];
        for i in 0..size {
            let mut inv = lagrange_denominators[i];

            inv *= u - big_domain[i];
            inv = P::ScalarField::one() / inv;
            denominator_inverses[i] = inv;
        }

        let mut result = T::ArithmeticShare::default();
        // Compute each term v_j / (d_j*(x-x_j)) of the sum
        for (i, &inverse) in denominator_inverses.iter().enumerate() {
            let mut term = evaluations[i];
            T::mul_assign_with_public(&mut term, inverse);
            T::add_assign(&mut result, term);
        }

        // Scale the sum by the value of B(x)
        T::mul_assign_with_public(&mut result, full_numerator_value);
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::{CoUtils, mpc::plain::PlainUltraHonkDriver};
    use ark_ff::UniformRand;
    use rand::thread_rng;

    // This is only for the plaindriver
    #[test]
    fn array_prod_inner_mul_many_test() {
        let vec_size = 4;
        let entries = 3;
        let mut rng = thread_rng();
        let mut input = Vec::with_capacity(vec_size);
        for _ in 0..vec_size {
            let mut tmp = Vec::with_capacity(entries);
            for _ in 0..entries {
                tmp.push(ark_bn254::Fr::rand(&mut rng));
            }
            input.push(tmp);
        }
        let is_result = CoUtils::array_prod_inner_mul_many::<
            PlainUltraHonkDriver,
            ark_bn254::G1Projective,
            _,
        >(&(), &mut (), &input)
        .unwrap();
        let should_result = {
            let mut out = Vec::with_capacity(vec_size);
            for inp in input.iter() {
                let mut tmp = Vec::with_capacity(entries);
                let mut acc = ark_bn254::Fr::from(1u64);
                for &i in inp.iter() {
                    acc *= i;
                    tmp.push(acc);
                }
                out.push(tmp);
            }
            out
        };
        assert_eq!(is_result, should_result);
    }
}
