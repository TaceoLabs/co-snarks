use ark_ff::{Field, Zero};
use co_builder::{
    HonkProofResult, TranscriptFieldType,
    prelude::{HonkCurve, ProverCrs},
};
use ultrahonk::Utils as UltraHonkUtils;
use ultrahonk::prelude::{ShpleminiOpeningClaim, Transcript, TranscriptHasher};

use crate::CONST_ECCVM_LOG_N;

pub(crate) fn compute_ipa_opening_proof<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
>(
    transcript: &mut Transcript<TranscriptFieldType, H>,
    opening_claim: ShpleminiOpeningClaim<P::ScalarField>,
    commitment_key: &ProverCrs<P>,
) -> HonkProofResult<()> {
    // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1150): Hash more things here.
    // Step 1.
    // Send polynomial degree + 1 = d to the verifier
    let poly_length = opening_claim.polynomial.len();
    let log_poly_length = UltraHonkUtils::get_msb64(poly_length as u64);
    if log_poly_length > CONST_ECCVM_LOG_N as u32 {
        panic!("IPA log_poly_length is too large: {log_poly_length}");
    }
    transcript.send_u64_to_verifier("IPA:poly_degree_plus_1".to_string(), poly_length as u64);

    // Step 2.
    // Receive challenge for the auxiliary generator
    let generator_challenge = transcript.get_challenge::<P>("IPA:generator_challenge".to_string());

    if generator_challenge.is_zero() {
        panic!("The generator challenge can't be zero");
    }

    // Step 3.
    // Compute auxiliary generator U
    let aux_generator = commitment_key.monomials[0] * generator_challenge;

    // Checks poly_degree is greater than zero and a power of two
    // In the future, we might want to consider if non-powers of two are needed
    assert!(
        (poly_length > 0) && (poly_length & (poly_length - 1) == 0),
        "The polynomial degree plus 1 should be positive and a power of two"
    );

    // Step 4.
    // Set initial vector a to the polynomial monomial coefficients and load vector G
    // Ensure the polynomial copy is fully-formed
    let mut a_vec = opening_claim.polynomial.clone();
    let mut g_vec_local = commitment_key.monomials[..poly_length].to_vec();

    if poly_length > commitment_key.monomials.len() {
        panic!("potential bug: Not enough SRS points for IPA!");
    }

    // Step 5.
    // Compute vector b (vector of the powers of the challenge)
    let mut b_vec = Vec::with_capacity(poly_length);
    let mut b_power = opening_claim.opening_pair.challenge.pow([0u64]);
    for _ in 0..poly_length {
        b_vec.push(b_power);
        b_power *= opening_claim.opening_pair.challenge;
    }

    // Allocate space for L_i and R_i elements
    let mut l_i: P;
    let mut r_i: P;
    let mut round_size = poly_length;

    // Step 6.
    // Perform IPA reduction rounds
    for i in 0..log_poly_length {
        round_size /= 2;

        // Run scalar products in parallel
        let inner_prods: Vec<(P::ScalarField, P::ScalarField)> = (0..round_size)
            .map(|j| {
                let inner_prod_l = a_vec[j] * b_vec[round_size + j];
                let inner_prod_r = a_vec[round_size + j] * b_vec[j];
                (inner_prod_l, inner_prod_r)
            })
            .collect();

        // Sum inner product contributions computed in parallel and unpack the tuple
        let (inner_prod_l, inner_prod_r) = inner_prods.iter().fold(
            (P::ScalarField::zero(), P::ScalarField::zero()),
            |(acc_l, acc_r), (prod_l, prod_r)| (acc_l + prod_l, acc_r + prod_r),
        );

        // Step 6.a (using letters, because doxygen automatically converts the sublist counters to letters :( )
        // L_i = < a_vec_lo, G_vec_hi > + inner_prod_L * aux_generator
        l_i = UltraHonkUtils::msm::<P>(
            &a_vec.coefficients[0..round_size],
            &g_vec_local[round_size..2 * round_size],
        )?;

        l_i += aux_generator * inner_prod_l;

        // Step 6.b
        // R_i = < a_vec_hi, G_vec_lo > + inner_prod_R * aux_generator
        r_i = UltraHonkUtils::msm::<P>(
            &a_vec.coefficients[round_size..2 * round_size],
            &g_vec_local[0..round_size],
        )?;
        r_i += aux_generator * inner_prod_r;

        // Step 6.c
        // Send commitments to the verifier
        let index = (CONST_ECCVM_LOG_N - i as usize - 1).to_string();
        transcript.send_point_to_verifier::<P>(format!("IPA:L_{index}"), l_i.into());
        transcript.send_point_to_verifier::<P>(format!("IPA:R_{index}"), r_i.into());

        // Step 6.d
        // Receive the challenge from the verifier
        let round_challenge = transcript.get_challenge::<P>(format!("IPA:round_challenge_{index}"));

        if round_challenge.is_zero() {
            panic!("IPA round challenge is zero");
        }
        let round_challenge_inv = round_challenge
            .inverse()
            .expect("IPA round challenge should not be zero");

        // Step 6.e
        // G_vec_new = G_vec_lo + G_vec_hi * round_challenge_inv
        let g_hi_by_inverse_challenge: Vec<_> = g_vec_local[round_size..2 * round_size]
            .iter()
            .map(|g| *g * round_challenge_inv)
            .collect();
        for j in 0..round_size {
            g_vec_local[j] = (g_vec_local[j] + g_hi_by_inverse_challenge[j]).into();
        }

        // Steps 6.e and 6.f
        // Update the vectors a_vec, b_vec.
        // a_vec_new = a_vec_lo + a_vec_hi * round_challenge
        // b_vec_new = b_vec_lo + b_vec_hi * round_challenge_inv
        for j in 0..round_size {
            let tmp = a_vec[round_size + j];
            a_vec[j] += tmp * round_challenge;
            let tmp = b_vec[round_size + j];
            b_vec[j] += tmp * round_challenge_inv;
        }
    }
    Ok(())
}

// // For dummy rounds, send commitments of zero()
// for i in log_poly_length..CONST_ECCVM_LOG_N as u32 {
//     let index = CONST_ECCVM_LOG_N - i as usize - 1;
//     transcript.send_to_verifier(format!("IPA:L_{}", index), P::G1::zero());
//     transcript.send_to_verifier(format!("IPA:R_{}", index), P::G1::zero());
//     transcript.get_challenge::<P::ScalarField>(format!("IPA:round_challenge_{}", index));
// }

// // Step 7
// // Send G_0 to the verifier
// transcript.send_to_verifier("IPA:G_0".to_string(), g_vec_local[0]);

// // Step 8
// // Send a_0 to the verifier
// transcript.send_to_verifier("IPA:a_0".to_string(), a_vec[0]);
