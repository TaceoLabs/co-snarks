use ark_ec::AffineRepr;
use ark_ff::One;
use ark_ff::{Field, Zero};
use co_builder::eccvm::CONST_ECCVM_LOG_N;
use co_noir_common::CoUtils;
use co_noir_common::co_shplemini::ShpleminiOpeningClaim;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::transcript::{Transcript, TranscriptHasher};
use mpc_net::Network;
use ultrahonk::Utils as UltraHonkUtils;

pub(crate) fn compute_ipa_opening_proof<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, T, P>,
    N: Network,
>(
    net: &N,
    state: &mut T::State,
    transcript: &mut Transcript<TranscriptFieldType, H, T, P>,
    opening_claim: ShpleminiOpeningClaim<T, P>,
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
    let aux_generator = P::Affine::generator() * generator_challenge;

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
    let mut b_power = P::ScalarField::one();
    for _ in 0..poly_length {
        b_vec.push(b_power);
        b_power *= opening_claim.opening_pair.challenge;
    }

    // Allocate space for L_i and R_i elements
    let mut l_i: T::PointShare;
    let mut r_i: T::PointShare;
    let mut round_size = poly_length;

    // Step 6.
    // Perform IPA reduction rounds
    for i in 0..log_poly_length {
        round_size /= 2;

        // Run scalar products in parallel
        let inner_prods: Vec<(_, _)> = (0..round_size)
            .map(|j| {
                let inner_prod_l = T::mul_with_public(b_vec[round_size + j], a_vec[j]);
                let inner_prod_r = T::mul_with_public(b_vec[j], a_vec[round_size + j]);
                (inner_prod_l, inner_prod_r)
            })
            .collect();

        // Sum inner product contributions computed in parallel and unpack the tuple
        let (inner_prod_l, inner_prod_r) = inner_prods.iter().fold(
            (T::ArithmeticShare::default(), T::ArithmeticShare::default()),
            |(acc_l, acc_r), (prod_l, prod_r)| (T::add(acc_l, *prod_l), T::add(acc_r, *prod_r)),
        );

        // Step 6.a (using letters, because doxygen automatically converts the sublist counters to letters :( )
        // L_i = < a_vec_lo, G_vec_hi > + inner_prod_L * aux_generator
        l_i = CoUtils::msm::<T, P>(
            &a_vec.coefficients[0..round_size],
            &g_vec_local[round_size..2 * round_size],
        );
        l_i = T::point_add(
            &l_i,
            &T::scalar_mul_public_point(&aux_generator, inner_prod_l),
        );

        // Step 6.b
        // R_i = < a_vec_hi, G_vec_lo > + inner_prod_R * aux_generator
        r_i = CoUtils::msm::<T, P>(
            &a_vec.coefficients[round_size..2 * round_size],
            &g_vec_local[0..round_size],
        );

        r_i = T::point_add(
            &r_i,
            &T::scalar_mul_public_point(&aux_generator, inner_prod_r),
        );

        // Step 6.c
        // Send commitments to the verifier
        //TACEO TODO: Can this be avoided somehow?
        let open = T::open_point_many(&[l_i, r_i], net, state)?;
        let open_l_i = open[0];
        let open_r_i = open[1];

        let index = (CONST_ECCVM_LOG_N - i as usize - 1).to_string();
        transcript.send_point_to_verifier::<P>(format!("IPA:L_{index}"), open_l_i.into());
        transcript.send_point_to_verifier::<P>(format!("IPA:R_{index}"), open_r_i.into());
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
            let mut tmp = a_vec[round_size + j];
            T::mul_assign_with_public(&mut tmp, round_challenge);
            T::add_assign(&mut a_vec[j], tmp);
            let tmp = b_vec[round_size + j];
            b_vec[j] += tmp * round_challenge_inv;
        }
    }
    // For dummy rounds, send commitments of zero()
    for i in log_poly_length..CONST_ECCVM_LOG_N as u32 {
        let index = CONST_ECCVM_LOG_N - i as usize - 1;
        transcript.send_point_to_verifier::<P>(format!("IPA:L_{index}"), P::Affine::generator());
        transcript.send_point_to_verifier::<P>(format!("IPA:R_{index}"), P::Affine::generator());
        transcript.get_challenge::<P>(format!("IPA:round_challenge_{index}"));
    }

    // Step 7
    // Send G_0 to the verifier
    transcript.send_point_to_verifier::<P>("IPA:G_0".to_string(), g_vec_local[0]);

    // Step 8
    // Send a_0 to the verifier
    let opened = T::open_many(&[a_vec[0]], net, state)?;
    transcript.send_fr_to_verifier::<P>("IPA:a_0".to_string(), opened[0]);
    Ok(())
}
