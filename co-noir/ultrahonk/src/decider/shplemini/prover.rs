use super::{
    super::{prover::Decider, sumcheck::SumcheckOutput},
    types::{PolyF, PolyG},
    ShpleminiOpeningClaim,
};
use crate::{
    decider::{shplemini::OpeningPair, verifier::DeciderVerifier},
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
    types::AllEntities,
    Utils, CONST_PROOF_SIZE_LOG_N,
};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use co_builder::{
    prelude::{HonkCurve, Polynomial, ProverCrs},
    HonkProofResult,
};

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> Decider<P, H> {
    fn get_f_polynomials(polys: &AllEntities<Vec<P::ScalarField>>) -> PolyF<Vec<P::ScalarField>> {
        PolyF {
            precomputed: &polys.precomputed,
            witness: &polys.witness,
        }
    }

    fn get_g_polynomials(polys: &AllEntities<Vec<P::ScalarField>>) -> PolyG<Vec<P::ScalarField>> {
        PolyG {
            wires: polys.witness.to_be_shifted().try_into().unwrap(),
        }
    }

    fn compute_batched_polys(
        &self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        n: usize,
    ) -> (Polynomial<P::ScalarField>, Polynomial<P::ScalarField>) {
        let f_polynomials = Self::get_f_polynomials(&self.memory.polys);
        let g_polynomials = Self::get_g_polynomials(&self.memory.polys);

        // Generate batching challenge \rho and powers 1,...,\rho^{m-1}
        let rho = transcript.get_challenge::<P>("rho".to_string());

        // Compute batching of unshifted polynomials f_i and to-be-shifted polynomials g_i:
        // f_batched = sum_{i=0}^{m-1}\rho^i*f_i and g_batched = sum_{i=0}^{l-1}\rho^{m+i}*g_i,
        // and also batched evaluation
        // v = sum_{i=0}^{m-1}\rho^i*f_i(u) + sum_{i=0}^{l-1}\rho^{m+i}*h_i(u).
        // Note: g_batched is formed from the to-be-shifted polynomials, but the batched evaluation incorporates the
        // evaluations produced by sumcheck of h_i = g_i_shifted.

        let mut rho_challenge = P::ScalarField::ONE;
        let mut batched_unshifted = Polynomial::new_zero(n); // batched unshifted polynomials

        for f_poly in f_polynomials.iter() {
            batched_unshifted.add_scaled_slice(f_poly, &rho_challenge);
            rho_challenge *= rho;
        }

        let mut batched_to_be_shifted = Polynomial::new_zero(n); // batched to-be-shifted polynomials

        for g_poly in g_polynomials.iter() {
            batched_to_be_shifted.add_scaled_slice(g_poly, &rho_challenge);
            rho_challenge *= rho;
        }

        (batched_unshifted, batched_to_be_shifted)
    }

    // /**
    //  * @brief Protocol for opening several multi-linear polynomials at the same point.
    //  *
    //  *
    //  * m = number of variables
    //  * n = 2ᵐ
    //  * u = (u₀,...,uₘ₋₁)
    //  * f₀, …, fₖ₋₁ = multilinear polynomials,
    //  * g₀, …, gₕ₋₁ = shifted multilinear polynomial,
    //  *  Each gⱼ is the left-shift of some f↺ᵢ, and gⱼ points to the same memory location as fᵢ.
    //  * v₀, …, vₖ₋₁, v↺₀, …, v↺ₕ₋₁ = multilinear evalutions  s.t. fⱼ(u) = vⱼ, and gⱼ(u) = f↺ⱼ(u) = v↺ⱼ
    //  *
    //  * We use a challenge ρ to create a random linear combination of all fⱼ,
    //  * and actually define A₀ = F + G↺, where
    //  *   F  = ∑ⱼ ρʲ fⱼ
    //  *   G  = ∑ⱼ ρᵏ⁺ʲ gⱼ,
    //  *   G↺ = is the shift of G
    //  * where fⱼ is normal, and gⱼ is shifted.
    //  * The evaluations are also batched, and
    //  *   v  = ∑ ρʲ⋅vⱼ + ∑ ρᵏ⁺ʲ⋅v↺ⱼ = F(u) + G↺(u)
    //  *
    //  * The prover then creates the folded polynomials A₀, ..., Aₘ₋₁,
    //  * and opens them at different points, as univariates.
    //  *
    //  * We open A₀ as univariate at r and -r.
    //  * Since A₀ = F + G↺, but the verifier only has commitments to the gⱼs,
    //  * we need to partially evaluate A₀ at both evaluation points.
    //  * As univariate, we have
    //  *  A₀(X) = F(X) + G↺(X) = F(X) + G(X)/X
    //  * So we define
    //  *  - A₀₊(X) = F(X) + G(X)/r
    //  *  - A₀₋(X) = F(X) − G(X)/r
    //  * So that A₀₊(r) = A₀(r) and A₀₋(-r) = A₀(-r).
    //  * The verifier is able to computed the simulated commitments to A₀₊(X) and A₀₋(X)
    //  * since they are linear-combinations of the commitments [fⱼ] and [gⱼ].
    //  */
    pub(crate) fn gemini_prove(
        &self,
        multilinear_challenge: Vec<P::ScalarField>,
        log_n: usize,
        commitment_key: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<Vec<ShpleminiOpeningClaim<P::ScalarField>>> {
        tracing::trace!("Gemini prove");
        let n = 1 << log_n;

        // Compute batched polynomials
        let (batched_unshifted, batched_to_be_shifted) = self.compute_batched_polys(transcript, n);

        // Construct the batched polynomial A₀(X) = F(X) + G↺(X) = F(X) + G(X)/X
        let mut a_0 = batched_unshifted.to_owned();
        a_0 += batched_to_be_shifted.shifted().as_ref();

        // Construct the d-1 Gemini foldings of A₀(X)
        let fold_polynomials = Self::compute_fold_polynomials(log_n, multilinear_challenge, a_0);

        for (l, f_poly) in fold_polynomials
            .iter()
            .take(CONST_PROOF_SIZE_LOG_N)
            .enumerate()
        {
            let res = Utils::commit(&f_poly.coefficients, commitment_key)?;
            transcript.send_point_to_verifier::<P>(format!("Gemini:a_{}", l + 1), res.into());
        }
        let res = P::G1Affine::generator();
        for l in fold_polynomials.len()..CONST_PROOF_SIZE_LOG_N - 1 {
            transcript.send_point_to_verifier::<P>(format!("Gemini:a_{}", l + 1), res);
        }

        let r_challenge: P::ScalarField = transcript.get_challenge::<P>("Gemini:r".to_string());

        let (a_0_pos, a_0_neg) = Self::compute_partially_evaluated_batch_polynomials(
            batched_unshifted,
            batched_to_be_shifted,
            r_challenge,
        );

        let claims = Self::construct_univariate_opening_claims(
            log_n,
            a_0_pos,
            a_0_neg,
            fold_polynomials,
            r_challenge,
        );

        for (l, claim) in claims
            .iter()
            .skip(1)
            .take(CONST_PROOF_SIZE_LOG_N)
            .enumerate()
        {
            transcript
                .send_fr_to_verifier::<P>(format!("Gemini:a_{}", l), claim.opening_pair.evaluation);
        }
        for l in claims.len()..=CONST_PROOF_SIZE_LOG_N {
            transcript.send_fr_to_verifier::<P>(format!("Gemini:a_{}", l), P::ScalarField::zero());
        }

        Ok(claims)
    }

    pub(crate) fn compute_fold_polynomials(
        log_n: usize,
        multilinear_challenge: Vec<P::ScalarField>,
        a_0: Polynomial<P::ScalarField>,
    ) -> Vec<Polynomial<P::ScalarField>> {
        tracing::trace!("Compute fold polynomials");
        // Note: bb uses multithreading here
        let mut fold_polynomials = Vec::with_capacity(log_n - 1);

        // A_l = Aₗ(X) is the polynomial being folded
        // in the first iteration, we take the batched polynomial
        // in the next iteration, it is the previously folded one
        let mut a_l = a_0.coefficients;
        debug_assert!(multilinear_challenge.len() >= log_n - 1);
        for (l, u_l) in multilinear_challenge
            .into_iter()
            .take(log_n - 1)
            .enumerate()
        {
            // size of the previous polynomial/2
            let n_l = 1 << (log_n - l - 1);

            // A_l_fold = Aₗ₊₁(X) = (1-uₗ)⋅even(Aₗ)(X) + uₗ⋅odd(Aₗ)(X)
            let mut a_l_fold = Polynomial::new_zero(n_l);

            // Process each element in a single-threaded manner
            for j in 0..n_l {
                // fold(Aₗ)[j] = (1-uₗ)⋅even(Aₗ)[j] + uₗ⋅odd(Aₗ)[j]
                //            = (1-uₗ)⋅Aₗ[2j]      + uₗ⋅Aₗ[2j+1]
                //            = Aₗ₊₁[j]
                a_l_fold[j] = a_l[j << 1] + u_l * (a_l[(j << 1) + 1] - a_l[j << 1]);
            }

            // Set Aₗ₊₁ = Aₗ for the next iteration
            fold_polynomials.push(a_l_fold.clone());
            a_l = a_l_fold.coefficients;
        }

        fold_polynomials
    }

    // /**
    //  * @brief Computes partially evaluated batched polynomials A₀₊(X) = F(X) + G(X)/r and A₀₋(X) = F(X) - G(X)/r
    //  *
    fn compute_partially_evaluated_batch_polynomials(
        batched_f: Polynomial<P::ScalarField>,
        mut batched_g: Polynomial<P::ScalarField>,
        r_challenge: P::ScalarField,
    ) -> (Polynomial<P::ScalarField>, Polynomial<P::ScalarField>) {
        tracing::trace!("Compute_partially_evaluated_batch_polynomials");

        let mut a_0_pos = batched_f.to_owned(); // A₀₊ = F
        let mut a_0_neg = batched_f; // A₀₋ = F

        // Compute G/r
        let r_inv = r_challenge.inverse().unwrap();
        batched_g.iter_mut().for_each(|x| {
            *x *= r_inv;
        });

        a_0_pos += batched_g.as_ref(); // A₀₊ = F + G/r
        a_0_neg -= batched_g.as_ref(); // A₀₋ = F - G/r

        (a_0_pos, a_0_neg)
    }

    // /**
    //  *
    //  * @param mle_opening_point u = (u₀,...,uₘ₋₁) is the MLE opening point
    //  * @param fold_polynomials vector of polynomials whose first two elements are F(X) = ∑ⱼ ρʲfⱼ(X)
    //  * and G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X), and the next d-1 elements are Fold_i, i = 1, ..., d-1.
    //  * @param r_challenge univariate opening challenge
    //  */
    // /**
    //  * @brief Computes/aggragates d+1 univariate polynomial opening claims of the form {polynomial, (challenge, evaluation)}
    //  *
    //  * @details The d+1 evaluations are A₀₊(r), A₀₋(-r), and Aₗ(−r^{2ˡ}) for l = 1, ..., d-1, where the Aₗ are the fold
    //  * polynomials.
    //  *
    //  * @param A_0_pos A₀₊
    //  * @param A_0_neg A₀₋
    //  * @param fold_polynomials Aₗ, l = 1, ..., d-1
    //  * @param r_challenge
    //  * @return std::vector<typename GeminiProver_<Curve>::Claim> d+1 univariate opening claims
    //  */
    fn construct_univariate_opening_claims(
        log_n: usize,
        a_0_pos: Polynomial<P::ScalarField>,
        a_0_neg: Polynomial<P::ScalarField>,
        fold_polynomials: Vec<Polynomial<P::ScalarField>>,
        r_challenge: P::ScalarField,
    ) -> Vec<ShpleminiOpeningClaim<P::ScalarField>> {
        let mut claims = Vec::with_capacity(log_n + 1);

        // Compute evaluation of partially evaluated batch polynomial (positive) A₀₊(r)
        let evaluation = a_0_pos.eval_poly(r_challenge);
        claims.push(ShpleminiOpeningClaim {
            polynomial: a_0_pos,
            opening_pair: OpeningPair {
                challenge: r_challenge,
                evaluation,
            },
        });
        // Compute evaluation of partially evaluated batch polynomial (negative) A₀₋(-r)
        let evaluation = a_0_neg.eval_poly(-r_challenge);
        claims.push(ShpleminiOpeningClaim {
            polynomial: a_0_neg,
            opening_pair: OpeningPair {
                challenge: -r_challenge,
                evaluation,
            },
        });

        // Compute univariate opening queries rₗ = r^{2ˡ} for l = 0, 1, ..., m-1
        let r_squares = DeciderVerifier::<P, H>::powers_of_evaluation_challenge(r_challenge, log_n);

        // Compute the remaining m opening pairs {−r^{2ˡ}, Aₗ(−r^{2ˡ})}, l = 1, ..., m-1.

        for (r_square, fold_poly) in r_squares.into_iter().skip(1).zip(fold_polynomials) {
            let evaluation = fold_poly.eval_poly(-r_square);
            claims.push(ShpleminiOpeningClaim {
                polynomial: fold_poly,
                opening_pair: OpeningPair {
                    challenge: -r_square,
                    evaluation,
                },
            });
        }

        claims
    }

    /**
     * @brief Returns a batched opening claim equivalent to a set of opening claims consisting of polynomials, each
     * opened at a single point.
     *
     * @param commitment_key
     * @param opening_claims
     * @param transcript
     * @return ProverOpeningClaim<Curve>
     */
    pub(crate) fn shplonk_prove(
        &self,
        opening_claims: Vec<ShpleminiOpeningClaim<P::ScalarField>>,
        commitment_key: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<ShpleminiOpeningClaim<P::ScalarField>> {
        tracing::trace!("Shplonk prove");
        let nu = transcript.get_challenge::<P>("Shplonk:nu".to_string());
        let batched_quotient = Self::compute_batched_quotient(&opening_claims, nu);
        let batched_quotient_commitment =
            Utils::commit(&batched_quotient.coefficients, commitment_key)?;
        transcript.send_point_to_verifier::<P>(
            "Shplonk:Q".to_string(),
            batched_quotient_commitment.into(),
        );

        let z = transcript.get_challenge::<P>("Shplonk:z".to_string());

        Ok(Self::compute_partially_evaluated_batched_quotient(
            opening_claims,
            batched_quotient,
            nu,
            z,
        ))
    }

    pub(crate) fn shplemini_prove(
        &self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
    ) -> HonkProofResult<ShpleminiOpeningClaim<P::ScalarField>> {
        tracing::trace!("Shplemini prove");
        let log_circuit_size = Utils::get_msb32(circuit_size);
        let opening_claims = self.gemini_prove(
            sumcheck_output.challenges,
            log_circuit_size as usize,
            crs,
            transcript,
        )?;
        let batched_claim = self.shplonk_prove(opening_claims, crs, transcript)?;
        Ok(batched_claim)
    }

    /**
     * @brief Compute partially evaluated batched quotient polynomial difference Q(X) - Q_z(X)
     *
     * @param opening_pairs list of opening pairs (xⱼ, vⱼ) for a witness polynomial fⱼ(X), s.t. fⱼ(xⱼ) = vⱼ.
     * @param witness_polynomials list of polynomials fⱼ(X).
     * @param batched_quotient_Q Q(X) = ∑ⱼ νʲ ⋅ ( fⱼ(X) − vⱼ) / ( X − xⱼ )
     * @param nu_challenge
     * @param z_challenge
     * @return Output{OpeningPair, Polynomial}
     */
    pub(crate) fn compute_partially_evaluated_batched_quotient(
        opening_claims: Vec<ShpleminiOpeningClaim<P::ScalarField>>,
        batched_quotient_q: Polynomial<P::ScalarField>,
        nu_challenge: P::ScalarField,
        z_challenge: P::ScalarField,
    ) -> ShpleminiOpeningClaim<P::ScalarField> {
        tracing::trace!("Compute partially evaluated batched quotient");
        let num_opening_claims = opening_claims.len();

        let mut inverse_vanishing_evals: Vec<P::ScalarField> =
            Vec::with_capacity(num_opening_claims);
        for claim in &opening_claims {
            inverse_vanishing_evals.push(z_challenge - claim.opening_pair.challenge);
        }
        inverse_vanishing_evals.iter_mut().for_each(|x| {
            x.inverse_in_place();
        });

        let mut g = batched_quotient_q;

        let mut current_nu = P::ScalarField::one();
        for (idx, claim) in opening_claims.into_iter().enumerate() {
            let mut tmp = claim.polynomial;
            tmp[0] -= claim.opening_pair.evaluation;
            let scaling_factor = current_nu * inverse_vanishing_evals[idx];

            g.add_scaled(&tmp, &-scaling_factor);

            current_nu *= nu_challenge;
        }

        ShpleminiOpeningClaim {
            polynomial: g,
            opening_pair: OpeningPair {
                challenge: z_challenge,
                evaluation: P::ScalarField::zero(),
            },
        }
    }
    /**
     * @brief Compute batched quotient polynomial Q(X) = ∑ⱼ νʲ ⋅ ( fⱼ(X) − vⱼ) / ( X − xⱼ )
     *
     * @param opening_claims list of prover opening claims {fⱼ(X), (xⱼ, vⱼ)} for a witness polynomial fⱼ(X), s.t. fⱼ(xⱼ)
     * = vⱼ.
     * @param nu batching challenge
     * @return Polynomial Q(X)
     */
    pub(crate) fn compute_batched_quotient(
        opening_claims: &Vec<ShpleminiOpeningClaim<P::ScalarField>>,
        nu_challenge: P::ScalarField,
    ) -> Polynomial<P::ScalarField> {
        tracing::trace!("Compute batched quotient");
        // Find n, the maximum size of all polynomials fⱼ(X)
        let mut max_poly_size: usize = 0;
        for claim in opening_claims {
            max_poly_size = max_poly_size.max(claim.polynomial.len());
        }

        // Q(X) = ∑ⱼ νʲ ⋅ ( fⱼ(X) − vⱼ) / ( X − xⱼ )
        let mut q = Polynomial::new_zero(max_poly_size);
        let mut current_nu = P::ScalarField::one();
        for claim in opening_claims {
            // Compute individual claim quotient tmp = ( fⱼ(X) − vⱼ) / ( X − xⱼ )
            let mut tmp = claim.polynomial.clone();
            tmp[0] -= claim.opening_pair.evaluation;
            tmp.factor_roots(&claim.opening_pair.challenge);

            // Add the claim quotient to the batched quotient polynomial
            q.add_scaled(&tmp, &current_nu);
            current_nu *= nu_challenge;
        }

        // Return batched quotient polynomial Q(X)
        q
    }
}
