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
            tables: polys
                .precomputed
                .get_table_polynomials()
                .try_into()
                .unwrap(),
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

        let mut batching_scalar = P::ScalarField::ONE;
        let mut f_batched = Polynomial::new_zero(n); // batched unshifted polynomials

        for f_poly in f_polynomials.iter() {
            f_batched.add_scaled_slice(f_poly, &batching_scalar);
            batching_scalar *= rho;
        }

        let mut g_batched = Polynomial::new_zero(n); // batched to-be-shifted polynomials

        for g_poly in g_polynomials.iter() {
            g_batched.add_scaled_slice(g_poly, &batching_scalar);
            batching_scalar *= rho;
        }

        (f_batched, g_batched)
    }

    /**
     * @brief  * @brief Returns a univariate opening claim equivalent to a set of multilinear evaluation claims for
     * unshifted polynomials f_i and to-be-shifted polynomials g_i to be subsequently proved with a univariate PCS
     *
     * @param f_polynomials Unshifted polynomials
     * @param g_polynomials To-be-shifted polynomials (of which the shifts h_i were evaluated by sumcheck)
     * @param evaluations Set of evaluations v_i = f_i(u), w_i = h_i(u) = g_i_shifted(u)
     * @param multilinear_challenge Multilinear challenge point u
     * @param commitment_key
     * @param transcript
     *
     * @AZTEC todo https://github.com/AztecProtocol/barretenberg/issues/1030: document concatenation trick
     */
    pub(crate) fn gemini_prove(
        &self,
        multilinear_challenge: Vec<P::ScalarField>,
        log_n: u32,
        commitment_key: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<Vec<ShpleminiOpeningClaim<P::ScalarField>>> {
        tracing::trace!("Gemini prove");
        let n = 1 << log_n;

        // Compute batched polynomials
        let (batched_unshifted, batched_to_be_shifted) = self.compute_batched_polys(transcript, n);

        let fold_polynomials = Self::compute_fold_polynomials(
            log_n as usize,
            multilinear_challenge,
            batched_unshifted,
            batched_to_be_shifted,
        );

        for l in 1..CONST_PROOF_SIZE_LOG_N {
            if l < log_n as usize {
                let res = Utils::commit(&fold_polynomials[l + 1].coefficients, commitment_key)?;
                transcript.send_point_to_verifier::<P>(format!("Gemini:FOLD_{}", l), res.into());
            } else {
                let res = P::G1Affine::generator();
                let label = format!("Gemini:FOLD_{}", l);
                transcript.send_point_to_verifier::<P>(label, res);
            }
        }

        let r_challenge: P::ScalarField = transcript.get_challenge::<P>("Gemini:r".to_string());

        let claims = Self::compute_fold_polynomial_evaluations(fold_polynomials, r_challenge)?;
        for l in 1..=CONST_PROOF_SIZE_LOG_N {
            if l < claims.len() && l <= log_n as usize {
                transcript.send_fr_to_verifier::<P>(
                    format!("Gemini:a_{}", l),
                    claims[l].opening_pair.evaluation,
                );
            } else {
                transcript
                    .send_fr_to_verifier::<P>(format!("Gemini:a_{}", l), P::ScalarField::zero());
            }
        }

        Ok(claims)
    }

    pub(crate) fn compute_fold_polynomials(
        num_variables: usize,
        mle_opening_point: Vec<P::ScalarField>,
        batched_unshifted: Polynomial<P::ScalarField>,
        batched_to_be_shifted: Polynomial<P::ScalarField>,
    ) -> Vec<Polynomial<P::ScalarField>> {
        tracing::trace!("Compute fold polynomials");
        // Note: bb uses multithreading here
        let mut fold_polynomials: Vec<Polynomial<P::ScalarField>> =
            Vec::with_capacity(num_variables + 1);

        // A₀(X) = F(X) + G↺(X) = F(X) + G(X)/X
        let mut a_0 = batched_unshifted.clone();

        // If proving the opening for translator, add a non-zero contribution of the batched concatenation polynomials
        a_0 += batched_to_be_shifted.shifted().as_ref();

        // F(X) = ∑ⱼ ρʲ fⱼ(X) and G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X)
        fold_polynomials.push(batched_unshifted);
        fold_polynomials.push(batched_to_be_shifted);

        // A_l = Aₗ(X) is the polynomial being folded
        // in the first iteration, we take the batched polynomial
        // in the next iteration, it is the previously folded one
        let mut a_l = a_0.coefficients;
        debug_assert!(mle_opening_point.len() >= num_variables - 1);
        for (l, u_l) in mle_opening_point
            .into_iter()
            .take(num_variables - 1)
            .enumerate()
        {
            // size of the previous polynomial/2
            let n_l = 1 << (num_variables - l - 1);

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
    /**
     * @brief Computes/aggragates d+1 Fold polynomials and their opening pairs (challenge, evaluation)
     *
     * @details This function assumes that, upon input, last d-1 entries in fold_polynomials are Fold_i.
     * The first two entries are assumed to be, respectively, the batched unshifted and batched to-be-shifted
     * polynomials F(X) = ∑ⱼ ρʲfⱼ(X) and G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X). This function completes the computation
     * of the first two Fold polynomials as F + G/r and F - G/r. It then evaluates each of the d+1
     * fold polynomials at, respectively, the points r, rₗ = r^{2ˡ} for l = 0, 1, ..., d-1.
     *
     * @param mle_opening_point u = (u₀,...,uₘ₋₁) is the MLE opening point
     * @param fold_polynomials vector of polynomials whose first two elements are F(X) = ∑ⱼ ρʲfⱼ(X)
     * and G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X), and the next d-1 elements are Fold_i, i = 1, ..., d-1.
     * @param r_challenge univariate opening challenge
     */
    pub(crate) fn compute_fold_polynomial_evaluations(
        mut fold_polynomials: Vec<Polynomial<P::ScalarField>>,
        r_challenge: P::ScalarField,
    ) -> HonkProofResult<Vec<ShpleminiOpeningClaim<P::ScalarField>>> {
        tracing::trace!("Compute fold polynomial evaluations");

        let num_variables = fold_polynomials.len() - 1;
        let batched_f = &mut fold_polynomials.remove(0); // F(X) = ∑ⱼ ρʲ fⱼ(X)
        let batched_g = &mut fold_polynomials.remove(0); // G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X)

        // Compute univariate opening queries rₗ = r^{2ˡ} for l = 0, 1, ..., m-1
        let r_squares: Vec<P::ScalarField> =
            DeciderVerifier::<P, H>::powers_of_evaluation_challenge(r_challenge, num_variables);

        // Compute G / r and update batched_G
        let r_inv = r_challenge.inverse().unwrap();
        let mut batched_g_div_r = batched_g.clone();
        batched_g_div_r.iter_mut().for_each(|x| {
            *x *= r_inv;
        });

        // Construct A₀₊ = F + G/r and A₀₋ = F - G/r in place in fold_polynomials

        // A₀₊(X) = F(X) + G(X)/r, s.t. A₀₊(r) = A₀(r)
        let mut a_0_pos = batched_f.clone();
        a_0_pos += batched_g_div_r.as_ref();

        // A₀₋(X) = F(X) - G(X)/r, s.t. A₀₋(-r) = A₀(-r)
        let mut a_0_neg = batched_f.clone();
        a_0_neg -= batched_g_div_r.as_ref(); //TACEO TODO is this always correct?

        fold_polynomials.insert(0, a_0_pos);
        fold_polynomials.insert(1, a_0_neg);
        // end
        let mut opening_claims: Vec<ShpleminiOpeningClaim<P::ScalarField>> =
            Vec::with_capacity(num_variables + 1);

        let mut fold_polynomials_iter = fold_polynomials.into_iter();

        // Compute first opening pair {r, A₀(r)}
        let fold_poly = fold_polynomials_iter.next().expect("Is Present");
        let evaluation = fold_poly.eval_poly(r_challenge);
        opening_claims.push(ShpleminiOpeningClaim {
            polynomial: fold_poly,
            opening_pair: OpeningPair {
                challenge: r_challenge,
                evaluation,
            },
        });

        // Compute the remaining m opening pairs {−r^{2ˡ}, Aₗ(−r^{2ˡ})}, l = 0, ..., m-1
        for (r_square, fold_poly) in r_squares.into_iter().zip(fold_polynomials_iter) {
            let evaluation = fold_poly.eval_poly(-r_square);
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: fold_poly,
                opening_pair: OpeningPair {
                    challenge: -r_square,
                    evaluation,
                },
            });
        }

        Ok(opening_claims)
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
            log_circuit_size,
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
