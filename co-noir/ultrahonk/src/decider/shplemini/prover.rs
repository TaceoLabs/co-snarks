use super::{
    super::{prover::Decider, sumcheck::SumcheckOutput},
    types::{PolyF, PolyG, PolyGShift},
};
use crate::{
    decider::{
        polynomial::Polynomial,
        types::ClaimedEvaluations,
        verifier::DeciderVerifier,
        zeromorph::{OpeningPair, ZeroMorphOpeningClaim},
    },
    honk_curve::HonkCurve,
    prover::HonkProofResult,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
    types::{AllEntities, ProverCrs},
    Utils, CONST_PROOF_SIZE_LOG_N,
};
use ark_ec::Group;
use ark_ff::{Field, One, Zero};

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> Decider<P, H> {
    fn get_f_polynomials_shplemini(
        polys: &AllEntities<Vec<P::ScalarField>>,
    ) -> PolyF<Vec<P::ScalarField>> {
        PolyF {
            precomputed: &polys.precomputed,
            witness: &polys.witness,
        }
    }

    fn get_g_shift_evaluations_shplemini(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyGShift<P::ScalarField> {
        PolyGShift {
            tables: &evaluations.shifted_tables,
            wires: &evaluations.shifted_witness,
        }
    }

    fn get_g_polynomials_shplemini(
        polys: &AllEntities<Vec<P::ScalarField>>,
    ) -> PolyG<Vec<P::ScalarField>> {
        PolyG {
            tables: polys
                .precomputed
                .get_table_polynomials()
                .try_into()
                .unwrap(),
            wires: polys.witness.to_be_shifted().try_into().unwrap(),
        }
    }

    fn get_f_evaluations_shplemini(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyF<P::ScalarField> {
        PolyF {
            precomputed: &evaluations.precomputed,
            witness: &evaluations.witness,
        }
    }

    // TODO to adjust it for our needs
    fn compute_batched_polysss(
        &self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        claimed_evaluations: AllEntities<P::ScalarField>,
        n: usize,
    ) -> (
        Polynomial<P::ScalarField>,
        Polynomial<P::ScalarField>,
        P::ScalarField,
    ) {
        let f_polynomials = Self::get_f_polynomials_shplemini(&self.memory.polys);
        let g_polynomials = Self::get_g_polynomials_shplemini(&self.memory.polys);
        let f_evaluations = Self::get_f_evaluations_shplemini(&claimed_evaluations);
        let g_shift_evaluations = Self::get_g_shift_evaluations_shplemini(&claimed_evaluations);

        // Generate batching challenge \rho and powers 1,...,\rho^{m-1}
        let rho = transcript.get_challenge::<P>("rho".to_string());

        // Compute batching of unshifted polynomials f_i and to-be-shifted polynomials g_i:
        // f_batched = sum_{i=0}^{m-1}\rho^i*f_i and g_batched = sum_{i=0}^{l-1}\rho^{m+i}*g_i,
        // and also batched evaluation
        // v = sum_{i=0}^{m-1}\rho^i*f_i(u) + sum_{i=0}^{l-1}\rho^{m+i}*h_i(u).
        // Note: g_batched is formed from the to-be-shifted polynomials, but the batched evaluation incorporates the
        // evaluations produced by sumcheck of h_i = g_i_shifted.

        let mut batched_evaluation = P::ScalarField::ZERO;
        let mut batching_scalar = P::ScalarField::ONE;
        let mut f_batched = Polynomial::new_zero(n); // batched unshifted polynomials

        for (f_poly, f_eval) in f_polynomials.iter().zip(f_evaluations.iter()) {
            f_batched.add_scaled_slice(f_poly, &batching_scalar);
            batched_evaluation += batching_scalar * f_eval;
            batching_scalar *= rho;
        }

        let mut g_batched = Polynomial::new_zero(n); // batched to-be-shifted polynomials

        for (g_poly, g_shift_eval) in g_polynomials.iter().zip(g_shift_evaluations.iter()) {
            g_batched.add_scaled_slice(g_poly, &batching_scalar);
            batched_evaluation += batching_scalar * g_shift_eval;
            batching_scalar *= rho;
        }

        (f_batched, g_batched, batched_evaluation)
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
        claimed_evaluations: ClaimedEvaluations<P::ScalarField>,
        commitment_key: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<Vec<ZeroMorphOpeningClaim<P::ScalarField>>> {
        let n = 1 << log_n;

        // Compute batched polynomials
        let (batched_unshifted, batched_to_be_shifted, _) =
            self.compute_batched_polysss(transcript, claimed_evaluations, n);

        let fold_polynomials = Self::compute_fold_polynomials(
            log_n as usize,
            multilinear_challenge,
            batched_unshifted,
            batched_to_be_shifted,
        );

        for l in 0..CONST_PROOF_SIZE_LOG_N - 1 {
            if l < log_n as usize - 1 {
                let res = Utils::commit(&fold_polynomials[l + 2].coefficients, commitment_key)?;
                transcript
                    .send_point_to_verifier::<P>(format!("Gemini:FOLD_{}", l + 1), res.into());
            } else {
                let res = P::G1::generator();
                let label = format!("Gemini:FOLD_{}", l + 1);
                transcript.send_point_to_verifier::<P>(label, res.into());
            }
        }

        let r_challenge: P::ScalarField = transcript.get_challenge::<P>("Gemini:r".to_string());

        let claims = Self::compute_fold_polynomial_evaluations(
            log_n as usize,
            fold_polynomials,
            r_challenge,
        )?;

        for (l, claim) in claims
            .iter()
            .enumerate()
            .skip(1)
            .take(CONST_PROOF_SIZE_LOG_N)
        {
            if l <= log_n as usize {
                transcript.send_fr_to_verifier::<P>(
                    format!("Gemini:a_{}", l),
                    claim.opening_pair.evaluation,
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
        // Note: bb uses multithreading here
        let mut fold_polynomials: Vec<Polynomial<P::ScalarField>> =
            Vec::with_capacity(num_variables + 1);

        // F(X) = ∑ⱼ ρʲ fⱼ(X) and G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X)
        fold_polynomials.push(batched_unshifted.clone());
        fold_polynomials.push(batched_to_be_shifted.clone());
        const OFFSET_TO_FOLDED: usize = 2; // Offset because of F and G

        // A₀(X) = F(X) + G↺(X) = F(X) + G(X)/X
        let mut a_0 = batched_unshifted.clone();

        // If proving the opening for translator, add a non-zero contribution of the batched concatenation polynomials
        a_0 += batched_to_be_shifted.shifted().as_ref(); //todo is this correct?

        // Allocate everything before parallel computation
        for l in 0..num_variables - 1 {
            // size of the previous polynomial/2
            let n_l = 1 << (num_variables - l - 1);

            // A_l_fold = Aₗ₊₁(X) = (1-uₗ)⋅even(Aₗ)(X) + uₗ⋅odd(Aₗ)(X)
            fold_polynomials.push(Polynomial::new_zero(n_l));
        }

        // A_l = Aₗ(X) is the polynomial being folded
        // in the first iteration, we take the batched polynomial
        // in the next iteration, it is the previously folded one
        let mut a_l = a_0.coefficients;
        for l in 0..num_variables - 1 {
            // size of the previous polynomial/2
            let n_l = 1 << (num_variables - l - 1);

            // Opening point is the same for all
            let u_l = mle_opening_point[l];

            // A_l_fold = Aₗ₊₁(X) = (1-uₗ)⋅even(Aₗ)(X) + uₗ⋅odd(Aₗ)(X)
            let a_l_fold = &mut fold_polynomials[l + OFFSET_TO_FOLDED].coefficients;

            // Process each element in a single-threaded manner
            for j in 0..n_l {
                // fold(Aₗ)[j] = (1-uₗ)⋅even(Aₗ)[j] + uₗ⋅odd(Aₗ)[j]
                //            = (1-uₗ)⋅Aₗ[2j]      + uₗ⋅Aₗ[2j+1]
                //            = Aₗ₊₁[j]
                a_l_fold[j] = a_l[j << 1] + u_l * (a_l[(j << 1) + 1] - a_l[j << 1]);
            }

            // Set Aₗ₊₁ = Aₗ for the next iteration
            a_l = a_l_fold.to_vec();
        }

        fold_polynomials
    }

    pub(crate) fn compute_fold_polynomial_evaluations(
        num_variables: usize,
        mut fold_polynomials: Vec<Polynomial<P::ScalarField>>,
        r_challenge: P::ScalarField,
    ) -> HonkProofResult<Vec<ZeroMorphOpeningClaim<P::ScalarField>>> {
        // // // Assuming `Polynomial` and `Fr` types are defined elsewhere in your code.

        // let batched_f = fold_polynomials[0].clone(); // F(X) = ∑ⱼ ρʲ fⱼ(X)
        // let mut batched_g = fold_polynomials[0].clone(); // G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X)

        // // Compute univariate opening queries rₗ = r^{2ˡ} for l = 0, 1, ..., m-1
        // let r_squares: Vec<P::ScalarField> =
        //     DeciderVerifier::<P, H>::powers_of_evaluation_challenge(r_challenge, &num_variables);

        // // Compute G/r
        // let r_inv = r_challenge.inverse().unwrap();
        // batched_g.iter_mut().for_each(|x| {
        //     *x *= r_inv;
        // });

        // // Construct A₀₊ = F + G/r and A₀₋ = F - G/r in place in fold_polynomials
        // let mut tmp = batched_f.clone();
        // let mut a_0_pos = batched_f.clone(); // A₀₊(X) = F(X) + G(X)/r

        // // A₀₊(X) = F(X) + G(X)/r
        // a_0_pos.add_assign(batched_g.as_ref());

        // // Perform a swap so that tmp = G(X)/r and A_0_neg = F(X)
        // std::mem::swap(&mut tmp, &mut batched_g);
        // let a_0_neg = &mut fold_polynomials[1]; // A₀₋(X) = F(X) - G(X)/r

        // // A₀₋(X) = F(X) - G(X)/r
        // a_0_neg.sub_assign(tmp.as_ref());
        // start
        // References to the first two polynomials in fold_polynomials
        let batched_f = &mut fold_polynomials.remove(0); // F(X) = ∑ⱼ ρʲ fⱼ(X)
        let batched_g = &mut fold_polynomials.remove(0); // G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X)

        // Compute univariate opening queries rₗ = r^{2ˡ} for l = 0, 1, ..., m-1
        let r_squares: Vec<P::ScalarField> =
            DeciderVerifier::<P, H>::powers_of_evaluation_challenge(r_challenge, &num_variables);

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
        a_0_neg -= batched_g_div_r.as_ref();

        fold_polynomials.insert(0, a_0_pos);
        fold_polynomials.insert(1, a_0_neg);
        // end
        let mut opening_claims: Vec<ZeroMorphOpeningClaim<P::ScalarField>> =
            Vec::with_capacity(num_variables + 1);

        // Compute first opening pair {r, A₀(r)}
        let evaluation = fold_polynomials[0].eval_poly(r_challenge);
        opening_claims.push(ZeroMorphOpeningClaim {
            polynomial: fold_polynomials[0].clone(),
            opening_pair: OpeningPair {
                challenge: r_challenge,
                evaluation,
            },
        });

        // Compute the remaining m opening pairs {−r^{2ˡ}, Aₗ(−r^{2ˡ})}, l = 0, ..., m-1
        for l in 0..num_variables {
            let evaluation = fold_polynomials[l + 1].eval_poly(-r_squares[l]);
            opening_claims.push(ZeroMorphOpeningClaim {
                polynomial: fold_polynomials[l + 1].clone(),
                opening_pair: OpeningPair {
                    challenge: -r_squares[l],
                    evaluation,
                },
            });
        }

        Ok(opening_claims)
    }

    pub(crate) fn shplonk_prove(
        &self,
        opening_claims: Vec<ZeroMorphOpeningClaim<P::ScalarField>>,
        commitment_key: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<ZeroMorphOpeningClaim<P::ScalarField>> {
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
            &batched_quotient,
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
    ) -> HonkProofResult<ZeroMorphOpeningClaim<P::ScalarField>> {
        tracing::trace!("Shplemini prove");
        let log_circuit_size = Utils::get_msb32(circuit_size);
        let opening_claims = self.gemini_prove(
            sumcheck_output.challenges,
            log_circuit_size,
            sumcheck_output.claimed_evaluations,
            crs,
            transcript,
        )?;
        let batched_claim = self.shplonk_prove(opening_claims, crs, transcript)?;
        Ok(batched_claim)
    }

    pub(crate) fn compute_partially_evaluated_batched_quotient(
        opening_claims: Vec<ZeroMorphOpeningClaim<P::ScalarField>>,
        batched_quotient_q: &Polynomial<P::ScalarField>,
        nu_challenge: P::ScalarField,
        z_challenge: P::ScalarField,
    ) -> ZeroMorphOpeningClaim<P::ScalarField> {
        let num_opening_claims = opening_claims.len();

        let mut inverse_vanishing_evals: Vec<P::ScalarField> =
            Vec::with_capacity(num_opening_claims);
        for claim in &opening_claims {
            inverse_vanishing_evals.push(z_challenge - claim.opening_pair.challenge);
        }
        inverse_vanishing_evals.iter_mut().for_each(|x| {
            x.inverse_in_place();
        });

        let mut g = batched_quotient_q.clone();

        let mut current_nu = P::ScalarField::one();
        for (idx, claim) in opening_claims.iter().enumerate() {
            let mut tmp = claim.polynomial.clone();
            tmp[0] -= claim.opening_pair.evaluation;
            let scaling_factor = current_nu * inverse_vanishing_evals[idx];

            g.add_scaled(&tmp, &-scaling_factor);

            current_nu *= nu_challenge;
        }

        ZeroMorphOpeningClaim {
            polynomial: g,
            opening_pair: OpeningPair {
                challenge: z_challenge,
                evaluation: P::ScalarField::zero(),
            },
        }
    }

    pub(crate) fn compute_batched_quotient(
        opening_claims: &Vec<ZeroMorphOpeningClaim<P::ScalarField>>,
        nu_challenge: P::ScalarField,
    ) -> Polynomial<P::ScalarField> {
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
