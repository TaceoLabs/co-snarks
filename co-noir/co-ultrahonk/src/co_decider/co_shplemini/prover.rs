use super::types::{PolyF, PolyG};
use crate::{
    co_decider::{
        co_shplemini::{ShpleminiOpeningClaim, ShpleminiOpeningPair},
        co_sumcheck::SumcheckOutput,
        co_zeromorph::{OpeningPair, ZeroMorphOpeningClaim},
        polynomial::SharedPolynomial,
        prover::CoDecider,
    },
    mpc::NoirUltraHonkProver,
    types::AllEntities,
    CoUtils, CONST_PROOF_SIZE_LOG_N,
};
use ark_ec::PrimeGroup;
use ark_ff::{Field, One, Zero};
use co_builder::prelude::{HonkCurve, Polynomial, ProverCrs};
use co_builder::HonkProofResult;
use ultrahonk::{
    prelude::{Transcript, TranscriptFieldType, TranscriptHasher},
    Utils,
};

impl<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasher<TranscriptFieldType>,
    > CoDecider<T, P, H>
{
    fn get_f_polynomials(
        polys: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
    ) -> PolyF<Vec<T::ArithmeticShare>, Vec<P::ScalarField>> {
        PolyF {
            precomputed: &polys.precomputed,
            witness: &polys.witness,
        }
    }

    fn get_g_polynomials(
        polys: &AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>>,
    ) -> PolyG<Vec<T::ArithmeticShare>, Vec<P::ScalarField>> {
        let tables = [
            polys.precomputed.table_1(),
            polys.precomputed.table_2(),
            polys.precomputed.table_3(),
            polys.precomputed.table_4(),
        ];

        let wires = [
            polys.witness.w_l(),
            polys.witness.w_r(),
            polys.witness.w_o(),
            polys.witness.w_4(),
        ];

        PolyG {
            tables,
            wires,
            z_perm: polys.witness.z_perm(),
        }
    }
    pub fn powers_of_evaluation_challenge(
        gemini_evaluation_challenge: P::ScalarField,
        proof_size: &usize,
    ) -> Vec<P::ScalarField> {
        let mut squares = Vec::with_capacity(*proof_size);
        squares.push(gemini_evaluation_challenge);
        for j in 1..*proof_size {
            squares.push(squares[j - 1] * squares[j - 1]);
        }
        squares
    }

    fn compute_batched_polys(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        n: usize,
    ) -> (SharedPolynomial<T, P>, SharedPolynomial<T, P>) {
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

        // Precomputed part of f_batched
        for f_poly in f_polynomials.precomputed.iter() {
            f_batched.add_scaled_slice(f_poly, &batching_scalar);

            batching_scalar *= rho;
        }

        // Shared part of f_batched
        let mut f_batched = SharedPolynomial::<T, P>::promote_poly(&self.driver, f_batched);
        for f_poly in f_polynomials.witness.iter() {
            f_batched.add_scaled_slice(&mut self.driver, f_poly, &batching_scalar);

            batching_scalar *= rho;
        }

        // For g_batched the order of public first and shared later is ok
        let mut g_batched = Polynomial::new_zero(n); // batched to-be-shifted polynomials

        // Public part of g_batched
        for g_poly in g_polynomials.public_iter() {
            g_batched.add_scaled_slice(g_poly, &batching_scalar);

            batching_scalar *= rho;
        }

        // Shared part of g_batched
        let mut g_batched = SharedPolynomial::<T, P>::promote_poly(&self.driver, g_batched);
        for g_poly in g_polynomials.shared_iter() {
            g_batched.add_scaled_slice(&mut self.driver, g_poly, &batching_scalar);

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
        &mut self,
        multilinear_challenge: Vec<P::ScalarField>,
        log_n: u32,
        commitment_key: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<Vec<ShpleminiOpeningClaim<T, P>>> {
        tracing::trace!("Gemini prove");
        let n = 1 << log_n;

        // Compute batched polynomials
        let (batched_unshifted, batched_to_be_shifted) = self.compute_batched_polys(transcript, n);

        let fold_polynomials = self.compute_fold_polynomials(
            log_n as usize,
            multilinear_challenge,
            batched_unshifted,
            batched_to_be_shifted,
        );

        // Compute and send commitments C_{q_k} = [q_k], k = 0,...,d-1
        let mut commitments = Vec::with_capacity(log_n as usize);
        for q in fold_polynomials.iter().skip(2) {
            let commitment = CoUtils::commit::<T, P>(q.as_ref(), commitment_key);
            commitments.push(commitment);
        }
        let commitments = self.driver.open_point_many(&commitments)?;
        for (idx, val) in commitments.into_iter().enumerate() {
            let label = format!("Gemini:FOLD_{}", idx + 1);
            transcript.send_point_to_verifier::<P>(label, val.into());
        }
        // Add buffer elements to remove log_N dependence in proof
        for idx in log_n as usize..CONST_PROOF_SIZE_LOG_N {
            let res = P::G1::generator();
            let label = format!("Gemini:FOLD_{}", idx);
            transcript.send_point_to_verifier::<P>(label, res.into());
        }

        let r_challenge: P::ScalarField = transcript.get_challenge::<P>("Gemini:r".to_string());

        let claims = self.compute_fold_polynomial_evaluations(fold_polynomials, r_challenge)?;
        let mut commitments_claims = Vec::with_capacity(log_n as usize);
        commitments_claims.extend(
            claims
                .iter()
                .take(log_n as usize + 1)
                .map(|claim| claim.opening_pair.evaluation),
        );

        let commitments_claims = self.driver.open_many(&commitments_claims)?;

        for l in 1..=CONST_PROOF_SIZE_LOG_N {
            if l < commitments_claims.len() && l <= log_n as usize {
                transcript
                    .send_fr_to_verifier::<P>(format!("Gemini:a_{}", l), commitments_claims[l]);
            } else {
                transcript
                    .send_fr_to_verifier::<P>(format!("Gemini:a_{}", l), P::ScalarField::zero());
            }
        }

        Ok(claims)
    }

    pub(crate) fn compute_fold_polynomials(
        &mut self,
        num_variables: usize,
        mle_opening_point: Vec<P::ScalarField>,
        batched_unshifted: SharedPolynomial<T, P>,
        batched_to_be_shifted: SharedPolynomial<T, P>,
    ) -> Vec<SharedPolynomial<T, P>> {
        tracing::trace!("Compute fold polynomials");
        // Note: bb uses multithreading here
        let mut fold_polynomials: Vec<SharedPolynomial<T, P>> =
            Vec::with_capacity(num_variables + 1);

        // A₀(X) = F(X) + G↺(X) = F(X) + G(X)/X
        let mut a_0 = batched_unshifted.clone();

        // If proving the opening for translator, add a non-zero contribution of the batched concatenation polynomials
        a_0.add_assign_slice(&mut self.driver, batched_to_be_shifted.shifted());

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
            let mut a_l_fold = SharedPolynomial::<T, P>::new_zero(n_l);

            for j in 0..n_l {
                // fold(Aₗ)[j] = (1-uₗ)⋅even(Aₗ)[j] + uₗ⋅odd(Aₗ)[j]
                //            = (1-uₗ)⋅Aₗ[2j]      + uₗ⋅Aₗ[2j+1]
                //            = Aₗ₊₁[j]
                let a_l_neg = self.driver.neg(a_l[j << 1]);
                a_l_fold[j] = self.driver.add(
                    a_l[j << 1],
                    self.driver
                        .mul_with_public(u_l, self.driver.add(a_l[(j << 1) + 1], a_l_neg)),
                );
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
        &mut self,
        mut fold_polynomials: Vec<SharedPolynomial<T, P>>,
        r_challenge: P::ScalarField,
    ) -> HonkProofResult<Vec<ShpleminiOpeningClaim<T, P>>> {
        tracing::trace!("Compute fold polynomial evaluations");

        let num_variables = fold_polynomials.len() - 1;
        let batched_f = &mut fold_polynomials.remove(0); // F(X) = ∑ⱼ ρʲ fⱼ(X)
        let batched_g = &mut fold_polynomials.remove(0); // G(X) = ∑ⱼ ρᵏ⁺ʲ gⱼ(X)

        // Compute univariate opening queries rₗ = r^{2ˡ} for l = 0, 1, ..., m-1
        let r_squares = Self::powers_of_evaluation_challenge(r_challenge, &num_variables);

        // Compute G / r and update batched_G
        let r_inv = r_challenge.inverse().unwrap();
        let mut batched_g_div_r = batched_g.clone();
        batched_g_div_r.coefficients.iter_mut().for_each(|x| {
            *x = self.driver.mul_with_public(r_inv, *x);
        });

        // Construct A₀₊ = F + G/r and A₀₋ = F - G/r in place in fold_polynomials

        // A₀₊(X) = F(X) + G(X)/r, s.t. A₀₊(r) = A₀(r)
        let mut a_0_pos = batched_f.clone();
        a_0_pos.add_assign_slice(&mut self.driver, batched_g_div_r.as_ref());

        // A₀₋(X) = F(X) - G(X)/r, s.t. A₀₋(-r) = A₀(-r)
        let mut a_0_neg = batched_f.clone();
        let mut batched_g_div_r_neg = batched_g_div_r;
        batched_g_div_r_neg.coefficients.iter_mut().for_each(|x| {
            *x = self.driver.neg(*x);
        });
        a_0_neg.add_assign_slice(&mut self.driver, batched_g_div_r_neg.as_ref()); //TACEO TODO is this always correct?

        fold_polynomials.insert(0, a_0_pos);
        fold_polynomials.insert(1, a_0_neg);
        // end
        let mut opening_claims: Vec<ShpleminiOpeningClaim<T, P>> =
            Vec::with_capacity(num_variables + 1);

        let mut fold_polynomials_iter = fold_polynomials.into_iter();

        // Compute first opening pair {r, A₀(r)}
        let fold_poly = fold_polynomials_iter.next().expect("Is Present");
        let evaluation: <T as NoirUltraHonkProver<P>>::ArithmeticShare =
            self.driver.eval_poly(fold_poly.as_ref(), r_challenge);
        opening_claims.push(ShpleminiOpeningClaim {
            polynomial: fold_poly,
            opening_pair: ShpleminiOpeningPair {
                challenge: r_challenge,
                evaluation,
            },
        });

        // Compute the remaining m opening pairs {−r^{2ˡ}, Aₗ(−r^{2ˡ})}, l = 0, ..., m-1
        for (r_square, fold_poly) in r_squares.into_iter().zip(fold_polynomials_iter) {
            let evaluation = self.driver.eval_poly(fold_poly.as_ref(), -r_square);
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: fold_poly,
                opening_pair: ShpleminiOpeningPair {
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
        &mut self,
        opening_claims: Vec<ShpleminiOpeningClaim<T, P>>,
        commitment_key: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<ZeroMorphOpeningClaim<T, P>> {
        tracing::trace!("Shplonk prove");
        let nu = transcript.get_challenge::<P>("Shplonk:nu".to_string());
        let batched_quotient =
            Self::compute_batched_quotient(&mut self.driver, &opening_claims, nu);
        let batched_quotient_commitment =
            CoUtils::commit::<T, P>(batched_quotient.as_ref(), commitment_key);
        let batched_quotient_commitment = self.driver.open_point(batched_quotient_commitment)?;
        transcript.send_point_to_verifier::<P>(
            "Shplonk:Q".to_string(),
            batched_quotient_commitment.into(),
        );

        let z = transcript.get_challenge::<P>("Shplonk:z".to_string());

        Ok(self.compute_partially_evaluated_batched_quotient(
            opening_claims,
            batched_quotient,
            nu,
            z,
        ))
    }

    pub(crate) fn shplemini_prove(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
    ) -> HonkProofResult<ZeroMorphOpeningClaim<T, P>> {
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
        &mut self,
        opening_claims: Vec<ShpleminiOpeningClaim<T, P>>,
        batched_quotient_q: SharedPolynomial<T, P>,
        nu_challenge: P::ScalarField,
        z_challenge: P::ScalarField,
    ) -> ZeroMorphOpeningClaim<T, P> {
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
            let claim_neg = self.driver.neg(claim.opening_pair.evaluation);
            tmp[0] = self.driver.add(tmp[0], claim_neg);
            let scaling_factor = current_nu * inverse_vanishing_evals[idx];

            g.add_scaled(&mut self.driver, &tmp, &-scaling_factor);

            current_nu *= nu_challenge;
        }

        crate::co_decider::co_zeromorph::ZeroMorphOpeningClaim {
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
        driver: &mut T,
        opening_claims: &Vec<ShpleminiOpeningClaim<T, P>>,
        nu_challenge: P::ScalarField,
    ) -> SharedPolynomial<T, P> {
        tracing::trace!("Compute batched quotient");
        // Find n, the maximum size of all polynomials fⱼ(X)
        let mut max_poly_size: usize = 0;
        for claim in opening_claims {
            max_poly_size = std::cmp::max(max_poly_size, claim.polynomial.len());
        }

        // Q(X) = ∑ⱼ νʲ ⋅ ( fⱼ(X) − vⱼ) / ( X − xⱼ )

        let mut q = SharedPolynomial::<T, P>::new_zero(max_poly_size);
        let mut current_nu = P::ScalarField::one();
        for claim in opening_claims {
            // Compute individual claim quotient tmp = ( fⱼ(X) − vⱼ) / ( X − xⱼ )
            let mut tmp = claim.polynomial.clone();
            let claim_neg = driver.neg(claim.opening_pair.evaluation);
            tmp[0] = driver.add(tmp[0], claim_neg);
            tmp.factor_roots(driver, &claim.opening_pair.challenge);

            // Add the claim quotient to the batched quotient polynomial
            q.add_scaled(driver, &tmp, &current_nu);

            current_nu *= nu_challenge;
        }

        // Return batched quotient polynomial Q(X)
        q
    }
}
