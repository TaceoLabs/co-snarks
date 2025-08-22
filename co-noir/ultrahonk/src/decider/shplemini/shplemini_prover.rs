use super::super::{decider_prover::Decider, sumcheck::SumcheckOutput};
use crate::plain_prover_flavour::PlainProverFlavour;
use crate::{
    NUM_INTERLEAVING_CLAIMS, NUM_SMALL_IPA_EVALUATIONS, Utils,
    decider::decider_verifier::DeciderVerifier, types::AllEntities,
};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use co_builder::polynomials::polynomial_flavours::PolyGFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::ZeroKnowledge;
use co_builder::{
    HonkProofError, HonkProofResult,
    prelude::{HonkCurve, Polynomial, ProverCrs},
};
use common::shplemini::OpeningPair;
use common::shplemini::ShpleminiOpeningClaim;
use common::transcript::TranscriptFieldType;
use common::transcript::{Transcript, TranscriptHasher};
use itertools::izip;

impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> Decider<P, H, L>
{
    // fn get_f_polynomials(
    //     polys: &'_ AllEntities<Vec<P::ScalarField>, L>,
    // ) -> PolyF<'_, Vec<P::ScalarField>, L> {
    //     PolyF {
    //         precomputed: &polys.precomputed,
    //         witness: &polys.witness,
    //     }
    // }

    fn get_g_polynomials<'a>(
        polys: &'a AllEntities<Vec<P::ScalarField>, L>,
    ) -> L::PolyG<'a, Vec<P::ScalarField>> {
        L::PolyG::from_slice(polys.witness.to_be_shifted())
    }

    #[expect(clippy::type_complexity)]
    fn compute_batched_polys(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        multilinear_challenge: &[P::ScalarField],
        log_n: usize,
        commitment_key: &ProverCrs<P>,
    ) -> HonkProofResult<(
        Polynomial<P::ScalarField>,
        Polynomial<P::ScalarField>,
        Option<Polynomial<P::ScalarField>>,
        Option<Vec<Polynomial<P::ScalarField>>>,
    )> {
        //TODO FLORIN: MAYBE MAKE THIS NICER
        let f_polynomials = self
            .memory
            .polys
            .precomputed
            .iter()
            .chain(self.memory.polys.witness.get_unshifted());
        let g_polynomials = Self::get_g_polynomials(&self.memory.polys);
        let interleaved_polynomials = self.memory.polys.witness.get_interleaved();
        let groups_to_be_interleaved = self.memory.polys.witness.get_groups_to_be_interleaved();

        let n = 1 << log_n;
        let mut batched_unshifted = Polynomial::new_zero(n); // batched unshifted polynomials

        // To achieve ZK, we mask the batched polynomial by a random polynomial of the same size
        if self.has_zk == ZeroKnowledge::Yes {
            batched_unshifted = Polynomial::<P::ScalarField>::random(n, &mut self.rng);
            let masking_poly_comm = Utils::commit(&batched_unshifted.coefficients, commitment_key)?;
            transcript.send_point_to_verifier::<P>(
                "Gemini:masking_poly_comm".to_string(),
                masking_poly_comm.into(),
            );
            // In the provers, the size of multilinear_challenge is `virtual_log_n`, but we need to evaluate the
            // hiding polynomial as multilinear in log_n variables
            let masking_poly_eval =
                batched_unshifted.evaluate_mle(&multilinear_challenge[0..log_n]);
            transcript.send_fr_to_verifier::<P>(
                "Gemini:masking_poly_eval".to_string(),
                masking_poly_eval,
            );
        }

        // Generate batching challenge \rho and powers 1,...,\rho^{m-1}
        let rho = transcript.get_challenge::<P>("rho".to_string());
        println!("rho: {rho}");

        // Compute batching of unshifted polynomials f_i and to-be-shifted polynomials g_i:
        // f_batched = sum_{i=0}^{m-1}\rho^i*f_i and g_batched = sum_{i=0}^{l-1}\rho^{m+i}*g_i,
        // and also batched evaluation
        // v = sum_{i=0}^{m-1}\rho^i*f_i(u) + sum_{i=0}^{l-1}\rho^{m+i}*h_i(u).
        // Note: g_batched is formed from the to-be-shifted polynomials, but the batched evaluation incorporates the
        // evaluations produced by sumcheck of h_i = g_i_shifted.

        let mut running_scalar = P::ScalarField::ONE;

        if self.has_zk == ZeroKnowledge::Yes {
            // ρ⁰ is used to batch the hiding polynomial
            running_scalar *= rho;
        }
        println!("initial running_scalar: {running_scalar}");

        for f_poly in f_polynomials {
            batched_unshifted.add_scaled_slice(f_poly, &running_scalar);
            running_scalar *= rho;
        }
        println!("running_scalar after f_polys: {running_scalar}");

        let mut batched_to_be_shifted = Polynomial::new_zero(n); // batched to-be-shifted polynomials

        for g_poly in g_polynomials.iter() {
            batched_to_be_shifted.add_scaled_slice(g_poly, &running_scalar);
            running_scalar *= rho;
        }
        println!("running_scalar after g_polys: {running_scalar}");
        if let Some(interleaved) = interleaved_polynomials
            && let Some(groups) = groups_to_be_interleaved
        {
            let mut batched_interleaved = Polynomial::new_zero(n); // batched interleaved polynomials
            println!("full_batched_size: {n}");

            let mut batched_group: Vec<Polynomial<P::ScalarField>> =
                Vec::with_capacity(groups[0].len());
            for _ in 0..groups[0].len() {
                batched_group.push(Polynomial::new_zero(n));
            }

            for (inter_poly, group_polys) in interleaved.iter().zip(groups.iter()) {
                println!("running_scalar: {running_scalar}");
                batched_interleaved.add_scaled_slice(inter_poly, &running_scalar);
                println!(
                    "batched_interleaved after adding: {:?}",
                    batched_interleaved
                );
                for (j, grp_poly) in group_polys.iter().enumerate() {
                    batched_group[j].add_scaled_slice(grp_poly, &running_scalar);
                }
                running_scalar *= rho;
            }
            // println!("batched interleaved: {:?}", batched_interleaved);

            Ok((
                batched_unshifted,
                batched_to_be_shifted,
                Some(batched_interleaved),
                Some(batched_group),
            ))
        } else {
            Ok((batched_unshifted, batched_to_be_shifted, None, None))
        }
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
        &mut self,
        multilinear_challenge: &[P::ScalarField],
        log_n: usize,
        commitment_key: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<Vec<ShpleminiOpeningClaim<P::ScalarField>>> {
        tracing::trace!("Gemini prove");
        // To achieve fixed proof size in Ultra and Mega, the multilinear opening challenge is be padded to a fixed size.
        let virtual_log_n: usize = multilinear_challenge.len();
        // Compute batched polynomials
        let (batched_unshifted, batched_to_be_shifted, interleaved, groups) =
            self.compute_batched_polys(transcript, multilinear_challenge, log_n, commitment_key)?;

        // We do not have any concatenated polynomials in UltraHonk

        // Construct the batched polynomial A₀(X) = F(X) + G↺(X) = F(X) + G(X)/X
        let mut a_0 = batched_unshifted.to_owned();
        a_0 += batched_to_be_shifted.shifted().as_ref();
        if let Some(interleaved) = interleaved {
            a_0 += interleaved.as_ref();
        }
        // Construct the d-1 Gemini foldings of A₀(X)
        let fold_polynomials = Self::compute_fold_polynomials(log_n, multilinear_challenge, a_0);

        for (l, f_poly) in fold_polynomials.iter().take(log_n).enumerate() {
            let res = Utils::commit(&f_poly.coefficients, commitment_key)?;
            transcript.send_point_to_verifier::<P>(format!("Gemini:FOLD_{}", l + 1), res.into());
        }
        let res = P::Affine::generator();
        for l in log_n - 1..virtual_log_n - 1 {
            transcript.send_point_to_verifier::<P>(format!("Gemini:FOLD_{}", l + 1), res);
        }

        let r_challenge = transcript.get_challenge::<P>("Gemini:r".to_string());

        let gemini_challenge_in_small_subgroup: bool = (has_zk == ZeroKnowledge::Yes)
            && (r_challenge.pow([P::SUBGROUP_SIZE as u64]) == P::ScalarField::one());

        // If Gemini evaluation challenge lands in the multiplicative subgroup used by SmallSubgroupIPA protocol, the
        // evaluations of prover polynomials at this challenge would leak witness data.
        // Aztec TODO(https://github.com/AztecProtocol/barretenberg/issues/1194). Handle edge cases in PCS
        if gemini_challenge_in_small_subgroup {
            return Err(HonkProofError::GeminiSmallSubgroup);
        }

        // Compute polynomials A₀₊(X) = F(X) + G(X)/r and A₀₋(X) = F(X) - G(X)/r
        let (a_0_pos, a_0_neg) = Self::compute_partially_evaluated_batch_polynomials(
            batched_unshifted,
            batched_to_be_shifted,
            r_challenge,
        );

        // Construct claims for the d + 1 univariate evaluations A₀₊(r), A₀₋(-r), and Foldₗ(−r^{2ˡ}), l = 1, ..., d-1
        let mut claims = Self::construct_univariate_opening_claims(
            log_n,
            a_0_pos,
            a_0_neg,
            fold_polynomials,
            r_challenge,
        );

        // If virtual_log_n >= log_n, pad the negative fold evaluations with zeroes.
        for (l, claim) in claims.iter().skip(1).take(log_n).enumerate() {
            transcript.send_fr_to_verifier::<P>(
                format!("Gemini:a_{}", l + 1),
                claim.opening_pair.evaluation,
            );
        }
        for l in log_n + 1..=virtual_log_n {
            transcript.send_fr_to_verifier::<P>(format!("Gemini:a_{l}"), P::ScalarField::zero());
        }

        if let Some(groups) = groups {
            let (p_pos, p_neg) =
                Self::compute_partially_evaluated_interleaved_polynomial(&groups, r_challenge);
            let groups_size = groups.len();
            let r_pow = r_challenge.pow([groups_size as u64]);
            let p_pos_eval = p_pos.eval_poly(r_pow);
            let p_neg_eval = p_neg.eval_poly(r_pow);
            claims.push(ShpleminiOpeningClaim {
                polynomial: p_pos,
                opening_pair: OpeningPair {
                    challenge: r_pow,
                    evaluation: p_pos_eval,
                },
                gemini_fold: false,
            });
            claims.push(ShpleminiOpeningClaim {
                polynomial: p_neg,
                opening_pair: OpeningPair {
                    challenge: r_pow,
                    evaluation: p_neg_eval,
                },
                gemini_fold: false,
            });
            transcript.send_fr_to_verifier::<P>("Gemini:P_pos".to_string(), p_pos_eval);
            transcript.send_fr_to_verifier::<P>("Gemini:P_neg".to_string(), p_neg_eval);
        }

        Ok(claims)
    }

    pub(crate) fn compute_fold_polynomials(
        log_n: usize,
        multilinear_challenge: &[P::ScalarField],
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
        for (l, u_l) in multilinear_challenge.iter().take(log_n - 1).enumerate() {
            // size of the previous polynomial/2
            let n_l = 1 << (log_n - l - 1);

            // A_l_fold = Aₗ₊₁(X) = (1-uₗ)⋅even(Aₗ)(X) + uₗ⋅odd(Aₗ)(X)
            let mut a_l_fold = Polynomial::new_zero(n_l);

            // Process each element in a single-threaded manner
            for j in 0..n_l {
                // fold(Aₗ)[j] = (1-uₗ)⋅even(Aₗ)[j] + uₗ⋅odd(Aₗ)[j]
                //            = (1-uₗ)⋅Aₗ[2j]      + uₗ⋅Aₗ[2j+1]
                //            = Aₗ₊₁[j]
                a_l_fold[j] = a_l[j << 1] + *u_l * (a_l[(j << 1) + 1] - a_l[j << 1]);
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

    /**
     * @brief Compute the partially evaluated polynomials P₊(X, r) and P₋(X, -r)
     *
     * @details If the interleaved polynomials are set, the full partially evaluated identites A₀(r) and  A₀(-r)
     * contain the contributions of P₊(r^s) and  P₋(r^s) respectively where s is the size of the interleaved group
     * assumed even. This function computes P₊(X) = ∑ r^i Pᵢ(X) and P₋(X) = ∑ (-r)^i Pᵢ(X) where Pᵢ(X) is the i-th
     * polynomial in the batched group.
     * @param r_challenge partial evaluation challenge
     * @return std::pair<Polynomial, Polynomial> {P₊, P₋}
     */
    fn compute_partially_evaluated_interleaved_polynomial(
        batched_group: &[Polynomial<P::ScalarField>],
        r_challenge: P::ScalarField,
    ) -> (Polynomial<P::ScalarField>, Polynomial<P::ScalarField>) {
        let mut p_pos = batched_group[0].clone();
        let mut p_neg = batched_group[0].clone();

        let mut current_r_shift_pos = r_challenge;
        let mut current_r_shift_neg = -r_challenge;
        for poly in batched_group.iter().skip(1) {
            p_pos.add_scaled(poly, &current_r_shift_pos);
            p_neg.add_scaled(poly, &current_r_shift_neg);
            current_r_shift_pos *= r_challenge;
            current_r_shift_neg *= -r_challenge;
        }

        (p_pos, p_neg)
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
            gemini_fold: false,
        });
        // Compute evaluation of partially evaluated batch polynomial (negative) A₀₋(-r)
        let evaluation = a_0_neg.eval_poly(-r_challenge);
        claims.push(ShpleminiOpeningClaim {
            polynomial: a_0_neg,
            opening_pair: OpeningPair {
                challenge: -r_challenge,
                evaluation,
            },
            gemini_fold: false,
        });

        // Compute univariate opening queries rₗ = r^{2ˡ} for l = 0, 1, ..., m-1
        let r_squares =
            DeciderVerifier::<P, H, L>::powers_of_evaluation_challenge(r_challenge, log_n);

        // Each fold polynomial Aₗ has to be opened at −r^{2ˡ} and r^{2ˡ}. To avoid storing two copies of Aₗ for l = 1,...,
        // m-1, we use a flag that is processed by ShplonkProver.
        let gemini_fold = true;

        // Compute the remaining m opening pairs {−r^{2ˡ}, Aₗ(−r^{2ˡ})}, l = 1, ..., m-1.

        for (r_square, fold_poly) in r_squares.into_iter().skip(1).zip(fold_polynomials) {
            let evaluation = fold_poly.eval_poly(-r_square);
            claims.push(ShpleminiOpeningClaim {
                polynomial: fold_poly,
                opening_pair: OpeningPair {
                    challenge: -r_square,
                    evaluation,
                },
                gemini_fold,
            });
        }

        claims
    }

    /**
     * @brief Compute evaluations of fold polynomials Fold_i at r^{2^i} for i>0.
     * AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1223): Reconsider minor performance/memory
     * optimizations in Gemini.
     * @param opening_claims
     * @return std::vector<Fr>
     */
    fn compute_gemini_fold_pos_evaluations(
        opening_claims: &[ShpleminiOpeningClaim<P::ScalarField>],
    ) -> Vec<P::ScalarField> {
        tracing::trace!("Compute gemini fold pos evaluations");
        let mut gemini_fold_pos_evaluations = Vec::with_capacity(opening_claims.len());

        for claim in opening_claims {
            if claim.gemini_fold {
                // -r^{2^i} is stored in the claim
                let evaluation_point = -claim.opening_pair.challenge;
                // Compute Fold_i(r^{2^i})
                let evaluation = claim.polynomial.eval_poly(evaluation_point);
                gemini_fold_pos_evaluations.push(evaluation);
            }
        }

        gemini_fold_pos_evaluations
    }

    /// Returns a batched opening claim equivalent to a set of opening claims consisting of polynomials, each opened at a single point.
    pub fn shplonk_prove(
        &self,
        opening_claims: Vec<ShpleminiOpeningClaim<P::ScalarField>>,
        commitment_key: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        libra_opening_claims: Option<Vec<ShpleminiOpeningClaim<P::ScalarField>>>,
        sumcheck_round_claims: Option<Vec<ShpleminiOpeningClaim<P::ScalarField>>>,
        virtual_log_n: usize,
    ) -> HonkProofResult<ShpleminiOpeningClaim<P::ScalarField>> {
        tracing::trace!("Shplonk prove");
        let nu = transcript.get_challenge::<P>("Shplonk:nu".to_string());
        // Compute the evaluations Fold_i(r^{2^i}) for i>0.
        let gemini_fold_pos_evaluations =
            Self::compute_gemini_fold_pos_evaluations(&opening_claims);
        let batched_quotient = Self::compute_batched_quotient(
            virtual_log_n,
            &opening_claims,
            nu,
            &gemini_fold_pos_evaluations,
            &libra_opening_claims,
            &sumcheck_round_claims,
        );
        let batched_quotient_commitment =
            Utils::commit(&batched_quotient.coefficients, commitment_key)?;
        transcript.send_point_to_verifier::<P>(
            "Shplonk:Q".to_string(),
            batched_quotient_commitment.into(),
        );

        let z = transcript.get_challenge::<P>("Shplonk:z".to_string());

        Ok(Self::compute_partially_evaluated_batched_quotient(
            virtual_log_n,
            opening_claims,
            batched_quotient,
            nu,
            z,
            &gemini_fold_pos_evaluations,
            libra_opening_claims,
            sumcheck_round_claims,
        ))
    }

    /// Computes a Shplemini proof which is a combination of Gemini and Shplonk (Shplonk reduces multiple openings into one).
    pub fn shplemini_prove(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField, L>,
        libra_polynomials: Option<[Polynomial<P::ScalarField>; NUM_SMALL_IPA_EVALUATIONS]>,
    ) -> HonkProofResult<ShpleminiOpeningClaim<P::ScalarField>> {
        let has_zk = self.has_zk;

        // When padding is enabled, the size of the multilinear challenge may be bigger than the log of `circuit_size`.
        let virtual_log_n: usize = sumcheck_output.challenges.len();

        tracing::trace!("Shplemini prove");
        let log_circuit_size = Utils::get_msb32(circuit_size);
        let opening_claims = self.gemini_prove(
            &sumcheck_output.challenges,
            log_circuit_size as usize,
            crs,
            has_zk,
            transcript,
        )?;

        let libra_opening_claims = if has_zk == ZeroKnowledge::Yes {
            let gemini_r = opening_claims[0].opening_pair.challenge;
            let libra_opening_claims = Self::compute_libra_opening_claims(
                gemini_r,
                libra_polynomials.expect("we have ZK"),
                transcript,
            );
            Some(libra_opening_claims)
        } else {
            None
        };

        let sumcheck_round_claims = if let (Some(univariates), Some(evaluations)) = (
            sumcheck_output.round_univariates.as_ref(),
            sumcheck_output.round_univariate_evaluations.as_ref(),
        ) {
            Some(Self::compute_sumcheck_round_claims(
                circuit_size,
                &sumcheck_output.challenges,
                univariates,
                evaluations,
            ))
        } else {
            None
        };

        self.shplonk_prove(
            opening_claims,
            crs,
            transcript,
            libra_opening_claims,
            sumcheck_round_claims,
            virtual_log_n,
        )
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
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn compute_partially_evaluated_batched_quotient(
        virtual_log_n: usize,
        opening_claims: Vec<ShpleminiOpeningClaim<P::ScalarField>>,
        batched_quotient_q: Polynomial<P::ScalarField>,
        nu_challenge: P::ScalarField,
        z_challenge: P::ScalarField,
        gemini_fold_pos_evaluations: &[P::ScalarField],
        libra_opening_claims: Option<Vec<ShpleminiOpeningClaim<P::ScalarField>>>,
        sumcheck_round_claims: Option<Vec<ShpleminiOpeningClaim<P::ScalarField>>>,
    ) -> ShpleminiOpeningClaim<P::ScalarField> {
        tracing::trace!("Compute partially evaluated batched quotient");
        let has_zk = ZeroKnowledge::from(libra_opening_claims.is_some());
        // Our main use case is the opening of Gemini fold polynomials and each Gemini fold is opened at 2 points.
        let num_gemini_opening_claims = 2 * opening_claims.len();
        let num_opening_claims = num_gemini_opening_claims
            + libra_opening_claims
                .as_ref()
                .map_or(0, |claims| claims.len());

        let mut inverse_vanishing_evals: Vec<P::ScalarField> =
            Vec::with_capacity(num_opening_claims);
        for claim in &opening_claims {
            if claim.gemini_fold {
                inverse_vanishing_evals.push(z_challenge + claim.opening_pair.challenge);
            }
            inverse_vanishing_evals.push(z_challenge - claim.opening_pair.challenge);
        }

        // Add the terms (z - uₖ) for k = 0, …, d−1 where d is the number of rounds in Sumcheck
        if let Some(libra_opening_claims) = &libra_opening_claims {
            for claim in libra_opening_claims.iter() {
                inverse_vanishing_evals.push(z_challenge - claim.opening_pair.challenge);
            }
        }

        if let Some(sumcheck_round_claims) = &sumcheck_round_claims {
            for claim in sumcheck_round_claims.iter() {
                inverse_vanishing_evals.push(z_challenge - claim.opening_pair.challenge);
            }
        }

        inverse_vanishing_evals.iter_mut().for_each(|x| {
            x.inverse_in_place();
        });

        let mut g = batched_quotient_q;
        let mut current_nu = P::ScalarField::one();
        let mut idx = 0;
        let mut fold_idx = 0;
        for claim in opening_claims.into_iter() {
            if claim.gemini_fold {
                let mut tmp = claim.polynomial.clone();
                tmp[0] -= gemini_fold_pos_evaluations[fold_idx];
                let scaling_factor = current_nu * inverse_vanishing_evals[idx]; // = νʲ / (z − xⱼ )
                // G -= νʲ ⋅ ( fⱼ(X) − vⱼ) / ( z − xⱼ )
                g.add_scaled(&tmp, &-scaling_factor);

                current_nu *= nu_challenge;
                idx += 1;
                fold_idx += 1;
            }
            let mut tmp = claim.polynomial;
            tmp[0] -= claim.opening_pair.evaluation;
            let scaling_factor = current_nu * inverse_vanishing_evals[idx];

            g.add_scaled(&tmp, &-scaling_factor);

            current_nu *= nu_challenge;
            idx += 1;
        }

        // Take into account the constant proof size in Gemini
        if has_zk == ZeroKnowledge::Yes {
            current_nu =
                nu_challenge.pow([2 * virtual_log_n as u64 + NUM_INTERLEAVING_CLAIMS as u64]);
        }

        if has_zk == ZeroKnowledge::Yes {
            for claim in libra_opening_claims.expect("Has ZK").into_iter() {
                // Compute individual claim quotient tmp = ( fⱼ(X) − vⱼ) / ( X − xⱼ )
                let mut tmp = claim.polynomial;
                tmp[0] -= claim.opening_pair.evaluation;
                let scaling_factor = current_nu * inverse_vanishing_evals[idx]; // = νʲ / (z − xⱼ )

                // Add the claim quotient to the batched quotient polynomial
                g.add_scaled(&tmp, &-scaling_factor);
                current_nu *= nu_challenge;
                idx += 1;
            }
        }

        if let Some(sumcheck_round_claims) = sumcheck_round_claims {
            for claim in sumcheck_round_claims.into_iter() {
                // Compute individual claim quotient tmp = ( fⱼ(X) − vⱼ) / ( X − xⱼ )
                let mut tmp = claim.polynomial;
                tmp[0] -= claim.opening_pair.evaluation;
                let scaling_factor = current_nu * inverse_vanishing_evals[idx]; // = νʲ / (z − xⱼ )

                // Add the claim quotient to the batched quotient polynomial
                g.add_scaled(&tmp, &-scaling_factor);
                current_nu *= nu_challenge;
                idx += 1;
            }
        }

        ShpleminiOpeningClaim {
            polynomial: g,
            opening_pair: OpeningPair {
                challenge: z_challenge,
                evaluation: P::ScalarField::zero(),
            },
            gemini_fold: false,
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
        virtual_log_n: usize,
        opening_claims: &Vec<ShpleminiOpeningClaim<P::ScalarField>>,
        nu_challenge: P::ScalarField,
        gemini_fold_pos_evaluations: &[P::ScalarField],
        libra_opening_claims: &Option<Vec<ShpleminiOpeningClaim<P::ScalarField>>>,
        sumcheck_round_claims: &Option<Vec<ShpleminiOpeningClaim<P::ScalarField>>>,
    ) -> Polynomial<P::ScalarField> {
        tracing::trace!("Compute batched quotient");
        let has_zk = ZeroKnowledge::from(libra_opening_claims.is_some());
        // Find n, the maximum size of all polynomials fⱼ(X)
        let mut max_poly_size: usize = 0;

        for claim in opening_claims.iter() {
            max_poly_size = max_poly_size.max(claim.polynomial.len());
        }

        if let Some(libra_claims) = libra_opening_claims {
            for claim in libra_claims.iter() {
                max_poly_size = max_poly_size.max(claim.polynomial.len());
            }
        }
        if let Some(sumcheck_claims) = sumcheck_round_claims {
            for claim in sumcheck_claims.iter() {
                max_poly_size = max_poly_size.max(claim.polynomial.len());
            }
        }

        // The polynomials in Libra opening claims are generally not dyadic,
        // so we round up to the next power of 2.
        max_poly_size = max_poly_size.next_power_of_two();

        // Q(X) = ∑ⱼ νʲ ⋅ ( fⱼ(X) − vⱼ) / ( X − xⱼ )
        let mut q = Polynomial::new_zero(max_poly_size);
        let mut current_nu = P::ScalarField::one();
        let mut fold_idx = 0;
        for claim in opening_claims {
            // Gemini Fold Polynomials have to be opened at -r^{2^j} and r^{2^j}.
            if claim.gemini_fold {
                let mut tmp = claim.polynomial.clone();
                tmp[0] -= gemini_fold_pos_evaluations[fold_idx];
                tmp.factor_roots(&-claim.opening_pair.challenge);
                // Add the claim quotient to the batched quotient polynomial
                q.add_scaled(&tmp, &current_nu);
                current_nu *= nu_challenge;
                fold_idx += 1;
            }
            // Compute individual claim quotient tmp = ( fⱼ(X) − vⱼ) / ( X − xⱼ )
            let mut tmp = claim.polynomial.clone();
            tmp[0] -= claim.opening_pair.evaluation;
            tmp.factor_roots(&claim.opening_pair.challenge);

            // Add the claim quotient to the batched quotient polynomial
            q.add_scaled(&tmp, &current_nu);
            current_nu *= nu_challenge;
        }

        // We use the same batching challenge for Gemini and Libra opening claims. The number of the claims
        // batched before adding Libra commitments and evaluations is bounded by 2 * CONST_PROOF_SIZE_LOG_N + 2, where
        // 2 * CONST_PROOF_SIZE_LOG_N is the number of fold claims including the dummy ones, and +2 is reserved for
        // interleaving.
        if has_zk == ZeroKnowledge::Yes {
            current_nu =
                nu_challenge.pow([2 * virtual_log_n as u64 + NUM_INTERLEAVING_CLAIMS as u64]);
        }

        if let Some(libra_claims) = libra_opening_claims {
            for claim in libra_claims.iter() {
                // Compute individual claim quotient tmp = ( fⱼ(X) − vⱼ) / ( X − xⱼ )
                let mut tmp = claim.polynomial.clone();
                tmp[0] -= claim.opening_pair.evaluation;
                tmp.factor_roots(&claim.opening_pair.challenge);

                // Add the claim quotient to the batched quotient polynomial
                q.add_scaled(&tmp, &current_nu);
                current_nu *= nu_challenge;
            }
        }
        if let Some(sumcheck_claim) = sumcheck_round_claims {
            for claim in sumcheck_claim.iter() {
                // Compute individual claim quotient tmp = ( fⱼ(X) − vⱼ) / ( X − xⱼ )
                let mut tmp = claim.polynomial.clone();
                tmp[0] -= claim.opening_pair.evaluation;
                tmp.factor_roots(&claim.opening_pair.challenge);

                // Add the claim quotient to the batched quotient polynomial
                q.add_scaled(&tmp, &current_nu);
                current_nu *= nu_challenge;
            }
        }

        // Return batched quotient polynomial Q(X)
        q
    }

    /**
     * @brief For ZK Flavors: Evaluate the polynomials used in SmallSubgroupIPA argument, send the evaluations to the
     * verifier, and populate a vector of the opening claims.
     *
     */
    fn compute_libra_opening_claims(
        gemini_r: P::ScalarField,
        libra_polynomials: [Polynomial<P::ScalarField>; NUM_SMALL_IPA_EVALUATIONS],
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> Vec<ShpleminiOpeningClaim<P::ScalarField>> {
        tracing::trace!("Compute libra opening claims");
        let mut libra_opening_claims = Vec::with_capacity(NUM_SMALL_IPA_EVALUATIONS);

        let subgroup_generator = P::get_subgroup_generator();

        let libra_eval_labels = [
            "Libra:concatenation_eval",
            "Libra:shifted_grand_sum_eval",
            "Libra:grand_sum_eval",
            "Libra:quotient_eval",
        ];
        let evaluation_points = [gemini_r, gemini_r * subgroup_generator, gemini_r, gemini_r];

        for (label, poly, point) in izip!(libra_eval_labels, libra_polynomials, evaluation_points) {
            let eval = poly.eval_poly(point);
            let new_claim = ShpleminiOpeningClaim {
                polynomial: poly,
                opening_pair: OpeningPair {
                    challenge: point,
                    evaluation: eval,
                },
                gemini_fold: false,
            };
            transcript
                .send_fr_to_verifier::<P>(label.to_string(), new_claim.opening_pair.evaluation);
            libra_opening_claims.push(new_claim);
        }

        libra_opening_claims
    }

    // Create a vector of 3*log_n opening claims for the evaluations of Sumcheck Round Univariates at
    //  0, 1, and a round challenge.
    fn compute_sumcheck_round_claims(
        circuit_size: u32,
        multilinear_challenge: &[P::ScalarField],
        sumcheck_round_univariates: &[Polynomial<P::ScalarField>],
        sumcheck_round_evaluations: &[[P::ScalarField; 3]],
    ) -> Vec<ShpleminiOpeningClaim<P::ScalarField>> {
        let log_n = Utils::get_msb32(circuit_size) as usize;
        let mut sumcheck_round_claims = Vec::with_capacity(2 * log_n);
        for (idx, univariate) in sumcheck_round_univariates.iter().enumerate().take(log_n) {
            let evaluation_points = [
                P::ScalarField::zero(),
                P::ScalarField::one(),
                multilinear_challenge[idx],
            ];

            for (eval_idx, eval_point) in evaluation_points.iter().enumerate() {
                let new_claim = ShpleminiOpeningClaim {
                    polynomial: univariate.clone(),
                    opening_pair: OpeningPair {
                        challenge: *eval_point,
                        evaluation: sumcheck_round_evaluations[idx][eval_idx],
                    },
                    gemini_fold: false,
                };
                sumcheck_round_claims.push(new_claim);
            }
        }

        sumcheck_round_claims
    }
}
