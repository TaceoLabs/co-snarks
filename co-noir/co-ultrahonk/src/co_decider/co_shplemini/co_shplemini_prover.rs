use super::types::PolyF;
use crate::mpc_prover_flavour::MPCProverFlavour;
use crate::{
    co_decider::{co_decider_prover::CoDecider, co_sumcheck::SumcheckOutput},
    types::AllEntities,
};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use co_builder::HonkProofResult;
use co_builder::TranscriptFieldType;
use co_builder::polynomials::polynomial_flavours::PolyGFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::{
    HonkProofError,
    prelude::{HonkCurve, Polynomial, ProverCrs},
};
use common::CoUtils;
use common::co_shplemini::{OpeningPair, ShpleminiOpeningClaim};
use common::mpc::NoirUltraHonkProver;
use common::shared_polynomial::SharedPolynomial;
use common::transcript::{Transcript, TranscriptHasher};
use itertools::izip;
use mpc_core::MpcState as _;
use mpc_net::Network;
use ultrahonk::prelude::ZeroKnowledge;
use ultrahonk::{NUM_INTERLEAVING_CLAIMS, NUM_SMALL_IPA_EVALUATIONS, Utils};

impl<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
    L: MPCProverFlavour,
> CoDecider<'_, T, P, H, N, L>
{
    fn get_f_polynomials(
        polys: &'_ AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
    ) -> PolyF<'_, Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L> {
        PolyF {
            precomputed: &polys.precomputed,
            witness: &polys.witness,
        }
    }

    fn get_g_polynomials<'a>(
        polys: &'a AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
    ) -> L::PolyG<'a, Vec<T::ArithmeticShare>> {
        L::PolyG::from_slice(polys.witness.to_be_shifted())
    }

    fn compute_batched_polys(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        multilinear_challenge: &[P::ScalarField],
        log_n: usize,
        commitment_key: &ProverCrs<P>,
        has_zk: ZeroKnowledge,
    ) -> HonkProofResult<(SharedPolynomial<T, P>, SharedPolynomial<T, P>)> {
        let f_polynomials = Self::get_f_polynomials(&self.memory.polys);
        let g_polynomials = Self::get_g_polynomials(&self.memory.polys);
        let n = 1 << log_n;
        let mut batched_unshifted = SharedPolynomial::new_zero(n); // batched unshifted polynomials

        // To achieve ZK, we mask the batched polynomial by a random polynomial of the same size
        if has_zk == ZeroKnowledge::Yes {
            batched_unshifted = SharedPolynomial::<T, P>::random(n, self.net, self.state)?;
            let masking_poly_comm_shared =
                CoUtils::commit::<T, P>(batched_unshifted.as_ref(), commitment_key);

            // In the provers, the size of multilinear_challenge is `virtual_log_n`, but we need to evaluate the
            // hiding polynomial as multilinear in log_n variables
            let masking_poly_eval_shared =
                batched_unshifted.evaluate_mle(&multilinear_challenge[0..log_n]);
            let (masking_poly_comm, masking_poly_eval) = T::open_point_and_field(
                masking_poly_comm_shared,
                masking_poly_eval_shared,
                self.net,
                self.state,
            )?;
            transcript.send_point_to_verifier::<P>(
                "Gemini:masking_poly_comm".to_string(),
                masking_poly_comm.into(),
            );
            transcript.send_fr_to_verifier::<P>(
                "Gemini:masking_poly_eval".to_string(),
                masking_poly_eval,
            );
        }

        // Generate batching challenge \rho and powers 1,...,\rho^{m-1}
        let rho = transcript.get_challenge::<P>("rho".to_string());

        // Compute batching of unshifted polynomials f_i and to-be-shifted polynomials g_i:
        // f_batched = sum_{i=0}^{m-1}\rho^i*f_i and g_batched = sum_{i=0}^{l-1}\rho^{m+i}*g_i,
        // and also batched evaluation
        // v = sum_{i=0}^{m-1}\rho^i*f_i(u) + sum_{i=0}^{l-1}\rho^{m+i}*h_i(u).
        // Note: g_batched is formed from the to-be-shifted polynomials, but the batched evaluation incorporates the
        // evaluations produced by sumcheck of h_i = g_i_shifted.

        let mut running_scalar = P::ScalarField::ONE;

        if has_zk == ZeroKnowledge::Yes {
            // ρ⁰ is used to batch the hiding polynomial
            running_scalar *= rho;
        }

        if has_zk == ZeroKnowledge::Yes {
            // Precomputed part of batched_unshifted
            for f_poly in f_polynomials.precomputed.iter() {
                batched_unshifted.add_scaled_slice_public(self.state.id(), f_poly, &running_scalar);
                running_scalar *= rho;
            }
        } else {
            let mut batched_unshifted_plain = Polynomial::new_zero(n); // batched unshifted polynomials

            // Precomputed part of batched_unshifted
            for f_poly in f_polynomials.precomputed.iter() {
                batched_unshifted_plain.add_scaled_slice(f_poly, &running_scalar);
                running_scalar *= rho;
            }

            // Shared part of batched_unshifted
            batched_unshifted =
                SharedPolynomial::<T, P>::promote_poly(self.state.id(), batched_unshifted_plain);
        }
        for f_poly in f_polynomials.witness.iter() {
            batched_unshifted.add_scaled_slice(f_poly, &running_scalar);
            running_scalar *= rho;
        }

        // For batched_to_be_shifted we only have shared
        let mut batched_to_be_shifted = SharedPolynomial::<T, P>::new_zero(n); // batched to-be-shifted polynomials

        for g_poly in g_polynomials.iter() {
            batched_to_be_shifted.add_scaled_slice(g_poly, &running_scalar);
            running_scalar *= rho;
        }

        Ok((batched_unshifted, batched_to_be_shifted))
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
    ) -> HonkProofResult<Vec<ShpleminiOpeningClaim<T, P>>> {
        tracing::trace!("Gemini prove");
        // To achieve fixed proof size in Ultra and Mega, the multilinear opening challenge is be padded to a fixed size.
        let virtual_log_n: usize = multilinear_challenge.len();
        // Compute batched polynomials
        let (batched_unshifted, batched_to_be_shifted) = self.compute_batched_polys(
            transcript,
            multilinear_challenge,
            log_n,
            commitment_key,
            has_zk,
        )?;

        // We do not have any concatenated polynomials in UltraHonk

        // Construct the batched polynomial A₀(X) = F(X) + G↺(X) = F(X) + G(X)/X
        let mut a_0 = batched_unshifted.to_owned();
        a_0.add_assign_slice(batched_to_be_shifted.shifted());

        // Construct the d-1 Gemini foldings of A₀(X)
        let fold_polynomials = self.compute_fold_polynomials(log_n, multilinear_challenge, a_0);

        let mut commitments = Vec::with_capacity(fold_polynomials.len());
        for f_poly in fold_polynomials.iter().take(log_n) {
            commitments.push(CoUtils::commit::<T, P>(
                &f_poly.coefficients,
                commitment_key,
            ));
        }
        let commitments = T::open_point_many(&commitments, self.net, self.state)?;
        for (l, res) in commitments.into_iter().enumerate() {
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

        let (a_0_pos, a_0_neg) = self.compute_partially_evaluated_batch_polynomials(
            batched_unshifted,
            batched_to_be_shifted,
            r_challenge,
        );

        let claims = self.construct_univariate_opening_claims(
            log_n,
            a_0_pos,
            a_0_neg,
            fold_polynomials,
            r_challenge,
        );

        let claim_eval = claims
            .iter()
            .skip(1)
            .take(log_n)
            .map(|claim| claim.opening_pair.evaluation)
            .collect::<Vec<_>>();
        let claim_eval = T::open_many(&claim_eval, self.net, self.state)?;
        for (l, claim) in claim_eval.into_iter().enumerate() {
            transcript.send_fr_to_verifier::<P>(format!("Gemini:a_{}", l + 1), claim);
        }
        for l in log_n + 1..=virtual_log_n {
            transcript.send_fr_to_verifier::<P>(format!("Gemini:a_{l}"), P::ScalarField::zero());
        }

        Ok(claims)
    }

    pub(crate) fn compute_fold_polynomials(
        &mut self,
        log_n: usize,
        multilinear_challenge: &[P::ScalarField],
        a_0: SharedPolynomial<T, P>,
    ) -> Vec<SharedPolynomial<T, P>> {
        tracing::trace!("Compute fold polynomials");
        // Note: bb uses multithreading here
        let mut fold_polynomials: Vec<SharedPolynomial<T, P>> = Vec::with_capacity(log_n + 1);

        // A_l = Aₗ(X) is the polynomial being folded
        // in the first iteration, we take the batched polynomial
        // in the next iteration, it is the previously folded one
        let mut a_l = a_0.coefficients;
        debug_assert!(multilinear_challenge.len() >= log_n - 1);
        for (l, u_l) in multilinear_challenge.iter().take(log_n - 1).enumerate() {
            // size of the previous polynomial/2
            let n_l = 1 << (log_n - l - 1);

            // A_l_fold = Aₗ₊₁(X) = (1-uₗ)⋅even(Aₗ)(X) + uₗ⋅odd(Aₗ)(X)
            let mut a_l_fold = SharedPolynomial::<T, P>::new_zero(n_l);

            for j in 0..n_l {
                // fold(Aₗ)[j] = (1-uₗ)⋅even(Aₗ)[j] + uₗ⋅odd(Aₗ)[j]
                //            = (1-uₗ)⋅Aₗ[2j]      + uₗ⋅Aₗ[2j+1]
                //            = Aₗ₊₁[j]
                let a_l_neg = T::neg(a_l[j << 1]);
                a_l_fold[j] = T::add(
                    a_l[j << 1],
                    T::mul_with_public(*u_l, T::add(a_l[(j << 1) + 1], a_l_neg)),
                );
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
        &mut self,
        batched_f: SharedPolynomial<T, P>,
        mut batched_g: SharedPolynomial<T, P>,
        r_challenge: P::ScalarField,
    ) -> (SharedPolynomial<T, P>, SharedPolynomial<T, P>) {
        tracing::trace!("Compute_partially_evaluated_batch_polynomials");

        let mut a_0_pos = batched_f.to_owned(); // A₀₊ = F
        let mut a_0_neg = batched_f; // A₀₋ = F

        // Compute G/r
        let r_inv = r_challenge.inverse().unwrap();
        batched_g.coefficients.iter_mut().for_each(|x| {
            *x = T::mul_with_public(r_inv, *x);
        });

        a_0_pos.add_assign_slice(batched_g.as_ref()); // A₀₊ = F + G/r
        a_0_neg.sub_assign_slice(batched_g.as_ref()); // A₀₋ = F - G/r

        (a_0_pos, a_0_neg)
    }

    fn powers_of_evaluation_challenge(
        gemini_evaluation_challenge: P::ScalarField,
        num_squares: usize,
    ) -> Vec<P::ScalarField> {
        let mut squares = Vec::with_capacity(num_squares);
        squares.push(gemini_evaluation_challenge);
        for j in 1..num_squares {
            squares.push(squares[j - 1].square());
        }
        squares
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
        &mut self,
        log_n: usize,
        a_0_pos: SharedPolynomial<T, P>,
        a_0_neg: SharedPolynomial<T, P>,
        fold_polynomials: Vec<SharedPolynomial<T, P>>,
        r_challenge: P::ScalarField,
    ) -> Vec<ShpleminiOpeningClaim<T, P>> {
        let mut claims = Vec::with_capacity(log_n + 1);

        // Compute evaluation of partially evaluated batch polynomial (positive) A₀₊(r)
        let evaluation = T::eval_poly(a_0_pos.as_ref(), r_challenge);
        claims.push(ShpleminiOpeningClaim {
            polynomial: a_0_pos,
            opening_pair: OpeningPair {
                challenge: r_challenge,
                evaluation,
            },
            gemini_fold: false,
        });
        // Compute evaluation of partially evaluated batch polynomial (negative) A₀₋(-r)
        let evaluation = T::eval_poly(a_0_neg.as_ref(), -r_challenge);
        claims.push(ShpleminiOpeningClaim {
            polynomial: a_0_neg,
            opening_pair: OpeningPair {
                challenge: -r_challenge,
                evaluation,
            },
            gemini_fold: false,
        });

        // Compute univariate opening queries rₗ = r^{2ˡ} for l = 0, 1, ..., m-1
        let r_squares = Self::powers_of_evaluation_challenge(r_challenge, log_n);

        // Each fold polynomial Aₗ has to be opened at −r^{2ˡ} and r^{2ˡ}. To avoid storing two copies of Aₗ for l = 1,...,
        // m-1, we use a flag that is processed by ShplonkProver.
        let gemini_fold = true;

        // Compute the remaining m opening pairs {−r^{2ˡ}, Aₗ(−r^{2ˡ})}, l = 1, ..., m-1.

        for (r_square, fold_poly) in r_squares.into_iter().skip(1).zip(fold_polynomials) {
            let evaluation = T::eval_poly(fold_poly.as_ref(), -r_square);
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
        opening_claims: &[ShpleminiOpeningClaim<T, P>],
    ) -> Vec<T::ArithmeticShare> {
        tracing::trace!("Compute gemini fold pos evaluations");
        let mut gemini_fold_pos_evaluations = Vec::with_capacity(opening_claims.len());

        for claim in opening_claims {
            if claim.gemini_fold {
                // -r^{2^i} is stored in the claim
                let evaluation_point = -claim.opening_pair.challenge;
                // Compute Fold_i(r^{2^i})
                let evaluation = T::eval_poly(claim.polynomial.as_ref(), evaluation_point);
                gemini_fold_pos_evaluations.push(evaluation);
            }
        }

        gemini_fold_pos_evaluations
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
        libra_opening_claims: Option<Vec<ShpleminiOpeningClaim<T, P>>>,
        sumcheck_round_claims: Option<Vec<ShpleminiOpeningClaim<T, P>>>,
        virtual_log_n: usize,
    ) -> HonkProofResult<ShpleminiOpeningClaim<T, P>> {
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
            CoUtils::commit::<T, P>(batched_quotient.as_ref(), commitment_key);
        let batched_quotient_commitment =
            T::open_point(batched_quotient_commitment, self.net, self.state)?;
        transcript.send_point_to_verifier::<P>(
            "Shplonk:Q".to_string(),
            batched_quotient_commitment.into(),
        );

        let z = transcript.get_challenge::<P>("Shplonk:z".to_string());

        Ok(self.compute_partially_evaluated_batched_quotient(
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

    pub(crate) fn shplemini_prove(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        circuit_size: u32,
        crs: &ProverCrs<P>,
        sumcheck_output: SumcheckOutput<T, P, L>,
        libra_polynomials: Option<[SharedPolynomial<T, P>; NUM_SMALL_IPA_EVALUATIONS]>,
    ) -> HonkProofResult<ShpleminiOpeningClaim<T, P>> {
        let has_zk = ZeroKnowledge::from(libra_polynomials.is_some());

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
                self.net,
                self.state,
            )?;
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

        let batched_claim = self.shplonk_prove(
            opening_claims,
            crs,
            transcript,
            libra_opening_claims,
            sumcheck_round_claims,
            virtual_log_n,
        )?;
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
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn compute_partially_evaluated_batched_quotient(
        &mut self,
        virtual_log_n: usize,
        opening_claims: Vec<ShpleminiOpeningClaim<T, P>>,
        batched_quotient_q: SharedPolynomial<T, P>,
        nu_challenge: P::ScalarField,
        z_challenge: P::ScalarField,
        gemini_fold_pos_evaluations: &[T::ArithmeticShare],
        libra_opening_claims: Option<Vec<ShpleminiOpeningClaim<T, P>>>,
        sumcheck_round_claims: Option<Vec<ShpleminiOpeningClaim<T, P>>>,
    ) -> ShpleminiOpeningClaim<T, P> {
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
                let sub = T::sub(tmp[0], gemini_fold_pos_evaluations[fold_idx]);
                tmp[0] = sub;
                let scaling_factor = current_nu * inverse_vanishing_evals[idx]; // = νʲ / (z − xⱼ )
                // G -= νʲ ⋅ ( fⱼ(X) − vⱼ) / ( z − xⱼ )
                g.add_scaled(&tmp, &-scaling_factor);

                current_nu *= nu_challenge;
                idx += 1;
                fold_idx += 1;
            }
            let mut tmp = claim.polynomial;
            let claim_neg = T::neg(claim.opening_pair.evaluation);
            tmp[0] = T::add(tmp[0], claim_neg);
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
                tmp[0] = T::sub(tmp[0], claim.opening_pair.evaluation);
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
                tmp[0] = T::sub(tmp[0], claim.opening_pair.evaluation);
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
                evaluation: T::ArithmeticShare::default(),
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
        opening_claims: &Vec<ShpleminiOpeningClaim<T, P>>,
        nu_challenge: P::ScalarField,
        gemini_fold_pos_evaluations: &[T::ArithmeticShare],
        libra_opening_claims: &Option<Vec<ShpleminiOpeningClaim<T, P>>>,
        sumcheck_round_claims: &Option<Vec<ShpleminiOpeningClaim<T, P>>>,
    ) -> SharedPolynomial<T, P> {
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

        // Q(X) = ∑ⱼ νʲ ⋅ ( fⱼ(X) − vⱼ) / ( X − xⱼ )
        let mut q = SharedPolynomial::<T, P>::new_zero(max_poly_size);
        let mut current_nu = P::ScalarField::one();
        let mut fold_idx = 0;
        for claim in opening_claims {
            // Gemini Fold Polynomials have to be opened at -r^{2^j} and r^{2^j}.
            if claim.gemini_fold {
                let mut tmp = claim.polynomial.clone();
                let sub = T::sub(tmp[0], gemini_fold_pos_evaluations[fold_idx]);
                tmp[0] = sub;
                tmp.factor_roots(&-claim.opening_pair.challenge);
                // Add the claim quotient to the batched quotient polynomial
                q.add_scaled(&tmp, &current_nu);
                current_nu *= nu_challenge;
                fold_idx += 1;
            }
            // Compute individual claim quotient tmp = ( fⱼ(X) − vⱼ) / ( X − xⱼ )
            let mut tmp = claim.polynomial.clone();
            let claim_neg = T::neg(claim.opening_pair.evaluation);
            tmp[0] = T::add(tmp[0], claim_neg);
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
                tmp[0] = T::sub(tmp[0], claim.opening_pair.evaluation);
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
                tmp[0] = T::sub(tmp[0], claim.opening_pair.evaluation);
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
        libra_polynomials: [SharedPolynomial<T, P>; NUM_SMALL_IPA_EVALUATIONS],
        transcript: &mut Transcript<TranscriptFieldType, H>,
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<Vec<ShpleminiOpeningClaim<T, P>>> {
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

        let mut to_open = Vec::with_capacity(libra_eval_labels.len());
        for (poly, point) in izip!(libra_polynomials, evaluation_points) {
            let eval = T::eval_poly(&poly.coefficients, point);

            let new_claim = ShpleminiOpeningClaim {
                polynomial: poly,
                opening_pair: OpeningPair {
                    challenge: point,
                    evaluation: eval,
                },
                gemini_fold: false,
            };
            to_open.push(new_claim.opening_pair.evaluation);
            libra_opening_claims.push(new_claim);
        }
        let opened = T::open_many(&to_open, net, state)?;
        for (val, label) in izip!(opened, libra_eval_labels) {
            transcript.send_fr_to_verifier::<P>(label.to_string(), val);
        }

        Ok(libra_opening_claims)
    }
    // Create a vector of 3*log_n opening claims for the evaluations of Sumcheck Round Univariates at
    //  0, 1, and a round challenge.
    fn compute_sumcheck_round_claims(
        circuit_size: u32,
        multilinear_challenge: &[P::ScalarField],
        sumcheck_round_univariates: &[SharedPolynomial<T, P>],
        sumcheck_round_evaluations: &[[T::ArithmeticShare; 3]],
    ) -> Vec<ShpleminiOpeningClaim<T, P>> {
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
