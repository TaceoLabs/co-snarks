use super::{
    super::{prover::Decider, sumcheck::SumcheckOutput},
    types::{PolyF, PolyG, PolyGShift},
    ZeroMorphOpeningClaim,
};
use crate::{
    decider::{polynomial::Polynomial, types::ClaimedEvaluations, zeromorph::OpeningPair},
    get_msb,
    honk_curve::HonkCurve,
    prover::HonkProofResult,
    transcript::{TranscriptFieldType, TranscriptType},
    types::ProvingKey,
    CONST_PROOF_SIZE_LOG_N, N_MAX,
};
use ark_ec::Group;
use ark_ff::{Field, One, Zero};
use itertools::izip;

impl<P: HonkCurve<TranscriptFieldType>> Decider<P> {
    // /**
    //  * @brief Compute multivariate quotients q_k(X_0, ..., X_{k-1}) for f(X_0, ..., X_{n-1})
    //  * @details Starting from the coefficients of f, compute q_k inductively from k = n - 1, to k = 0.
    //  *          f needs to be updated at each step.
    //  *
    //  *          First, compute q_{n-1} of size N/2 by
    //  *          q_{n-1}[l] = f[N/2 + l ] - f[l].
    //  *
    //  *          Update f by f[l] <- f[l] + u_{n-1} * q_{n-1}[l]; f now has size N/2.
    //  *          Compute q_{n-2} of size N/(2^2) by
    //  *          q_{n-2}[l] = f[N/2^2 + l] - f[l].
    //  *
    //  *          Update f by f[l] <- f[l] + u_{n-2} * q_{n-2}[l]; f now has size N/(2^2).
    //  *          Compute q_{n-3} of size N/(2^3) by
    //  *          q_{n-3}[l] = f[N/2^3 + l] - f[l]. Repeat similarly until you reach q_0.
    //  *
    //  * @param polynomial Multilinear polynomial f(X_0, ..., X_{d-1})
    //  * @param u_challenge Multivariate challenge u = (u_0, ..., u_{d-1})
    //  * @return std::vector<Polynomial> The quotients q_k
    //  */
    fn compute_multilinear_quotients(
        polynomial: &Polynomial<P::ScalarField>,
        u_challenge: &[P::ScalarField],
    ) -> Vec<Polynomial<P::ScalarField>> {
        let log_n = get_msb(polynomial.len() as u32);
        // Define the vector of quotients q_k, k = 0, ..., log_N-1
        // let mut quotients = Vec::with_capacity(log_n as usize);
        let mut quotients = vec![Polynomial::default(); log_n as usize];

        // Compute the coefficients of q_{n-1}
        let mut size_q = 1 << (log_n - 1);
        let mut q = Vec::with_capacity(size_q);
        let (half_a, half_b) = polynomial.coefficients.split_at(size_q);
        for (a, b) in half_a.iter().zip(half_b.iter()) {
            q.push(*b - a);
        }

        quotients[log_n as usize - 1].coefficients = q;

        let mut g = half_a.to_owned();

        // Compute q_k in reverse order from k= n-2, i.e. q_{n-2}, ..., q_0
        for k in 1..log_n {
            // Compute f_k
            let mut f_k = Vec::with_capacity(size_q);
            let index = log_n as usize - k as usize;
            for (g, q) in izip!(g, quotients[index].iter()) {
                f_k.push(g + u_challenge[index] * q);
            }
            size_q >>= 1;
            let mut q = Vec::with_capacity(size_q);
            let (half_a, half_b) = f_k.split_at(size_q);
            for (a, b) in half_a.iter().zip(half_b.iter()) {
                q.push(*b - a);
            }

            quotients[index - 1].coefficients = q;
            g = f_k;
        }

        quotients
    }

    /**
     * @brief Construct batched, lifted-degree univariate quotient \hat{q} = \sum_k y^k * X^{N - d_k - 1} * q_k
     * @details The purpose of the batched lifted-degree quotient is to reduce the individual degree checks
     * deg(q_k) <= 2^k - 1 to a single degree check on \hat{q}. This is done by first shifting each of the q_k to the
     * right (i.e. multiplying by an appropriate power of X) so that each is degree N-1, then batching them all together
     * using powers of the provided challenge. Note: In practice, we do not actually compute the shifted q_k, we simply
     * accumulate them into \hat{q} at the appropriate offset.
     *
     * @param quotients Polynomials q_k, interpreted as univariates; deg(q_k) = 2^k - 1
     * @param N circuit size
     * @return Polynomial
     */
    fn compute_batched_lifted_degree_quotient(
        quotients: &[Polynomial<P::ScalarField>],
        y_challenge: &P::ScalarField,
        n: usize,
    ) -> Polynomial<P::ScalarField> {
        // Batched lifted degree quotient polynomial
        let mut result = vec![P::ScalarField::zero(); n];

        // Compute \hat{q} = \sum_k y^k * X^{N - d_k - 1} * q_k
        let mut scalar = P::ScalarField::one();
        for (k, quotient) in quotients.iter().enumerate() {
            // Rather than explicitly computing the shifts of q_k by N - d_k - 1 (i.e. multiplying q_k by X^{N - d_k -
            // 1}) then accumulating them, we simply accumulate y^k*q_k into \hat{q} at the index offset N - d_k - 1
            let deg_k = (1 << k) - 1;
            let offset = n - deg_k - 1;

            for (r, q) in result
                .iter_mut()
                .skip(offset)
                .take(deg_k + 1)
                .zip(quotient.iter())
            {
                *r += scalar * q;
            }

            scalar *= y_challenge; // update batching scalar y^k
        }

        Polynomial::new(result)
    }

    // /**
    //  * @brief Compute partially evaluated degree check polynomial \zeta_x = q - \sum_k y^k * x^{N - d_k - 1} * q_k
    //  * @details Compute \zeta_x, where
    //  *
    //  *                          \zeta_x = q - \sum_k y^k * x^{N - d_k - 1} * q_k
    //  *
    //  * @param batched_quotient
    //  * @param quotients
    //  * @param y_challenge
    //  * @param x_challenge
    //  * @return Polynomial Degree check polynomial \zeta_x such that \zeta_x(x) = 0
    //  */
    fn compute_partially_evaluated_degree_check_polynomial(
        batched_quotient: &Polynomial<P::ScalarField>,
        quotients: &[Polynomial<P::ScalarField>],
        y_challenge: &P::ScalarField,
        x_challenge: &P::ScalarField,
    ) -> Polynomial<P::ScalarField> {
        let n = batched_quotient.len();

        // Initialize partially evaluated degree check polynomial \zeta_x to \hat{q}
        let mut result = batched_quotient.clone();

        let mut y_power = P::ScalarField::ONE; // y^k
        for (k, q) in quotients.iter().enumerate() {
            // Accumulate y^k * x^{N - d_k - 1} * q_k into \hat{q}
            let deg_k = (1 << k) - 1;
            let exponent = (n - deg_k - 1) as u64;
            let x_power = x_challenge.pow([exponent]); // x^{N - d_k - 1}

            result.add_scaled(q, &(-y_power * x_power));

            y_power *= y_challenge; // update batching scalar y^k
        }

        result
    }

    /**
     * @brief Compute partially evaluated zeromorph identity polynomial Z_x
     * @details Compute Z_x, where
     *
     *  Z_x = x * f_batched + g_batched - v * x * \Phi_n(x)
     *           - x * \sum_k (x^{2^k}\Phi_{n-k-1}(x^{2^{k-1}}) - u_k\Phi_{n-k}(x^{2^k})) * q_k
     *           + concatentation_term
     *
     * where f_batched = \sum_{i=0}^{m-1}\rho^i*f_i, g_batched = \sum_{i=0}^{l-1}\rho^{m+i}*g_i
     *
     * and concatenation_term = \sum_{i=0}^{num_chunks_per_group}(x^{i * min_N + 1}concatenation_groups_batched_{i})
     *
     * @note The concatenation term arises from an implementation detail in the Translator and is not part of the
     * conventional ZM protocol
     * @param input_polynomial
     * @param quotients
     * @param v_evaluation
     * @param x_challenge
     * @return Polynomial
     */
    fn compute_partially_evaluated_zeromorph_identity_polynomial(
        f_batched: Polynomial<P::ScalarField>,
        g_batched: Polynomial<P::ScalarField>,
        quotients: Vec<Polynomial<P::ScalarField>>,
        v_evaluation: P::ScalarField,
        u_challenge: &[P::ScalarField],
        x_challenge: P::ScalarField,
    ) -> Polynomial<P::ScalarField> {
        let n = f_batched.len();

        // Initialize Z_x with x * \sum_{i=0}^{m-1} f_i + \sum_{i=0}^{l-1} g_i
        let mut result = g_batched;
        result.add_scaled(&f_batched, &x_challenge);

        // Compute Z_x -= v * x * \Phi_n(x)
        let phi_numerator = x_challenge.pow([n as u64]) - P::ScalarField::ONE; // x^N - 1
        let phi_n_x = phi_numerator / (x_challenge - P::ScalarField::ONE);
        result[0] -= v_evaluation * x_challenge * phi_n_x;

        // Add contribution from q_k polynomials
        for (k, (q, u)) in izip!(quotients.iter(), u_challenge.iter()).enumerate() {
            let exp_1 = 1 << k;
            let x_power = x_challenge.pow([exp_1]); // x^{2^k}

            // \Phi_{n-k-1}(x^{2^{k + 1}})
            let exp_2 = 1 << (k + 1);
            let phi_term_1 = phi_numerator / (x_challenge.pow([exp_2]) - P::ScalarField::ONE);

            // \Phi_{n-k}(x^{2^k})
            let phi_term_2 = phi_numerator / (x_challenge.pow([exp_1]) - P::ScalarField::ONE);

            // x^{2^k} * \Phi_{n-k-1}(x^{2^{k+1}}) - u_k *  \Phi_{n-k}(x^{2^k})
            let mut scalar = x_power * phi_term_1 - phi_term_2 * u;

            scalar *= x_challenge;
            scalar *= -P::ScalarField::ONE;

            result.add_scaled(q, &scalar);
        }

        // We don't have groups, so we are done already

        result
    }

    /**
     * @brief Compute combined evaluation and degree-check polynomial pi
     * @details Compute univariate polynomial pi, where
     *
     *  pi = (\zeta_c + z*Z_x) X^{N_{max}-(N-1)}
     *
     * The proof that pi(x) = 0 for some verifier challenge x will then be computed as part of the univariate PCS
     * opening. If this is instantiated with KZG, the PCS is going to compute the quotient
     * q_pi = (q_\zeta + z*q_Z)X^{N_{max}-(N-1)}, with q_\zeta = \zeta_x/(X-x), q_Z = Z_x/(X-x),
     *
     * @param Z_x
     * @param zeta_x
     * @param x_challenge
     * @param z_challenge
     * @param N_max
     * @return Polynomial
     */
    fn compute_batched_evaluation_and_degree_check_polynomial(
        zeta_x: Polynomial<P::ScalarField>,
        z_x: Polynomial<P::ScalarField>,
        z_challenge: P::ScalarField,
    ) -> Polynomial<P::ScalarField> {
        // We cannot commit to polynomials with size > N_max
        let n = zeta_x.len();
        assert!(n <= N_MAX);
        let mut batched_polynomial = zeta_x;
        batched_polynomial.add_scaled(&z_x, &z_challenge);

        // TODO(#742): To complete the degree check, we need to do an opening proof for x_challenge with a univariate
        // PCS for the degree-lifted polynomial (\zeta_c + z*Z_x)*X^{N_max - N - 1}. If this PCS is KZG, verification
        // then requires a pairing check similar to the standard KZG check but with [1]_2 replaced by [X^{N_max - N
        // -1}]_2. Two issues: A) we do not have an SRS with these G2 elements (so need to generate a fake setup until
        // we can do the real thing), and B) its not clear to me how to update our pairing algorithms to do this type of
        // pairing. For now, simply construct pi without the shift and do a standard KZG pairing check if the PCS is
        // KZG. When we're ready, all we have to do to make this fully legit is commit to the shift here and update the
        // pairing check accordingly. Note: When this is implemented properly, it doesnt make sense to store the
        // (massive) shifted polynomial of size N_max. Ideally would only store the unshifted version and just compute
        // the shifted commitment directly via a new method.
        batched_polynomial
    }

    fn get_f_polyomials<'a>(
        &'a self,
        proving_key: &'a ProvingKey<P>,
    ) -> PolyF<'a, Vec<P::ScalarField>> {
        let memory = [
            self.memory.memory.w_4(),
            self.memory.memory.z_perm(),
            self.memory.memory.lookup_inverses(),
        ];

        PolyF {
            precomputed: &proving_key.polynomials.precomputed,
            witness: &proving_key.polynomials.witness,
            memory,
        }
    }

    fn get_g_shift_evaluations(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyGShift<P::ScalarField> {
        PolyGShift {
            tables: &evaluations.polys.shifted_tables,
            wires: &evaluations.polys.shifted_witness,
            z_perm: evaluations.memory.z_perm_shift(),
        }
    }

    fn get_g_polyomials<'a>(
        &'a self,
        proving_key: &'a ProvingKey<P>,
    ) -> PolyG<'a, Vec<P::ScalarField>> {
        let tables = [
            proving_key.polynomials.precomputed.table_1(),
            proving_key.polynomials.precomputed.table_2(),
            proving_key.polynomials.precomputed.table_3(),
            proving_key.polynomials.precomputed.table_4(),
        ];

        let wires = [
            proving_key.polynomials.witness.w_l(),
            proving_key.polynomials.witness.w_r(),
            proving_key.polynomials.witness.w_o(),
            self.memory.memory.w_4(),
        ];

        PolyG {
            tables,
            wires,
            z_perm: self.memory.memory.z_perm(),
        }
    }

    fn get_f_evaluations(
        evaluations: &ClaimedEvaluations<P::ScalarField>,
    ) -> PolyF<P::ScalarField> {
        let memory = [
            evaluations.memory.w_4(),
            evaluations.memory.z_perm(),
            evaluations.memory.lookup_inverses(),
        ];

        PolyF {
            precomputed: &evaluations.polys.precomputed,
            witness: &evaluations.polys.witness,
            memory,
        }
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
     * @todo https://github.com/AztecProtocol/barretenberg/issues/1030: document concatenation trick
     */
    pub(crate) fn zeromorph_prove(
        &mut self,
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<P>,
        sumcheck_output: SumcheckOutput<P::ScalarField>,
    ) -> HonkProofResult<ZeroMorphOpeningClaim<P::ScalarField>> {
        let circuit_size = proving_key.circuit_size;
        let f_polynomials = self.get_f_polyomials(proving_key);
        let g_polynomials = self.get_g_polyomials(proving_key);
        let f_evaluations = Self::get_f_evaluations(&sumcheck_output.claimed_evaluations);
        let g_shift_evaluations =
            Self::get_g_shift_evaluations(&sumcheck_output.claimed_evaluations);
        let multilinear_challenge = &sumcheck_output.challenges;
        let commitment_key = &proving_key.crs;

        // Generate batching challenge \rho and powers 1,...,\rho^{m-1}
        let rho = transcript.get_challenge::<P>("rho".to_string());

        // Extract multilinear challenge u and claimed multilinear evaluations from Sumcheck output
        let u_challenge = multilinear_challenge;
        let log_n = crate::get_msb(circuit_size);
        let n = 1 << log_n;

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

        // We don't have groups, so we skip a lot now

        // Compute the full batched polynomial f = f_batched + g_batched.shifted() = f_batched + h_batched. This is the
        // polynomial for which we compute the quotients q_k and prove f(u) = v_batched.
        let mut f_polynomial = f_batched.to_owned();
        f_polynomial += g_batched.shifted();
        // f_polynomial += concatenated_batched; // No groups

        // Compute the multilinear quotients q_k = q_k(X_0, ..., X_{k-1})
        let quotients = Self::compute_multilinear_quotients(&f_polynomial, u_challenge);
        debug_assert_eq!(quotients.len(), log_n as usize);
        // Compute and send commitments C_{q_k} = [q_k], k = 0,...,d-1
        for (idx, val) in quotients.iter().enumerate() {
            let res = crate::commit(&val.coefficients, commitment_key)?;
            let label = format!("ZM:C_q_{}", idx);
            transcript.send_point_to_verifier::<P>(label, res.into());
        }
        // Add buffer elements to remove log_N dependence in proof
        for idx in log_n as usize..CONST_PROOF_SIZE_LOG_N {
            let res = P::G1::generator(); // TODO Is this one?
            let label = format!("ZM:C_q_{}", idx);
            transcript.send_point_to_verifier::<P>(label, res.into());
        }

        // Get challenge y
        let y_challenge = transcript.get_challenge::<P>("ZM:y".to_string());

        // Compute the batched, lifted-degree quotient \hat{q}
        let batched_quotient =
            Self::compute_batched_lifted_degree_quotient(&quotients, &y_challenge, n as usize);

        // Compute and send the commitment C_q = [\hat{q}]
        let q_commitment = crate::commit(&batched_quotient.coefficients, commitment_key)?;
        transcript.send_point_to_verifier::<P>("ZM:C_q".to_string(), q_commitment.into());

        // Get challenges x and z
        let challs = transcript.get_challenges::<P>(&["ZM:x".to_string(), "ZM:z".to_string()]);
        let x_challenge = challs[0];
        let z_challenge = challs[1];

        // Compute degree check polynomial \zeta partially evaluated at x
        let zeta_x = Self::compute_partially_evaluated_degree_check_polynomial(
            &batched_quotient,
            &quotients,
            &y_challenge,
            &x_challenge,
        );

        // Compute ZeroMorph identity polynomial Z partially evaluated at x
        let z_x = Self::compute_partially_evaluated_zeromorph_identity_polynomial(
            f_batched,
            g_batched,
            quotients,
            batched_evaluation,
            u_challenge,
            x_challenge,
        );

        // Compute batched degree-check and ZM-identity quotient polynomial pi
        let pi_polynomial =
            Self::compute_batched_evaluation_and_degree_check_polynomial(zeta_x, z_x, z_challenge);

        let res = ZeroMorphOpeningClaim {
            polynomial: pi_polynomial,
            opening_pair: OpeningPair {
                challenge: x_challenge,
                evaluation: P::ScalarField::zero(),
            },
        };
        Ok(res)
    }
}
