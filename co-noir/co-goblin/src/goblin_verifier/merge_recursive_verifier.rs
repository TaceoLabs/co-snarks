#![expect(non_snake_case)]
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{
    mega_builder::MegaCircuitBuilder,
    prelude::NUM_WIRES,
    transcript::{TranscriptCT, TranscriptHasherCT},
    types::{field_ct::FieldCT, goblin_types::GoblinElement},
};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

pub struct OpeningClaim<
    P: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
> {
    pub opening_pair: (FieldCT<P::ScalarField>, FieldCT<P::ScalarField>),
    pub commitment: GoblinElement<P, T>,
}
pub struct MergeRecursiveVerifier;

impl MergeRecursiveVerifier {
    /**
     * @brief Computes inputs to a pairing check that, if verified, establishes proper construction of the aggregate Goblin
     * ECC op queue polynomials T_j, j = 1,2,3,4.
     * @details Let T_j be the jth column of the aggregate ecc op table after prepending the subtable columns t_j containing
     * the contribution from a single circuit. T_{j,prev} corresponds to the columns of the aggregate table at the
     * previous stage. For each column we have the relationship T_j = t_j + right_shift(T_{j,prev}, k), where k is the
     * length of the subtable columns t_j. This protocol demonstrates, assuming the length of t is at most k, that the
     * aggregate ecc op table has been constructed correctly via the simple Schwartz-Zippel check:
     *
     * T_j(\kappa) = t_j(\kappa) + \kappa^k * (T_{j,prev}(\kappa)).
     *
     * @tparam CircuitBuilder
     * @param proof
     * @return std::array<typename Flavor::GroupElement, 2> Inputs to final pairing
     */
    pub fn verify_proof<
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        H: TranscriptHasherCT<P>,
    >(
        &self,
        proof: Vec<FieldCT<P::ScalarField>>,
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> HonkProofResult<(GoblinElement<P, T>, GoblinElement<P, T>)> {
        // Transform proof into a stdlib object
        let mut transcript = TranscriptCT::<P, H>::new_verifier(proof);

        let subtable_size = transcript.receive_fr_from_prover("subtable_size".to_owned())?;

        // Receive table column polynomial commitments [t_j], [T_{j,prev}], and [T_j], j = 1,2,3,4
        let mut t_commitments = Vec::with_capacity(NUM_WIRES);
        let mut T_prev_commitments = Vec::with_capacity(NUM_WIRES);
        let mut T_commitments = Vec::with_capacity(NUM_WIRES);

        // TACEO TODO: batch `is_zero` calls on `receive_point_from_prover`
        for idx in 0..NUM_WIRES {
            let suffix = idx.to_string();
            t_commitments.push(transcript.receive_point_from_prover(
                format!("t_CURRENT_{suffix}"),
                builder,
                driver,
            )?);
            T_prev_commitments.push(transcript.receive_point_from_prover(
                format!("T_PREV_{suffix}"),
                builder,
                driver,
            )?);
            T_commitments.push(transcript.receive_point_from_prover(
                format!("T_CURRENT_{suffix}"),
                builder,
                driver,
            )?);
        }

        let kappa = transcript.get_challenge("kappa".to_owned(), builder, driver)?;

        // Receive evaluations t_j(kappa), T_{j,prev}(kappa), T_j(kappa), j = 1,2,3,4
        let mut t_evals = Vec::with_capacity(NUM_WIRES);
        let mut T_prev_evals = Vec::with_capacity(NUM_WIRES);
        let mut T_evals = Vec::with_capacity(NUM_WIRES);
        let mut opening_claims = Vec::new();

        for (idx, commitment) in t_commitments.iter().enumerate().take(NUM_WIRES) {
            let eval = transcript.receive_fr_from_prover(format!("t_eval_{}", idx + 1))?;
            t_evals.push(eval.clone());
            opening_claims.push(OpeningClaim {
                opening_pair: (kappa.clone(), eval),
                commitment: commitment.clone(),
            });
        }
        for (idx, commitment) in T_prev_commitments.iter().enumerate().take(NUM_WIRES) {
            let eval = transcript.receive_fr_from_prover(format!("T_prev_eval_{}", idx + 1))?;
            T_prev_evals.push(eval.clone());
            opening_claims.push(OpeningClaim {
                opening_pair: (kappa.clone(), eval),
                commitment: commitment.clone(),
            });
        }
        for (idx, commitment) in T_commitments.iter().enumerate().take(NUM_WIRES) {
            let eval = transcript.receive_fr_from_prover(format!("T_eval_{}", idx + 1))?;
            T_evals.push(eval.clone());
            opening_claims.push(OpeningClaim {
                opening_pair: (kappa.clone(), eval),
                commitment: commitment.clone(),
            });
        }

        // Check the identity T_j(kappa) = t_j(kappa) + kappa^m * T_{j,prev}(kappa)
        let kappa_pow = kappa.pow(&subtable_size, builder, driver)?;
        for idx in 0..NUM_WIRES {
            // TACEO TODO: batch these multiplications
            let T_prev_shifted_eval_reconstructed =
                T_prev_evals[idx].multiply(&kappa_pow, builder, driver)?;
            let rhs = t_evals[idx].add(&T_prev_shifted_eval_reconstructed, builder, driver);
            T_evals[idx].assert_equal(&rhs, builder, driver);
        }

        let alpha = transcript.get_challenge("alpha".to_string(), builder, driver)?;

        // Construct inputs to batched commitment and batched evaluation from constituents using batching challenge alpha
        let mut scalars = Vec::new();
        let mut commitments = Vec::new();
        scalars.push(P::ScalarField::ONE.into());
        commitments.push(opening_claims[0].commitment.clone());
        let mut batched_eval = opening_claims[0].opening_pair.1.clone();
        let mut alpha_pow = alpha.clone();
        for claim in opening_claims.iter().skip(1) {
            scalars.push(alpha_pow.clone());
            commitments.push(claim.commitment.clone());
            let tmp = alpha_pow.multiply(&claim.opening_pair.1, builder, driver)?;
            batched_eval = batched_eval.add(&tmp, builder, driver);
            alpha_pow = alpha_pow.multiply(&alpha, builder, driver)?;
        }

        let batched_commitment = GoblinElement::batch_mul(&commitments, &scalars, builder, driver)?;
        let opening_claim = OpeningClaim {
            commitment: batched_commitment,
            opening_pair: (kappa, batched_eval),
        };

        MergeRecursiveVerifier::reduce_verify(opening_claim, &mut transcript, builder, driver)
    }

    /**
     * @brief Computes the input points for the pairing check needed to verify a KZG opening claim of a single
     * polynomial commitment. This reduction is non-interactive and always succeeds.
     * @details This is used in the recursive setting where we want to "aggregate" proofs, not verify them.
     *
     * @param claim OpeningClaim ({r, v}, C)
     * @return  {P₀, P₁} where
     *      - P₀ = C − v⋅[1]₁ + r⋅[W(x)]₁
     *      - P₁ = - [W(x)]₁
     */
    fn reduce_verify<
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        H: TranscriptHasherCT<P>,
    >(
        opening_claim: OpeningClaim<P, T>,
        transcript: &mut TranscriptCT<P, H>,
        builder: &mut MegaCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> HonkProofResult<(GoblinElement<P, T>, GoblinElement<P, T>)> {
        let quotient_commitment =
            transcript.receive_point_from_prover("KZG:W".to_owned(), builder, driver)?;

        // Note: The pairing check can be expressed naturally as
        // e(C - v * [1]_1, [1]_2) = e([W]_1, [X - r]_2) where C =[p(X)]_1. This can be rearranged (e.g. see the plonk
        // paper) as e(C + r*[W]_1 - v*[1]_1, [1]_2) * e(-[W]_1, [X]_2) = 1, or e(P_0, [1]_2) * e(P_1, [X]_2) = 1
        let one = FieldCT::from_witness(P::ScalarField::ONE.into(), builder);
        let commitments = vec![
            opening_claim.commitment.clone(),
            quotient_commitment.clone(),
            GoblinElement::one(builder),
        ];
        let scalars = vec![
            one.clone(),
            opening_claim.opening_pair.0,
            opening_claim.opening_pair.1.neg(),
        ];

        let p_0 = GoblinElement::batch_mul(&commitments, &scalars, builder, driver)?;

        // Construct P₁ = -[W(x)]
        let p_1 = quotient_commitment.neg(builder, driver)?;

        Ok((p_0, p_1))
    }
}
