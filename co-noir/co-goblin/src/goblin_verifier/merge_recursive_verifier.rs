use ark_ec::CurveGroup;
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{mega_builder::MegaCircuitBuilder, prelude::NUM_WIRES, transcript::TranscriptCT, types::{field_ct::FieldCT, goblin_types::GoblinElement}};
use common::{co_shplemini::ShpleminiOpeningClaim, honk_curve::HonkCurve, honk_proof::{HonkProof, HonkProofError, HonkProofResult, TranscriptFieldType}, mpc::NoirUltraHonkProver, shplemini::ShpleminiVerifierOpeningClaim};

pub struct OpeningClaim<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
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
     *      T_j(\kappa) = t_j(\kappa) + \kappa^k * (T_{j,prev}(\kappa)).
     *
     * @tparam CircuitBuilder
     * @param proof
     * @return std::array<typename Flavor::GroupElement, 2> Inputs to final pairing
     */
    pub fn verify_proof<
        P: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
>(&self, proof: Vec<FieldCT<P::ScalarField>>, builder: &mut MegaCircuitBuilder<P, T>, driver: &mut T) -> HonkProofResult<GoblinElement<P, T>> {
    // Transform proof into a stdlib object
    let mut transcript = TranscriptCT::new_verifier(proof);

    let subtable_size = transcript.receive_fr_from_prover("subtable_size".to_owned())?;

    // Receive table column polynomial commitments [t_j], [T_{j,prev}], and [T_j], j = 1,2,3,4
    let mut t_commitments = Vec::with_capacity(NUM_WIRES);
    let mut T_prev_commitments = Vec::with_capacity(NUM_WIRES);
    let mut T_commitments = Vec::with_capacity(NUM_WIRES);

    for idx in 0..NUM_WIRES {
        let suffix = idx.to_string();
        t_commitments.push(transcript.receive_point_from_prover(format!("t_CURRENT_{}", suffix), builder, driver)?);
        T_prev_commitments.push(transcript.receive_point_from_prover(format!("T_PREV_{}", suffix), builder, driver)?);
        T_commitments.push(transcript.receive_point_from_prover(format!("T_CURRENT_{}", suffix), builder, driver)?);
    }

    let kappa = transcript.get_challenge("kappa".to_owned(), builder, driver)?;

    // Receive evaluations t_j(kappa), T_{j,prev}(kappa), T_j(kappa), j = 1,2,3,4
    let mut t_evals = Vec::with_capacity(NUM_WIRES);
    let mut T_prev_evals = Vec::with_capacity(NUM_WIRES);
    let mut T_evals = Vec::with_capacity(NUM_WIRES);
    let mut opening_claims = Vec::new();

    for idx in 0..NUM_WIRES {
        let eval = transcript.receive_fr_from_prover(format!("t_eval_{}", idx + 1))?;
        t_evals.push(eval);
        opening_claims.push(OpeningClaim {
            opening_pair: (kappa, eval),
            commitment: t_commitments[idx].clone(),
        });
    }
    for idx in 0..NUM_WIRES {
        let eval = transcript.receive_fr_from_prover(format!("T_prev_eval_{}", idx + 1))?;
        T_prev_evals.push(eval);
        opening_claims.push(OpeningClaim {
            opening_pair: (kappa, eval),
            commitment: T_prev_commitments[idx].clone(),
        });
    }
    for idx in 0..NUM_WIRES {
        let eval = transcript.receive_fr_from_prover(format!("T_eval_{}", idx + 1))?;
        T_evals.push(eval);
        opening_claims.push(OpeningClaim {
            opening_pair: (kappa, eval),
            commitment: T_commitments[idx].clone(),
        });
    }

    // Check the identity T_j(kappa) = t_j(kappa) + kappa^m * T_{j,prev}(kappa)
    let kappa_pow = kappa.pow(&subtable_size, builder, driver);
    for idx in 0..NUM_WIRES {
        let T_prev_shifted_eval_reconstructed = T_prev_evals[idx].multiply(&kappa_pow, builder, driver).unwrap();
        let rhs = t_evals[idx].add(&T_prev_shifted_eval_reconstructed, builder, driver);
        T_evals[idx].assert_equal(&rhs, builder, driver);
    }

    let alpha = transcript.get_challenge("alpha".to_string(), builder, driver)?;

    // Construct inputs to batched commitment and batched evaluation from constituents using batching challenge alpha
    let mut scalars = Vec::new();
    let mut commitments = Vec::new();
    scalars.push(P::ScalarField::one());
    commitments.push(opening_claims[0].commitment.clone());
    let mut batched_eval = opening_claims[0].opening_pair.1;
    let mut alpha_pow = alpha;
    for claim in opening_claims.iter().skip(1) {
        scalars.push(alpha_pow);
        commitments.push(claim.commitment.clone());
        batched_eval += alpha_pow * claim.opening_pair.1;
        alpha_pow *= alpha;
    }

    let batched_commitment = Commitment::batch_mul(&commitments, &scalars, 0, true);

    let batched_claim = ShpleminiVerifierOpeningClaim {
        opening_pair: (kappa, batched_eval),
        commitment: batched_commitment,
    };

    let pairing_points = KZG::reduce_verify(&batched_claim, &mut transcript)?;

    Ok(pairing_points)
}
}