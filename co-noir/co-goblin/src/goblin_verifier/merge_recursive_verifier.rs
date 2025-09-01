
pub struct MergeRecursiveVerifier<P, T>
where
    P: CurveGroup,
    T: NoirUltraHonkProver<P>,
{
    builder: MegaCircuitBuilder,
}

impl MergeRecursiveVerifier {
    pub fn new(builder: MegaCircuitBuilder) -> Self {
        MergeRecursiveVerifier { builder }
    }
}

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
impl MergeRecursiveVerifier {
    pub fn verify_proof(&self, proof: Vec<FieldCT<P::ScalarField>>) -> bool {
        // Transform proof into a stdlib object
        let transcript = TranscriptCT::new_verifier(proof);
    }
}