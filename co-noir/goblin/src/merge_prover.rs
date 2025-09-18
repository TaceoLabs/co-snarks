use ark_ec::AdditiveGroup;
use ark_ff::Field;
use co_builder::prelude::{HonkCurve, Polynomial, ProverCrs, Utils};
use co_builder::{HonkProofResult, TranscriptFieldType};
use common::shplemini::OpeningPair;
use common::shplemini::ShpleminiOpeningClaim;
use common::transcript::Transcript;
use common::transcript::TranscriptHasher;
use ultrahonk::prelude::HonkProof;

use crate::eccvm::ecc_op_queue::ECCOpQueue;

const NUM_WIRES: usize = 4;

pub struct MergeProver<C, H>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    ecc_op_queue: ECCOpQueue<C>,
    transcript: Transcript<TranscriptFieldType, H>,
}

impl<C, H> MergeProver<C, H>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    pub fn new(ecc_op_queue: ECCOpQueue<C>) -> Self {
        Self {
            ecc_op_queue,
            transcript: Transcript::new(),
        }
    }

    pub fn construct_proof(
        mut self,
        commitment_key: &ProverCrs<C>,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        self.transcript = Transcript::new();

        let curr_table = self.ecc_op_queue.construct_ultra_ops_table_columns();
        let prev_table = self
            .ecc_op_queue
            .construct_previous_ultra_ops_table_columns();
        let curr_subtable = self
            .ecc_op_queue
            .construct_current_ultra_ops_subtable_columns();

        let (current_table_size, current_subtable_size) = (
            curr_table[0].coefficients.len(),
            curr_subtable[0].coefficients.len(),
        );

        self.transcript
            .send_u64_to_verifier("subtable_size".to_owned(), current_subtable_size as u64);

        for i in 0..NUM_WIRES {
            let curr_subtable_commitment =
                Utils::commit(&curr_subtable[i].coefficients, commitment_key)?;
            let prev_table_commitment = Utils::commit(&prev_table[i].coefficients, commitment_key)?;
            let curr_table_commitment = Utils::commit(&curr_table[i].coefficients, commitment_key)?;

            self.transcript.send_point_to_verifier::<C>(
                format!("t_CURRENT_{i}"),
                curr_subtable_commitment.into(),
            );
            self.transcript
                .send_point_to_verifier::<C>(format!("T_PREV_{i}"), prev_table_commitment.into());
            self.transcript.send_point_to_verifier::<C>(
                format!("T_CURRENT_{i}"),
                curr_table_commitment.into(),
            );
        }

        let kappa = self.transcript.get_challenge::<C>("kappa".to_owned());

        let mut opening_claims = Vec::with_capacity(3 * NUM_WIRES);

        self.compute_opening_claims(&curr_subtable, "subtable", &mut opening_claims, kappa);
        self.compute_opening_claims(&prev_table, "previous_table", &mut opening_claims, kappa);
        self.compute_opening_claims(&curr_table, "current_table", &mut opening_claims, kappa);

        let alpha = self.transcript.get_challenge::<C>("alpha".to_owned());

        let mut batched_eval = C::ScalarField::ZERO;
        let mut alpha_pow = C::ScalarField::ONE;

        let batched_polynomial = opening_claims.iter().fold(
            Polynomial::new_zero(current_table_size),
            |mut acc, claim| {
                acc.add_scaled(&claim.polynomial, &alpha_pow);
                batched_eval += claim.opening_pair.evaluation * alpha_pow;
                alpha_pow *= alpha;
                acc
            },
        );

        let batched_claim = ShpleminiOpeningClaim {
            polynomial: batched_polynomial,
            opening_pair: OpeningPair {
                challenge: kappa,
                evaluation: batched_eval,
            },
            gemini_fold: false,
        };

        Self::compute_opening_proof(batched_claim, &mut self.transcript, commitment_key)?;

        Ok(self.transcript.get_proof())
    }

    fn compute_opening_claims(
        &mut self,
        polynomials: &[Polynomial<C::ScalarField>],
        label: &str,
        opening_claims: &mut Vec<ShpleminiOpeningClaim<C::ScalarField>>,
        kappa: C::ScalarField,
    ) {
        (0..NUM_WIRES).for_each(move |i| {
            let evaluation = polynomials[i].eval_poly(kappa);
            self.transcript
                .send_fr_to_verifier::<C>(format!("{label}_evaluation_{i}"), evaluation);
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: polynomials[i].clone(),
                opening_pair: OpeningPair {
                    challenge: kappa,
                    evaluation,
                },
                gemini_fold: false,
            });
        });
    }

    // TACEO TODO: Avoid duplicate code in co-noir/ultrahonk/src/decider/decider_prover.rs#48
    fn compute_opening_proof(
        opening_claim: ShpleminiOpeningClaim<C::ScalarField>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<C>,
    ) -> eyre::Result<()> {
        let mut quotient = opening_claim.polynomial;
        let pair = opening_claim.opening_pair;
        quotient[0] -= pair.evaluation;
        // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
        quotient.factor_roots(&pair.challenge);
        let quotient_commitment = Utils::commit(&quotient.coefficients, crs)?;
        // AZTEC TODO(#479): compute_opening_proof
        // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
        // pthreads) or even the work queue itself
        transcript.send_point_to_verifier::<C>("KZG:W".to_string(), quotient_commitment.into());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::eccvm::ecc_op_queue::{
        EccOpCode, EccvmOpsTable, EccvmRowTracker, UltraEccOpsTable, UltraOp,
    };

    use super::*;
    use ark_bn254::Bn254;
    use co_builder::prelude::CrsParser;
    use common::transcript::Poseidon2Sponge;
    use mpc_core::gadgets::field_from_hex_string;
    use ultrahonk::prelude::ZeroKnowledge;

    type Bn254G1 = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;
    type Bn254G1Affine = ark_bn254::G1Affine;

    const CRS_PATH_G1: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../co-builder/src/crs/bn254_g1.dat"
    );
    const CRS_PATH_G2: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../co-builder/src/crs/bn254_g2.dat"
    );
    const PROOF_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test_vectors/noir/merge_prover/merge_proof"
    );

    #[test]
    fn test_merge_prover_construct_proof() {
        // Op code: 4
        //   x_lo: 0x0000000000000000000000000000000000000000000000000000000000000001
        //   x_hi: 0x0000000000000000000000000000000000000000000000000000000000000000
        //   y_lo: 0x0000000000000000000000000000000000000000000000000000000000000002
        //   y_hi: 0x0000000000000000000000000000000000000000000000000000000000000000
        //   z_1:  0x0000000000000000000000000000000000000000000000000000000000000002
        //   z_2:  0x0000000000000000000000000000000000000000000000000000000000000000
        let ultra_op_1 = UltraOp {
            op_code: EccOpCode {
                mul: true,
                ..Default::default()
            },
            x_lo: field_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            x_hi: field_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            y_lo: field_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
            y_hi: field_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            z_1: field_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
            z_2: field_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            return_is_infinity: false,
        };

        // Op code: 3
        //   x_lo: 0x00000000000000000000000000000085d97816a916871ca8d3c208c16d87cfd3
        //   x_hi: 0x0000000000000000000000000000000000030644e72e131a029b85045b681815
        //   y_lo: 0x0000000000000000000000000000000a68a6a449e3538fc7ff3ebf7a5a18a2c4
        //   y_hi: 0x000000000000000000000000000000000015ed738c0e0a7c92e7845f96b2ae9c
        //   z_1:  0x0000000000000000000000000000000000000000000000000000000000000000
        //   z_2:  0x0000000000000000000000000000000000000000000000000000000000000000
        let ultra_op_2 = UltraOp {
            op_code: EccOpCode {
                eq: true,
                reset: true,
                ..Default::default()
            },
            x_lo: field_from_hex_string(
                "0x00000000000000000000000000000085d97816a916871ca8d3c208c16d87cfd3",
            )
            .unwrap(),
            x_hi: field_from_hex_string(
                "0x0000000000000000000000000000000000030644e72e131a029b85045b681815",
            )
            .unwrap(),
            y_lo: field_from_hex_string(
                "0x0000000000000000000000000000000a68a6a449e3538fc7ff3ebf7a5a18a2c4",
            )
            .unwrap(),
            y_hi: field_from_hex_string(
                "0x0000000000000000000000000000000015ed738c0e0a7c92e7845f96b2ae9c",
            )
            .unwrap(),
            z_1: field_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            z_2: field_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            return_is_infinity: false,
        };

        let queue = ECCOpQueue::<Bn254G1> {
            accumulator: Bn254G1Affine::identity(),
            eccvm_ops_table: EccvmOpsTable::new(),
            ultra_ops_table: UltraEccOpsTable {
                table: vec![vec![ultra_op_1, ultra_op_2]],
            },
            eccvm_ops_reconstructed: Vec::new(),
            ultra_ops_reconstructed: Vec::new(),
            eccvm_row_tracker: EccvmRowTracker::new(),
        };

        let crs =
            CrsParser::<Bn254G1>::get_crs::<Bn254>(CRS_PATH_G1, CRS_PATH_G2, 5, ZeroKnowledge::No)
                .unwrap();
        let (prover_crs, _) = crs.split();

        let proof = MergeProver::<Bn254G1, Poseidon2Sponge>::new(queue)
            .construct_proof(&prover_crs)
            .unwrap();

        let expected_proof = HonkProof::<TranscriptFieldType>::from_buffer(
            &std::fs::read(PROOF_FILE).expect("Failed to read expected proof from file"),
        )
        .expect("Failed to deserialize expected proof");

        assert_eq!(
            proof, expected_proof,
            "The constructed proof does not match the expected proof."
        );
    }
}
