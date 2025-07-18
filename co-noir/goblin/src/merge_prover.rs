
use co_builder::prelude::{HonkCurve, Polynomial, ProverCrs, Utils};
use co_builder::TranscriptFieldType;
use ultrahonk::prelude::HonkProof;
use ultrahonk::{prelude::{OpeningPair, ShpleminiOpeningClaim, Transcript, TranscriptHasher}};
use ark_ec::AdditiveGroup;
use ark_ff::Field;

use crate::eccvm::ecc_op_queue::ECCOpQueue;

const NUM_WIRES: usize = 4;

pub(crate) struct MergeProver<C, H>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    ecc_op_queue: ECCOpQueue<C>,
    commitment_key: ProverCrs<C>,
    transcript: Transcript<TranscriptFieldType, H>,
}

impl<C, H> MergeProver<C, H>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    pub fn new(
        ecc_op_queue: ECCOpQueue<C>,
        commitment_key: ProverCrs<C>,
     ) -> Self {
        Self {
            ecc_op_queue,
            commitment_key,
            transcript: Transcript::new(),
        }
    }

    pub fn construct_proof(mut self) -> HonkProof<TranscriptFieldType> {
        self.transcript = Transcript::new();

        let T_current = self.ecc_op_queue.construct_ultra_ops_table_columns();
        let T_prev = self.ecc_op_queue.construct_previous_ultra_ops_table_columns();
        let t_current = self.ecc_op_queue.construct_current_ultra_ops_subtable_columns();
    
        let (current_table_size, current_subtable_size) = (
            T_current[0].coefficients.len(),
            t_current[0].coefficients.len(),
        );

        self.transcript.send_u64_to_verifier("subtable_size".to_owned(), current_subtable_size as u64);  
    
        for i in 0..NUM_WIRES {
            let t_commitment = Utils::commit(&t_current[i].coefficients, &self.commitment_key)
                .expect("Failed to commit to subtable column");
            let T_prev_commitment = Utils::commit(&T_prev[i].coefficients, &self.commitment_key)
                            .expect("Failed to commit to previous table column");
            let T_commitment = Utils::commit(&T_current[i].coefficients, &self.commitment_key)
                            .expect("Failed to commit to current table column");

            self.transcript.send_point_to_verifier::<C>(
                format!("t_CURRENT_{i}"),
                t_commitment.into(),
            );
            self.transcript.send_point_to_verifier::<C>(
                format!("T_PREV_{i}"),
                T_prev_commitment.into(),
            );
            self.transcript.send_point_to_verifier::<C>(
                format!("T_CURRENT_{i}"),
                T_commitment.into(),
            );
        }

        let kappa = self.transcript.get_challenge::<C>("kappa".to_owned());

        let mut opening_claims = Vec::with_capacity(3 * NUM_WIRES);

        self.compute_opening_claims(&t_current, "subtable", &mut opening_claims, kappa);
        self.compute_opening_claims(&T_prev, "previous_table", &mut opening_claims, kappa);
        self.compute_opening_claims(&T_current, "current_table", &mut opening_claims, kappa);

        let alpha = self.transcript.get_challenge::<C>("alpha".to_owned());

        let mut batched_eval = C::ScalarField::ZERO;
        let mut alpha_pow = C::ScalarField::ONE;

        let batched_polynomial = opening_claims.iter().fold(
            Polynomial::new_zero(
                current_table_size
            ),
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

        Self::compute_opening_proof(batched_claim, &mut self.transcript, &self.commitment_key)
            .expect("Failed to compute opening proof");

        self.transcript.get_proof()
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
            self.transcript.send_fr_to_verifier::<C>(
                format!("{label}_evaluation_{i}"),
                evaluation,
            );
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
    use crate::eccvm::ecc_op_queue::{EccOpCode, EccOpsTable, EccvmOpsTable, EccvmRowTracker, UltraEccOpsTable, UltraOp};

    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::bn::Bn;
    use ark_ec::pairing::Pairing;
    use co_builder::prelude::CrsParser;
    use num_bigint::BigUint;
    use ultrahonk::prelude::{Poseidon2Sponge, ZeroKnowledge};

    type Bn254G1 = <Bn<ark_bn254::Config> as Pairing>::G1;
    type F = <Bn<ark_bn254::Config> as Pairing>::ScalarField;
    const CRS_PATH_G1: &str = "../co-builder/src/crs/bn254_g1.dat";
    const CRS_PATH_G2: &str = "../co-builder/src/crs/bn254_g2.dat";
    const PROOF_FILE: &str = "../../test_vectors/noir/merge_prover/merge_proof";
    
    fn hex_to_field_element(hex: &str) -> F {
        let bytes = (2..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();

        let bigint = BigUint::from_bytes_be(&bytes);
        F::from(bigint)
    }

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
            x_lo: hex_to_field_element("0x0000000000000000000000000000000000000000000000000000000000000001"),
            x_hi: hex_to_field_element("0x0000000000000000000000000000000000000000000000000000000000000000"),
            y_lo: hex_to_field_element("0x0000000000000000000000000000000000000000000000000000000000000002"),
            y_hi: hex_to_field_element("0x0000000000000000000000000000000000000000000000000000000000000000"),
            z_1: hex_to_field_element("0x0000000000000000000000000000000000000000000000000000000000000002"),
            z_2: hex_to_field_element("0x0000000000000000000000000000000000000000000000000000000000000000"),
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
            x_lo: hex_to_field_element("0x00000000000000000000000000000085d97816a916871ca8d3c208c16d87cfd3"),
            x_hi: hex_to_field_element("0x0000000000000000000000000000000000030644e72e131a029b85045b681815"),
            y_lo: hex_to_field_element("0x0000000000000000000000000000000a68a6a449e3538fc7ff3ebf7a5a18a2c4"),
            y_hi: hex_to_field_element("0x0000000000000000000000000000000015ed738c0e0a7c92e7845f96b2ae9c"),
            z_1: hex_to_field_element("0x0000000000000000000000000000000000000000000000000000000000000000"),
            z_2: hex_to_field_element("0x0000000000000000000000000000000000000000000000000000000000000000"),
            return_is_infinity: false,
        };

        let queue = ECCOpQueue::<Bn254G1> {
            point_at_infinity: Bn254G1::ZERO.into(),
            accumulator: Bn254G1::ZERO.into(),
            eccvm_ops_table: EccvmOpsTable::new(),
            ultra_ops_table: UltraEccOpsTable {
                table: EccOpsTable {
                    table: vec![vec![
                        ultra_op_1,
                        ultra_op_2,
                    ]],
                }
            },
            eccvm_ops_reconstructed: Vec::new(),
            ultra_ops_reconstructed: Vec::new(),
            eccvm_row_tracker: EccvmRowTracker::new(),
        };
        
        let crs = CrsParser::<Bn254>::get_crs(CRS_PATH_G1, CRS_PATH_G2, 5, ZeroKnowledge::No).unwrap();
        let (prover_crs, _) = crs.split();

        let proof = MergeProver::<Bn254G1, Poseidon2Sponge>::new(queue, prover_crs).construct_proof();

        let expected_proof = HonkProof::<TranscriptFieldType>::from_buffer(
            &std::fs::read(PROOF_FILE).expect("Failed to read expected proof from file"),
        ).expect("Failed to deserialize expected proof");

        assert_eq!(proof, expected_proof, "The constructed proof does not match the expected proof.");
    }
}