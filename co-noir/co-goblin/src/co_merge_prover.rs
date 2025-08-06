use std::collections::VecDeque;

use ark_ff::Field;
use co_builder::prelude::{HonkCurve, ProverCrs};
use co_builder::{HonkProofResult, TranscriptFieldType};
use common::CoUtils;
use common::co_shplemini::{OpeningPair, ShpleminiOpeningClaim};
use common::mpc::NoirUltraHonkProver;
use common::shared_polynomial::SharedPolynomial;
use common::transcript::Transcript;
use common::transcript::TranscriptHasher;

use common::HonkProof;
use itertools::{Itertools, izip};
use mpc_net::Network;

use crate::eccvm::co_ecc_op_queue::CoECCOpQueue;

const NUM_WIRES: usize = 4;
pub struct CoMergeProver<'a, C, H, T, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    net: &'a N,
    state: &'a mut T::State,
    ecc_op_queue: CoECCOpQueue<T, C>,
    transcript: Transcript<TranscriptFieldType, H>,
    // has_zk: ZeroKnowledge,
}

impl<'a, C, H, T, N> CoMergeProver<'a, C, H, T, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    pub fn new(ecc_op_queue: CoECCOpQueue<T, C>, net: &'a N, state: &'a mut T::State) -> Self {
        Self {
            ecc_op_queue,
            net,
            state,
            transcript: Transcript::new(),
        }
    }

    pub fn construct_proof(
        mut self,
        commitment_key: &ProverCrs<C>,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        self.transcript = Transcript::new();

        let curr_subtable = self
            .ecc_op_queue
            .construct_current_ultra_ops_subtable_columns();
        let curr_table = self.ecc_op_queue.construct_ultra_ops_table_columns();
        let prev_table = self
            .ecc_op_queue
            .construct_previous_ultra_ops_table_columns();

        let (current_table_size, current_subtable_size) = (
            curr_table[0].coefficients.len(),
            curr_subtable[0].coefficients.len(),
        );

        self.transcript
            .send_u64_to_verifier("subtable_size".to_owned(), current_subtable_size as u64);

        // Compute commiments shares
        let curr_subtable_shared_commitments = (0..NUM_WIRES)
            .map(|i| CoUtils::commit::<T, C>(&curr_subtable[i].coefficients, commitment_key))
            .collect_vec();
        let prev_table_shared_prev_commitments = (0..NUM_WIRES)
            .map(|i| CoUtils::commit::<T, C>(&prev_table[i].coefficients, commitment_key))
            .collect_vec();
        let curr_table_shared_commitments = (0..NUM_WIRES)
            .map(|i| CoUtils::commit::<T, C>(&curr_table[i].coefficients, commitment_key))
            .collect_vec();

        // Interleave the commitments and open them
        let shared_commitments = izip!(
            curr_subtable_shared_commitments,
            prev_table_shared_prev_commitments,
            curr_table_shared_commitments
        )
        .flat_map(|(a, b, c)| vec![a, b, c])
        .collect_vec();

        let mut commitments: VecDeque<_> =
            T::open_point_many(shared_commitments.as_slice(), self.net, self.state)?.into();

        // Send commitments to the verifier
        let num_chunks = commitments.len() / 3;
        for i in 0..num_chunks {
            for label in ["current_subtable_", "previous_table_", "current_table_"] {
                self.transcript.send_point_to_verifier::<C>(
                    format!("{label}{i}"),
                    commitments.pop_front().unwrap().into(),
                );
            }
        }

        let kappa = self.transcript.get_challenge::<C>("kappa".to_owned());

        let mut opening_claims: Vec<ShpleminiOpeningClaim<T, C>> =
            Vec::with_capacity(3 * NUM_WIRES);

        self.compute_opening_claims(
            &curr_subtable,
            "current_subtable",
            &mut opening_claims,
            kappa,
        )?;
        self.compute_opening_claims(&prev_table, "previous_table", &mut opening_claims, kappa)?;
        self.compute_opening_claims(&curr_table, "current_table", &mut opening_claims, kappa)?;

        let alpha = self.transcript.get_challenge::<C>("alpha".to_owned());

        let mut batched_eval = T::ArithmeticShare::default();
        let mut alpha_pow = C::ScalarField::ONE;

        let batched_polynomial = opening_claims.iter().fold(
            SharedPolynomial::new_zero(current_table_size),
            |mut acc, claim| {
                acc.add_scaled(&claim.polynomial, &alpha_pow);
                T::add_assign(
                    &mut batched_eval,
                    T::mul_with_public(alpha_pow, claim.opening_pair.evaluation),
                );
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

        common::compute_co_opening_proof(
            self.net,
            self.state,
            batched_claim,
            &mut self.transcript,
            commitment_key,
        )?;

        Ok(self.transcript.get_proof())
    }

    fn compute_opening_claims(
        &mut self,
        polynomials: &[SharedPolynomial<T, C>],
        label: &str,
        opening_claims: &mut Vec<ShpleminiOpeningClaim<T, C>>,
        kappa: C::ScalarField,
    ) -> eyre::Result<()> {
        // Compute the evaluations of the shared polynomials at kappa
        let shared_evals = (0..NUM_WIRES)
            .map(|i| T::eval_poly(&polynomials[i].coefficients, kappa))
            .collect_vec();

        izip!(polynomials.iter(), shared_evals.iter()).for_each(|(poly, &evaluation)| {
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: poly.clone(),
                opening_pair: OpeningPair {
                    challenge: kappa,
                    evaluation,
                },
                gemini_fold: false,
            });
        });

        // Open the evaluations and send them to the verifier
        let evaluations = T::open_many(shared_evals.as_slice(), self.net, self.state)?;
        evaluations
            .into_iter()
            .enumerate()
            .for_each(|(i, evaluation)| {
                self.transcript
                    .send_fr_to_verifier::<C>(format!("{label}_{i}"), evaluation);
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use crate::eccvm::co_ecc_op_queue::{
        CoEccOpCode, CoEccvmOpsTable, CoUltraEccOpsTable, CoUltraOp,
    };

    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::bn::Bn;
    use ark_ec::pairing::Pairing;
    use co_builder::prelude::CrsParser;
    use common::mpc::rep3::Rep3UltraHonkDriver;
    use common::transcript::Poseidon2Sponge;
    use goblin::eccvm::ecc_op_queue::{EccOpCode, EccOpsTable, EccvmRowTracker, UltraOp};
    use mpc_core::{
        gadgets::field_from_hex_string,
        protocols::rep3::{Rep3State, conversion::A2BType, share_field_element},
    };
    use mpc_net::local::LocalNetwork;
    use rand::thread_rng;
    use ultrahonk::prelude::ZeroKnowledge;

    type Bn254G1 = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;
    type Bn254G1Affine = ark_bn254::G1Affine;
    type F = <Bn<ark_bn254::Config> as Pairing>::ScalarField;
    type Driver = Rep3UltraHonkDriver;

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

    fn co_ultra_ops_from_ultra_op(ultra_op: UltraOp<Bn254G1>) -> Vec<CoUltraOp<Driver, Bn254G1>> {
        let mut rng = thread_rng();
        izip!(
            share_field_element(F::from(ultra_op.op_code.add as u8), &mut rng),
            share_field_element(F::from(ultra_op.op_code.mul as u8), &mut rng),
            share_field_element(F::from(ultra_op.op_code.eq as u8), &mut rng),
            share_field_element(F::from(ultra_op.op_code.reset as u8), &mut rng),
            share_field_element(ultra_op.x_lo, &mut rng),
            share_field_element(ultra_op.x_hi, &mut rng),
            share_field_element(ultra_op.y_lo, &mut rng),
            share_field_element(ultra_op.y_hi, &mut rng),
            share_field_element(ultra_op.z_1, &mut rng),
            share_field_element(ultra_op.z_2, &mut rng),
        )
        .map(
            |(add, mul, eq, reset, x_lo, x_hi, y_lo, y_hi, z_1, z_2)| CoUltraOp {
                op_code: CoEccOpCode {
                    add,
                    mul,
                    eq,
                    reset,
                },
                x_lo,
                x_hi,
                y_lo,
                y_hi,
                z_1,
                z_2,
                return_is_infinity: ultra_op.return_is_infinity,
            },
        )
        .collect_vec()
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

        let mut co_ultra_ops_1: VecDeque<_> = co_ultra_ops_from_ultra_op(ultra_op_1).into();

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

        let mut co_ultra_ops_2: VecDeque<_> = co_ultra_ops_from_ultra_op(ultra_op_2).into();

        let mut get_queues = || CoECCOpQueue::<Driver, Bn254G1> {
            accumulator: Bn254G1Affine::identity(),
            eccvm_ops_table: CoEccvmOpsTable::new(),
            ultra_ops_table: CoUltraEccOpsTable {
                table: EccOpsTable {
                    table: vec![vec![
                        co_ultra_ops_1.pop_front().unwrap(),
                        co_ultra_ops_2.pop_front().unwrap(),
                    ]],
                },
            },
            eccvm_ops_reconstructed: Vec::new(),
            eccvm_row_tracker: EccvmRowTracker::new(),
        };

        let queue: [CoECCOpQueue<Driver, Bn254G1>; 3] = core::array::from_fn(|_| get_queues());

        let crs =
            CrsParser::<Bn254>::get_crs(CRS_PATH_G1, CRS_PATH_G2, 5, ZeroKnowledge::No).unwrap();
        let (prover_crs, _) = crs.split();

        let nets = LocalNetwork::new_3_parties();
        let mut threads = Vec::with_capacity(3);

        for (net, queue) in nets.into_iter().zip(queue.into_iter()) {
            let crs = prover_crs.clone();
            threads.push(thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let prover = CoMergeProver::<Bn254G1, Poseidon2Sponge, Driver, _>::new(
                    queue, &net, &mut state,
                );
                prover.construct_proof(&crs)
            }));
        }

        let mut results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

        let expected_proof = HonkProof::<TranscriptFieldType>::from_buffer(
            &std::fs::read(PROOF_FILE).expect("Failed to read expected proof from file"),
        )
        .expect("Failed to deserialize expected proof");

        assert_eq!(
            results.pop().unwrap().unwrap(),
            expected_proof,
            "The constructed proof does not match the expected proof."
        );
    }
}
