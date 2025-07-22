use std::io::SeekFrom;
use std::marker::PhantomData;

use ark_ec::AdditiveGroup;
use ark_ff::Field;
use co_builder::TranscriptFieldType;
use co_builder::prelude::{HonkCurve, Polynomial, ProverCrs, Utils};
use co_ultrahonk::CoUtils;
use co_ultrahonk::prelude::{NoirUltraHonkProver, SharedPolynomial};
use co_ultrahonk::prelude::{OpeningPair, ShpleminiOpeningClaim};
use itertools::{Interleave, Itertools, interleave, izip};
use mpc_core::protocols::rep3::poly;
use mpc_net::Network;
use ultrahonk::prelude::HonkProof;
use ultrahonk::prelude::{Transcript, TranscriptHasher};

use crate::eccvm::co_ecc_op_queue::CoECCOpQueue;

const NUM_WIRES: usize = 4;
pub(crate) struct CoMergeProver<'a, C, H, T, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    net: &'a N,
    state: &'a mut T::State,
    ecc_op_queue: CoECCOpQueue<T, C>,
    commitment_key: ProverCrs<C>,
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
    pub fn new(
        ecc_op_queue: CoECCOpQueue<T, C>,
        commitment_key: ProverCrs<C>,
        net: &'a N,
        state: &'a mut T::State,
    ) -> Self {
        println!("Creating CoMergeProver with {} wires", NUM_WIRES);
        Self {
            ecc_op_queue,
            commitment_key,
            net,
            state,
            transcript: Transcript::new(),
        }
    }

    pub fn construct_proof(mut self) -> HonkProof<TranscriptFieldType> {
        println!("Constructing proof with {} wires", NUM_WIRES);

        self.transcript = Transcript::new();

        let T_current = self
            .ecc_op_queue
            .construct_ultra_ops_table_columns(self.net, self.state);
        let T_prev = self
            .ecc_op_queue
            .construct_previous_ultra_ops_table_columns(self.net, self.state);
        let t_current = self
            .ecc_op_queue
            .construct_current_ultra_ops_subtable_columns(self.net, self.state);

        let (current_table_size, current_subtable_size) = (
            T_current[0].coefficients.len(),
            t_current[0].coefficients.len(),
        );

        self.transcript
            .send_u64_to_verifier("subtable_size".to_owned(), current_subtable_size as u64);

        // Compute commiments shares
        let t_shared_commitments = (0..NUM_WIRES)
            .map(|i| CoUtils::commit::<T, C>(&t_current[i].coefficients, &self.commitment_key))
            .collect_vec();
        let T_shared_prev_commitments = (0..NUM_WIRES)
            .map(|i| CoUtils::commit::<T, C>(&T_prev[i].coefficients, &self.commitment_key))
            .collect_vec();
        let T_shared_commitments = (0..NUM_WIRES)
            .map(|i| CoUtils::commit::<T, C>(&T_current[i].coefficients, &self.commitment_key))
            .collect_vec();

        // Open commitments
        let t_commitments =
            T::open_point_many(t_shared_commitments.as_slice(), self.net, self.state)
                .expect("Failed to open t_current commitments");
        let T_prev_commitments =
            T::open_point_many(T_shared_prev_commitments.as_slice(), self.net, self.state)
                .expect("Failed to open T_prev commitments");
        let T_commitments =
            T::open_point_many(T_shared_commitments.as_slice(), self.net, self.state)
                .expect("Failed to open T_current commitments");

        // Interleave the commitments and send them to the verifier
        izip!(t_commitments, T_prev_commitments, T_commitments)
            .enumerate()
            .flat_map(|(i, (a, b, c))| {
                vec![
                    (format!("t_CURRENT_{i}"), a),
                    (format!("T_PREV_{i}"), b),
                    (format!("T_CURRENT_{i}"), c),
                ]
            })
            .for_each(|(i, commitment)| {
                self.transcript.send_point_to_verifier::<C>(
                    format!("t_CURRENT_{i}"),
                    commitment.clone().into(),
                );
            });

        let kappa = self.transcript.get_challenge::<C>("kappa".to_owned());

        let mut opening_claims: Vec<ShpleminiOpeningClaim<T, C>> =
            Vec::with_capacity(3 * NUM_WIRES);

        self.compute_opening_claims(&t_current, "subtable", &mut opening_claims, kappa);
        self.compute_opening_claims(&T_prev, "previous_table", &mut opening_claims, kappa);
        self.compute_opening_claims(&T_current, "current_table", &mut opening_claims, kappa);

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

        Self::compute_opening_proof(&mut self, batched_claim)
            .expect("Failed to compute opening proof");

        self.transcript.get_proof()
    }

    fn compute_opening_claims(
        &mut self,
        polynomials: &[SharedPolynomial<T, C>],
        label: &str,
        opening_claims: &mut Vec<ShpleminiOpeningClaim<T, C>>,
        kappa: C::ScalarField,
    ) {
        // Compute the evaluations of the shared polynomials at kappa
        let shared_evals = (0..NUM_WIRES)
            .map(|i| T::eval_poly(&polynomials[i].coefficients, kappa))
            .collect_vec();

        izip!(polynomials.iter(), shared_evals.iter()).for_each(|(poly, evaluation)| {
            opening_claims.push(ShpleminiOpeningClaim {
                polynomial: poly.clone(),
                opening_pair: OpeningPair {
                    challenge: kappa,
                    evaluation: evaluation.clone(),
                },
                gemini_fold: false,
            });
        });

        // Open the evaluations and send them to the verifier
        let evaluations = T::open_many(shared_evals.as_slice(), self.net, self.state)
            .expect("Failed to open evaluations");
        evaluations
            .into_iter()
            .enumerate()
            .for_each(|(i, evaluation)| {
                self.transcript
                    .send_fr_to_verifier::<C>(format!("{}_{i}", label), evaluation);
            });
    }

    // TACEO TODO: Avoid duplicate code in co-noir/ultrahonk/src/decider/decider_prover.rs#48
    fn compute_opening_proof(
        &mut self,
        opening_claim: ShpleminiOpeningClaim<T, C>,
    ) -> eyre::Result<()> {
        let mut quotient = opening_claim.polynomial;
        let pair = opening_claim.opening_pair;
        quotient[0] = T::sub(quotient[0], pair.evaluation);
        // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
        quotient.factor_roots(&pair.challenge);
        let quotient_commitment =
            CoUtils::commit::<T, C>(&quotient.coefficients, &self.commitment_key);

        // AZTEC TODO(#479): compute_opening_proof
        // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
        // pthreads) or even the work queue itself
        self.transcript.send_point_to_verifier::<C>(
            "KZG:W".to_string(),
            T::open_point(quotient_commitment, self.net, &mut self.state)?.into(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use crate::eccvm::co_ecc_op_queue::{
        CoEccOpCode, CoEccvmOpsTable, CoUltraEccOpsTable, CoUltraOp, EccOpsTable, EccvmRowTracker,
    };

    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::bn::Bn;
    use ark_ec::pairing::Pairing;
    use co_builder::prelude::CrsParser;
    use co_ultrahonk::prelude::Rep3UltraHonkDriver;
    use goblin::eccvm::ecc_op_queue::{EccOpCode, UltraOp};
    use mpc_core::protocols::{
        rep3::{
            Rep3State, conversion::A2BType, id::PartyID, network::Rep3NetworkExt,
            share_field_element,
        },
        shamir::share,
    };
    use mpc_net::local::LocalNetwork;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use ultrahonk::prelude::{Poseidon2Sponge, ZeroKnowledge};

    type Bn254G1 = <Bn<ark_bn254::Config> as Pairing>::G1;
    type F = <Bn<ark_bn254::Config> as Pairing>::ScalarField;
    type Driver = Rep3UltraHonkDriver;
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
        .into_iter()
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
            x_lo: hex_to_field_element(
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            ),
            x_hi: hex_to_field_element(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            y_lo: hex_to_field_element(
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            ),
            y_hi: hex_to_field_element(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            z_1: hex_to_field_element(
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            ),
            z_2: hex_to_field_element(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            return_is_infinity: false,
        };

        let co_ultra_ops_1 = co_ultra_ops_from_ultra_op(ultra_op_1);

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
            x_lo: hex_to_field_element(
                "0x00000000000000000000000000000085d97816a916871ca8d3c208c16d87cfd3",
            ),
            x_hi: hex_to_field_element(
                "0x0000000000000000000000000000000000030644e72e131a029b85045b681815",
            ),
            y_lo: hex_to_field_element(
                "0x0000000000000000000000000000000a68a6a449e3538fc7ff3ebf7a5a18a2c4",
            ),
            y_hi: hex_to_field_element(
                "0x0000000000000000000000000000000015ed738c0e0a7c92e7845f96b2ae9c",
            ),
            z_1: hex_to_field_element(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            z_2: hex_to_field_element(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            return_is_infinity: false,
        };

        let co_ultra_ops_2 = co_ultra_ops_from_ultra_op(ultra_op_2);

        let get_queues = |id: usize| CoECCOpQueue::<Driver, Bn254G1> {
            point_at_infinity: Bn254G1::ZERO.into(),
            accumulator: Bn254G1::ZERO.into(),
            eccvm_ops_table: CoEccvmOpsTable::new(),
            ultra_ops_table: CoUltraEccOpsTable {
                table: EccOpsTable {
                    table: vec![vec![co_ultra_ops_1[id].clone(), co_ultra_ops_2[id].clone()]],
                },
            },
            eccvm_ops_reconstructed: Vec::new(),
            ultra_ops_reconstructed: Vec::new(),
            eccvm_row_tracker: EccvmRowTracker::new(),
        };

        let queue = [get_queues(0), get_queues(1), get_queues(2)];

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
                    queue, crs, &net, &mut state,
                );
                prover.construct_proof()
            }));
        }

        let mut results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

        let expected_proof = HonkProof::<TranscriptFieldType>::from_buffer(
            &std::fs::read(PROOF_FILE).expect("Failed to read expected proof from file"),
        )
        .expect("Failed to deserialize expected proof");

        assert_eq!(
            results.pop().unwrap(),
            expected_proof,
            "The constructed proof does not match the expected proof."
        );
    }
}
