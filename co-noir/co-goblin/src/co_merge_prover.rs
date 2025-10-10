use ark_ff::Field;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::CoUtils;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofResult, TranscriptFieldType};
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::transcript::TranscriptHasher;
use co_noir_common::transcript_mpc::TranscriptRef;
use co_noir_common::transcript_mpc::TranscriptRep3;
use itertools::{Itertools, izip};
use mpc_core::MpcState;
use mpc_net::Network;
use std::collections::VecDeque;
use ultrahonk::prelude::Transcript;

use co_builder::eccvm::co_ecc_op_queue::CoECCOpQueue;
use ultrahonk::prelude::HonkProof;

// (Polynomial, Evaluation, Challenge)
type OpeningClaim<T, F> = (Vec<T>, T, F);

const NUM_WIRES: usize = 4;
pub struct CoMergeProver<'a, C, H, N, T>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    N: Network,
    H: TranscriptHasher<TranscriptFieldType, T, C>,
{
    net: &'a N,
    state: &'a mut T::State,
    current_ultra_ops_subtable: Vec<Vec<T::ArithmeticShare>>,
    ultra_ops_table: Vec<Vec<T::ArithmeticShare>>,
    previous_ultra_ops_table: Vec<Vec<T::ArithmeticShare>>,
    phantom: std::marker::PhantomData<H>,
}

impl<'a, C, H, N, T> CoMergeProver<'a, C, H, N, T>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    N: Network,
    H: TranscriptHasher<TranscriptFieldType, T, C>,
{
    pub fn new<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        net: &'a N,
        state: &'a mut T::State,
        ecc_op_queue: CoECCOpQueue<U, C>,
        driver: &mut U,
    ) -> Self {
        let curr_subtable = ecc_op_queue.construct_current_ultra_ops_subtable_columns();
        let curr_table = ecc_op_queue.construct_ultra_ops_table_columns();
        let prev_table = ecc_op_queue.construct_previous_ultra_ops_table_columns();
        let curr_subtable_shares = curr_subtable
            .iter()
            .map(|subtable| {
                subtable
                    .iter()
                    .map(|x| {
                        if let Some(public) = U::get_public(x) {
                            driver.promote_to_trivial_share(public)
                        } else if let Some(secret) = U::get_shared(x) {
                            secret
                        } else {
                            panic!("Value is neither public nor secret")
                        }
                    })
                    .collect_vec()
            })
            .collect_vec();

        let prev_table_shares = prev_table
            .iter()
            .map(|subtable| {
                subtable
                    .iter()
                    .map(|x| {
                        if let Some(public) = U::get_public(x) {
                            driver.promote_to_trivial_share(public)
                        } else if let Some(secret) = U::get_shared(x) {
                            secret
                        } else {
                            panic!("Value is neither public nor secret")
                        }
                    })
                    .collect_vec()
            })
            .collect_vec();

        let curr_table_shares = curr_table
            .iter()
            .map(|subtable| {
                subtable
                    .iter()
                    .map(|x| {
                        if let Some(public) = U::get_public(x) {
                            driver.promote_to_trivial_share(public)
                        } else if let Some(secret) = U::get_shared(x) {
                            secret
                        } else {
                            panic!("Value is neither public nor secret")
                        }
                    })
                    .collect_vec()
            })
            .collect_vec();
        Self {
            net,
            state,
            current_ultra_ops_subtable: curr_subtable_shares,
            ultra_ops_table: curr_table_shares,
            previous_ultra_ops_table: prev_table_shares,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn construct_proof_plain_transcript(
        mut self,
        commitment_key: &ProverCrs<C>,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        let mut transcript = Transcript::new();
        let transcript = TranscriptRef::Plain(&mut transcript);
        let (proof, _) = self.construct_proof_inner(commitment_key, transcript)?;
        Ok(proof.expect("Proof is Some"))
    }

    pub fn construct_proof_rep3_transcript(
        mut self,
        commitment_key: &ProverCrs<C>,
    ) -> HonkProofResult<Vec<T::ArithmeticShare>> {
        let mut transcript = TranscriptRep3::new();
        let transcript = TranscriptRef::Rep3(&mut transcript);
        let (_, proof_shared) = self.construct_proof_inner(commitment_key, transcript)?;
        Ok(proof_shared.expect("Proof shared is Some"))
    }

    #[expect(clippy::type_complexity)]
    pub fn construct_proof_inner(
        &mut self,
        commitment_key: &ProverCrs<C>,
        mut transcript: TranscriptRef<TranscriptFieldType, T, C, H>,
    ) -> HonkProofResult<(
        Option<HonkProof<TranscriptFieldType>>,
        Option<Vec<T::ArithmeticShare>>,
    )> {
        let (current_table_size, current_subtable_size) = (
            self.ultra_ops_table[0].len(),
            self.current_ultra_ops_subtable[0].len(),
        );

        match &mut transcript {
            TranscriptRef::Plain(transcript) => transcript
                .send_u64_to_verifier("subtable_size".to_owned(), current_subtable_size as u64),
            TranscriptRef::Rep3(transcript_rep3) => transcript_rep3
                .send_u64_to_verifier("subtable_size".to_owned(), current_subtable_size as u64),
        }

        let curr_subtable_shares = &self.current_ultra_ops_subtable;
        let prev_table_shares = &self.previous_ultra_ops_table;
        let curr_table_shares = &self.ultra_ops_table;

        // Compute commitments shares
        let curr_subtable_shared_commitments = (0..NUM_WIRES)
            .map(|i| {
                let monomials = &commitment_key.monomials[..curr_subtable_shares[i].len()];
                CoUtils::msm::<T, C>(&curr_subtable_shares[i], monomials)
            })
            .collect_vec();
        let prev_table_shared_prev_commitments = (0..NUM_WIRES)
            .map(|i| {
                let monomials = &commitment_key.monomials[..prev_table_shares[i].len()];
                CoUtils::msm::<T, C>(&prev_table_shares[i], monomials)
            })
            .collect_vec();
        let curr_table_shared_commitments = (0..NUM_WIRES)
            .map(|i| {
                let monomials = &commitment_key.monomials[..curr_table_shares[i].len()];
                CoUtils::msm::<T, C>(&curr_table_shares[i], monomials)
            })
            .collect_vec();
        // Interleave the commitments and open them
        let shared_commitments = izip!(
            curr_subtable_shared_commitments,
            prev_table_shared_prev_commitments,
            curr_table_shared_commitments
        )
        .flat_map(|(a, b, c)| vec![a, b, c])
        .collect_vec();
        match &mut transcript {
            TranscriptRef::Plain(transcript) => {
                let mut commitments: VecDeque<C> =
                    T::open_point_many(&shared_commitments, self.net, self.state)?.into();

                // Send commitments to the verifier
                let num_chunks = commitments.len() / 3;
                for i in 0..num_chunks {
                    for label in ["current_subtable_", "previous_table_", "current_table_"] {
                        transcript.send_point_to_verifier::<C>(
                            format!("{label}{i}"),
                            commitments
                                .pop_front()
                                .expect("Commitment vector is not empty")
                                .into(),
                        );
                    }
                }
            }
            TranscriptRef::Rep3(transcript_rep3) => {
                let mut shared_commitments: VecDeque<_> = shared_commitments.into();
                // Send commitments to the verifier
                let num_chunks = shared_commitments.len() / 3;
                for i in 0..num_chunks {
                    for label in ["current_subtable_", "previous_table_", "current_table_"] {
                        transcript_rep3.send_point_to_verifier_shared(
                            format!("{label}{i}"),
                            shared_commitments
                                .pop_front()
                                .expect("Commitment vector is not empty"),
                        );
                    }
                }
            }
        }

        let kappa = match &mut transcript {
            TranscriptRef::Plain(transcript) => transcript.get_challenge::<C>("kappa".to_owned()),
            TranscriptRef::Rep3(transcript_rep3) => {
                transcript_rep3.get_challenge("kappa".to_owned(), self.net, self.state)?
            }
        };

        let mut opening_claims: Vec<OpeningClaim<T::ArithmeticShare, C::ScalarField>> =
            Vec::with_capacity(3 * NUM_WIRES);

        let all_polys = curr_subtable_shares
            .clone()
            .into_iter()
            .chain(prev_table_shares.clone())
            .chain(curr_table_shares.clone())
            .collect_vec();

        self.compute_opening_claims(
            &all_polys,
            "all_polys",
            &mut opening_claims,
            kappa,
            &mut transcript,
        )?;

        let alpha = match &mut transcript {
            TranscriptRef::Plain(transcript) => transcript.get_challenge::<C>("alpha".to_owned()),
            TranscriptRef::Rep3(transcript_rep3) => {
                transcript_rep3.get_challenge("alpha".to_owned(), self.net, self.state)?
            }
        };

        let mut batched_eval = T::ArithmeticShare::default();
        let mut alpha_pow = C::ScalarField::ONE;

        let batched_polynomial = opening_claims.iter().fold(
            vec![T::ArithmeticShare::default(); current_table_size],
            |mut acc, (polynomial, evaluation, _)| {
                let alpha_pow_many =
                    vec![T::promote_to_trivial_share(self.state.id(), alpha_pow); polynomial.len()];
                let scaled_poly = T::mul_many(polynomial, &alpha_pow_many, self.net, self.state)
                    .expect("Scaling polynomial by alpha_pow failed");
                acc.iter_mut()
                    .zip(scaled_poly.iter())
                    .for_each(|(a, b)| T::add_assign(a, *b));

                let scaled_evaluation = T::mul_with_public(alpha_pow, *evaluation);
                T::add_assign(&mut batched_eval, scaled_evaluation);
                alpha_pow *= alpha;
                acc
            },
        );

        self.compute_opening_proof(
            batched_polynomial,
            (batched_eval, kappa),
            &mut transcript,
            commitment_key,
        )?;

        match transcript {
            TranscriptRef::Plain(t) => Ok((Some(t.get_proof_ref()), None)),
            TranscriptRef::Rep3(t) => Ok((None, Some(t.get_proof()))),
        }
    }

    fn compute_opening_claims(
        &mut self,
        polynomials: &[Vec<T::ArithmeticShare>],
        label: &str,
        opening_claims: &mut Vec<OpeningClaim<T::ArithmeticShare, C::ScalarField>>,
        kappa: C::ScalarField,
        transcript: &mut TranscriptRef<TranscriptFieldType, T, C, H>,
    ) -> eyre::Result<()> {
        // Compute the evaluations of the shared polynomials at kappa
        let shared_evals = (0..3 * NUM_WIRES)
            .map(|i| T::eval_poly(&polynomials[i], kappa))
            .collect::<Vec<_>>();

        izip!(polynomials.iter(), shared_evals.iter()).for_each(|(poly, &evaluation)| {
            opening_claims.push((poly.to_vec(), evaluation, kappa))
        });
        match transcript {
            TranscriptRef::Plain(transcript) => {
                // Open the evaluations and send them to the verifier
                let evaluations = T::open_many(&shared_evals, self.net, self.state)?;
                evaluations
                    .into_iter()
                    .enumerate()
                    .for_each(|(i, evaluation)| {
                        transcript.send_fr_to_verifier::<C>(format!("{label}_{i}"), evaluation);
                    });
            }
            TranscriptRef::Rep3(transcript_rep3) => {
                shared_evals
                    .into_iter()
                    .enumerate()
                    .for_each(|(i, evaluation)| {
                        transcript_rep3
                            .send_fr_to_verifier_shared(format!("{label}_{i}"), evaluation);
                    });
            }
        }

        Ok(())
    }

    pub fn compute_opening_proof(
        &mut self,
        polynomial: Vec<T::ArithmeticShare>,
        (evaluation, challenge): (T::ArithmeticShare, C::ScalarField),
        transcript: &mut TranscriptRef<TranscriptFieldType, T, C, H>,
        crs: &ProverCrs<C>,
    ) -> HonkProofResult<()> {
        let mut quotient = polynomial;

        quotient[0] = T::sub(quotient[0], evaluation);
        // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
        self.factor_roots(&mut quotient, &challenge);

        // Compute the commitment to the quotient polynomial
        let monomials = &crs.monomials[..quotient.len()];
        let quotient_commitment = CoUtils::msm::<T, C>(&quotient, monomials);
        match transcript {
            TranscriptRef::Plain(transcript) => {
                // AZTEC TODO(#479): for now we compute the KZG commitment directly to unify the KZG and IPA interfaces but in the
                // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
                // pthreads) or even the work queue itself
                let quotient_commitment = T::open_point(quotient_commitment, self.net, self.state)?;

                transcript
                    .send_point_to_verifier::<C>("KZG:W".to_string(), quotient_commitment.into());
            }
            TranscriptRef::Rep3(transcript_rep3) => {
                transcript_rep3
                    .send_point_to_verifier_shared("KZG:W".to_string(), quotient_commitment);
            }
        }

        Ok(())
    }

    /**
     * @brief Divides p(X) by (X-r) in-place.
     */
    pub fn factor_roots(
        &mut self,
        coefficients: &mut Vec<T::ArithmeticShare>,
        root: &C::ScalarField,
    ) {
        if root.is_zero() {
            // if one of the roots is 0 after having divided by all other roots,
            // then p(X) = a₁⋅X + ⋯ + aₙ₋₁⋅Xⁿ⁻¹
            // so we shift the array of coefficients to the left
            // and the result is p(X) = a₁ + ⋯ + aₙ₋₁⋅Xⁿ⁻² and we subtract 1 from the size.
            coefficients.remove(0);
        } else {
            // assume
            //  • r != 0
            //  • (X−r) | p(X)
            //  • q(X) = ∑ᵢⁿ⁻² bᵢ⋅Xⁱ
            //  • p(X) = ∑ᵢⁿ⁻¹ aᵢ⋅Xⁱ = (X-r)⋅q(X)
            //
            // p(X)         0           1           2       ...     n-2             n-1
            //              a₀          a₁          a₂              aₙ₋₂            aₙ₋₁
            //
            // q(X)         0           1           2       ...     n-2             n-1
            //              b₀          b₁          b₂              bₙ₋₂            0
            //
            // (X-r)⋅q(X)   0           1           2       ...     n-2             n-1
            //              -r⋅b₀       b₀-r⋅b₁     b₁-r⋅b₂         bₙ₋₃−r⋅bₙ₋₂      bₙ₋₂
            //
            // b₀   = a₀⋅(−r)⁻¹
            // b₁   = (a₁ - b₀)⋅(−r)⁻¹
            // b₂   = (a₂ - b₁)⋅(−r)⁻¹
            //      ⋮
            // bᵢ   = (aᵢ − bᵢ₋₁)⋅(−r)⁻¹
            //      ⋮
            // bₙ₋₂ = (aₙ₋₂ − bₙ₋₃)⋅(−r)⁻¹
            // bₙ₋₁ = 0

            // For the simple case of one root we compute (−r)⁻¹ and
            let root_inverse = (-*root).inverse().expect("Root is not zero here");
            // set b₋₁ = 0
            let mut temp = Default::default();
            // We start multiplying lower coefficient by the inverse and subtracting those from highter coefficients
            // Since (x - r) should divide the polynomial cleanly, we can guide division with lower coefficients
            for coeff in coefficients.iter_mut() {
                // at the start of the loop, temp = bᵢ₋₁
                // and we can compute bᵢ   = (aᵢ − bᵢ₋₁)⋅(−r)⁻¹
                temp = T::sub(*coeff, temp);
                temp = T::mul_with_public(root_inverse, temp);
                *coeff = temp.to_owned();
            }
            // remove the last (zero) coefficient after synthetic division
            coefficients.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use co_acvm::{Rep3AcvmPoint, Rep3AcvmSolver};
    use co_builder::eccvm::co_ecc_op_queue::{CoEccvmOpsTable, CoUltraEccOpsTable, CoUltraOp};
    use mpc_core::protocols::rep3::{Rep3PointShare, Rep3State, share_curve_point};

    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::bn::Bn;
    use ark_ec::pairing::Pairing;
    use co_builder::eccvm::ecc_op_queue::{EccOpCode, EccOpsTable, EccvmRowTracker, UltraOp};
    use co_noir_common::transcript::Poseidon2Sponge;
    use co_noir_common::types::ZeroKnowledge;
    use co_noir_common::{crs::parse::CrsParser, mpc::rep3::Rep3UltraHonkDriver};
    use mpc_core::{
        gadgets::field_from_hex_string,
        protocols::rep3::{conversion::A2BType, share_field_element},
    };
    use mpc_net::local::LocalNetwork;
    use rand::thread_rng;

    type Bn254G1 = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;
    type Bn254G1Affine = ark_bn254::G1Affine;
    type F = <Bn<ark_bn254::Config> as Pairing>::ScalarField;
    type AcvmDriver<'a> = Rep3AcvmSolver<'a, F, LocalNetwork>;

    const CRS_PATH_G1: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../co-noir-common/src/crs/bn254_g1.dat"
    );
    const CRS_PATH_G2: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../co-noir-common/src/crs/bn254_g2.dat"
    );
    const PROOF_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test_vectors/noir/merge_prover/merge_proof"
    );

    fn co_ultra_ops_from_ultra_op(
        ultra_op: UltraOp<Bn254G1>,
    ) -> Vec<CoUltraOp<AcvmDriver<'static>, Bn254G1>> {
        let mut rng = thread_rng();
        izip!(
            share_field_element(ultra_op.x_lo, &mut rng),
            share_field_element(ultra_op.x_hi, &mut rng),
            share_field_element(ultra_op.y_lo, &mut rng),
            share_field_element(ultra_op.y_hi, &mut rng),
            share_field_element(ultra_op.z_1, &mut rng),
            share_field_element(ultra_op.z_2, &mut rng),
            share_field_element(F::from(ultra_op.return_is_infinity as u8), &mut rng)
        )
        .map(
            |(x_lo, x_hi, y_lo, y_hi, z_1, z_2, return_is_infinity)| CoUltraOp {
                op_code: EccOpCode {
                    add: ultra_op.op_code.add,
                    mul: ultra_op.op_code.mul,
                    eq: ultra_op.op_code.eq,
                    reset: ultra_op.op_code.reset,
                },
                x_lo: x_lo.into(),
                x_hi: x_hi.into(),
                y_lo: y_lo.into(),
                y_hi: y_hi.into(),
                z_1: z_1.into(),
                z_2: z_2.into(),
                return_is_infinity: return_is_infinity.into(),
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
        let mut acc: VecDeque<Rep3PointShare<Bn254G1>> =
            share_curve_point(Bn254G1Affine::identity().into(), &mut thread_rng()).into();

        let mut get_queues = || CoECCOpQueue::<AcvmDriver, Bn254G1> {
            accumulator: Rep3AcvmPoint::Shared(acc.pop_front().unwrap()),
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
            ultra_ops_reconstructed: Vec::new(),
            eccvm_row_tracker: EccvmRowTracker::default(),
        };

        let queue: [CoECCOpQueue<AcvmDriver, Bn254G1>; 3] = core::array::from_fn(|_| get_queues());

        let crs =
            CrsParser::<Bn254G1>::get_crs::<Bn254>(CRS_PATH_G1, CRS_PATH_G2, 5, ZeroKnowledge::No)
                .unwrap();
        let (prover_crs, _) = crs.split();

        let nets = LocalNetwork::new_3_parties();
        let mut threads = Vec::with_capacity(3);

        for (net, queue) in nets.into_iter().zip(queue.into_iter()) {
            let crs = prover_crs.clone();
            let net_b = Box::leak(Box::new(net));
            threads.push(thread::spawn(move || {
                let mut driver = AcvmDriver::new(net_b, net_b, A2BType::Direct).unwrap();
                let mut state = Rep3State::new(net_b, A2BType::default()).unwrap();
                let prover = CoMergeProver::<
                    Bn254G1,
                    Poseidon2Sponge,
                    LocalNetwork,
                    Rep3UltraHonkDriver,
                >::new(net_b, &mut state, queue, &mut driver);
                prover.construct_proof_plain_transcript(&crs)
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
