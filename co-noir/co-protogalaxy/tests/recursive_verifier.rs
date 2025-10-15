use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::AdditiveGroup;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use co_acvm::PlainAcvmSolver;
use co_acvm::Rep3AcvmSolver;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::eccvm::co_ecc_op_queue::CoECCOpQueue;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prover_flavour::ProverFlavour;
use co_builder::types::field_ct::BoolCT;
use co_builder::types::field_ct::WitnessCT;
use co_builder::{
    mega_builder::MegaCircuitBuilder,
    transcript::Poseidon2Sponge,
    types::{
        field_ct::FieldCT,
        goblin_types::{GoblinElement, GoblinField},
    },
};
use co_noir_common::honk_proof::TranscriptFieldType;
use co_ultrahonk::co_decider::types::RelationParameters;
use itertools::Itertools;
use itertools::izip;
use mpc_core::gadgets::field_from_hex_string;

use co_protogalaxy::{
    CONST_PG_LOG_N, PrecomputedCommitments, ProtogalaxyRecursiveVerifier,
    RecursiveDeciderVerificationKey, VerificationKey, WitnessCommitments,
};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::share_field_element;
use mpc_net::local::LocalNetwork;

type Bn254G1 = <Bn254 as Pairing>::G1;
type PlainDriver = PlainAcvmSolver<TranscriptFieldType>;
type Rep3Driver = Rep3AcvmSolver<'static, TranscriptFieldType, LocalNetwork>;
type Fr = ark_bn254::Fr;

type ProtogalaxyKeyTestData = (
    String,
    String,
    String,
    String,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<((String, String), (String, String), u8)>,
    Vec<((String, String), (String, String), u8)>,
);

macro_rules! to_field {
    ($x:expr) => {
        field_from_hex_string($x.as_str()).unwrap()
    };
    ($x:expr, 1) => {
        $x.into_iter().map(|s| to_field!(s)).collect::<Vec<_>>()
    };
    ($x:expr, 2) => {
        $x.into_iter().map(|s| to_field!(s, 1)).collect::<Vec<_>>()
    };
}

#[test]
fn test_protogalaxy_recursive_verifier_plaindriver() {
    let (
        fold_proof,
        (
            (
                target_sum_1,
                circuit_size_1,
                num_public_inputs_1,
                pub_inputs_offset_1,
                gate_challenges_1,
                alphas_1,
                relation_parameters_1,
                precomputed_commitments_1,
                witness_commitments_1,
            ),
            (
                _,
                circuit_size_2,
                num_public_inputs_2,
                pub_inputs_offset_2,
                _,
                alphas_2,
                relation_parameters_2,
                precomputed_commitments_2,
                _,
            ),
        ),
        (
            target_sum_result,
            _,
            _,
            _,
            gate_challenges_result,
            alphas_result,
            relation_parameters_result,
            precomputed_commitments_result,
            witness_commitments_result,
        ),
    ): (
        Vec<String>,
        (ProtogalaxyKeyTestData, ProtogalaxyKeyTestData),
        ProtogalaxyKeyTestData,
    ) = serde_json::from_str(include_str!("recursive_verifier_testdata")).unwrap();

    let fold_proof = to_field!(fold_proof, 1);

    let (circuit_size_1, num_public_inputs_1, pub_inputs_offset_1): (Fr, Fr, Fr) = (
        to_field!(circuit_size_1),
        to_field!(num_public_inputs_1),
        to_field!(pub_inputs_offset_1),
    );
    let log_circuit_size_1 = Fr::from(circuit_size_1.into_bigint().num_bits() as u64);
    let target_sum_1 = to_field!(target_sum_1);
    let gate_challenges_1 = to_field!(gate_challenges_1, 1);
    let alphas_1 = to_field!(alphas_1, 1);
    let relation_parameters_1 = to_field!(relation_parameters_1, 1);
    let precomputed_commitments_1 = precomputed_commitments_1
        .into_iter()
        .map(|((x1, x2), (y1, y2), z)| {
            (
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(z as u64),
            )
        })
        .collect::<Vec<_>>();

    let (circuit_size_2, num_public_inputs_2, pub_inputs_offset_2): (Fr, Fr, Fr) = (
        to_field!(circuit_size_2),
        to_field!(num_public_inputs_2),
        to_field!(pub_inputs_offset_2),
    );
    let log_circuit_size_2 = Fr::from(circuit_size_2.into_bigint().num_bits() as u64);
    let alphas_2 = to_field!(alphas_2, 1);
    let relation_parameters_2 = to_field!(relation_parameters_2, 1);
    let precomputed_commitments_2 = precomputed_commitments_2
        .into_iter()
        .map(|((x1, x2), (y1, y2), z)| {
            (
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(z as u64),
            )
        })
        .collect::<Vec<_>>();

    let mut builder = MegaCircuitBuilder::<Bn254G1, PlainDriver>::new(CoECCOpQueue::default());
    let mut driver = PlainDriver::new();

    let mut stdlib_fold_proof = Vec::with_capacity(fold_proof.len());
    for &fr in &fold_proof {
        stdlib_fold_proof.push(FieldCT::from_witness(fr, &mut builder));
    }

    let gate_challenges_1 = gate_challenges_1
        .into_iter()
        .map(|fr| FieldCT::from_witness(fr, &mut builder))
        .collect::<Vec<_>>();
    let alphas_1 = alphas_1
        .into_iter()
        .map(|fr| FieldCT::from_witness(fr, &mut builder))
        .collect::<Vec<_>>();
    let relation_parameters_1 = relation_parameters_1
        .into_iter()
        .map(|fr| FieldCT::from_witness(fr, &mut builder))
        .collect::<Vec<_>>();
    let precomputed_commitments_1 = precomputed_commitments_1
        .into_iter()
        .map(|(x1, x2, y1, y2, is_inf)| {
            let mut point = GoblinElement::<Bn254G1, PlainDriver>::new(
                GoblinField::new([
                    FieldCT::from_witness(x1, &mut builder),
                    FieldCT::from_witness(x2, &mut builder),
                ]),
                GoblinField::new([
                    FieldCT::from_witness(y1, &mut builder),
                    FieldCT::from_witness(y2, &mut builder),
                ]),
            );
            point.set_point_at_infinity(BoolCT::from_witness_ct(
                WitnessCT::from_acvm_type(is_inf, &mut builder),
                &mut builder,
            ));
            point
        })
        .collect::<Vec<_>>();
    let witness_commitments_1 = witness_commitments_1
        .into_iter()
        .map(|((x1, x2), (y1, y2), is_inf)| {
            let mut point = GoblinElement::<Bn254G1, PlainDriver>::new(
                GoblinField::new([
                    FieldCT::from_witness(to_field!(x1), &mut builder),
                    FieldCT::from_witness(to_field!(x2), &mut builder),
                ]),
                GoblinField::new([
                    FieldCT::from_witness(to_field!(y1), &mut builder),
                    FieldCT::from_witness(to_field!(y2), &mut builder),
                ]),
            );
            point.set_point_at_infinity(BoolCT::from_witness_ct(
                WitnessCT::from_acvm_type(Fr::from(is_inf as u64), &mut builder),
                &mut builder,
            ));
            point
        })
        .collect::<Vec<_>>();
    let relation_parameters_1 = RelationParameters {
        eta_1: relation_parameters_1[0].clone(),
        eta_2: relation_parameters_1[1].clone(),
        eta_3: relation_parameters_1[2].clone(),
        beta: relation_parameters_1[3].clone(),
        gamma: relation_parameters_1[4].clone(),
        public_input_delta: relation_parameters_1[5].clone(),
        lookup_grand_product_delta: relation_parameters_1[6].clone(),
        ..Default::default()
    };

    let alphas_2 = alphas_2
        .into_iter()
        .map(|fr| FieldCT::from_witness(fr, &mut builder))
        .collect::<Vec<_>>();
    let relation_parameters_2 = relation_parameters_2
        .into_iter()
        .map(|fr| FieldCT::from_witness(fr, &mut builder))
        .collect::<Vec<_>>();
    let precomputed_commitments_2 = precomputed_commitments_2
        .into_iter()
        .map(|(x1, x2, y1, y2, is_inf)| {
            let mut point = GoblinElement::<Bn254G1, PlainDriver>::new(
                GoblinField::new([
                    FieldCT::from_witness(x1, &mut builder),
                    FieldCT::from_witness(x2, &mut builder),
                ]),
                GoblinField::new([
                    FieldCT::from_witness(y1, &mut builder),
                    FieldCT::from_witness(y2, &mut builder),
                ]),
            );
            point.set_point_at_infinity(BoolCT::from_witness_ct(
                WitnessCT::from_acvm_type(is_inf, &mut builder),
                &mut builder,
            ));
            point
        })
        .collect::<Vec<_>>();
    let witness_commitments_2 = (0..MegaFlavour::WITNESS_ENTITIES_SIZE)
        .map(|_| GoblinElement::point_at_infinity(&mut builder))
        .collect::<Vec<_>>();
    let relation_parameters_2 = RelationParameters {
        eta_1: relation_parameters_2[0].clone(),
        eta_2: relation_parameters_2[1].clone(),
        eta_3: relation_parameters_2[2].clone(),
        beta: relation_parameters_2[3].clone(),
        gamma: relation_parameters_2[4].clone(),
        public_input_delta: relation_parameters_2[5].clone(),
        lookup_grand_product_delta: relation_parameters_2[6].clone(),
        ..Default::default()
    };

    let target_sum_result = to_field!(target_sum_result);
    let gate_challenges_result = to_field!(gate_challenges_result, 1);
    let alphas_result = to_field!(alphas_result, 1);
    let relation_parameters_result = to_field!(relation_parameters_result, 1);
    let precomputed_commitments_result = precomputed_commitments_result
        .into_iter()
        .map(|((x1, x2), (y1, y2), z)| {
            (
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(z as u64),
            )
        })
        .collect::<Vec<_>>();
    let witness_commitments_result = witness_commitments_result
        .into_iter()
        .map(|((x1, x2), (y1, y2), z)| {
            (
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(z as u64),
            )
        })
        .collect::<Vec<_>>();

    let mut accumulator = RecursiveDeciderVerificationKey {
        verification_key: VerificationKey {
            circuit_size: FieldCT::from_witness(circuit_size_1, &mut builder),
            log_circuit_size: FieldCT::from_witness(log_circuit_size_1, &mut builder),
            num_public_inputs: FieldCT::from_witness(num_public_inputs_1, &mut builder),
            pub_inputs_offset: FieldCT::from_witness(pub_inputs_offset_1, &mut builder),
        },
        is_accumulator: true,
        public_inputs: vec![],
        relation_parameters: relation_parameters_1,
        alphas: alphas_1,
        gate_challenges: gate_challenges_1,
        target_sum: FieldCT::from_witness(target_sum_1, &mut builder),
        precomputed_commitments: PrecomputedCommitments::from_elements(precomputed_commitments_1),
        witness_commitments: WitnessCommitments::from_elements(witness_commitments_1),
    };

    let mut key_to_fold = RecursiveDeciderVerificationKey {
        verification_key: VerificationKey {
            circuit_size: FieldCT::from_witness(circuit_size_2, &mut builder),
            log_circuit_size: FieldCT::from_witness(log_circuit_size_2, &mut builder),
            num_public_inputs: FieldCT::from_witness(num_public_inputs_2, &mut builder),
            pub_inputs_offset: FieldCT::from_witness(pub_inputs_offset_2, &mut builder),
        },
        is_accumulator: false,
        public_inputs: vec![],
        relation_parameters: relation_parameters_2,
        alphas: alphas_2,
        gate_challenges: vec![FieldCT::from_witness(Fr::ZERO, &mut builder); CONST_PG_LOG_N],
        target_sum: FieldCT::from_witness(Fr::from(0u64), &mut builder),
        precomputed_commitments: PrecomputedCommitments::from_elements(precomputed_commitments_2),
        witness_commitments: WitnessCommitments::from_elements(witness_commitments_2),
    };

    ProtogalaxyRecursiveVerifier::verify_folding_proofs::<Bn254G1, PlainDriver, Poseidon2Sponge>(
        &mut accumulator,
        &mut key_to_fold,
        stdlib_fold_proof,
        &mut builder,
        &mut driver,
    )
    .unwrap();

    assert_eq!(
        accumulator.target_sum.get_value(&builder, &mut driver),
        target_sum_result
    );

    assert_eq!(
        accumulator
            .gate_challenges
            .iter()
            .map(|c| c.get_value(&builder, &mut driver))
            .collect::<Vec<_>>(),
        gate_challenges_result
    );

    assert_eq!(
        accumulator
            .alphas
            .iter()
            .map(|a| a.get_value(&builder, &mut driver))
            .collect::<Vec<_>>(),
        alphas_result
    );

    assert_eq!(
        accumulator
            .relation_parameters
            .get_params()
            .iter()
            .map(|p| p.get_value(&builder, &mut driver))
            .collect::<Vec<_>>(),
        relation_parameters_result
    );

    assert_eq!(
        accumulator
            .precomputed_commitments
            .iter()
            .map(|c| {
                let (x1, x2) = c.x.get_value(&mut builder, &mut driver);
                let (y1, y2) = c.y.get_value(&mut builder, &mut driver);
                let is_inf = c.is_infinity.get_value(&mut driver);
                (x1, x2, y1, y2, is_inf)
            })
            .collect::<Vec<_>>(),
        precomputed_commitments_result
    );

    assert_eq!(
        accumulator
            .witness_commitments
            .iter()
            .map(|c| {
                let (x1, x2) = c.x.get_value(&mut builder, &mut driver);
                let (y1, y2) = c.y.get_value(&mut builder, &mut driver);
                let is_inf = c.is_infinity.get_value(&mut driver);
                (x1, x2, y1, y2, is_inf)
            })
            .collect::<Vec<_>>(),
        witness_commitments_result
    );
}

#[test]
fn test_protogalaxy_recursive_verifier_rep3() {
    let (
        fold_proof,
        (
            (
                target_sum_1,
                circuit_size_1,
                num_public_inputs_1,
                pub_inputs_offset_1,
                gate_challenges_1,
                alphas_1,
                relation_parameters_1,
                precomputed_commitments_1,
                witness_commitments_1,
            ),
            (
                _,
                circuit_size_2,
                num_public_inputs_2,
                pub_inputs_offset_2,
                _,
                alphas_2,
                relation_parameters_2,
                precomputed_commitments_2,
                _,
            ),
        ),
        (
            target_sum_result,
            _,
            _,
            _,
            gate_challenges_result,
            alphas_result,
            relation_parameters_result,
            precomputed_commitments_result,
            witness_commitments_result,
        ),
    ): (
        Vec<String>,
        (ProtogalaxyKeyTestData, ProtogalaxyKeyTestData),
        ProtogalaxyKeyTestData,
    ) = serde_json::from_str(include_str!("recursive_verifier_testdata")).unwrap();
    let mut rng = rand::thread_rng();

    let fold_proof: Vec<Fr> = to_field!(fold_proof, 1);

    let (circuit_size_1, num_public_inputs_1, pub_inputs_offset_1): (Fr, Fr, Fr) = (
        to_field!(circuit_size_1),
        to_field!(num_public_inputs_1),
        to_field!(pub_inputs_offset_1),
    );

    let log_circuit_size_1 = Fr::from(circuit_size_1.into_bigint().num_bits() as u64);
    let target_sum_1 = to_field!(target_sum_1);
    let gate_challenges_1 = to_field!(gate_challenges_1, 1);
    let alphas_1 = to_field!(alphas_1, 1);
    let relation_parameters_1 = to_field!(relation_parameters_1, 1);
    let precomputed_commitments_1 = precomputed_commitments_1
        .into_iter()
        .map(|((x1, x2), (y1, y2), z)| {
            (
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(z as u64),
            )
        })
        .collect::<Vec<_>>();

    let witness_commitments_1 = witness_commitments_1
        .into_iter()
        .map(|((x1, x2), (y1, y2), is_inf)| {
            (
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(is_inf as u64),
            )
        })
        .collect::<Vec<_>>();

    let target_sum_1 = share_field_element(target_sum_1, &mut rng);
    let gate_challenges_1 = gate_challenges_1
        .into_iter()
        .map(|fr| share_field_element(fr, &mut rng))
        .collect::<Vec<_>>();
    let alphas_1 = alphas_1
        .into_iter()
        .map(|fr| share_field_element(fr, &mut rng))
        .collect::<Vec<_>>();
    let relation_parameters_1 = relation_parameters_1
        .into_iter()
        .map(|fr| share_field_element(fr, &mut rng))
        .collect::<Vec<_>>();
    let precomputed_commitments_1 = precomputed_commitments_1
        .into_iter()
        .map(|(x1, x2, y1, y2, is_inf)| {
            (
                share_field_element(x1, &mut rng),
                share_field_element(x2, &mut rng),
                share_field_element(y1, &mut rng),
                share_field_element(y2, &mut rng),
                share_field_element(is_inf, &mut rng),
            )
        })
        .collect::<Vec<_>>();

    let witness_commitments_1 = witness_commitments_1
        .into_iter()
        .map(|(x1, x2, y1, y2, is_inf)| {
            (
                share_field_element(x1, &mut rng),
                share_field_element(x2, &mut rng),
                share_field_element(y1, &mut rng),
                share_field_element(y2, &mut rng),
                share_field_element(is_inf, &mut rng),
            )
        })
        .collect::<Vec<_>>();

    let (circuit_size_2, num_public_inputs_2, pub_inputs_offset_2): (Fr, Fr, Fr) = (
        to_field!(circuit_size_2),
        to_field!(num_public_inputs_2),
        to_field!(pub_inputs_offset_2),
    );
    let log_circuit_size_2 = Fr::from(circuit_size_2.into_bigint().num_bits() as u64);
    let alphas_2 = to_field!(alphas_2, 1);
    let relation_parameters_2 = to_field!(relation_parameters_2, 1);
    let precomputed_commitments_2 = precomputed_commitments_2
        .into_iter()
        .map(|((x1, x2), (y1, y2), z)| {
            (
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(z as u64),
            )
        })
        .collect::<Vec<_>>();

    let alphas_2 = alphas_2
        .into_iter()
        .map(|fr| share_field_element(fr, &mut rng))
        .collect::<Vec<_>>();
    let relation_parameters_2 = relation_parameters_2
        .into_iter()
        .map(|fr| share_field_element(fr, &mut rng))
        .collect::<Vec<_>>();
    let precomputed_commitments_2 = precomputed_commitments_2
        .into_iter()
        .map(|(x1, x2, y1, y2, is_inf)| {
            (
                share_field_element(x1, &mut rng),
                share_field_element(x2, &mut rng),
                share_field_element(y1, &mut rng),
                share_field_element(y2, &mut rng),
                share_field_element(is_inf, &mut rng),
            )
        })
        .collect::<Vec<_>>();

    let mut builders = (0..3)
        .map(|_| MegaCircuitBuilder::<Bn254G1, Rep3Driver>::new(CoECCOpQueue::default()))
        .collect::<Vec<_>>();

    let mut stdlib_fold_proofs = (0..3)
        .map(|_| Vec::with_capacity(fold_proof.len()))
        .collect::<Vec<_>>();
    for &fr in &fold_proof {
        for (stdlib_fold_proof, builder) in
            izip!(stdlib_fold_proofs.iter_mut(), builders.iter_mut())
        {
            stdlib_fold_proof.push(FieldCT::from_witness(fr.into(), builder));
        }
    }

    let gate_challenges_1: (Vec<_>, Vec<_>, Vec<_>) = gate_challenges_1
        .iter()
        .map(|shares| {
            let shares = builders
                .iter_mut()
                .zip(shares.iter())
                .map(|(builder, &share)| FieldCT::from_witness(share.into(), builder))
                .collect::<Vec<_>>();
            (shares[0].clone(), shares[1].clone(), shares[2].clone())
        })
        .multiunzip();

    let gate_challenges_1 = [
        gate_challenges_1.0,
        gate_challenges_1.1,
        gate_challenges_1.2,
    ];

    let alphas_1: (Vec<_>, Vec<_>, Vec<_>) = alphas_1
        .iter()
        .map(|shares| {
            let shares = builders
                .iter_mut()
                .zip(shares.iter())
                .map(|(builder, &share)| FieldCT::from_witness(share.into(), builder))
                .collect::<Vec<_>>();
            (shares[0].clone(), shares[1].clone(), shares[2].clone())
        })
        .multiunzip();

    let alphas_1 = [alphas_1.0, alphas_1.1, alphas_1.2];

    let relation_parameters_1: (Vec<_>, Vec<_>, Vec<_>) = relation_parameters_1
        .iter()
        .map(|shares| {
            let shares = builders
                .iter_mut()
                .zip(shares.iter())
                .map(|(builder, &share)| FieldCT::from_witness(share.into(), builder))
                .collect::<Vec<_>>();
            (shares[0].clone(), shares[1].clone(), shares[2].clone())
        })
        .multiunzip();

    let relation_parameters_1 = [
        relation_parameters_1.0,
        relation_parameters_1.1,
        relation_parameters_1.2,
    ];

    let precomputed_commitments_1 = precomputed_commitments_1
        .iter()
        .map(|&(x1, x2, y1, y2, is_inf)| {
            let precomputed_commitment = izip!(builders.iter_mut(), x1, x2, y1, y2, is_inf)
                .map(|(builder, x1, x2, y1, y2, is_inf)| {
                    let mut point = GoblinElement::<Bn254G1, Rep3Driver>::new(
                        GoblinField::new([
                            FieldCT::from_witness(x1.into(), builder),
                            FieldCT::from_witness(x2.into(), builder),
                        ]),
                        GoblinField::new([
                            FieldCT::from_witness(y1.into(), builder),
                            FieldCT::from_witness(y2.into(), builder),
                        ]),
                    );
                    point.set_point_at_infinity(BoolCT::from_witness_ct(
                        WitnessCT::from_acvm_type(is_inf.into(), builder),
                        builder,
                    ));
                    point
                })
                .collect::<Vec<_>>();
            (
                precomputed_commitment[0].clone(),
                precomputed_commitment[1].clone(),
                precomputed_commitment[2].clone(),
            )
        })
        .collect::<Vec<_>>();

    let precomputed_commitments_1 = precomputed_commitments_1.into_iter().fold(
        [vec![], vec![], vec![]],
        |[mut acc0, mut acc1, mut acc2], (x, y, z)| {
            acc0.push(x);
            acc1.push(y);
            acc2.push(z);
            [acc0, acc1, acc2]
        },
    );

    let witness_commitments_1 = witness_commitments_1
        .iter()
        .map(|&(x1, x2, y1, y2, is_inf)| {
            let witness_commitment = izip!(builders.iter_mut(), x1, x2, y1, y2, is_inf)
                .map(|(builder, x1, x2, y1, y2, is_inf)| {
                    let mut point = GoblinElement::<Bn254G1, Rep3Driver>::new(
                        GoblinField::new([
                            FieldCT::from_witness(x1.into(), builder),
                            FieldCT::from_witness(x2.into(), builder),
                        ]),
                        GoblinField::new([
                            FieldCT::from_witness(y1.into(), builder),
                            FieldCT::from_witness(y2.into(), builder),
                        ]),
                    );
                    point.set_point_at_infinity(BoolCT::from_witness_ct(
                        WitnessCT::from_acvm_type(is_inf.into(), builder),
                        builder,
                    ));
                    point
                })
                .collect::<Vec<_>>();
            (
                witness_commitment[0].clone(),
                witness_commitment[1].clone(),
                witness_commitment[2].clone(),
            )
        })
        .collect::<Vec<_>>();

    let witness_commitments_1 = witness_commitments_1.into_iter().fold(
        [vec![], vec![], vec![]],
        |[mut acc0, mut acc1, mut acc2], (x, y, z)| {
            acc0.push(x);
            acc1.push(y);
            acc2.push(z);
            [acc0, acc1, acc2]
        },
    );

    let relation_parameters_1 = relation_parameters_1
        .into_iter()
        .map(|params| RelationParameters {
            eta_1: params[0].clone(),
            eta_2: params[1].clone(),
            eta_3: params[2].clone(),
            beta: params[3].clone(),
            gamma: params[4].clone(),
            public_input_delta: params[5].clone(),
            lookup_grand_product_delta: params[6].clone(),
            ..Default::default()
        })
        .collect::<Vec<_>>();

    let alphas_2: (Vec<_>, Vec<_>, Vec<_>) = alphas_2
        .iter()
        .map(|shares| {
            let shares = builders
                .iter_mut()
                .zip(shares.iter())
                .map(|(builder, &share)| FieldCT::from_witness(share.into(), builder))
                .collect::<Vec<_>>();
            (shares[0].clone(), shares[1].clone(), shares[2].clone())
        })
        .multiunzip();

    let alphas_2 = [alphas_2.0, alphas_2.1, alphas_2.2];

    let relation_parameters_2: (Vec<_>, Vec<_>, Vec<_>) = relation_parameters_2
        .iter()
        .map(|shares| {
            let shares = builders
                .iter_mut()
                .zip(shares.iter())
                .map(|(builder, &share)| FieldCT::from_witness(share.into(), builder))
                .collect::<Vec<_>>();
            (shares[0].clone(), shares[1].clone(), shares[2].clone())
        })
        .multiunzip();

    let relation_parameters_2 = [
        relation_parameters_2.0,
        relation_parameters_2.1,
        relation_parameters_2.2,
    ];

    let precomputed_commitments_2 = precomputed_commitments_2
        .iter()
        .map(|&(x1, x2, y1, y2, is_inf)| {
            let precomputed_commitment = izip!(builders.iter_mut(), x1, x2, y1, y2, is_inf)
                .map(|(builder, x1, x2, y1, y2, is_inf)| {
                    let mut point = GoblinElement::<Bn254G1, Rep3Driver>::new(
                        GoblinField::new([
                            FieldCT::from_witness(x1.into(), builder),
                            FieldCT::from_witness(x2.into(), builder),
                        ]),
                        GoblinField::new([
                            FieldCT::from_witness(y1.into(), builder),
                            FieldCT::from_witness(y2.into(), builder),
                        ]),
                    );
                    point.set_point_at_infinity(BoolCT::from_witness_ct(
                        WitnessCT::from_acvm_type(is_inf.into(), builder),
                        builder,
                    ));
                    point
                })
                .collect::<Vec<_>>();
            (
                precomputed_commitment[0].clone(),
                precomputed_commitment[1].clone(),
                precomputed_commitment[2].clone(),
            )
        })
        .collect::<Vec<_>>();

    let precomputed_commitments_2 = precomputed_commitments_2.into_iter().fold(
        [vec![], vec![], vec![]],
        |[mut acc0, mut acc1, mut acc2], (x, y, z)| {
            acc0.push(x);
            acc1.push(y);
            acc2.push(z);
            [acc0, acc1, acc2]
        },
    );

    let witness_commitments_2 = (0..MegaFlavour::WITNESS_ENTITIES_SIZE)
        .map(|_| {
            let res = builders
                .iter_mut()
                .map(GoblinElement::point_at_infinity)
                .collect::<Vec<_>>();
            (res[0].clone(), res[1].clone(), res[2].clone())
        })
        .collect::<Vec<_>>();

    let witness_commitments_2 = witness_commitments_2.into_iter().fold(
        [vec![], vec![], vec![]],
        |[mut acc0, mut acc1, mut acc2], (x, y, z)| {
            acc0.push(x);
            acc1.push(y);
            acc2.push(z);
            [acc0, acc1, acc2]
        },
    );
    let relation_parameters_2 = relation_parameters_2
        .into_iter()
        .map(|params| RelationParameters {
            eta_1: params[0].clone(),
            eta_2: params[1].clone(),
            eta_3: params[2].clone(),
            beta: params[3].clone(),
            gamma: params[4].clone(),
            public_input_delta: params[5].clone(),
            lookup_grand_product_delta: params[6].clone(),
            ..Default::default()
        })
        .collect::<Vec<_>>();

    let target_sum_result = to_field!(target_sum_result);
    let gate_challenges_result = to_field!(gate_challenges_result, 1);
    let alphas_result = to_field!(alphas_result, 1);
    let relation_parameters_result = to_field!(relation_parameters_result, 1);
    let precomputed_commitments_result = precomputed_commitments_result
        .into_iter()
        .flat_map(|((x1, x2), (y1, y2), z)| {
            vec![
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(z as u64),
            ]
        })
        .collect::<Vec<_>>();
    let witness_commitments_result = witness_commitments_result
        .into_iter()
        .flat_map(|((x1, x2), (y1, y2), z)| {
            vec![
                to_field!(x1),
                to_field!(x2),
                to_field!(y1),
                to_field!(y2),
                Fr::from(z as u64),
            ]
        })
        .collect::<Vec<_>>();

    let accumulators = izip!(
        builders.iter_mut(),
        target_sum_1,
        relation_parameters_1,
        alphas_1,
        gate_challenges_1,
        precomputed_commitments_1,
        witness_commitments_1
    )
    .map(
        |(
            builder,
            target_sum,
            relation_parameters,
            alphas,
            gate_challenges,
            precomputed_commitments,
            witness_commitments,
        )| RecursiveDeciderVerificationKey {
            verification_key: VerificationKey {
                circuit_size: FieldCT::from_witness(circuit_size_1.into(), builder),
                log_circuit_size: FieldCT::from_witness(log_circuit_size_1.into(), builder),
                num_public_inputs: FieldCT::from_witness(num_public_inputs_1.into(), builder),
                pub_inputs_offset: FieldCT::from_witness(pub_inputs_offset_1.into(), builder),
            },
            is_accumulator: true,
            public_inputs: vec![],
            relation_parameters,
            alphas,
            gate_challenges,
            target_sum: FieldCT::from_witness(target_sum.into(), builder),
            precomputed_commitments: PrecomputedCommitments::from_elements(precomputed_commitments),
            witness_commitments: WitnessCommitments::from_elements(witness_commitments),
        },
    )
    .collect::<Vec<_>>();

    let keys_to_fold = izip!(
        builders.iter_mut(),
        relation_parameters_2,
        alphas_2,
        precomputed_commitments_2,
        witness_commitments_2
    )
    .map(
        |(builder, relation_parameters, alphas, precomputed_commitments, witness_commitments)| {
            RecursiveDeciderVerificationKey {
                verification_key: VerificationKey {
                    circuit_size: FieldCT::from_witness(circuit_size_2.into(), builder),
                    log_circuit_size: FieldCT::from_witness(log_circuit_size_2.into(), builder),
                    num_public_inputs: FieldCT::from_witness(num_public_inputs_2.into(), builder),
                    pub_inputs_offset: FieldCT::from_witness(pub_inputs_offset_2.into(), builder),
                },
                is_accumulator: false,
                public_inputs: vec![],
                relation_parameters,
                alphas,
                gate_challenges: vec![
                    FieldCT::from_witness(Fr::ZERO.into(), builder);
                    CONST_PG_LOG_N
                ],
                target_sum: FieldCT::from_witness(Fr::from(0u64).into(), builder),
                precomputed_commitments: PrecomputedCommitments::from_elements(
                    precomputed_commitments,
                ),
                witness_commitments: WitnessCommitments::from_elements(witness_commitments),
            }
        },
    )
    .collect::<Vec<_>>();

    let nets_1 = LocalNetwork::new_3_parties();
    let nets_2 = LocalNetwork::new_3_parties();

    let mut threads = Vec::with_capacity(3);

    for (net_1, net_2, mut builder, mut accumulator, mut key_to_fold, stdlib_fold_proof) in izip!(
        nets_1,
        nets_2,
        builders,
        accumulators,
        keys_to_fold,
        stdlib_fold_proofs,
    ) {
        threads.push(std::thread::spawn(move || {
            let net_1b = Box::leak(Box::new(net_1));
            let net_2b = Box::leak(Box::new(net_2));
            let mut driver = Rep3Driver::new(net_1b, net_2b, A2BType::Direct).unwrap();

            ProtogalaxyRecursiveVerifier::verify_folding_proofs::<
                Bn254G1,
                Rep3Driver,
                Poseidon2Sponge,
            >(
                &mut accumulator,
                &mut key_to_fold,
                stdlib_fold_proof,
                &mut builder,
                &mut driver,
            )
            .unwrap();

            let target_sum = accumulator.target_sum.get_value(&builder, &mut driver);
            let gate_challenges = accumulator
                .gate_challenges
                .iter()
                .map(|c| c.get_value(&builder, &mut driver))
                .collect::<Vec<_>>();
            let alphas = accumulator
                .alphas
                .iter()
                .map(|a| a.get_value(&builder, &mut driver))
                .collect::<Vec<_>>();
            let relation_parameters = accumulator
                .relation_parameters
                .get_params()
                .iter()
                .map(|p: &_| p.get_value(&builder, &mut driver))
                .collect::<Vec<_>>();
            let precomputed_commitments = accumulator
                .precomputed_commitments
                .iter()
                .flat_map(|c| {
                    let (x1, x2) = c.x.get_value(&mut builder, &mut driver);
                    let (y1, y2) = c.y.get_value(&mut builder, &mut driver);
                    let is_inf = c.is_infinity.get_value(&mut driver);
                    vec![x1, x2, y1, y2, is_inf]
                })
                .collect::<Vec<_>>();
            let witness_commitments = accumulator
                .witness_commitments
                .iter()
                .flat_map(|c| {
                    let (x1, x2) = c.x.get_value(&mut builder, &mut driver);
                    let (y1, y2) = c.y.get_value(&mut builder, &mut driver);
                    let is_inf = c.is_infinity.get_value(&mut driver);
                    vec![x1, x2, y1, y2, is_inf]
                })
                .collect::<Vec<_>>();

            // Target sum
            let target_sum = driver.open_many_acvm_type(&[target_sum]).unwrap()[0];

            // Gate challenges
            let gate_challenges = driver.open_many_acvm_type(&gate_challenges).unwrap();

            // Alphas
            let alphas = driver.open_many_acvm_type(&alphas).unwrap();

            // Relation parameters
            let relation_parameters = driver.open_many_acvm_type(&relation_parameters).unwrap();

            // Precomputed commitments
            let precomputed_commitments = driver
                .open_many_acvm_type(&precomputed_commitments)
                .unwrap();

            // Witness commitments
            let witness_commitments = driver.open_many_acvm_type(&witness_commitments).unwrap();

            (
                target_sum,
                gate_challenges,
                alphas,
                relation_parameters,
                precomputed_commitments,
                witness_commitments,
            )
        }));
    }

    let (
        target_sum,
        gate_challenges,
        alphas,
        relation_parameters,
        precomputed_commitments,
        witness_commitments,
    ) = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>()
        .pop()
        .unwrap();

    assert_eq!(target_sum, target_sum_result);

    assert_eq!(gate_challenges, gate_challenges_result);

    assert_eq!(alphas, alphas_result);

    assert_eq!(relation_parameters, relation_parameters_result);

    assert_eq!(precomputed_commitments, precomputed_commitments_result);

    assert_eq!(witness_commitments, witness_commitments_result);
}
