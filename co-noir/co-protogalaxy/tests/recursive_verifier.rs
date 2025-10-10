use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::AdditiveGroup;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use co_acvm::PlainAcvmSolver;
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
use mpc_core::gadgets::field_from_hex_string;

use co_protogalaxy::{
    CONST_PG_LOG_N, PrecomputedCommitments, ProtogalaxyRecursiveVerifier,
    RecursiveDeciderVerificationKey, VerificationKey, WitnessCommitments,
};

type Bn254G1 = <Bn254 as Pairing>::G1;
type T<'a> = PlainAcvmSolver<TranscriptFieldType>;
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
#[expect(clippy::type_complexity)]
fn test_recursive_protogalaxy_recursive_verifier() {
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

    let mut builder = MegaCircuitBuilder::<Bn254G1, T>::new(CoECCOpQueue::default());
    let mut driver = T::new();

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
            let mut point = GoblinElement::<Bn254G1, T>::new(
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
            let mut point = GoblinElement::<Bn254G1, T>::new(
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
            let mut point = GoblinElement::<Bn254G1, T>::new(
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

    ProtogalaxyRecursiveVerifier::verify_folding_proofs::<Bn254G1, T, Poseidon2Sponge>(
        &mut accumulator,
        &mut key_to_fold,
        stdlib_fold_proof,
        &mut builder,
        &mut driver,
    )
    .unwrap();

    assert_eq!(
        accumulator.target_sum.get_value(&mut builder, &mut driver),
        target_sum_result
    );

    assert_eq!(
        accumulator
            .gate_challenges
            .iter()
            .map(|c| c.get_value(&mut builder, &mut driver))
            .collect::<Vec<_>>(),
        gate_challenges_result
    );

    assert_eq!(
        accumulator
            .alphas
            .iter()
            .map(|a| a.get_value(&mut builder, &mut driver))
            .collect::<Vec<_>>(),
        alphas_result
    );

    assert_eq!(
        accumulator
            .relation_parameters
            .get_params()
            .iter()
            .map(|p| p.get_value(&mut builder, &mut driver))
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
