use ark_bn254::Fr;
use co_acvm::PlainAcvmSolver;
use co_builder::eccvm::co_ecc_op_queue::CoECCOpQueue;
use co_builder::flavours::mega_flavour::MegaPrecomputedEntities;
use co_builder::flavours::mega_flavour::MegaWitnessEntities;
use co_builder::mega_builder::MegaCircuitBuilder;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::transcript::Poseidon2Sponge;
use co_builder::types::field_ct::BoolCT;
use co_builder::types::field_ct::FieldCT;
use co_builder::types::field_ct::WitnessCT;
use co_builder::types::goblin_types::GoblinElement;
use co_builder::types::goblin_types::GoblinField;
use co_protogalaxy::RecursiveDeciderVerificationKey;
use co_protogalaxy::VerificationKey;
use co_ultrahonk::co_decider::types::RelationParameters;

use honk_verifier::decider_recursive_verifier::DeciderRecursiveVerifier;
use mpc_core::gadgets::field_from_hex_string;

type GoblinTestData = ((String, String), (String, String), u8);

type DeciderKeyTestData = (
    String,
    String,
    String,
    String,
    String,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<GoblinTestData>,
    Vec<GoblinTestData>,
);

type Bn254G1 = ark_bn254::G1Projective;
type Driver = PlainAcvmSolver<Fr>;

macro_rules! to_field_ct {
    ($x:expr, $builder:expr) => {
        FieldCT::from_witness(field_from_hex_string($x.as_str()).unwrap(), $builder)
    };
    ($x:expr, $builder:expr, 1) => {
        $x.into_iter()
            .map(|s| to_field_ct!(s, $builder))
            .collect::<Vec<_>>()
    };
    ($x:expr, $builder:expr, 2) => {
        $x.into_iter()
            .map(|s| to_field_ct!(s, $builder, 1))
            .collect::<Vec<_>>()
    };
}

fn to_goblin_element(
    data: GoblinTestData,
    builder: &mut MegaCircuitBuilder<Bn254G1, Driver>,
) -> GoblinElement<Bn254G1, Driver> {
    let ((x0, x1), (y0, y1), z) = data;
    let x0 = to_field_ct!(x0, builder);
    let x1 = to_field_ct!(x1, builder);
    let y0 = to_field_ct!(y0, builder);
    let y1 = to_field_ct!(y1, builder);
    let z = BoolCT::from_witness_ct(WitnessCT::from_acvm_type(Fr::from(z), builder), builder);
    let mut res = GoblinElement::new(GoblinField::new([x0, x1]), GoblinField::new([y0, y1]));
    res.set_point_at_infinity(z);
    res
}

#[test]
fn test_recursive_verifier() {
    let (
        (pairing_point_1, pairing_point_2),
        honk_proof,
        (
            circuit_size,
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
            target_sum,
            gate_challenges,
            alphas,
            relation_parameters,
            precomputed_commitments,
            witness_commitments,
        ),
    ): (
        (GoblinTestData, GoblinTestData),
        Vec<String>,
        DeciderKeyTestData,
    ) = serde_json::from_str(include_str!("test_data")).unwrap();

    let mut builder = MegaCircuitBuilder::<Bn254G1, Driver>::new(CoECCOpQueue::default());

    let honk_proof = to_field_ct!(honk_proof, &mut builder, 1);

    let circuit_size = to_field_ct!(circuit_size, &mut builder);
    let log_circuit_size = to_field_ct!(log_circuit_size, &mut builder);
    let num_public_inputs = to_field_ct!(num_public_inputs, &mut builder);
    let pub_inputs_offset = to_field_ct!(pub_inputs_offset, &mut builder);
    let target_sum = to_field_ct!(target_sum, &mut builder);
    let gate_challenges = to_field_ct!(gate_challenges, &mut builder, 1);
    let alphas = to_field_ct!(alphas, &mut builder, 1);
    let relation_parameters = to_field_ct!(relation_parameters, &mut builder, 1);

    let relation_parameters = RelationParameters {
        eta_1: relation_parameters[0].clone(),
        eta_2: relation_parameters[1].clone(),
        eta_3: relation_parameters[2].clone(),
        beta: relation_parameters[3].clone(),
        gamma: relation_parameters[4].clone(),
        public_input_delta: relation_parameters[5].clone(),
        lookup_grand_product_delta: relation_parameters[6].clone(),
        ..Default::default()
    };

    let precomputed_commitments = precomputed_commitments
        .into_iter()
        .map(|data| to_goblin_element(data, &mut builder))
        .collect::<Vec<_>>();

    let witness_commitments = witness_commitments
        .into_iter()
        .map(|data| to_goblin_element(data, &mut builder))
        .collect::<Vec<_>>();

    let precomputed_commitments = MegaPrecomputedEntities::from_elements(precomputed_commitments);

    let witness_commitments = MegaWitnessEntities::from_elements(witness_commitments);

    let expected_pairing_point_1 = to_goblin_element(pairing_point_1, &mut builder);
    let expected_pairing_point_2 = to_goblin_element(pairing_point_2, &mut builder);

    let mut accumulator = RecursiveDeciderVerificationKey {
        verification_key: VerificationKey {
            circuit_size,
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
        },
        is_accumulator: false,
        public_inputs: vec![],
        relation_parameters,
        gate_challenges,
        alphas,
        target_sum,
        precomputed_commitments,
        witness_commitments,
    };

    let mut driver = Driver::new();

    let (p1, p2) = DeciderRecursiveVerifier::verify_proof::<_, _, Poseidon2Sponge>(
        honk_proof,
        &mut accumulator,
        &mut builder,
        &mut driver,
    )
    .unwrap();

    assert_eq!(
        [expected_pairing_point_1, expected_pairing_point_2]
            .into_iter()
            .flat_map(|point| [
                point.x.limbs[0].get_value(&builder, &mut driver),
                point.x.limbs[1].get_value(&builder, &mut driver),
                point.y.limbs[0].get_value(&builder, &mut driver),
                point.y.limbs[1].get_value(&builder, &mut driver),
                point.is_infinity.get_value(&mut driver)
            ])
            .collect::<Vec<_>>(),
        [p1, p2]
            .into_iter()
            .flat_map(|point| [
                point.x.limbs[0].get_value(&builder, &mut driver),
                point.x.limbs[1].get_value(&builder, &mut driver),
                point.y.limbs[0].get_value(&builder, &mut driver),
                point.y.limbs[1].get_value(&builder, &mut driver),
                point.is_infinity.get_value(&mut driver)
            ])
            .collect::<Vec<_>>()
    );
}
