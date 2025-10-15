use ark_bn254::Fr;
use co_acvm::Rep3AcvmSolver;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
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
use itertools::Itertools;
use itertools::izip;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::share_field_element;

use honk_verifier::decider_recursive_verifier::DeciderRecursiveVerifier;
use mpc_core::gadgets::field_from_hex_string;
use mpc_net::local::LocalNetwork;

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
type Driver = Rep3AcvmSolver<'static, Fr, LocalNetwork>;

macro_rules! to_shared_field_cts {
    ($x:expr, $builders:expr) => {
        share_field_element(
            field_from_hex_string($x.as_str()).unwrap(),
            &mut rand::thread_rng(),
        )
        .into_iter()
        .zip($builders.iter_mut())
        .map(|(share, builder)| FieldCT::from_witness(share.into(), builder))
        .collect::<Vec<_>>()
    };
    ($x:expr, $builders:expr, 1) => {
        $x.into_iter()
            .map(|s| to_shared_field_cts!(s, $builders))
            .map(|s| (s[0].clone(), s[1].clone(), s[2].clone()))
            .multiunzip::<(Vec<_>, Vec<_>, Vec<_>)>()
    };
}

fn to_goblin_elements(
    data: GoblinTestData,
    builders: &mut Vec<MegaCircuitBuilder<Bn254G1, Driver>>,
) -> Vec<GoblinElement<Bn254G1, Driver>> {
    let ((x0, x1), (y0, y1), z) = data;
    let x0 = to_shared_field_cts!(x0, builders);
    let x1 = to_shared_field_cts!(x1, builders);
    let y0 = to_shared_field_cts!(y0, builders);
    let y1 = to_shared_field_cts!(y1, builders);
    let z = share_field_element(Fr::from(z), &mut rand::thread_rng())
        .into_iter()
        .zip(builders.iter_mut())
        .map(|(share, builder)| {
            BoolCT::from_witness_ct(WitnessCT::from_acvm_type(share.into(), builder), builder)
        });
    izip!(x0, x1, y0, y1, z)
        .map(|(x0, x1, y0, y1, z)| {
            let mut res =
                GoblinElement::new(GoblinField::new([x0, x1]), GoblinField::new([y0, y1]));
            res.set_point_at_infinity(z);
            res
        })
        .collect::<Vec<_>>()
}

#[test]
fn test_recursive_verifier_rep3() {
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

    let mut builders = (0..3)
        .map(|_| MegaCircuitBuilder::<Bn254G1, Driver>::new(CoECCOpQueue::default()))
        .collect::<Vec<_>>();

    let mut honk_proofs = [vec![], vec![], vec![]];
    for (proof, builder) in izip!(honk_proofs.iter_mut(), builders.iter_mut()) {
        *proof = honk_proof
            .iter()
            .map(|s| {
                FieldCT::from_witness(
                    field_from_hex_string::<Fr>(s.as_str()).unwrap().into(),
                    builder,
                )
            })
            .collect::<Vec<_>>();
    }

    let circuit_size = to_shared_field_cts!(circuit_size, &mut builders);
    let log_circuit_size = to_shared_field_cts!(log_circuit_size, &mut builders);
    let num_public_inputs = to_shared_field_cts!(num_public_inputs, &mut builders);
    let pub_inputs_offset = to_shared_field_cts!(pub_inputs_offset, &mut builders);
    let target_sum = to_shared_field_cts!(target_sum, &mut builders);

    let gate_challenges = to_shared_field_cts!(gate_challenges, &mut builders, 1);
    let gate_challenges = [gate_challenges.0, gate_challenges.1, gate_challenges.2];

    let alphas = to_shared_field_cts!(alphas, &mut builders, 1);
    let alphas = [alphas.0, alphas.1, alphas.2];

    let relation_parameters = to_shared_field_cts!(relation_parameters, &mut builders, 1);
    let relation_parameters = [
        relation_parameters.0,
        relation_parameters.1,
        relation_parameters.2,
    ]
    .into_iter()
    .map(|x| RelationParameters {
        eta_1: x[0].clone(),
        eta_2: x[1].clone(),
        eta_3: x[2].clone(),
        beta: x[3].clone(),
        gamma: x[4].clone(),
        public_input_delta: x[5].clone(),
        lookup_grand_product_delta: x[6].clone(),
        ..Default::default()
    })
    .collect::<Vec<_>>();

    let precomputed_commitments = precomputed_commitments
        .into_iter()
        .map(|data| to_goblin_elements(data, &mut builders))
        .map(|data| (data[0].clone(), data[1].clone(), data[2].clone()))
        .multiunzip::<(Vec<_>, Vec<_>, Vec<_>)>();

    let precomputed_commitments = [
        MegaPrecomputedEntities::from_elements(precomputed_commitments.0),
        MegaPrecomputedEntities::from_elements(precomputed_commitments.1),
        MegaPrecomputedEntities::from_elements(precomputed_commitments.2),
    ];

    let witness_commitments = witness_commitments
        .into_iter()
        .map(|data| to_goblin_elements(data, &mut builders))
        .map(|data| (data[0].clone(), data[1].clone(), data[2].clone()))
        .multiunzip::<(Vec<_>, Vec<_>, Vec<_>)>();

    let witness_commitments = [
        MegaWitnessEntities::from_elements(witness_commitments.0),
        MegaWitnessEntities::from_elements(witness_commitments.1),
        MegaWitnessEntities::from_elements(witness_commitments.2),
    ];

    let accumulators = izip!(
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
    )
    .map(
        |(
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
        )| RecursiveDeciderVerificationKey {
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
        },
    )
    .collect::<Vec<_>>();

    let expected_pairing_data = [pairing_point_1, pairing_point_2]
        .into_iter()
        .flat_map(|((x0, x1), (y0, y1), z)| {
            let x0 = field_from_hex_string(x0.as_str()).unwrap();
            let x1 = field_from_hex_string(x1.as_str()).unwrap();
            let y0 = field_from_hex_string(y0.as_str()).unwrap();
            let y1 = field_from_hex_string(y1.as_str()).unwrap();
            let z = z != 0;
            [x0, x1, y0, y1, Fr::from(z as u64)]
        })
        .collect::<Vec<_>>();

    let nets_1 = LocalNetwork::new_3_parties();
    let nets_2 = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);

    for (net_1, net_2, accumulator, builder, honk_proof) in
        izip!(nets_1, nets_2, accumulators, builders, honk_proofs)
    {
        let net_1b = Box::leak(Box::new(net_1));
        let net_2b = Box::leak(Box::new(net_2));
        threads.push(std::thread::spawn(move || {
            let mut accumulator = accumulator;
            let mut builder = builder;
            let mut driver = Driver::new(net_1b, net_2b, A2BType::Direct).unwrap();

            let (p1, p2) = DeciderRecursiveVerifier::verify_proof::<_, _, Poseidon2Sponge>(
                honk_proof,
                &mut accumulator,
                &mut builder,
                &mut driver,
            )
            .unwrap();

            let result = [p1, p2]
                .into_iter()
                .flat_map(|point| {
                    [
                        point.x.limbs[0].get_value(&builder, &mut driver),
                        point.x.limbs[1].get_value(&builder, &mut driver),
                        point.y.limbs[0].get_value(&builder, &mut driver),
                        point.y.limbs[1].get_value(&builder, &mut driver),
                        point.is_infinity.get_value(&mut driver),
                    ]
                })
                .collect::<Vec<_>>();

            driver.open_many_acvm_type(&result).unwrap()
        }));
    }

    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();

    for res in results {
        assert_eq!(res, expected_pairing_data.clone());
    }
}
