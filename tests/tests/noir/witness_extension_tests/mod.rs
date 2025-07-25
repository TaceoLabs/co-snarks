use acir::native_types::{WitnessMap, WitnessStack};
use ark_ff::PrimeField;
use co_acvm::Rep3AcvmType;
use itertools::izip;

mod plain_solver;
mod rep3;

macro_rules! add_plain_acvm_test {
        ($name: expr) => {
            paste::item! {
                #[test]
                fn [< test_plain_ $name >]() {
                    let program = std::fs::read_to_string(format!(
                        "../test_vectors/noir/{}/kat/{}.json",
                    $name, $name))
                    .unwrap();
                    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
                        .expect("failed to parse program artifact");
                    let should_witness =
                        std::fs::read(format!("../test_vectors/noir/{}/kat/{}.gz", $name, $name)).unwrap();
                    let should_witness =
                        WitnessStack::<FieldElement>::try_from(should_witness.as_slice()).unwrap();
                    let prover_toml = format!("../test_vectors/noir/{}/Prover.toml", $name);
                    let solver =
                        PlainCoSolver::init_plain_driver(program_artifact, prover_toml).unwrap();
                    let is_witness = solver.solve().unwrap();
                    let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
                    assert_eq!(is_witness, should_witness);
                }
            }
        };
    }

macro_rules! add_rep3_acvm_test {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_rep3_ $name >]() {
                let root = std::env!("CARGO_MANIFEST_DIR");
                let program = std::fs::read_to_string(format!(
                    "{root}/../test_vectors/noir/{}/kat/{}.json",
                    $name, $name
                ))
                .unwrap();
                let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
                    .expect("failed to parse program artifact");

                let should_witness =
                    std::fs::read(format!("{root}/../test_vectors/noir/{}/kat/{}.gz", $name, $name)).unwrap();

                let should_witness =
                    WitnessStack::<FieldElement>::try_from(should_witness.as_slice()).unwrap();
                let input = PathBuf::from(format!(
                    "{root}/../test_vectors/noir/{}/Prover.toml",
                    $name
                ));
                // read the input file
                let inputs = Rep3CoSolver::<_, ()>::partially_read_abi_bn254_fieldelement(
                    &input,
                    &program_artifact.abi,
                    &program_artifact.bytecode,
                ).expect("can share field elements for noir witness extension");

                // create input shares
                let mut rng = rand::thread_rng();
                let shares = co_noir::split_input_rep3::<Bn254, _>(inputs, &mut rng);
                let nets0 = LocalNetwork::new_3_parties();
                let nets1 = LocalNetwork::new_3_parties();
                let mut threads = vec![];
                for (net0, net1, program_artifact, share) in izip!(
                    nets0,
                    nets1,
                    [
                        program_artifact.clone(),
                        program_artifact.clone(),
                        program_artifact
                    ],
                    shares
                ) {
                    threads.push(std::thread::spawn(move || {
                        let input_share = co_noir::witness_to_witness_map(share, &program_artifact.abi).expect("can translate witness for noir witness extension");
                        let solver =
                            Rep3CoSolver::new_with_witness(&net0, &net1, program_artifact, input_share).unwrap();
                        let proof = solver.solve().unwrap();
                        proof
                    }));
                }

                let result3 = threads.pop().unwrap().join().unwrap();
                let result2 = threads.pop().unwrap().join().unwrap();
                let result1 = threads.pop().unwrap().join().unwrap();
                let is_witness = super::combine_field_elements_for_acvm(result1, result2, result3);
                let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
                assert_eq!(should_witness, is_witness)
            }
        }
    };
}

fn combine_field_elements_for_acvm<F: PrimeField>(
    mut a: WitnessStack<Rep3AcvmType<F>>,
    mut b: WitnessStack<Rep3AcvmType<F>>,
    mut c: WitnessStack<Rep3AcvmType<F>>,
) -> WitnessStack<F> {
    let mut res = WitnessStack::default();
    assert_eq!(a.length(), b.length());
    assert_eq!(b.length(), c.length());
    while let Some(stack_item_a) = a.pop() {
        let stack_item_b = b.pop().unwrap();
        let stack_item_c = c.pop().unwrap();
        assert_eq!(stack_item_a.index, stack_item_b.index);
        assert_eq!(stack_item_b.index, stack_item_c.index);
        let mut witness_map = WitnessMap::default();
        for ((witness_a, share_a), (witness_b, share_b), (witness_c, share_c)) in izip!(
            stack_item_a.witness.into_iter(),
            stack_item_b.witness.into_iter(),
            stack_item_c.witness.into_iter()
        ) {
            assert_eq!(witness_a, witness_b);
            assert_eq!(witness_b, witness_c);
            let reconstructed = match (share_a, share_b, share_c) {
                (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b), Rep3AcvmType::Public(c)) => {
                    if a == b && b == c {
                        a
                    } else {
                        panic!("must be all public")
                    }
                }
                (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b), Rep3AcvmType::Shared(c)) => {
                    mpc_core::protocols::rep3::combine_field_element(a, b, c)
                }
                _ => unimplemented!(),
            };
            witness_map.insert(witness_a, reconstructed);
        }
        res.push(stack_item_a.index, witness_map);
    }
    res
}

use add_plain_acvm_test;
use add_rep3_acvm_test;
