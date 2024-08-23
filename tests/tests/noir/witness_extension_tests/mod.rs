use acir::{
    native_types::{WitnessMap, WitnessStack},
    FieldElement,
};
use itertools::izip;
use mpc_core::protocols::rep3::acvm_impl::Rep3AcvmType;

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
                let program = std::fs::read_to_string(format!(
                    "../test_vectors/noir/{}/kat/{}.json",
                    $name, $name
                ))
                .unwrap();
                let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
                    .expect("failed to parse program artifact");

                let should_witness =
                    std::fs::read(format!("../test_vectors/noir/{}/kat/{}.gz", $name, $name)).unwrap();

                let should_witness =
                    WitnessStack::<FieldElement>::try_from(should_witness.as_slice()).unwrap();
                let prover_toml = format!("../test_vectors/noir/{}/Prover.toml", $name);
                let test_network = Rep3TestNetwork::default();
                let mut threads = vec![];
                for (net, program_artifact, prover_toml) in izip!(
                    test_network.get_party_networks(),
                    [
                        program_artifact.clone(),
                        program_artifact.clone(),
                        program_artifact
                    ],
                    [prover_toml.clone(), prover_toml.clone(), prover_toml]
                ) {
                    threads.push(thread::spawn(move || {
                        let solver =
                            Rep3CoSolver::from_network(net, program_artifact, prover_toml).unwrap();
                        solver.solve()
                    }));
                }

                let result3 = threads.pop().unwrap().join().unwrap().unwrap();
                let result2 = threads.pop().unwrap().join().unwrap().unwrap();
                let result1 = threads.pop().unwrap().join().unwrap().unwrap();
                let is_witness = super::combine_field_elements_for_vm(result1, result2, result3);
                assert_eq!(should_witness, is_witness)
            }
        }
    };
}
fn combine_field_elements_for_vm(
    mut a: WitnessStack<Rep3AcvmType<FieldElement>>,
    mut b: WitnessStack<Rep3AcvmType<FieldElement>>,
    mut c: WitnessStack<Rep3AcvmType<FieldElement>>,
) -> WitnessStack<FieldElement> {
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
            let test = Rep3AcvmType::combine_elements(share_a, share_b, share_c).unwrap();
            witness_map.insert(witness_a, test);
        }
        res.push(stack_item_a.index, witness_map);
    }
    res
}

use add_plain_acvm_test;
use add_rep3_acvm_test;
