use std::collections::BTreeMap;

use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_mpc_vm::{
    mpc_vm::{BatchedRep3WitnessExtension, VMConfig},
    BatchedRep3VmType,
};
use co_circom_types::{BatchedRep3SharedInput, Rep3InputType};
use co_noir::Bn254;
use itertools::izip;
use mpc_core::protocols::rep3;
use mpc_net::local::LocalNetwork;
use rand::{thread_rng, Rng as _};
use tests::test_utils::{self};

#[test]
fn batched_add_1() -> eyre::Result<()> {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let add_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/multiplier2.circom");

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&add_circuit, compiler_config)?;
    let num_public_inputs = parsed.public_inputs().len();

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();

    let batch_size = 1;
    let mut rng = thread_rng();
    let mut batch = vec![BatchedRep3SharedInput::default(); 3];
    let mut should_witness = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let mut plain_input = BTreeMap::new();

        let a = rng.gen::<ark_bn254::Fr>();
        let b = rng.gen::<ark_bn254::Fr>();
        let [a0, a1, a2] = rep3::share_field_element(a, &mut rng).map(Rep3InputType::Shared);
        let [b0, b1, b2] = rep3::share_field_element(b, &mut rng).map(Rep3InputType::Shared);
        batch[0].entry("a".to_string()).or_default().push(a0);
        batch[1].entry("a".to_string()).or_default().push(a1);
        batch[2].entry("a".to_string()).or_default().push(a2);
        batch[0].entry("b".to_string()).or_default().push(b0);
        batch[1].entry("b".to_string()).or_default().push(b1);
        batch[2].entry("b".to_string()).or_default().push(b2);

        plain_input.insert("a".to_string(), a);
        plain_input.insert("b".to_string(), b);

        let parsed = parsed.clone();
        let current_wtns = parsed
            .to_plain_vm(VMConfig::default())
            .run(plain_input, num_public_inputs)?
            .into_shared_witness();
        should_witness.push(current_wtns);
    }

    let compiler = [parsed.clone(), parsed.clone(), parsed];

    let mut threads = vec![];
    for (net0, net1, input, parsed) in izip!(nets0, nets1, batch, compiler) {
        threads.push(std::thread::spawn(move || {
            let witness_extension = BatchedRep3WitnessExtension::new(
                &net0,
                &net1,
                &parsed,
                VMConfig::default(),
                batch_size,
            )
            .unwrap();
            let input = input
                .into_iter()
                .map(|(name, vale)| {
                    (
                        name,
                        BatchedRep3VmType::<ark_bn254::Fr>::try_from(vale).unwrap(),
                    )
                })
                .collect();
            witness_extension
                .run(input, num_public_inputs)
                .unwrap()
                .into_shared_witness()
                .unbatch()
        }));
    }
    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();

    assert_eq!(result3.len(), should_witness.len());
    assert_eq!(result2.len(), should_witness.len());
    assert_eq!(result1.len(), should_witness.len());
    for (result1, result2, result3, should_shared_witness) in
        izip!(result1, result2, result3, should_witness)
    {
        let is_witness = test_utils::combine_field_elements_for_vm(result1, result2, result3);

        let mut should_witness = Vec::with_capacity(is_witness.len());
        should_witness.extend(should_shared_witness.public_inputs);
        should_witness.extend(should_shared_witness.witness);
        assert_eq!(is_witness, should_witness);
    }

    Ok(())
}

#[test]
fn batched_add_100() -> eyre::Result<()> {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let add_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/multiplier2.circom");

    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let parsed = CoCircomCompiler::<Bn254>::parse(&add_circuit, compiler_config)?;
    let num_public_inputs = parsed.public_inputs().len();

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();

    let batch_size = 100;
    let mut rng = thread_rng();
    let mut batch = vec![BatchedRep3SharedInput::default(); 3];
    let mut should_witness = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let mut plain_input = BTreeMap::new();

        let a = rng.gen::<ark_bn254::Fr>();
        let b = rng.gen::<ark_bn254::Fr>();
        let [a0, a1, a2] = rep3::share_field_element(a, &mut rng).map(Rep3InputType::Shared);
        let [b0, b1, b2] = rep3::share_field_element(b, &mut rng).map(Rep3InputType::Shared);
        batch[0].entry("a".to_string()).or_default().push(a0);
        batch[1].entry("a".to_string()).or_default().push(a1);
        batch[2].entry("a".to_string()).or_default().push(a2);
        batch[0].entry("b".to_string()).or_default().push(b0);
        batch[1].entry("b".to_string()).or_default().push(b1);
        batch[2].entry("b".to_string()).or_default().push(b2);

        plain_input.insert("a".to_string(), a);
        plain_input.insert("b".to_string(), b);

        let parsed = parsed.clone();
        let current_wtns = parsed
            .to_plain_vm(VMConfig::default())
            .run(plain_input, num_public_inputs)?
            .into_shared_witness();
        should_witness.push(current_wtns);
    }

    let compiler = [parsed.clone(), parsed.clone(), parsed];

    let mut threads = vec![];
    for (net0, net1, input, parsed) in izip!(nets0, nets1, batch, compiler) {
        threads.push(std::thread::spawn(move || {
            let witness_extension = BatchedRep3WitnessExtension::new(
                &net0,
                &net1,
                &parsed,
                VMConfig::default(),
                batch_size,
            )
            .unwrap();
            let input = input
                .into_iter()
                .map(|(name, vale)| {
                    (
                        name,
                        BatchedRep3VmType::<ark_bn254::Fr>::try_from(vale).unwrap(),
                    )
                })
                .collect();
            witness_extension
                .run(input, num_public_inputs)
                .unwrap()
                .into_shared_witness()
                .unbatch()
        }));
    }
    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();

    assert_eq!(result3.len(), should_witness.len());
    assert_eq!(result2.len(), should_witness.len());
    assert_eq!(result1.len(), should_witness.len());
    for (result1, result2, result3, should_shared_witness) in
        izip!(result1, result2, result3, should_witness)
    {
        let is_witness = test_utils::combine_field_elements_for_vm(result1, result2, result3);

        let mut should_witness = Vec::with_capacity(is_witness.len());
        should_witness.extend(should_shared_witness.public_inputs);
        should_witness.extend(should_shared_witness.witness);
        assert_eq!(is_witness, should_witness);
    }

    Ok(())
}

// #[test]
// fn batched_chacha20_1() -> eyre::Result<()> {
//     let root = std::env!("CARGO_MANIFEST_DIR");
//     let chacha_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/chacha20.circom");
//     let input = format!("{root}/../test_vectors/WitnessExtension/kats/chacha20/input0.json");

//     let mut compiler_config = CompilerConfig::new();
//     compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
//     let parsed = CoCircomCompiler::<Bn254>::parse(&chacha_circuit, compiler_config.clone())?;

//     let public_inputs =
//         CoCircomCompiler::<Bn254>::get_public_inputs(&chacha_circuit, compiler_config).unwrap();

//     let nets0 = LocalNetwork::new_3_parties();
//     let nets1 = LocalNetwork::new_3_parties();

//     let batch_size = 1;
//     let mut rng = thread_rng();
//     let input_file = BufReader::new(File::open(input)?);
//     let input_json: serde_json::Map<String, serde_json::Value> =
//         serde_json::from_reader(input_file).unwrap();
//     let mut plain_input = SharedInput::default();
//     let mut shared_input_0 = SharedInput::default();
//     let mut shared_input_1 = SharedInput::default();
//     let mut shared_input_2 = SharedInput::default();
//     for (k, v) in input_json {
//         let parsed_vals = if v.is_array() {
//             test_utils::parse_array::<ark_bn254::Fr>(&v).unwrap()
//         } else {
//             vec![test_utils::parse_field::<ark_bn254::Fr>(&v).unwrap()]
//         };
//         if public_inputs.contains(&k) {
//             plain_input.add_public_input(k.clone(), parsed_vals.clone());
//             shared_input_0.add_public_input(k.clone(), parsed_vals.clone());
//             shared_input_1.add_public_input(k.clone(), parsed_vals.clone());
//             shared_input_2.add_public_input(k.clone(), parsed_vals);
//         } else {
//             let [share0, share1, share2] = rep3::share_field_elements(&parsed_vals, &mut rng);
//             plain_input.add_shared_input(k.clone(), parsed_vals);
//             shared_input_0.add_shared_input(k.clone(), share0);
//             shared_input_1.add_shared_input(k.clone(), share1);
//             shared_input_2.add_shared_input(k.clone(), share2);
//         }
//     }
//     let batch = [
//         vec![shared_input_0; batch_size],
//         vec![shared_input_1; batch_size],
//         vec![shared_input_2; batch_size],
//     ];

//     let should_plain_witness = parsed
//         .clone()
//         .to_plain_vm(VMConfig::default())
//         .run(plain_input.clone())?
//         .into_shared_witness();

//     let mut should_witness = vec![];
//     should_witness.extend(should_plain_witness.public_inputs);
//     should_witness.extend(should_plain_witness.witness);

//     let compiler = [parsed.clone(), parsed.clone(), parsed];

//     let mut threads = vec![];
//     for (net0, net1, input, parsed) in izip!(nets0, nets1, batch, compiler) {
//         threads.push(std::thread::spawn(move || {
//             let witness_extension = BatchedRep3WitnessExtension::new(
//                 &net0,
//                 &net1,
//                 &parsed,
//                 VMConfig::default(),
//                 batch_size,
//             )
//             .unwrap();
//             witness_extension
//                 .run(BatchedSharedInput::try_from(input).unwrap())
//                 .unwrap()
//                 .into_shared_witness()
//                 .unbatch()
//         }));
//     }
//     let result3 = threads.pop().unwrap().join().unwrap();
//     let result2 = threads.pop().unwrap().join().unwrap();
//     let result1 = threads.pop().unwrap().join().unwrap();

//     assert_eq!(result3.len(), batch_size);
//     assert_eq!(result2.len(), batch_size);
//     assert_eq!(result1.len(), batch_size);
//     for (result1, result2, result3) in izip!(result1, result2, result3) {
//         let is_witness = test_utils::combine_field_elements_for_vm(result1, result2, result3);
//         assert_eq!(is_witness, should_witness);
//     }

//     Ok(())
// }

// #[test]
// fn batched_chacha20_30() -> eyre::Result<()> {
//     let root = std::env!("CARGO_MANIFEST_DIR");
//     let chacha_circuit = format!("{root}/../test_vectors/WitnessExtension/tests/chacha20.circom");
//     let input = format!("{root}/../test_vectors/WitnessExtension/kats/chacha20/input0.json");

//     let mut compiler_config = CompilerConfig::new();
//     compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
//     let parsed = CoCircomCompiler::<Bn254>::parse(&chacha_circuit, compiler_config.clone())?;

//     let public_inputs =
//         CoCircomCompiler::<Bn254>::get_public_inputs(&chacha_circuit, compiler_config).unwrap();

//     let nets0 = LocalNetwork::new_3_parties();
//     let nets1 = LocalNetwork::new_3_parties();

//     let batch_size = 30;
//     let mut rng = thread_rng();
//     let input_file = BufReader::new(File::open(input)?);
//     let input_json: serde_json::Map<String, serde_json::Value> =
//         serde_json::from_reader(input_file).unwrap();
//     let mut plain_input = SharedInput::default();
//     let mut shared_input_0 = SharedInput::default();
//     let mut shared_input_1 = SharedInput::default();
//     let mut shared_input_2 = SharedInput::default();
//     for (k, v) in input_json {
//         let parsed_vals = if v.is_array() {
//             test_utils::parse_array::<ark_bn254::Fr>(&v).unwrap()
//         } else {
//             vec![test_utils::parse_field::<ark_bn254::Fr>(&v).unwrap()]
//         };
//         if public_inputs.contains(&k) {
//             plain_input.add_public_input(k.clone(), parsed_vals.clone());
//             shared_input_0.add_public_input(k.clone(), parsed_vals.clone());
//             shared_input_1.add_public_input(k.clone(), parsed_vals.clone());
//             shared_input_2.add_public_input(k.clone(), parsed_vals);
//         } else {
//             let [share0, share1, share2] = rep3::share_field_elements(&parsed_vals, &mut rng);
//             plain_input.add_shared_input(k.clone(), parsed_vals);
//             shared_input_0.add_shared_input(k.clone(), share0);
//             shared_input_1.add_shared_input(k.clone(), share1);
//             shared_input_2.add_shared_input(k.clone(), share2);
//         }
//     }
//     let batch = [
//         vec![shared_input_0; batch_size],
//         vec![shared_input_1; batch_size],
//         vec![shared_input_2; batch_size],
//     ];

//     let should_plain_witness = parsed
//         .clone()
//         .to_plain_vm(VMConfig::default())
//         .run(plain_input.clone())?
//         .into_shared_witness();

//     let mut should_witness = vec![];
//     should_witness.extend(should_plain_witness.public_inputs);
//     should_witness.extend(should_plain_witness.witness);

//     let compiler = [parsed.clone(), parsed.clone(), parsed];

//     let mut threads = vec![];
//     for (net0, net1, input, parsed) in izip!(nets0, nets1, batch, compiler) {
//         threads.push(std::thread::spawn(move || {
//             let witness_extension = BatchedRep3WitnessExtension::new(
//                 &net0,
//                 &net1,
//                 &parsed,
//                 VMConfig::default(),
//                 batch_size,
//             )
//             .unwrap();
//             witness_extension
//                 .run(BatchedSharedInput::try_from(input).unwrap())
//                 .unwrap()
//                 .into_shared_witness()
//                 .unbatch()
//         }));
//     }
//     let result3 = threads.pop().unwrap().join().unwrap();
//     let result2 = threads.pop().unwrap().join().unwrap();
//     let result1 = threads.pop().unwrap().join().unwrap();

//     assert_eq!(result3.len(), batch_size);
//     assert_eq!(result2.len(), batch_size);
//     assert_eq!(result1.len(), batch_size);
//     for (result1, result2, result3) in izip!(result1, result2, result3) {
//         let is_witness = test_utils::combine_field_elements_for_vm(result1, result2, result3);
//         assert_eq!(is_witness, should_witness);
//     }

//     Ok(())
// }
