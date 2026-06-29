use ark_bn254::Bn254;
use circom_mpc_compiler::CoCircomCompiler;
use circom_types::Witness;
use itertools::izip;
use mpc_core::protocols::shamir;
use mpc_net::local::LocalNetwork;
use rand::thread_rng;
use std::fs;
use std::fs::File;
use std::str::FromStr;

use circom_mpc_compiler::CompilerConfig;
use circom_mpc_vm::{
    mpc_vm::{ShamirWitnessExtension, VMConfig},
    ShamirVmType,
};

pub struct TestInputs {
    inputs: Vec<Vec<ark_bn254::Fr>>,
    witnesses: Vec<Witness<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>>,
}

fn read_field_element(s: &str) -> ark_bn254::Fr {
    if let Some(striped) = s.strip_prefix('-') {
        -ark_bn254::Fr::from_str(striped).unwrap()
    } else {
        ark_bn254::Fr::from_str(s).unwrap()
    }
}

pub fn from_test_name(fn_name: &str) -> TestInputs {
    let mut witnesses: Vec<Witness<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>> =
        Vec::new();
    let mut inputs: Vec<Vec<ark_bn254::Fr>> = Vec::new();
    let mut i = 0;
    loop {
        if fs::metadata(format!(
            "../test_vectors/WitnessExtension/kats/{fn_name}/witness{i}.wtns"
        ))
        .is_err()
        {
            break;
        }
        let witness = File::open(format!(
            "../test_vectors/WitnessExtension/kats/{fn_name}/witness{i}.wtns"
        ))
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        witnesses.push(should_witness);
        let input_file = File::open(format!(
            "../test_vectors/WitnessExtension/kats/{fn_name}/input{i}.json"
        ))
        .unwrap();
        let json_str: serde_json::Value = serde_json::from_reader(input_file).unwrap();
        let input = json_str
            .get("in")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|s| read_field_element(s.as_str().unwrap()))
            .collect::<Vec<_>>();
        inputs.push(input);
        i += 1
    }
    if inputs.is_empty() {
        panic!("No test cases found for {fn_name}");
    }
    TestInputs { inputs, witnesses }
}

macro_rules! run_test {
    ($file: expr, $input: expr, $config: expr) => {{
        use tests::test_utils;
        let mut rng = thread_rng();
        // degree=1, num_parties=3
        let inputs = shamir::share_field_elements($input, 1, 3, &mut rng);
        let nets0 = LocalNetwork::new_3_parties();
        let nets1 = LocalNetwork::new_3_parties();
        let mut threads = vec![];

        let configs = [$config.clone(), $config.clone(), $config];

        for (net0, net1, input, config) in izip!(nets0, nets1, inputs, configs) {
            threads.push(std::thread::spawn(move || {
                let mut compiler_config = config;
                compiler_config.simplification =
                    circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
                compiler_config
                    .link_library
                    .push("../test_vectors/WitnessExtension/tests/libs/".into());
                let circuit =
                    CoCircomCompiler::<Bn254>::parse($file.to_owned(), compiler_config).unwrap();
                // TODO we are not creating any randomness here
                let witness_extension = ShamirWitnessExtension::new(
                    &net0,
                    &net1,
                    3,
                    1,
                    0,
                    &circuit,
                    VMConfig::default(),
                )
                .unwrap();
                witness_extension
                    .run_with_flat(
                        input
                            .into_iter()
                            .map(|x| ShamirVmType::Arithmetic(x))
                            .collect(),
                        0,
                    )
                    .unwrap()
                    .into_shared_witness()
            }));
        }
        let result3 = threads.pop().unwrap().join().unwrap();
        let result2 = threads.pop().unwrap().join().unwrap();
        let result1 = threads.pop().unwrap().join().unwrap();
        test_utils::combine_field_elements_for_vm_shamir(result1, result2, result3)
    }};
}

macro_rules! witness_extension_test_shamir {
    ($name: ident) => {
        mod $name {
            use super::*;
            fn inner(config: CompilerConfig) {
                let inp: TestInputs = from_test_name(stringify!($name));
                for i in 0..inp.inputs.len() {
                    let is_witness = run_test!(
                        format!(
                            "../test_vectors/WitnessExtension/tests/{}.circom",
                            stringify!($name),
                        ),
                        &inp.inputs[i],
                        config.clone()
                    );
                    assert_eq!(is_witness, inp.witnesses[i].values);
                }
            }

            #[test]
            fn debug() {
                inner(CompilerConfig::default());
            }

            #[test]
            fn release() {
                inner(CompilerConfig::release());
            }
        }
    };
}

// Ignored due to unimplemented functionality in the Shamir witness extension.
macro_rules! witness_extension_test_shamir_ignored {
    ($name: ident) => {
        mod $name {
            use super::*;
            fn inner(config: CompilerConfig) {
                let inp: TestInputs = from_test_name(stringify!($name));
                for i in 0..inp.inputs.len() {
                    let is_witness = run_test!(
                        format!(
                            "../test_vectors/WitnessExtension/tests/{}.circom",
                            stringify!($name),
                        ),
                        &inp.inputs[i],
                        config.clone()
                    );
                    assert_eq!(is_witness, inp.witnesses[i].values);
                }
            }

            #[test]
            #[ignore]
            fn debug() {
                inner(CompilerConfig::default());
            }

            #[test]
            #[ignore]
            fn release() {
                inner(CompilerConfig::release());
            }
        }
    };
}

witness_extension_test_shamir_ignored!(aliascheck_test);
witness_extension_test_shamir_ignored!(array_equals);
witness_extension_test_shamir_ignored!(babyadd_tester);
witness_extension_test_shamir_ignored!(babycheck_test);
witness_extension_test_shamir_ignored!(babypbk_test);
witness_extension_test_shamir_ignored!(binsub_test);
witness_extension_test_shamir_ignored!(binsum_test);
witness_extension_test_shamir_ignored!(constants_test);
witness_extension_test_shamir!(control_flow);
witness_extension_test_shamir_ignored!(eddsa_test);
witness_extension_test_shamir_ignored!(eddsa_verify);
witness_extension_test_shamir_ignored!(eddsamimc_test);
witness_extension_test_shamir_ignored!(eddsaposeidon_test);
witness_extension_test_shamir_ignored!(edwards2montgomery);
witness_extension_test_shamir_ignored!(escalarmul_test);
witness_extension_test_shamir_ignored!(escalarmul_test_min);
witness_extension_test_shamir_ignored!(escalarmulany_test);
witness_extension_test_shamir_ignored!(escalarmulfix_test);
witness_extension_test_shamir!(escalarmulw4table_test);
witness_extension_test_shamir!(escalarmulw4table_test3);
witness_extension_test_shamir_ignored!(functions);
witness_extension_test_shamir_ignored!(greatereqthan);
witness_extension_test_shamir_ignored!(greaterthan);
witness_extension_test_shamir_ignored!(isequal);
witness_extension_test_shamir_ignored!(iszero);
witness_extension_test_shamir_ignored!(lesseqthan);
witness_extension_test_shamir_ignored!(lessthan);
witness_extension_test_shamir!(mimc_hasher);
witness_extension_test_shamir!(mimc_sponge_hash_test);
witness_extension_test_shamir!(mimc_sponge_test);
witness_extension_test_shamir!(mimc_test);
witness_extension_test_shamir_ignored!(montgomery2edwards);
witness_extension_test_shamir_ignored!(montgomeryadd);
witness_extension_test_shamir_ignored!(montgomerydouble);
witness_extension_test_shamir!(multiplier16);
witness_extension_test_shamir_ignored!(mux1_1);
witness_extension_test_shamir_ignored!(mux2_1);
witness_extension_test_shamir_ignored!(mux3_1);
witness_extension_test_shamir_ignored!(mux4_1);
witness_extension_test_shamir_ignored!(pedersen2_test);
witness_extension_test_shamir_ignored!(pedersen_hasher);
witness_extension_test_shamir_ignored!(pedersen_test);
witness_extension_test_shamir_ignored!(pointbits_loopback);
witness_extension_test_shamir!(poseidon3_test);
witness_extension_test_shamir!(poseidon6_test);
witness_extension_test_shamir!(poseidon_hasher1);
witness_extension_test_shamir!(poseidon_hasher16);
witness_extension_test_shamir!(poseidon_hasher2);
witness_extension_test_shamir!(poseidonex_test);
witness_extension_test_shamir_ignored!(sha256_2_test);
witness_extension_test_shamir_ignored!(sha256_test448);
witness_extension_test_shamir_ignored!(sha256_test512);
witness_extension_test_shamir_ignored!(shared_control_flow);
witness_extension_test_shamir_ignored!(shared_control_flow_arrays);
witness_extension_test_shamir_ignored!(sign_test);
witness_extension_test_shamir_ignored!(sqrt_test);
witness_extension_test_shamir_ignored!(smtprocessor10_test);
witness_extension_test_shamir_ignored!(smtverifier10_test);
witness_extension_test_shamir_ignored!(sum_test);
witness_extension_test_shamir_ignored!(winner);
witness_extension_test_shamir_ignored!(bitonic_sort);
witness_extension_test_shamir_ignored!(num2bits_accelerator);
witness_extension_test_shamir_ignored!(reclaim_addbits_accelerator);
