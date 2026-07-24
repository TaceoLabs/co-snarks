use ark_bn254::Bn254;
use circom_mpc_compiler2::CoCircomCompiler as CoCircomCompiler2;
use circom_mpc_compiler2::CompilerConfig;
use circom_mpc_vm2::api::Rep3WitnessExtension;
use circom_mpc_vm2::drivers::rep3::Rep3VmType;
use circom_mpc_vm2::program::VMConfig;
use circom_types::Witness;
use itertools::izip;
use mpc_core::protocols::rep3::{self};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;
use std::fs;
use std::fs::File;
use std::str::FromStr;
use std::sync::Arc;

#[expect(dead_code)]
fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let fmt_layer = fmt::layer().with_target(true).with_line_number(true);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

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
        //install_tracing();
        let mut rng = thread_rng();
        let inputs = rep3::share_field_elements($input, &mut rng);
        let nets0 = LocalNetwork::new_3_parties();
        let nets1 = LocalNetwork::new_3_parties();
        let mut threads = vec![];

        let configs = [$config.clone(), $config.clone(), $config];

        for (net0, net1, input, config) in izip!(nets0, nets1, inputs, configs) {
            threads.push(std::thread::spawn(move || {
                let mut compiler_config = config;
                compiler_config.simplification =
                    circom_mpc_compiler2::SimplificationLevel::O2(usize::MAX);
                compiler_config
                    .link_library
                    .push("../test_vectors/WitnessExtension/tests/libs/".into());
                let circuit =
                    CoCircomCompiler2::<Bn254>::parse($file.to_owned(), compiler_config).unwrap();
                let witness_extension = Rep3WitnessExtension::new_rep3(
                    &net0,
                    &net1,
                    Arc::new(circuit),
                    VMConfig::default(),
                )
                .unwrap();
                witness_extension
                    .run_with_flat(
                        input
                            .into_iter()
                            .map(|x| Rep3VmType::Arithmetic(x))
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
        test_utils::combine_field_elements_for_vm(result1, result2, result3)
    }};
}

macro_rules! witness_extension_test_rep3_vm2 {
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
macro_rules! witness_extension_test_rep3_vm2_ignored {
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

// Priority four (least-tested shared-execution seams) first.
witness_extension_test_rep3_vm2!(shared_control_flow);
witness_extension_test_rep3_vm2!(shared_control_flow_arrays);
witness_extension_test_rep3_vm2!(functions);
witness_extension_test_rep3_vm2!(sqrt_test);

witness_extension_test_rep3_vm2!(aliascheck_test);
witness_extension_test_rep3_vm2!(array_equals);
witness_extension_test_rep3_vm2!(babyadd_tester);
witness_extension_test_rep3_vm2!(babycheck_test);
witness_extension_test_rep3_vm2!(babypbk_test);
witness_extension_test_rep3_vm2!(binsub_test);
witness_extension_test_rep3_vm2!(binsum_test);
witness_extension_test_rep3_vm2!(constants_test);
witness_extension_test_rep3_vm2!(control_flow);
witness_extension_test_rep3_vm2_ignored!(eddsa_test);
witness_extension_test_rep3_vm2_ignored!(eddsa_verify);
witness_extension_test_rep3_vm2_ignored!(eddsamimc_test);
witness_extension_test_rep3_vm2_ignored!(eddsaposeidon_test);
witness_extension_test_rep3_vm2!(edwards2montgomery);
witness_extension_test_rep3_vm2!(escalarmul_test);
witness_extension_test_rep3_vm2!(escalarmul_test_min);
witness_extension_test_rep3_vm2!(escalarmulany_test);
witness_extension_test_rep3_vm2_ignored!(escalarmulfix_test);
witness_extension_test_rep3_vm2!(escalarmulw4table_test);
witness_extension_test_rep3_vm2!(escalarmulw4table_test3);
witness_extension_test_rep3_vm2!(greatereqthan);
witness_extension_test_rep3_vm2!(greaterthan);
witness_extension_test_rep3_vm2!(isequal);
witness_extension_test_rep3_vm2!(iszero);
witness_extension_test_rep3_vm2!(lesseqthan);
witness_extension_test_rep3_vm2!(lessthan);
witness_extension_test_rep3_vm2!(mimc_hasher);
witness_extension_test_rep3_vm2!(mimc_sponge_hash_test);
witness_extension_test_rep3_vm2!(mimc_sponge_test);
witness_extension_test_rep3_vm2!(mimc_test);
witness_extension_test_rep3_vm2!(montgomery2edwards);
witness_extension_test_rep3_vm2!(montgomeryadd);
witness_extension_test_rep3_vm2!(montgomerydouble);
witness_extension_test_rep3_vm2!(multiplier16);
witness_extension_test_rep3_vm2!(mux1_1);
witness_extension_test_rep3_vm2!(mux2_1);
witness_extension_test_rep3_vm2!(mux3_1);
witness_extension_test_rep3_vm2!(mux4_1);
witness_extension_test_rep3_vm2_ignored!(pedersen2_test);
witness_extension_test_rep3_vm2!(pedersen_hasher);
witness_extension_test_rep3_vm2_ignored!(pedersen_test);
witness_extension_test_rep3_vm2!(pointbits_loopback);
witness_extension_test_rep3_vm2!(poseidon3_test);
witness_extension_test_rep3_vm2!(poseidon6_test);
witness_extension_test_rep3_vm2!(poseidon_hasher1);
witness_extension_test_rep3_vm2!(poseidon_hasher16);
witness_extension_test_rep3_vm2!(poseidon_hasher2);
witness_extension_test_rep3_vm2!(poseidonex_test);
witness_extension_test_rep3_vm2_ignored!(sha256_2_test);
witness_extension_test_rep3_vm2_ignored!(sha256_test448);
witness_extension_test_rep3_vm2_ignored!(sha256_test512);
witness_extension_test_rep3_vm2!(sign_test);
witness_extension_test_rep3_vm2!(smtprocessor10_test);
witness_extension_test_rep3_vm2!(smtverifier10_test);
witness_extension_test_rep3_vm2!(sum_test);
witness_extension_test_rep3_vm2!(winner);
witness_extension_test_rep3_vm2!(bitonic_sort);
witness_extension_test_rep3_vm2!(num2bits_accelerator);
witness_extension_test_rep3_vm2!(reclaim_addbits_accelerator);
