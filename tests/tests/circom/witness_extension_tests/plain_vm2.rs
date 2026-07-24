use ark_bn254::Bn254;
use circom_mpc_compiler2::CoCircomCompiler as CoCircomCompiler2;
use circom_mpc_compiler2::CompilerConfig;
use circom_mpc_vm2::api::PlainWitnessExtension;
use circom_mpc_vm2::program::VMConfig;
use circom_types::Witness;
use co_circom_types::SharedWitness;
use std::sync::Arc;
use std::{
    fs::{self, File},
    str::FromStr,
};

pub struct TestInputs {
    inputs: Vec<Vec<ark_bn254::Fr>>,
    witnesses: Vec<Witness<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>>,
}

fn convert_witness(mut witness: SharedWitness<ark_bn254::Fr, ark_bn254::Fr>) -> Vec<ark_bn254::Fr> {
    witness.public_inputs.extend(witness.witness);
    witness.public_inputs
}

fn read_field_element(s: &str) -> ark_bn254::Fr {
    if let Some(striped) = s.strip_prefix('-') {
        -ark_bn254::Fr::from_str(striped).unwrap()
    } else {
        ark_bn254::Fr::from_str(s).unwrap()
    }
}

macro_rules! witness_extension_test_plain2 {
    ($name:ident) => {
        mod $name {
            use super::*;
            fn inner(config: CompilerConfig) {
                let inp: TestInputs = from_test_name(stringify!($name));
                for i in 0..inp.inputs.len() {
                    let mut compiler_config = config.clone();
                    compiler_config.simplification =
                        circom_mpc_compiler2::SimplificationLevel::O2(usize::MAX);
                    compiler_config
                        .link_library
                        .push("../test_vectors/WitnessExtension/tests/libs/".into());

                    let parsed = CoCircomCompiler2::<Bn254>::parse(
                        format!(
                            "../test_vectors/WitnessExtension/tests/{}.circom",
                            stringify!($name)
                        ),
                        compiler_config,
                    )
                    .unwrap();

                    let is_witness =
                        PlainWitnessExtension::new_plain(Arc::new(parsed), VMConfig::default())
                            .run_with_flat(inp.inputs[i].to_owned(), 0)
                            .unwrap()
                            .into_shared_witness();

                    assert_eq!(convert_witness(is_witness), inp.witnesses[i].values);
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
        i += 1;
    }
    println!("i: {i}");
    TestInputs { inputs, witnesses }
}

witness_extension_test_plain2!(aliascheck_test);
witness_extension_test_plain2!(array_equals);
witness_extension_test_plain2!(babyadd_tester);
witness_extension_test_plain2!(babycheck_test);
witness_extension_test_plain2!(babypbk_test);
witness_extension_test_plain2!(binsub_test);
witness_extension_test_plain2!(binsum_test);
witness_extension_test_plain2!(constants_test);
witness_extension_test_plain2!(control_flow);
witness_extension_test_plain2!(eddsa_test);
witness_extension_test_plain2!(eddsa_verify);
witness_extension_test_plain2!(eddsamimc_test);
witness_extension_test_plain2!(eddsaposeidon_test);
witness_extension_test_plain2!(edwards2montgomery);
witness_extension_test_plain2!(escalarmul_test);
witness_extension_test_plain2!(escalarmul_test_min);
witness_extension_test_plain2!(escalarmulany_test);
witness_extension_test_plain2!(escalarmulfix_test);
witness_extension_test_plain2!(escalarmulw4table);
witness_extension_test_plain2!(escalarmulw4table_test);
witness_extension_test_plain2!(escalarmulw4table_test3);
witness_extension_test_plain2!(functions);
witness_extension_test_plain2!(greatereqthan);
witness_extension_test_plain2!(greaterthan);
witness_extension_test_plain2!(isequal);
witness_extension_test_plain2!(iszero);
witness_extension_test_plain2!(lesseqthan);
witness_extension_test_plain2!(lessthan);
witness_extension_test_plain2!(mimc_hasher);
witness_extension_test_plain2!(mimc_sponge_hash_test);
witness_extension_test_plain2!(mimc_sponge_test);
witness_extension_test_plain2!(mimc_test);
witness_extension_test_plain2!(montgomery2edwards);
witness_extension_test_plain2!(montgomeryadd);
witness_extension_test_plain2!(montgomerydouble);
witness_extension_test_plain2!(multiplier16);
witness_extension_test_plain2!(multiplier2);
witness_extension_test_plain2!(mux1_1);
witness_extension_test_plain2!(mux2_1);
witness_extension_test_plain2!(mux3_1);
witness_extension_test_plain2!(mux4_1);
witness_extension_test_plain2!(pedersen2_test);
witness_extension_test_plain2!(pedersen_hasher);
witness_extension_test_plain2!(pedersen_test);
witness_extension_test_plain2!(pointbits_loopback);
witness_extension_test_plain2!(poseidon3_test);
witness_extension_test_plain2!(poseidon6_test);
witness_extension_test_plain2!(poseidon_hasher1);
witness_extension_test_plain2!(poseidon_hasher16);
witness_extension_test_plain2!(poseidon_hasher2);
witness_extension_test_plain2!(poseidonex_test);
witness_extension_test_plain2!(sha256_2_test);
witness_extension_test_plain2!(sha256_test448);
witness_extension_test_plain2!(sha256_test512);
witness_extension_test_plain2!(shared_control_flow);
witness_extension_test_plain2!(shared_control_flow_arrays);
witness_extension_test_plain2!(sign_test);
witness_extension_test_plain2!(sqrt_test);
witness_extension_test_plain2!(smtprocessor10_test);
witness_extension_test_plain2!(smtverifier10_test);
witness_extension_test_plain2!(sum_test);
witness_extension_test_plain2!(winner);
witness_extension_test_plain2!(bitonic_sort);
witness_extension_test_plain2!(num2bits_accelerator);
witness_extension_test_plain2!(reclaim_addbits_accelerator);
witness_extension_test_plain2!(reclaim_addbits_accelerator_small);
