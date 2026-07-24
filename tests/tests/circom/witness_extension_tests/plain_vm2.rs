use ark_bn254::Bn254;
use circom_mpc_compiler2::CoCircomCompiler as CoCircomCompiler2;
use circom_mpc_compiler2::CompilerConfig;
use circom_mpc_vm2::api::PlainWitnessExtension;
use circom_mpc_vm2::program::{InputInfo, VMConfig};
use circom_types::Witness;
use co_circom_types::SharedWitness;
use std::sync::Arc;
use std::{
    fs::{self, File},
    str::FromStr,
};

pub struct TestInputs {
    inputs: Vec<serde_json::Value>,
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

/// Recursively flattens a KAT input field's JSON value (a string, or an array nested to
/// any depth) into `out`, row-major (outermost array dimension varies slowest) -- the
/// natural read order for a circom array signal serialized to JSON.
fn flatten_field(v: &serde_json::Value, out: &mut Vec<ark_bn254::Fr>) {
    match v {
        serde_json::Value::Array(items) => {
            for item in items {
                flatten_field(item, out);
            }
        }
        serde_json::Value::String(s) => out.push(read_field_element(s)),
        other => panic!("unexpected JSON value in KAT input: {other:?}"),
    }
}

/// Builds the flat `Vec<Fr>` `PlainWitnessExtension::run_with_flat` expects from a KAT
/// `input<i>.json`.
///
/// Every KAT this suite ran before Task 7 wraps its whole input under a single top-level
/// key (conventionally `"in"`, regardless of the circuit's own signal names) whose value
/// is already the correct flat concatenation for [`CompiledProgram::main_input_list`]'s
/// order -- `flatten_field` still recurses through it in case of nesting, but no
/// name-based reassembly is needed. A KAT whose JSON instead has one top-level key per
/// *actual* signal name (as `chacha20`'s does: `key`/`nonce`/`counter`/`in`) carries no
/// such pre-assembled order, and that order is not alphabetical, JSON-source, or
/// declaration order here (confirmed empirically for `chacha20`) -- so this looks each
/// name up in `main_input_list` (already offset-ordered) and concatenates in that order
/// instead.
fn build_flat_input(json: &serde_json::Value, main_input_list: &[InputInfo]) -> Vec<ark_bn254::Fr> {
    let obj = json.as_object().expect("KAT input JSON must be an object");
    let mut out = Vec::new();
    if obj.len() == 1 {
        flatten_field(obj.values().next().unwrap(), &mut out);
    } else {
        for info in main_input_list {
            let field = obj
                .get(&info.name)
                .unwrap_or_else(|| panic!("KAT input JSON missing field {:?}", info.name));
            let before = out.len();
            flatten_field(field, &mut out);
            assert_eq!(
                out.len() - before,
                info.size,
                "field {:?} flattened to the wrong number of field elements",
                info.name
            );
        }
    }
    out
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

                    let flat_input = build_flat_input(&inp.inputs[i], &parsed.main_input_list);
                    let is_witness =
                        PlainWitnessExtension::new_plain(Arc::new(parsed), VMConfig::default())
                            .run_with_flat(flat_input, 0)
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
    let mut inputs: Vec<serde_json::Value> = Vec::new();
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
        inputs.push(json_str);
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
// Bonus coverage beyond the old plain-VM suite's parity set (see `build_flat_input`'s
// docs above): the old suite never ran `chacha20` at all -- it has a KAT dir, but its
// `input0.json` needs the multi-key reassembly `build_flat_input` added for Task 7.
witness_extension_test_plain2!(chacha20);
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
