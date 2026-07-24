use ark_bn254::Bn254;
use circom_mpc_compiler2::CoCircomCompiler as CoCircomCompiler2;
use circom_mpc_compiler2::CompilerConfig;
use circom_mpc_vm2::api::Rep3WitnessExtension;
use circom_mpc_vm2::drivers::rep3::Rep3VmType;
use circom_mpc_vm2::program::{InputInfo, VMConfig};
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
    inputs: Vec<serde_json::Value>,
    witnesses: Vec<Witness<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>>,
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
/// natural read order for a circom array signal serialized to JSON. Kept in sync with
/// `plain_vm2.rs`'s copy (this file doesn't share helpers with it -- see that file's
/// `flatten_field` for the same doc comment).
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

/// Builds the flat `Vec<Fr>` [`rep3::share_field_elements`] expects from a KAT
/// `input<i>.json`. See `plain_vm2.rs`'s `build_flat_input` for the full rationale (this
/// file doesn't share helpers with it, so the doc lives there): a single-key JSON object
/// is already pre-flattened in `main_input_list` order; a multi-key one (e.g.
/// `chacha20`'s `key`/`nonce`/`counter`/`in`) is reassembled by looking each signal name
/// up in `main_input_list`, which is offset-ordered.
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

/// Compiles `circuit_file` once (outside the 3-party threads `run_test!` spawns) purely
/// to read off [`CompiledProgram::main_input_list`], then builds the flat `Vec<Fr>`
/// `run_test!` shares across parties (see `build_flat_input`'s docs). Secret-sharing
/// (`rep3::share_field_elements`) needs the plain flat vector *before* any party's own
/// compile happens, so unlike `plain_vm2.rs` (one compile per case) this necessarily
/// compiles twice -- once here, once (per party) inside `run_test!` -- both from the same
/// `config`, so both agree on the layout.
fn probe_and_flatten(
    circuit_file: &str,
    config: &CompilerConfig,
    json: &serde_json::Value,
) -> Vec<ark_bn254::Fr> {
    let mut probe_config = config.clone();
    probe_config.simplification = circom_mpc_compiler2::SimplificationLevel::O2(usize::MAX);
    probe_config
        .link_library
        .push("../test_vectors/WitnessExtension/tests/libs/".into());
    let probe = CoCircomCompiler2::<Bn254>::parse(circuit_file.to_owned(), probe_config).unwrap();
    build_flat_input(json, &probe.main_input_list)
}

macro_rules! witness_extension_test_rep3_vm2 {
    ($name: ident) => {
        mod $name {
            use super::*;
            fn inner(config: CompilerConfig) {
                let inp: TestInputs = from_test_name(stringify!($name));
                for i in 0..inp.inputs.len() {
                    let file = format!(
                        "../test_vectors/WitnessExtension/tests/{}.circom",
                        stringify!($name),
                    );
                    let flat_input = probe_and_flatten(&file, &config, &inp.inputs[i]);
                    let is_witness = run_test!(
                        format!(
                            "../test_vectors/WitnessExtension/tests/{}.circom",
                            stringify!($name),
                        ),
                        &flat_input,
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
                    let file = format!(
                        "../test_vectors/WitnessExtension/tests/{}.circom",
                        stringify!($name),
                    );
                    let flat_input = probe_and_flatten(&file, &config, &inp.inputs[i]);
                    let is_witness = run_test!(
                        format!(
                            "../test_vectors/WitnessExtension/tests/{}.circom",
                            stringify!($name),
                        ),
                        &flat_input,
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
