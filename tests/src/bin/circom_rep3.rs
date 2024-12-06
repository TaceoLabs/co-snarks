use std::{collections::BTreeMap, thread};

use ark_bn254::Bn254;
use ark_ff::PrimeField;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_mpc_vm::mpc_vm::VMConfig;
use co_circom::SeedRng;
use co_circom_snarks::{SerializeableSharedRep3Input, SharedInput};
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3ShareVecType};
use tests::rep3_network::Rep3TestNetwork;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_line_number(false)
        .with_timer(());
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}
fn main() {
    install_tracing();
    let circuit_path = "/home/fnieddu/tmp/secret-santa.circom";
    let input_path =
        "/home/fnieddu/repos/co-snarks-mpc-net/csn-dev-setup/circuits/secret-santa/input0.json";

    let mut compiler_config = CompilerConfig::default();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);

    let shares = co_circom::split_input::<Bn254>(
        input_path.into(),
        circuit_path.into(),
        compiler_config,
        false,
        false,
    )
    .unwrap();

    let test_network = Rep3TestNetwork::default();
    let mut threads = vec![];
    for (net, x) in itertools::izip!(test_network.get_party_networks(), shares.into_iter(),) {
        threads.push(thread::spawn(move || {
            let mut compiler_config = CompilerConfig::default();
            compiler_config.simplification =
                circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
            compiler_config
                .link_library
                .push("../test_vectors/WitnessExtension/tests/libs/".into());

            let x = parse_shared_input(x);
            let witness_extension =
                CoCircomCompiler::<Bn254>::parse(circuit_path.to_owned(), compiler_config)
                    .unwrap()
                    .to_rep3_vm_with_network(net, VMConfig::default())
                    .unwrap();
            witness_extension.run(x)
        }));
    }
    let _ = threads.pop().unwrap().join().unwrap();
    let _ = threads.pop().unwrap().join().unwrap();
    let _ = threads.pop().unwrap().join().unwrap();
}

/// Try to parse a [SharedInput] from a [Read]er.
pub fn parse_shared_input<F: PrimeField>(
    share: SerializeableSharedRep3Input<F, SeedRng>,
) -> SharedInput<F, Rep3PrimeFieldShare<F>> {
    if !share.maybe_shared_inputs.is_empty() {
        panic!();
    }

    let public_inputs = share.public_inputs;
    let shared_inputs_ = share.shared_inputs;

    let mut shared_inputs = BTreeMap::new();

    for (_, share) in shared_inputs_.iter() {
        match share {
            Rep3ShareVecType::Replicated(_) => {}
            Rep3ShareVecType::SeededReplicated(_) => {}
            Rep3ShareVecType::Additive(_) => panic!(),
            Rep3ShareVecType::SeededAdditive(_) => {
                panic!()
            }
        }
    }

    for (name, share) in shared_inputs_ {
        match share {
            Rep3ShareVecType::Replicated(vec) => {
                shared_inputs.insert(name, vec);
            }
            Rep3ShareVecType::SeededReplicated(replicated_seed_type) => {
                shared_inputs.insert(name, replicated_seed_type.expand_vec().unwrap());
            }
            Rep3ShareVecType::Additive(_) => {
                panic!()
            }
            Rep3ShareVecType::SeededAdditive(_) => {
                panic!()
            }
        }
    }

    SharedInput {
        public_inputs,
        shared_inputs,
    }
}
