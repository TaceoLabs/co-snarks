use std::{array, collections::BTreeMap, path::PathBuf, thread};

use acir::{
    acir_field::GenericFieldElement,
    native_types::{WitnessMap, WitnessStack},
    FieldElement,
};

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_acvm::{
    solver::{partial_abi::PublicMarker, PlainCoSolver, Rep3CoSolver},
    Rep3AcvmType,
};
use mpc_core::protocols::rep3;
use noirc_abi::Abi;
use noirc_artifacts::program::ProgramArtifact;
use rand::{CryptoRng, Rng};
use tests::rep3_network::{PartyTestNetwork, Rep3TestNetwork};

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

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    install_tracing();
    let root = std::env!("CARGO_MANIFEST_DIR");
    println!("{root}");
    let test_case = "quantized";

    let program = std::fs::read_to_string(format!(
        "{root}/../test_vectors/noir/{test_case}/kat/{test_case}.json",
    ))
    .unwrap();
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
        .expect("failed to parse program artifact");

    let should_witness = std::fs::read(format!(
        "{root}/../test_vectors/noir/{test_case}/kat/{test_case}.gz",
    ))
    .unwrap();

    let should_witness = WitnessStack::<FieldElement>::try_from(should_witness.as_slice()).unwrap();
    let input = PathBuf::from(format!(
        "{root}/../test_vectors/noir/{test_case}/Prover.toml",
    ));
    // read the input file
    let inputs = Rep3CoSolver::<_, PartyTestNetwork>::partially_read_abi_bn254_fieldelement(
        &input,
        &program_artifact.abi,
        &program_artifact.bytecode,
    )?;

    // create input shares
    let mut rng = rand::thread_rng();
    let shares = share_input_rep3::<Bn254, _>(inputs, &mut rng);
    let test_network = Rep3TestNetwork::default();
    let mut threads = vec![];
    for (net, program_artifact, share) in itertools::izip!(
        test_network.get_party_networks(),
        [
            program_artifact.clone(),
            program_artifact.clone(),
            program_artifact
        ],
        shares
    ) {
        threads.push(thread::spawn(move || {
            let input_share = translate_witness_share_rep3(share, &program_artifact.abi);
            let solver =
                Rep3CoSolver::from_network_with_witness(net, program_artifact, input_share)
                    .unwrap();
            solver.solve().unwrap().0
        }));
    }

    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();
    let is_witness = combine_field_elements_for_acvm(result1, result2, result3);
    let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
    assert_eq!(should_witness, is_witness);
    Ok(())
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
        for ((witness_a, share_a), (witness_b, share_b), (witness_c, share_c)) in itertools::izip!(
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

pub fn share_input_rep3<P: Pairing, R: Rng + CryptoRng>(
    initial_witness: BTreeMap<String, PublicMarker<GenericFieldElement<P::ScalarField>>>,
    rng: &mut R,
) -> [BTreeMap<String, Rep3AcvmType<P::ScalarField>>; 3] {
    let mut witnesses = array::from_fn(|_| BTreeMap::default());
    for (witness, v) in initial_witness.into_iter() {
        match v {
            PublicMarker::Public(v) => {
                for w in witnesses.iter_mut() {
                    w.insert(witness.to_owned(), Rep3AcvmType::Public(v.into_repr()));
                }
            }
            PublicMarker::Private(v) => {
                let shares = rep3::share_field_element(v.into_repr(), rng);
                for (w, share) in witnesses.iter_mut().zip(shares) {
                    w.insert(witness.clone(), Rep3AcvmType::Shared(share));
                }
            }
        }
    }

    witnesses
}

pub fn translate_witness_share_rep3(
    witness: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>,
    abi: &Abi,
) -> WitnessMap<Rep3AcvmType<ark_bn254::Fr>> {
    Rep3CoSolver::<ark_bn254::Fr, PartyTestNetwork>::witness_map_from_string_map(witness, abi)
        .unwrap()
}
