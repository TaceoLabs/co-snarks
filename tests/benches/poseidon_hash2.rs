use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use circom_mpc_compiler::{CompilerBuilder, CompilerConfig};
use circom_mpc_vm::mpc_vm::VMConfig;
use circom_types::{
    groth16::{
        Groth16Proof, JsonVerificationKey as Groth16JsonVerificationKey, ZKey as Groth16ZKey,
    },
    plonk::{JsonVerificationKey as PlonkJsonVerificationKey, PlonkProof, ZKey as PlonkZKey},
    traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
    Witness,
};
use co_circom_snarks::SharedInput;
use co_circom_snarks::SharedWitness;
use collaborative_groth16::groth16::{CollaborativeGroth16, Groth16};
use collaborative_plonk::{plonk::Plonk, CollaborativePlonk};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use itertools::izip;
use mpc_core::{
    protocols::{
        plain::PlainDriver,
        rep3::{self, Rep3Protocol},
        shamir::ShamirProtocol,
    },
    traits::FFTPostProcessing,
};
use rand::{distributions::Standard, prelude::Distribution, thread_rng, Rng};
use std::fs::File;
use tests::{
    rep3_network::{PartyTestNetwork as Rep3PartyTestNetwork, Rep3TestNetwork},
    shamir_network::{PartyTestNetwork as ShamirPartyTestNetwork, ShamirTestNetwork},
};
use tokio::runtime;

fn witness_extension_no_bench<P>(
    circuit: &str,
    link_lib: &str,
    num_inputs: usize,
) -> SharedWitness<PlainDriver<P::ScalarField>, P>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    let compiler_config = CompilerConfig::default();
    let vm_config = VMConfig::default();

    // parse circuit file & put through our compiler
    let mut builder = CompilerBuilder::<P>::new(compiler_config, circuit.to_string());
    builder = builder.link_library(link_lib);
    let parsed_circom_circuit = builder.build().parse().unwrap();

    let mut rng = thread_rng();
    let input = (0..num_inputs).map(|_| rng.gen()).collect::<Vec<_>>();

    // create input shares
    let input_name = "inputs";
    let mut share = SharedInput::default();
    share.shared_inputs.insert(input_name.to_string(), input);

    let vm = parsed_circom_circuit.clone().to_plain_vm(vm_config);
    let res = vm.run(share).unwrap();
    res.into_shared_witness()
}

fn groth16_proof_no_bench<P>(
    zkey: &str,
    witness: SharedWitness<PlainDriver<P::ScalarField>, P>,
) -> Groth16Proof<P>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    let pk = Groth16ZKey::<P>::from_reader(File::open(zkey).unwrap()).unwrap();

    let plain = PlainDriver::default();
    let mut prover = CollaborativeGroth16::new(plain);
    prover.prove(&pk, witness).unwrap()
}

fn plonk_proof_no_bench<P>(
    zkey: &str,
    witness: SharedWitness<PlainDriver<P::ScalarField>, P>,
) -> PlonkProof<P>
where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    let pk = PlonkZKey::<P>::from_reader(File::open(zkey).unwrap()).unwrap();

    let plain = PlainDriver::default();
    let prover = CollaborativePlonk::new(plain);
    prover.prove(pk, witness).unwrap()
}

fn rep3_witness_extension<P>(
    c: &mut Criterion,
    circuit: &str,
    link_lib: &str,
    num_inputs: usize,
    name: &str,
) where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    const NUM_PARTIES: usize = 3;
    let compiler_config = CompilerConfig::default();
    let vm_config = VMConfig::default();

    // parse circuit file & put through our compiler
    let mut builder = CompilerBuilder::<P>::new(compiler_config, circuit.to_string());
    builder = builder.link_library(link_lib);
    let parsed_circom_circuit = builder.build().parse().unwrap();

    let mut rng = thread_rng();
    let input = (0..num_inputs).map(|_| rng.gen()).collect::<Vec<_>>();

    // create input shares
    let mut shares = (0..NUM_PARTIES)
        .map(|_| SharedInput::default())
        .collect::<Vec<_>>();

    let input_name = "inputs";
    for (src, des) in izip!(
        rep3::utils::share_field_elements(&input, &mut rng),
        shares.iter_mut()
    ) {
        des.shared_inputs.insert(input_name.to_string(), src);
    }

    let rt = runtime::Builder::new_multi_thread()
        .worker_threads(NUM_PARTIES)
        .build()
        .unwrap();
    let id = format!(
        "Poseidon Witness extension Rep3, {} parties, {}",
        NUM_PARTIES, name
    );
    c.bench_function(&id, move |bench| {
        bench.to_async(&rt).iter_with_setup(
            || {
                let test_network = Rep3TestNetwork::default();
                let nets = test_network.get_party_networks();
                (nets, shares.clone())
            },
            |(nets, shares)| async {
                let mut parties = Vec::with_capacity(NUM_PARTIES);
                for (net, share) in izip!(nets, shares) {
                    let circ = parsed_circom_circuit.clone();
                    let conf = vm_config.clone();

                    let party = tokio::task::spawn_blocking(move || {
                        let vm = circ
                            .clone()
                            .to_rep3_vm_with_network(net, conf.clone())
                            .unwrap();
                        vm.run(share).unwrap()
                    });
                    parties.push(party);
                }
                for party in parties {
                    party.await.unwrap();
                    black_box(())
                }
            },
        )
    });
}

fn groth16_rep3_proof<P>(
    c: &mut Criterion,
    zkey: &str,
    witness: &[SharedWitness<Rep3Protocol<P::ScalarField, Rep3PartyTestNetwork>, P>],
    name: &str,
) where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    const NUM_PARTIES: usize = 3;
    let pk: Groth16ZKey<P> = Groth16ZKey::<P>::from_reader(File::open(zkey).unwrap()).unwrap();

    let rt = runtime::Builder::new_multi_thread()
        .worker_threads(NUM_PARTIES)
        .build()
        .unwrap();
    let id = format!(
        "Poseidon Groth16 Proof Rep3, {} parties, {}",
        NUM_PARTIES, name
    );
    c.bench_function(&id, move |bench| {
        bench.to_async(&rt).iter_with_setup(
            || {
                let test_network = Rep3TestNetwork::default();
                let nets = test_network.get_party_networks();
                (nets, witness.to_vec())
            },
            |(nets, witness)| async {
                let mut parties = Vec::with_capacity(NUM_PARTIES);
                for (net, witness) in izip!(nets, witness) {
                    let pk = pk.clone();

                    let party = tokio::task::spawn_blocking(move || {
                        let rep3 = Rep3Protocol::new(net).unwrap();
                        let mut prover = CollaborativeGroth16::new(rep3);
                        prover.prove(&pk, witness).unwrap()
                    });
                    parties.push(party);
                }
                for party in parties {
                    party.await.unwrap();
                    black_box(())
                }
            },
        )
    });
}

fn groth16_shamir_proof<P>(
    c: &mut Criterion,
    zkey: &str,
    witness: &[SharedWitness<ShamirProtocol<P::ScalarField, ShamirPartyTestNetwork>, P>],
    degree: usize,
    num_parties: usize,
    name: &str,
) where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    let pk = Groth16ZKey::<P>::from_reader(File::open(zkey).unwrap()).unwrap();

    let rt = runtime::Builder::new_multi_thread()
        .worker_threads(num_parties)
        .build()
        .unwrap();
    let id = format!(
        "Poseidon Groth16 Proof Shamir, {} parties, degree={}, {}",
        num_parties, degree, name
    );
    c.bench_function(&id, move |bench| {
        bench.to_async(&rt).iter_with_setup(
            || {
                let test_network = ShamirTestNetwork::new(num_parties);
                let nets = test_network.get_party_networks();
                (nets, witness.to_vec())
            },
            |(nets, witness)| async {
                let mut parties = Vec::with_capacity(num_parties);
                for (net, witness) in izip!(nets, witness) {
                    let pk = pk.clone();

                    let party = tokio::task::spawn_blocking(move || {
                        let shamir = ShamirProtocol::new(degree, net).unwrap();
                        let mut prover = CollaborativeGroth16::new(shamir);
                        prover.prove(&pk, witness).unwrap()
                    });
                    parties.push(party);
                }
                for party in parties {
                    party.await.unwrap();
                    black_box(())
                }
            },
        )
    });
}

fn groth16_verify<P>(
    c: &mut Criterion,
    verification_key: &str,
    proof: &Groth16Proof<P>,
    public_input: &[P::ScalarField],
    name: &str,
) where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    let vk: Groth16JsonVerificationKey<P> =
        serde_json::from_reader(File::open(verification_key).unwrap()).unwrap();

    let id = format!("Poseidon Groth16 Verify Rep3, {}", name);
    c.bench_function(&id, move |bench| {
        bench.iter(|| {
            let verified = Groth16::<P>::verify(&vk, proof, public_input).expect("can verify");
            assert!(verified);
        })
    });
}

fn plonk_rep3_proof<P>(
    c: &mut Criterion,
    zkey: &str,
    witness: &[SharedWitness<Rep3Protocol<P::ScalarField, Rep3PartyTestNetwork>, P>],
    name: &str,
) where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    const NUM_PARTIES: usize = 3;
    let pk = PlonkZKey::<P>::from_reader(File::open(zkey).unwrap()).unwrap();

    let rt = runtime::Builder::new_multi_thread()
        .worker_threads(NUM_PARTIES)
        .build()
        .unwrap();
    let id = format!(
        "Poseidon Plonk Proof Rep3, {} parties, {}",
        NUM_PARTIES, name
    );
    c.bench_function(&id, move |bench| {
        bench.to_async(&rt).iter_with_setup(
            || {
                let test_network = Rep3TestNetwork::default();
                let nets = test_network.get_party_networks();
                (nets, witness.to_vec())
            },
            |(nets, witness)| async {
                let mut parties = Vec::with_capacity(NUM_PARTIES);
                for (net, witness) in izip!(nets, witness) {
                    let pk = pk.clone();

                    let party = tokio::task::spawn_blocking(move || {
                        let rep3 = Rep3Protocol::new(net).unwrap();
                        let prover = CollaborativePlonk::new(rep3);
                        prover.prove(pk, witness).unwrap()
                    });
                    parties.push(party);
                }
                for party in parties {
                    party.await.unwrap();
                    black_box(())
                }
            },
        )
    });
}

fn plonk_shamir_proof<P>(
    c: &mut Criterion,
    zkey: &str,
    witness: &[SharedWitness<ShamirProtocol<P::ScalarField, ShamirPartyTestNetwork>, P>],
    degree: usize,
    num_parties: usize,
    name: &str,
) where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    let pk = PlonkZKey::<P>::from_reader(File::open(zkey).unwrap()).unwrap();

    let rt = runtime::Builder::new_multi_thread()
        .worker_threads(num_parties)
        .build()
        .unwrap();
    let id = format!(
        "Poseidon Plonk Proof Shamir, {} parties, degree={}, {}",
        num_parties, degree, name
    );
    c.bench_function(&id, move |bench| {
        bench.to_async(&rt).iter_with_setup(
            || {
                let test_network = ShamirTestNetwork::new(num_parties);
                let nets = test_network.get_party_networks();
                (nets, witness.to_vec())
            },
            |(nets, witness)| async {
                let mut parties = Vec::with_capacity(num_parties);
                for (net, witness) in izip!(nets, witness) {
                    let pk = pk.clone();

                    let party = tokio::task::spawn_blocking(move || {
                        let shamir = ShamirProtocol::new(degree, net).unwrap();
                        let prover = CollaborativePlonk::new(shamir);
                        prover.prove(pk, witness).unwrap()
                    });
                    parties.push(party);
                }
                for party in parties {
                    party.await.unwrap();
                    black_box(())
                }
            },
        )
    });
}

fn plonk_verify<P>(
    c: &mut Criterion,
    verification_key: &str,
    proof: &PlonkProof<P>,
    public_input: &[P::ScalarField],
    name: &str,
) where
    P: Pairing + CircomArkworksPairingBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge + FFTPostProcessing + Clone,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    Standard: Distribution<P::ScalarField>,
{
    let vk: PlonkJsonVerificationKey<P> =
        serde_json::from_reader(File::open(verification_key).unwrap()).unwrap();

    let id = format!("Poseidon Plonk Verify Rep3, {}", name);
    c.bench_function(&id, move |bench| {
        bench.iter(|| {
            let verified = Plonk::<P>::verify(&vk, proof, public_input).expect("can verify");
            assert!(verified);
        })
    });
}

fn rep3_witness_from_plain_witness<P: Pairing>(
    witness: SharedWitness<PlainDriver<P::ScalarField>, P>,
) -> Vec<SharedWitness<Rep3Protocol<P::ScalarField, Rep3PartyTestNetwork>, P>> {
    let mut rng = thread_rng();
    let mut values = witness.public_inputs.clone();
    values.extend(witness.witness);
    let num_public_inputs = witness.public_inputs.len();
    let witness = Witness { values };
    SharedWitness::share_rep3(witness, num_public_inputs, &mut rng).to_vec()
}

fn shamir_witness_from_plain_witness<P: Pairing>(
    witness: SharedWitness<PlainDriver<P::ScalarField>, P>,
    degree: usize,
    num_parties: usize,
) -> Vec<SharedWitness<ShamirProtocol<P::ScalarField, ShamirPartyTestNetwork>, P>> {
    let mut rng = thread_rng();
    let mut values = witness.public_inputs.clone();
    values.extend(witness.witness);
    let num_public_inputs = witness.public_inputs.len();
    let witness = Witness { values };
    SharedWitness::share_shamir(witness, num_public_inputs, degree, num_parties, &mut rng).to_vec()
}

fn poseidon_groth16_rep3_bn254(c: &mut Criterion) {
    const NUM_INPUTS: usize = 2;
    let circuit = "../test_vectors/benches/poseidon_hash2/circuit.circom";
    let lib = "../test_vectors/benches/poseidon_hash2/bn254/lib";
    let zkey = "../test_vectors/benches/poseidon_hash2/bn254/groth16/poseidon.zkey";
    let verification_key =
        "../test_vectors/benches/poseidon_hash2/bn254/groth16/verification_key.json";
    let name = "Bn254";

    // Generate without benchmarking
    let witness = witness_extension_no_bench::<Bn254>(circuit, lib, NUM_INPUTS);
    let proof = groth16_proof_no_bench::<Bn254>(zkey, witness.clone());
    let rep3_witness = rep3_witness_from_plain_witness(witness);
    let public_input = &rep3_witness[0].public_inputs[1..];

    // Benchmarks
    rep3_witness_extension::<Bn254>(c, circuit, lib, NUM_INPUTS, name);
    groth16_rep3_proof(c, zkey, &rep3_witness, name);
    groth16_verify(c, verification_key, &proof, public_input, name)
}

fn poseidon_groth16_shamir_bn254(c: &mut Criterion, degree: usize, num_parties: usize) {
    const NUM_INPUTS: usize = 2;
    let circuit = "../test_vectors/benches/poseidon_hash2/circuit.circom";
    let lib = "../test_vectors/benches/poseidon_hash2/bn254/lib";
    let zkey = "../test_vectors/benches/poseidon_hash2/bn254/groth16/poseidon.zkey";
    let verification_key =
        "../test_vectors/benches/poseidon_hash2/bn254/groth16/verification_key.json";
    let name = "Bn254";

    // Generate without benchmarking
    let witness = witness_extension_no_bench::<Bn254>(circuit, lib, NUM_INPUTS);
    let proof = groth16_proof_no_bench::<Bn254>(zkey, witness.clone());
    let shamir_witness = shamir_witness_from_plain_witness(witness, degree, num_parties);
    let public_input = &shamir_witness[0].public_inputs[1..];

    // Benchmarks
    groth16_shamir_proof(c, zkey, &shamir_witness, degree, num_parties, name);
    groth16_verify(c, verification_key, &proof, public_input, name)
}

fn poseidon_plonk_rep3_bn254(c: &mut Criterion) {
    const NUM_INPUTS: usize = 2;
    let circuit = "../test_vectors/benches/poseidon_hash2/circuit.circom";
    let lib = "../test_vectors/benches/poseidon_hash2/bn254/lib";
    let zkey = "../test_vectors/benches/poseidon_hash2/bn254/plonk/poseidon.zkey";
    let verification_key =
        "../test_vectors/benches/poseidon_hash2/bn254/plonk/verification_key.json";
    let name = "Bn254";

    // Generate without benchmarking
    let witness = witness_extension_no_bench::<Bn254>(circuit, lib, NUM_INPUTS);
    let proof = plonk_proof_no_bench::<Bn254>(zkey, witness.clone());
    let rep3_witness = rep3_witness_from_plain_witness(witness);
    let public_input = &rep3_witness[0].public_inputs[1..];

    // Benchmarks
    rep3_witness_extension::<Bn254>(c, circuit, lib, NUM_INPUTS, name);
    plonk_rep3_proof(c, zkey, &rep3_witness, name);
    plonk_verify(c, verification_key, &proof, public_input, name)
}

fn poseidon_plonk_shamir_bn254(c: &mut Criterion, degree: usize, num_parties: usize) {
    const NUM_INPUTS: usize = 2;
    let circuit = "../test_vectors/benches/poseidon_hash2/circuit.circom";
    let lib = "../test_vectors/benches/poseidon_hash2/bn254/lib";
    let zkey = "../test_vectors/benches/poseidon_hash2/bn254/plonk/poseidon.zkey";
    let verification_key =
        "../test_vectors/benches/poseidon_hash2/bn254/plonk/verification_key.json";
    let name = "Bn254";

    // Generate without benchmarking
    let witness = witness_extension_no_bench::<Bn254>(circuit, lib, NUM_INPUTS);
    let proof = plonk_proof_no_bench::<Bn254>(zkey, witness.clone());
    let shamir_witness = shamir_witness_from_plain_witness(witness, degree, num_parties);
    let public_input = &shamir_witness[0].public_inputs[1..];

    // Benchmarks
    plonk_shamir_proof(c, zkey, &shamir_witness, degree, num_parties, name);
    plonk_verify(c, verification_key, &proof, public_input, name)
}

fn criterion_benchmark_poseidon_hash2(c: &mut Criterion) {
    poseidon_groth16_rep3_bn254(c);
    poseidon_groth16_shamir_bn254(c, 1, 3);
    poseidon_plonk_rep3_bn254(c);
    poseidon_plonk_shamir_bn254(c, 1, 3);
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_poseidon_hash2
);
criterion_main!(benches);
