use co_circom::{
    Bn254, CheckElement, CoCircomCompiler, CompilerConfig, Groth16, Groth16JsonVerificationKey,
    Groth16ZKey, Input, Rep3CoGroth16, VMConfig, Value,
};
use color_eyre::Result;
use mpc_core::protocols::rep3::{PARTY_0, PARTY_1, PARTY_2};
use mpc_engine::{MpcEngine, Network, TcpNetwork, NUM_THREADS_CPU, NUM_THREADS_NET};
use std::{path::PathBuf, sync::Arc};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
    EnvFilter,
};

fn main() -> Result<()> {
    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_line_number(false)
        .with_span_events(FmtSpan::CLOSE | FmtSpan::ENTER);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    let id = PARTY_0;
    let party_addrs = ["localhost:10000", "localhost:10001", "localhost:10002"]
        .map(|addr| addr.parse().expect("valid address"));

    // connect to network
    let nets = TcpNetwork::networks(id, "0.0.0.0:10000", &party_addrs, 8)?;
    let engine = MpcEngine::new(id, NUM_THREADS_NET, NUM_THREADS_CPU, nets);

    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/groth16/test_vectors/multiplier2");

    // parse circuit file & put through our compiler
    let circuit =
        CoCircomCompiler::<Bn254>::parse(dir.join("circuit.circom"), CompilerConfig::default())?;

    // parse zkey, without performing extra checks (only advised for zkeys knwon to be valid)
    let zkey = Arc::new(Groth16ZKey::<Bn254>::from_reader(
        std::fs::read(dir.join("multiplier2.zkey"))?.as_slice(),
        CheckElement::No,
    )?);

    // split inputs
    let mut input = Input::new();
    input.insert("a".to_string(), Value::String("2".to_string()));
    input.insert("b".to_string(), Value::String("3".to_string()));
    let [share, share1, share2] = co_circom::split_input::<Bn254>(input, circuit.public_inputs())?;

    // send shares to other parties, only needed for this demo for private-proof delegation and for PSS this is done separately,
    // because the party with the shares usually does not take part in the computation
    engine.install_net(|net| {
        net.send(PARTY_1, &bincode::serialize(&share1)?)?;
        net.send(PARTY_2, &bincode::serialize(&share2)?)?;
        color_eyre::eyre::Ok(())
    })?;

    // generate witness
    let witness =
        co_circom::generate_witness_rep3::<Bn254, _>(&engine, circuit, share, VMConfig::default())?;
    let public_inputs = witness.public_inputs_for_verify();

    // generate proof
    let proof = Rep3CoGroth16::prove(&engine, zkey, witness)?;

    // verify proof
    let vk = Groth16JsonVerificationKey::<Bn254>::from_reader(
        std::fs::read(dir.join("verification_key.json"))?.as_slice(),
    )?;
    Groth16::verify(&vk, &proof, &public_inputs)?;

    Ok(())
}
