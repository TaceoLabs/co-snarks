use co_circom::{
    Bn254, CheckElement, CoCircomCompiler, CompilerConfig, Groth16, Groth16JsonVerificationKey,
    Groth16ZKey, Rep3CoGroth16, Rep3SharedInput, VMConfig,
};
use color_eyre::Result;
use mpc_core::protocols::rep3::{PARTY_0, PARTY_1};
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

    let id = PARTY_1;
    let party_addrs = ["localhost:10000", "localhost:10001", "localhost:10002"]
        .map(|addr| addr.parse().expect("valid address"));

    // connect to network
    let nets = TcpNetwork::networks(id, "0.0.0.0:10001", &party_addrs, 8)?;
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

    // recv share from party 0, only needed for this demo for private-proof delegation and for PSS this is done separately,
    // because the party with the shares usually does not take part in the computation
    let share: Rep3SharedInput<_> =
        bincode::deserialize(&engine.install_net(|net| net.recv(PARTY_0))?)?;

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
