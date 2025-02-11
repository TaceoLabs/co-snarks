use co_circom::{
    Address, Bn254, CheckElement, CoCircomCompiler, CompilerConfig, Groth16,
    Groth16JsonVerificationKey, Groth16ZKey, NetworkConfig, NetworkParty, PartyID, Rep3CoGroth16,
    Rep3MpcNet, Rep3SharedInput, VMConfig,
};
use color_eyre::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
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

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/data");

    // connect to network
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
        dir.join("key2.der"),
    )?))
    .clone_key();
    let parties = vec![
        NetworkParty::new(
            PartyID::ID0.into(),
            Address::new("localhost".to_string(), 10000),
            CertificateDer::from(std::fs::read(dir.join("cert0.der"))?).into_owned(),
        ),
        NetworkParty::new(
            PartyID::ID1.into(),
            Address::new("localhost".to_string(), 10001),
            CertificateDer::from(std::fs::read(dir.join("cert1.der"))?).into_owned(),
        ),
        NetworkParty::new(
            PartyID::ID2.into(),
            Address::new("localhost".to_string(), 10002),
            CertificateDer::from(std::fs::read(dir.join("cert2.der"))?).into_owned(),
        ),
    ];
    let network_config =
        NetworkConfig::new(PartyID::ID2.into(), "0.0.0.0:10002".parse()?, key, parties);
    let mut net = Rep3MpcNet::new(network_config)?;

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
    let share: Rep3SharedInput<_> = bincode::deserialize(&net.recv_bytes(PartyID::ID0)?)?;

    // generate witness
    let (witness, net) =
        co_circom::generate_witness_rep3::<Bn254>(circuit, share, net, VMConfig::default())?;
    let public_inputs = witness.public_inputs_for_verify();

    // generate proof
    let (proof, _) = Rep3CoGroth16::prove(net, zkey, witness)?;

    // verify proof
    let vk = Groth16JsonVerificationKey::<Bn254>::from_reader(
        std::fs::read(dir.join("verification_key.json"))?.as_slice(),
    )?;
    Groth16::verify(&vk, &proof, &public_inputs)?;

    Ok(())
}
