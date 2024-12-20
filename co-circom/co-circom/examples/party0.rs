use circom_types::traits::CheckElement;
use co_circom::{
    Address, Bn254, CoCircomCompiler, CompilerConfig, Groth16, Groth16JsonVerificationKey,
    Groth16ZKey, NetworkConfig, NetworkParty, PartyID, Rep3MpcNet, ShamirCoGroth16, VMConfig,
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
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(false)
                .with_span_events(FmtSpan::CLOSE),
        )
        .with(EnvFilter::from_default_env())
        .init();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/data");

    // connect to network
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
        dir.join("key0.der"),
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
        NetworkConfig::new(PartyID::ID0.into(), "0.0.0.0:10000".parse()?, key, parties);
    let mut net = Rep3MpcNet::new(network_config)?;

    // parse circuit file & put through our compiler
    let circuit = CoCircomCompiler::<Bn254>::parse(
        dir.join("multiplier2.circom"),
        CompilerConfig::default(),
    )?;

    // split inputs
    let input = r#"{ "a": "2", "b": "3" }"#;
    let [share0, share1, share2] =
        co_circom::split_input::<Bn254>(input.as_bytes(), circuit.public_inputs())?;

    // send shares to other parties
    net.send_bytes(PartyID::ID1, bincode::serialize(&share1)?.into())?;
    net.send_bytes(PartyID::ID2, bincode::serialize(&share2)?.into())?;

    // generate witness
    let (witness, net) =
        co_circom::generate_witness_rep3::<Bn254>(circuit, share0, net, VMConfig::default())?;

    // translate witness to shamir
    let (witness, net) = co_circom::translate_witness::<Bn254>(witness.into(), net)?;
    let public_inputs = witness.public_inputs[1..].to_vec(); // skip constant 1 at position 0

    // parse zkey
    let zkey = Arc::new(Groth16ZKey::<Bn254>::from_reader(
        std::fs::read(dir.join("multiplier2.zkey"))?.as_slice(),
        CheckElement::No,
    )?);

    // generate proof
    let threshold = 1;
    let (proof, _) = ShamirCoGroth16::prove(net, threshold, zkey, witness)?;

    // verify proof
    let vk = Groth16JsonVerificationKey::<Bn254>::from_reader(
        std::fs::read(dir.join("verification_key.json"))?.as_slice(),
    )?;
    Groth16::verify(&vk, &proof, &public_inputs)?;

    Ok(())
}
