use co_noir::{
    Address, Bn254, CrsParser, NetworkConfig, NetworkParty, PartyID, Poseidon2Sponge, Rep3AcvmType,
    Rep3CoUltraHonk, Rep3MpcNet, UltraHonk, Utils,
};
use color_eyre::{eyre::Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{collections::BTreeMap, path::PathBuf};
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

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/test_vectors");

    // parse constraint system
    let program_artifact =
        Utils::get_program_artifact_from_file(dir.join("poseidon/poseidon.json"))
            .context("while parsing program artifact")?;
    let constraint_system = Utils::get_constraint_system_from_artifact(&program_artifact, true);

    let recursive = true;

    // parse crs
    let crs_size = co_noir::compute_circuit_size::<Bn254>(&constraint_system, recursive)?;
    let (prover_crs, verifier_crs) =
        CrsParser::<Bn254>::get_crs(dir.join("bn254_g1.dat"), dir.join("bn254_g2.dat"), crs_size)?
            .split();

    // recv share from party 0
    let share: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>> =
        bincode::deserialize(&net.recv_bytes(PartyID::ID0)?)?;

    // generate witness
    let (witness_share, net) = co_noir::generate_witness_rep3(share, program_artifact, net)?;

    // generate proving key and vk
    let (pk, net) =
        co_noir::generate_proving_key_rep3(net, &constraint_system, witness_share, recursive)?;
    let vk = pk.create_vk(&prover_crs, verifier_crs)?;

    // generate proof
    let (proof, _) = Rep3CoUltraHonk::<_, _, Poseidon2Sponge>::prove(net, pk, &prover_crs)?;

    // verify proof
    assert!(UltraHonk::<_, Poseidon2Sponge>::verify(proof, vk).context("while verifying proof")?);

    Ok(())
}
