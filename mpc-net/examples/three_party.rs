use std::path::PathBuf;

use clap::Parser;
use color_eyre::{
    eyre::{eyre, Context},
    Result,
};
use mpc_net::{
    config::{NetworkConfig, NetworkConfigFile},
    GrpcNetworking,
};

#[derive(Parser)]
struct Args {
    /// The config file path
    #[clap(short, long, value_name = "FILE")]
    config_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("Could not install default rustls crypto provider"))?;

    let config: NetworkConfigFile =
        toml::from_str(&std::fs::read_to_string(args.config_file).context("opening config file")?)
            .context("parsing config file")?;
    let config = NetworkConfig::try_from(config).context("converting network config")?;
    let my_id = config.my_id;
    let parties = config.parties.clone();

    let network = GrpcNetworking::new(config).await?;

    // send to all parties
    for party in parties.iter() {
        if party.id == my_id {
            continue;
        }
        let buf = vec![party.id as u8; 1024];
        network.send(buf, party.id, 0).await?;
    }

    // recv from all parties
    for party in parties.iter() {
        if party.id == my_id {
            continue;
        }
        let buf = network.receive(party.id, 0).await?;
        assert!(buf.iter().all(|&x| x == my_id as u8))
    }

    network.shutdown().await?;

    Ok(())
}
