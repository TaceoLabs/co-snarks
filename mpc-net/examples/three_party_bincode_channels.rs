use std::path::PathBuf;

use clap::Parser;
use color_eyre::{
    Result,
    eyre::{Context, eyre},
};
use futures::{SinkExt, StreamExt};
use mpc_net::{
    MpcNetworkHandler,
    config::{NetworkConfig, NetworkConfigFile},
};
use serde::{Deserialize, Serialize};

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

    let network = MpcNetworkHandler::establish(config).await?;

    let mut channels = network.get_serde_bincode_channels().await?;

    // send to all channels
    for (&i, channel) in channels.iter_mut() {
        let mes = Message::Ping(vec![i as u8; 1024]);
        channel.send(mes).await?;
    }
    // recv from all channels
    for (&_, channel) in channels.iter_mut() {
        let buf = channel.next().await;
        if let Some(Ok(Message::Ping(b))) = buf {
            assert!(b.iter().all(|&x| x == my_id as u8))
        } else {
            panic!("could not receive message");
        }
    }
    // send to all channels
    for (&i, channel) in channels.iter_mut() {
        let mes = Message::Pong(vec![i as u8; 512]);
        channel.send(mes).await?;
    }
    // recv from all channels
    for (&_, channel) in channels.iter_mut() {
        let buf = channel.next().await;
        if let Some(Ok(Message::Pong(b))) = buf {
            assert!(b.iter().all(|&x| x == my_id as u8))
        } else {
            panic!("could not receive message");
        }
    }
    network.print_connection_stats(&mut std::io::stdout())?;

    Ok(())
}

// A message type that can be sent over the network
#[derive(Debug, Serialize, Deserialize)]

enum Message {
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}
