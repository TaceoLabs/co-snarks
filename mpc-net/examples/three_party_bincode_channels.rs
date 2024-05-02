use std::{fs::File, path::PathBuf};

use clap::Parser;
use color_eyre::{eyre::Context, Result};
use futures::{SinkExt, StreamExt};
use mpc_net::{
    config::{NetworkConfig, NetworkParty},
    MpcNetworkHandler,
};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
struct Args {
    /// The config file path
    #[clap(short, long, value_name = "FILE")]
    config_file: PathBuf,

    /// The path to the .der key file for our certificate
    #[clap(short, long, value_name = "FILE")]
    key_file: PathBuf,

    /// The If of our party in the config
    #[clap(short, long, value_name = "ID")]
    party: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let parties: Vec<NetworkParty> =
        serde_yaml::from_reader(File::open(args.config_file).context("opening config file")?)
            .context("parsing config file")?;

    let config = NetworkConfig {
        parties,
        my_id: args.party,
        key_path: args.key_file,
    };

    let mut network = MpcNetworkHandler::establish(config).await?;

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
            assert!(b.iter().all(|&x| x == args.party as u8))
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
            assert!(b.iter().all(|&x| x == args.party as u8))
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
