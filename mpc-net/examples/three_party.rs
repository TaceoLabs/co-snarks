use std::{fs::File, path::PathBuf};

use clap::Parser;
use color_eyre::{eyre::Context, Result};
use futures::{SinkExt, StreamExt};
use mpc_net::{
    config::{NetworkConfig, NetworkParty},
    MpcNetworkHandler,
};

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

    let mut channels = network.get_byte_channels().await?;

    // send to all channels
    for (&i, channel) in channels.iter_mut() {
        let buf = vec![i as u8; 1024];
        channel.send(buf.into()).await?;
    }
    // recv from all channels
    for (&_, channel) in channels.iter_mut() {
        let buf = channel.next().await;
        if let Some(Ok(b)) = buf {
            println!("received {}, should be {}", b[0], args.party);
            assert!(b.iter().all(|&x| x == args.party as u8))
        }
    }
    network.print_connection_stats(&mut std::io::stdout())?;

    Ok(())
}
