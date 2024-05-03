use std::{collections::HashMap, fs::File, path::PathBuf};

use clap::Parser;
use color_eyre::{eyre::Context, Result};
use mpc_net::{
    channel::ChannelHandle,
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

    let channels = network.get_byte_channels().await?;
    let mut managed_channels = channels
        .into_iter()
        .map(|(i, c)| (i, ChannelHandle::manage(c)))
        .collect::<HashMap<_, _>>();

    // send to all channels
    for (&i, channel) in managed_channels.iter_mut() {
        let buf = vec![i as u8; 1024];
        let _ = channel.send(buf.into()).await.await?;
    }
    // recv from all channels
    for (&_, channel) in managed_channels.iter_mut() {
        let buf = channel.recv().await.await;
        if let Ok(Ok(b)) = buf {
            println!("received {}, should be {}", b[0], args.party);
            assert!(b.iter().all(|&x| x == args.party as u8))
        }
    }
    network.print_connection_stats(&mut std::io::stdout())?;

    Ok(())
}
