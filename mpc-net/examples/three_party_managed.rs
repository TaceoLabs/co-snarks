use std::{collections::HashMap, path::PathBuf};

use clap::Parser;
use color_eyre::{
    eyre::{eyre, Context, ContextCompat},
    Result,
};
use mpc_net::{
    config::{NetworkConfig, NetworkConfigFile},
    MpcNetworkHandler,
};

#[derive(Parser)]
struct Args {
    /// The config file path
    #[clap(short, long, value_name = "FILE")]
    config_file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("Could not install default rustls crypto provider"))?;

    let config: NetworkConfigFile =
        toml::from_str(&std::fs::read_to_string(args.config_file).context("opening config file")?)
            .context("parsing config file")?;
    let config = NetworkConfig::try_from(config).context("converting network config")?;
    let my_id = config.my_id;

    let mut network = MpcNetworkHandler::establish(config)?;

    let channels = network.get_channels().context("get channels")?;
    let mut managed_channels = channels
        .into_iter()
        .map(|(i, c)| (i, network.spawn(c)))
        .collect::<HashMap<_, _>>();

    // send to all channels
    for (&i, channel) in managed_channels.iter_mut() {
        let buf = vec![i as u8; 1024];
        let _ = channel.send(buf.into()).recv()?;
    }
    // recv from all channels
    for (&_, channel) in managed_channels.iter_mut() {
        let buf = channel.recv().recv();
        if let Ok(Ok(b)) = buf {
            println!("received {}, should be {}", b[0], my_id as u8);
            assert!(b.iter().all(|&x| x == my_id as u8))
        }
    }

    network.print_connection_stats(&mut std::io::stdout())?;

    Ok(())
}
