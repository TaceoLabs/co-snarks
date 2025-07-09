use std::path::PathBuf;

use clap::Parser;
use color_eyre::{Result, eyre::Context};
use mpc_net::{
    Network as _,
    tcp::{NetworkConfig, TcpNetwork},
};

#[derive(Parser)]
struct Args {
    /// The config file path
    #[clap(short, long, value_name = "CONFIG")]
    config: PathBuf,
}

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        EnvFilter,
        fmt::{self, format::FmtSpan},
    };

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
}

fn main() -> Result<()> {
    let args = Args::parse();
    install_tracing();

    let config: NetworkConfig =
        toml::from_str(&std::fs::read_to_string(args.config).context("opening config file")?)
            .context("parsing config file")?;
    let my_id = config.my_id;

    let network = TcpNetwork::new(config)?;

    // send to all parties
    for id in 0..3 {
        if id != my_id {
            tracing::info!("party {my_id} sending to {id}");
            let buf = vec![id as u8; 1024];
            network.send(id, &buf)?;
        }
    }
    // recv from all parties
    for id in 0..3 {
        if id != my_id {
            let buf = network.recv(id)?;
            assert!(buf.iter().all(|&x| x == my_id as u8));
            tracing::info!("party {my_id} received from {id}");
        }
    }

    println!(
        "Network connection stats:\n{}",
        network.get_connection_stats()
    );

    Ok(())
}
