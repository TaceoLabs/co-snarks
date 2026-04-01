use std::path::PathBuf;

use clap::Parser;
use color_eyre::{Result, eyre::Context};
use mpc_net::{Network as _, libfabric_efa::FabricNetwork, tcp::NetworkConfig};

#[derive(Parser)]
struct Args {
    /// The config file path
    #[clap(short, long, value_name = "CONFIG")]
    config: PathBuf,

    #[clap(short, long, default_value = "1024")]
    size: usize,
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

    let network = FabricNetwork::new(config)?;

    let buf = [0u8; 128];
    let start = std::time::Instant::now();
    for _ in 0..args.size {
        // send to all parties
        for id in 0..3 {
            if id != my_id {
                // tracing::info!("party {my_id} sending to {id}");
                network.send(id, &buf)?;
            }
        }
        // recv from all parties
        for id in 0..3 {
            if id != my_id {
                let buf: [u8; 128] = network.recv(id)?;
                // assert!(buf.iter().all(|&x| x == my_id as u8));
                // tracing::info!("party {my_id} received from {id}");
            }
        }
    }
    let elapsed = start.elapsed();
    println!("Elapsed time: {elapsed:?}");

    println!(
        "Network connection stats:\n{}",
        network.get_connection_stats()
    );

    Ok(())
}
