use color_eyre::{eyre::Context, Result};
use std::path::PathBuf;

use clap::Parser;

/// Certificate Generator for MPC-NET
#[derive(Debug, PartialEq, Parser)]
struct CliArgs {
    /// The path to the .der certificate file
    #[clap(short, long)]
    cert_path: PathBuf,
    /// The path to the .der key file
    #[clap(short, long)]
    key_path: PathBuf,
    /// The subject alternative names for the certificate
    #[clap(short, long)]
    sans: Vec<String>,
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    let cert =
        rcgen::generate_simple_self_signed(args.sans).context("generating self-signed cert")?;
    let key = cert.serialize_private_key_der();
    std::fs::write(args.key_path, key).context("writing key file")?;
    let cert = cert.serialize_der().context("serializing certificate")?;
    std::fs::write(args.cert_path, cert).context("writing certificate file")?;
    Ok(())
}
