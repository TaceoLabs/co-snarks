use color_eyre::{eyre::Context, Result};
use rcgen::CertifiedKey;
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

    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(args.sans).context("generating self-signed cert")?;
    let key = key_pair.serialize_der();
    std::fs::write(args.key_path, key).context("writing key file")?;
    let cert = cert.der();
    std::fs::write(args.cert_path, cert).context("writing certificate file")?;
    Ok(())
}
