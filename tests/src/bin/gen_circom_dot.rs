use clap::Parser;
use rand::Rng;
use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
struct GenDotArgs {
    /// The size of the circuit as a power of two (i.e. real_circuit_size = 2^circuit_size) to generate
    #[arg(long, short = 'n')]
    circuit_size: u32,

    /// The circom file to generate
    #[arg(long, short = 'c')]
    circom_file: PathBuf,

    /// The input.json file to generate
    #[arg(long, short = 'i')]
    input_file: PathBuf,
}
use tracing_subscriber::fmt::format::FmtSpan;
fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

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

#[derive(Debug, serde::Serialize)]
struct Input {
    in1: Vec<u64>,
    in2: Vec<u64>,
}

fn generate_input_file(circuit_size: u32) -> Input {
    let mut rng = rand::thread_rng();
    let mut in1 = Vec::with_capacity(2usize.pow(circuit_size));
    let mut in2 = Vec::with_capacity(2usize.pow(circuit_size));
    (0..2usize.pow(circuit_size)).for_each(|_| {
        in1.push(rng.gen::<u64>());
        in2.push(rng.gen::<u64>());
    });
    Input { in1, in2 }
}

fn main() -> eyre::Result<()> {
    install_tracing();
    let args = GenDotArgs::parse();
    let circom_content = format!(
        "
pragma circom 2.0.0;

template Dot(N) {{
  signal input in1[N];
  signal input in2[N];
  signal output out;
  
  signal tmp[N + 1];
  tmp[0] <-- 0;
  
  var i;
  for (i = 0; i < N; i++) {{
    tmp[i + 1] <== in1[i] * in2[i] + tmp[i];
  }}
  out <-- tmp[N];
}}

component main = Dot(2 ** {});
",
        args.circuit_size
    );

    std::fs::write(&args.circom_file, circom_content)?;
    tracing::info!("circuit written to {:?}", args.circom_file);
    tracing::info!(
        "generating and writing input file to {:?} with a circuit size of {} (2^{})",
        args.input_file,
        2usize.pow(args.circuit_size),
        args.circuit_size
    );

    std::fs::write(
        &args.input_file,
        serde_json::to_string_pretty(&generate_input_file(args.circuit_size))?,
    )?;
    Ok(())
}
