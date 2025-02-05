use ark_ff::PrimeField;
use clap::Parser;
use color_eyre::eyre::{eyre, Context};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::{
        rep3::{
            self,
            network::{IoContext, Rep3MpcNet, Rep3Network},
            Rep3PrimeFieldShare,
        },
        shamir::{
            self,
            network::{ShamirMpcNet, ShamirNetwork},
            ShamirPreprocessing, ShamirPrimeFieldShare, ShamirProtocol,
        },
    },
};
use mpc_net::config::NetworkConfigFile;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    process::ExitCode,
    thread::sleep,
    time::{Duration, Instant},
};
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

/// Cli arguments
#[derive(Debug, Serialize, Parser)]
pub struct Cli {
    /// The path to the config file
    #[arg(long)]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub config: Option<PathBuf>,

    /// The number of testruns
    #[arg(short, long, default_value_t = 10)]
    pub runs: usize,

    /// The threshold of tolerated colluding parties
    #[arg(short, long, default_value_t = 1)]
    pub threshold: usize,
}

/// Config
#[derive(Debug, Deserialize)]
pub struct Config {
    /// The number of testruns
    pub runs: usize,
    /// The threshold of tolerated colluding parties
    pub threshold: usize,
    /// Network config
    pub network: NetworkConfigFile,
}

/// Prefix for config env variables
pub const CONFIG_ENV_PREFIX: &str = "COCIRCOM_";

/// Error type for config parsing and merging
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct ConfigError(#[from] figment::error::Error);

impl Config {
    /// Parse config from file, env, cli
    pub fn parse(cli: Cli) -> Result<Self, ConfigError> {
        if let Some(path) = &cli.config {
            Ok(Figment::new()
                .merge(Toml::file(path))
                .merge(Env::prefixed(CONFIG_ENV_PREFIX))
                .merge(Serialized::defaults(cli))
                .extract()?)
        } else {
            Ok(Figment::new()
                .merge(Env::prefixed(CONFIG_ENV_PREFIX))
                .merge(Serialized::defaults(cli))
                .extract()?)
        }
    }
}

fn main() -> color_eyre::Result<ExitCode> {
    install_tracing();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("Could not install default rustls crypto provider"))?;

    const T: usize = 4;
    const D: u64 = 5;

    let cli = Cli::parse();
    let config = Config::parse(cli).context("while parsing config")?;

    poseidon2_plain::<ark_bn254::Fr, T, D>(&config)?;

    poseidon2_rep3::<ark_bn254::Fr, T, D>(&config)?;
    poseidon2_rep3_with_precomp::<ark_bn254::Fr, T, D>(&config)?;
    poseidon2_rep3_with_precomp_additive::<ark_bn254::Fr, T, D>(&config)?;

    poseidon2_shamir::<ark_bn254::Fr, T, D>(&config)?;
    poseidon2_shamir_with_precomp::<ark_bn254::Fr, T, D>(&config)?;

    const NUM_POSEIDON: usize = 10;
    poseidon2_shamir_with_precomp_packed::<ark_bn254::Fr, T, D>(&config, NUM_POSEIDON)?;

    Ok(ExitCode::SUCCESS)
}

fn print_runtimes(times: Vec<f64>, id: usize, s: &str) {
    let mut min = f64::INFINITY;
    let mut max = 0f64;
    let mut avg = 0f64;

    let len = times.len();
    for runtime in times {
        avg += runtime;
        min = min.min(runtime);
        max = max.max(runtime);
    }
    avg /= len as f64;

    tracing::info!("{}: Party {}, {} runs", s, id, len);
    tracing::info!("\tavg: {:.2}µs", avg);
    tracing::info!("\tmin: {:.2}µs", min);
    tracing::info!("\tmax: {:.2}µs", max);
}

fn poseidon2_plain<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);

    for _ in 0..config.runs {
        let mut input: Vec<F> = (0..T).map(|_| F::rand(&mut rng)).collect();

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        poseidon2.permutation_in_place(input.as_mut_slice().try_into().unwrap());
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    print_runtimes(times, 0, "Poseidon2 plain");

    Ok(ExitCode::SUCCESS)
}

fn share_random_input_rep3<F: PrimeField, const T: usize, R: Rng + CryptoRng>(
    net: &mut Rep3MpcNet,
    rng: &mut R,
) -> color_eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let share = match net.get_id() {
        rep3::id::PartyID::ID0 => {
            let input: Vec<F> = (0..T).map(|_| F::rand(rng)).collect();
            let shares = rep3::share_field_elements(&input, rng);
            let shares = shares
                .into_iter()
                .map(|s| s.into_iter().collect::<Vec<_>>())
                .collect::<Vec<_>>();

            net.send_next_many(&shares[1])?;
            net.send_many(net.get_id().prev_id(), &shares[2])?;
            shares[0].clone()
        }
        rep3::id::PartyID::ID1 => net.recv_prev_many()?,
        rep3::id::PartyID::ID2 => net.recv_many(net.get_id().next_id())?,
    };

    Ok(share)
}

fn poseidon2_rep3<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    if config.threshold != 1 {
        return Err(color_eyre::Report::msg("Threshold must be 1 for rep3"));
    }

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut id = 0;

    for _ in 0..config.runs {
        // connect to network
        let mut net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
        id = usize::from(net.get_id());

        let mut share = share_random_input_rep3::<F, T, _>(&mut net, &mut rng)?;

        // init MPC protocol
        let mut protocol = IoContext::init(net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        poseidon2
            .rep3_permutation_in_place(share.as_mut_slice().try_into().unwrap(), &mut protocol)?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        sleep(Duration::from_millis(100));
    }

    print_runtimes(times, id, "Poseidon2 rep3");

    Ok(ExitCode::SUCCESS)
}

fn poseidon2_rep3_with_precomp<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    if config.threshold != 1 {
        return Err(color_eyre::Report::msg("Threshold must be 1 for rep3"));
    }

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut id = 0;

    for _ in 0..config.runs {
        // connect to network
        let mut net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
        id = usize::from(net.get_id());

        let mut share = share_random_input_rep3::<F, T, _>(&mut net, &mut rng)?;

        // init MPC protocol
        let mut protocol = IoContext::init(net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        poseidon2.rep3_permutation_in_place_with_precomputation(
            share.as_mut_slice().try_into().unwrap(),
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        sleep(Duration::from_millis(100));
    }

    print_runtimes(times, id, "Poseidon2 rep3 with precomp");

    Ok(ExitCode::SUCCESS)
}

fn poseidon2_rep3_with_precomp_additive<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    if config.threshold != 1 {
        return Err(color_eyre::Report::msg("Threshold must be 1 for rep3"));
    }

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut id = 0;

    for _ in 0..config.runs {
        // connect to network
        let mut net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
        id = usize::from(net.get_id());

        let mut share = share_random_input_rep3::<F, T, _>(&mut net, &mut rng)?;

        // init MPC protocol
        let mut protocol = IoContext::init(net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        poseidon2.rep3_permutation_additive_in_place_with_precomputation(
            share.as_mut_slice().try_into().unwrap(),
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        sleep(Duration::from_millis(100));
    }

    print_runtimes(times, id, "Poseidon2 rep3 with precomp (additive)");

    Ok(ExitCode::SUCCESS)
}

fn share_random_input_shamir<F: PrimeField, const T: usize, R: Rng + CryptoRng>(
    net: &mut ShamirMpcNet,
    threshold: usize,
    num_poseidon: usize,
    rng: &mut R,
) -> color_eyre::Result<Vec<ShamirPrimeFieldShare<F>>> {
    let share = if net.get_id() == 0 {
        let input: Vec<F> = (0..T * num_poseidon).map(|_| F::rand(rng)).collect();
        let shares = shamir::share_field_elements(&input, threshold, net.get_num_parties(), rng);
        let myshare = shares[0].clone();
        for (i, val) in shares.into_iter().enumerate().skip(1) {
            net.send_many(i, &val)?;
        }
        myshare
    } else {
        net.recv_many(0)?
    };

    Ok(share)
}

fn poseidon2_shamir<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);
    let mut id = 0;

    for _ in 0..config.runs {
        // connect to network
        let mut net = ShamirMpcNet::new(config.network.to_owned().try_into()?)?;
        id = net.get_id();

        let mut share =
            share_random_input_shamir::<F, T, _>(&mut net, config.threshold, 1, &mut rng)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(1, false);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(config.threshold, net, num_pairs)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        poseidon2
            .shamir_permutation_in_place(share.as_mut_slice().try_into().unwrap(), &mut protocol)?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        sleep(Duration::from_millis(100));
    }
    print_runtimes(preprocess_times, id, "Poseidon2 shamir-- rand_generation");
    print_runtimes(times, id, "Poseidon2 shamir -- online");

    Ok(ExitCode::SUCCESS)
}

fn poseidon2_shamir_with_precomp<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);
    let mut id = 0;

    for _ in 0..config.runs {
        // connect to network
        let mut net = ShamirMpcNet::new(config.network.to_owned().try_into()?)?;
        id = net.get_id();

        let mut share =
            share_random_input_shamir::<F, T, _>(&mut net, config.threshold, 1, &mut rng)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(1, true);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(config.threshold, net, num_pairs)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_shamir(1, &mut protocol)?;
        poseidon2.shamir_permutation_in_place_with_precomputation(
            share.as_mut_slice().try_into().unwrap(),
            &mut precomp,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        sleep(Duration::from_millis(100));
    }

    print_runtimes(
        preprocess_times,
        id,
        "Poseidon2 shamir with precomp -- rand_generation",
    );
    print_runtimes(times, id, "Poseidon2 shamir with precomp -- online");

    Ok(ExitCode::SUCCESS)
}

fn poseidon2_shamir_with_precomp_packed<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
    num_poseidon: usize,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);
    let mut id = 0;

    for _ in 0..config.runs {
        // connect to network
        let mut net = ShamirMpcNet::new(config.network.to_owned().try_into()?)?;
        id = net.get_id();

        let mut share = share_random_input_shamir::<F, T, _>(
            &mut net,
            config.threshold,
            num_poseidon,
            &mut rng,
        )?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(num_poseidon, true);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(config.threshold, net, num_pairs)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_shamir(num_poseidon, &mut protocol)?;
        poseidon2.shamir_permutation_in_place_with_precomputation_packed(
            &mut share,
            &mut precomp,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        sleep(Duration::from_millis(100));
    }

    print_runtimes(
        preprocess_times,
        id,
        format!(
            "Poseidon2 shamir with precomp packed n={} -- rand_generation",
            num_poseidon
        )
        .as_str(),
    );
    print_runtimes(
        times,
        id,
        format!(
            "Poseidon2 shamir with precomp packed n={} -- online",
            num_poseidon
        )
        .as_str(),
    );

    Ok(ExitCode::SUCCESS)
}
