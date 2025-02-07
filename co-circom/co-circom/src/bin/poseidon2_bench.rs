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

const SLEEP: Duration = Duration::from_millis(200);

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

    /// The batch size for the number of poseidon elements in parallel in packed implementation
    #[arg(short, long, default_value_t = 10)]
    pub batch_size: usize,

    /// The number of leafs in the Merkle tree tree benchmarks
    #[arg(short, long, default_value_t = 1024)]
    pub merkle_size: usize,

    /// Statesize for the hash function
    #[arg(short, long, default_value_t = 3)]
    pub statesize: usize,
}

/// Config
#[derive(Debug, Deserialize)]
pub struct Config {
    /// The number of testruns
    pub runs: usize,
    /// The threshold of tolerated colluding parties
    pub threshold: usize,
    /// The batch size for the number of poseidon elements in parallel in packed implementation
    pub batch_size: usize,
    /// The number of leafs in the Merkle tree benchmarks
    pub merkle_size: usize,
    /// Statesize for the hash function
    pub statesize: usize,
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

    let cli = Cli::parse();
    let config = Config::parse(cli).context("while parsing config")?;

    const D: u64 = 5;
    const ARITY: usize = 2;
    const COMPRESSION_MODE: bool = false;
    type F = ark_bn254::Fr;

    match config.statesize {
        3 => {
            benches::<F, 3, D, ARITY, COMPRESSION_MODE>(&config)?;
        }
        4 => {
            benches::<F, 4, D, ARITY, COMPRESSION_MODE>(&config)?;
        }
        t => {
            return Err(eyre!("Unsupported statesize: {}", t));
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn benches<
    F: PrimeField,
    const T: usize,
    const D: u64,
    const ARITY: usize,
    const COMPRESSION_MODE: bool,
>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    // One permutation
    poseidon2_benches::<F, T, D>(config)?;
    if config.batch_size != 0 {
        // Packed permutations
        poseidon2_packed_benches::<F, T, D>(config)?;
    }

    if config.merkle_size != 0 {
        poseidon2_mt_benches::<F, T, D, ARITY, COMPRESSION_MODE>(config)?;
    }

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_benches<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    poseidon2_plain::<F, T, D>(config)?;
    if config.threshold == 1 {
        // poseidon2_rep3::<F, T, D>(config)?;
        poseidon2_rep3_with_precomp::<F, T, D>(config)?;
        // poseidon2_rep3_with_precomp_additive::<F, T, D>(config)?;
    }
    // poseidon2_shamir::<F, T, D>(config)?;
    poseidon2_shamir_with_precomp::<F, T, D>(config)?;

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_packed_benches<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    poseidon2_plain_packed::<F, T, D>(config)?;
    if config.threshold == 1 {
        poseidon2_rep3_with_precomp_packed::<F, T, D>(config)?;
    }
    poseidon2_shamir_with_precomp_packed::<F, T, D>(config)?;

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_mt_benches<
    F: PrimeField,
    const T: usize,
    const D: u64,
    const ARITY: usize,
    const COMPRESSION_MODE: bool,
>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    poseidon2_mt_plain::<F, T, D, ARITY, COMPRESSION_MODE>(config)?;
    if config.threshold == 1 {
        poseidon2_mt_rep3::<F, T, D, ARITY, COMPRESSION_MODE>(config)?;
    }
    poseidon2_mt_shamir::<F, T, D, ARITY, COMPRESSION_MODE>(config)?;

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

    print_runtimes(times, config.network.my_id, "Poseidon2 plain");
    sleep(SLEEP);

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_plain_packed<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);

    for _ in 0..config.runs {
        let mut input: Vec<F> = (0..config.batch_size * T)
            .map(|_| F::rand(&mut rng))
            .collect();

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        for input in input.chunks_exact_mut(T) {
            poseidon2.permutation_in_place(input.try_into().unwrap());
        }
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    print_runtimes(
        times,
        config.network.my_id,
        format!("Poseidon2 plain packed n={}", config.batch_size).as_str(),
    );
    sleep(SLEEP);

    Ok(ExitCode::SUCCESS)
}

fn next_power_of_n(size: usize, n: usize) -> usize {
    let log = size.ilog(n);
    if size == n.pow(log) {
        size
    } else {
        n.pow(log + 1)
    }
}

#[allow(dead_code)]
fn poseidon2_mt_plain<
    F: PrimeField,
    const T: usize,
    const D: u64,
    const ARITY: usize,
    const COMPRESSION_MODE: bool,
>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();
    let mut times = Vec::with_capacity(config.runs);

    let size = next_power_of_n(config.merkle_size, ARITY);

    for _ in 0..config.runs {
        let input: Vec<F> = (0..size).map(|_| F::rand(&mut rng)).collect();

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        if COMPRESSION_MODE {
            poseidon2.merkle_tree_compression::<ARITY>(input);
        } else {
            poseidon2.merkle_tree_sponge::<ARITY>(input);
        }
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    print_runtimes(
        times,
        config.network.my_id,
        format!("Poseidon2 plain MT ({}:1, n={})", ARITY, config.merkle_size).as_str(),
    );
    sleep(SLEEP);

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn share_random_input_rep3<F: PrimeField, const T: usize, R: Rng + CryptoRng>(
    net: &mut Rep3MpcNet,
    num_elements: usize,
    rng: &mut R,
) -> color_eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let share = match net.get_id() {
        rep3::id::PartyID::ID0 => {
            let input: Vec<F> = (0..num_elements).map(|_| F::rand(rng)).collect();
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

#[allow(dead_code)]
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

    // connect to network
    let net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
    // init MPC protocol
    let mut protocol = IoContext::init(net)?;

    for _ in 0..config.runs {
        let mut share = share_random_input_rep3::<F, T, _>(&mut protocol.network, T, &mut rng)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        poseidon2
            .rep3_permutation_in_place(share.as_mut_slice().try_into().unwrap(), &mut protocol)?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(times, config.network.my_id, "Poseidon2 rep3");

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
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

    // connect to network
    let net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
    // init MPC protocol
    let mut protocol = IoContext::init(net)?;

    for _ in 0..config.runs {
        let mut share = share_random_input_rep3::<F, T, _>(&mut protocol.network, T, &mut rng)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_rep3(1, &mut protocol)?;
        poseidon2.rep3_permutation_in_place_with_precomputation(
            share.as_mut_slice().try_into().unwrap(),
            &mut precomp,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(times, config.network.my_id, "Poseidon2 rep3 with precomp");

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
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

    // connect to network
    let net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
    // init MPC protocol
    let mut protocol = IoContext::init(net)?;

    for _ in 0..config.runs {
        let mut share = share_random_input_rep3::<F, T, _>(&mut protocol.network, T, &mut rng)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_rep3_additive(1, &mut protocol)?;
        poseidon2.rep3_permutation_additive_in_place_with_precomputation(
            share.as_mut_slice().try_into().unwrap(),
            &mut precomp,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(
        times,
        config.network.my_id,
        "Poseidon2 rep3 with precomp (additive)",
    );

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_rep3_with_precomp_packed<F: PrimeField, const T: usize, const D: u64>(
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

    // connect to network
    let net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
    // init MPC protocol
    let mut protocol = IoContext::init(net)?;

    for _ in 0..config.runs {
        let mut share = share_random_input_rep3::<F, T, _>(
            &mut protocol.network,
            config.batch_size * T,
            &mut rng,
        )?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_rep3(config.batch_size, &mut protocol)?;
        poseidon2.rep3_permutation_in_place_with_precomputation_packed(
            &mut share,
            &mut precomp,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(
        times,
        config.network.my_id,
        format!("Poseidon2 rep3 with precomp packed n={}", config.batch_size).as_str(),
    );

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_mt_rep3<
    F: PrimeField,
    const T: usize,
    const D: u64,
    const ARITY: usize,
    const COMPRESSION_MODE: bool,
>(
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

    let size = next_power_of_n(config.merkle_size, ARITY);

    // connect to network
    let net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
    // init MPC protocol
    let mut protocol = IoContext::init(net)?;

    for _ in 0..config.runs {
        let share = share_random_input_rep3::<F, T, _>(&mut protocol.network, size, &mut rng)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        if COMPRESSION_MODE {
            poseidon2.merkle_tree_compression_rep3::<ARITY, _>(share, &mut protocol)?;
        } else {
            poseidon2.merkle_tree_sponge_rep3::<ARITY, _>(share, &mut protocol)?;
        }
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(
        times,
        config.network.my_id,
        format!("Poseidon2 rep3 MT ({}:1, n={})", ARITY, config.merkle_size).as_str(),
    );

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn share_random_input_shamir<F: PrimeField, const T: usize, R: Rng + CryptoRng>(
    net: &mut ShamirMpcNet,
    threshold: usize,
    num_elements: usize,
    rng: &mut R,
) -> color_eyre::Result<Vec<ShamirPrimeFieldShare<F>>> {
    let share = if net.get_id() == 0 {
        let input: Vec<F> = (0..num_elements).map(|_| F::rand(rng)).collect();
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

#[allow(dead_code)]
fn poseidon2_shamir<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);

    // connect to network
    let mut net = ShamirMpcNet::new(config.network.to_owned().try_into()?)?;

    for _ in 0..config.runs {
        let mut share =
            share_random_input_shamir::<F, T, _>(&mut net, config.threshold, T, &mut rng)?;

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

        net = protocol.into_network();
    }

    sleep(SLEEP);
    print_runtimes(
        preprocess_times,
        config.network.my_id,
        "Poseidon2 shamir-- rand_generation",
    );
    print_runtimes(times, config.network.my_id, "Poseidon2 shamir -- online");

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_shamir_with_precomp<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);

    // connect to network
    let mut net = ShamirMpcNet::new(config.network.to_owned().try_into()?)?;

    for _ in 0..config.runs {
        let mut share =
            share_random_input_shamir::<F, T, _>(&mut net, config.threshold, T, &mut rng)?;

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

        net = protocol.into_network();
    }

    sleep(SLEEP);
    print_runtimes(
        preprocess_times,
        config.network.my_id,
        "Poseidon2 shamir with precomp -- rand_generation",
    );
    print_runtimes(
        times,
        config.network.my_id,
        "Poseidon2 shamir with precomp -- online",
    );

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_shamir_with_precomp_packed<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);

    // connect to network
    let mut net = ShamirMpcNet::new(config.network.to_owned().try_into()?)?;

    for _ in 0..config.runs {
        let mut share = share_random_input_shamir::<F, T, _>(
            &mut net,
            config.threshold,
            config.batch_size * T,
            &mut rng,
        )?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(config.batch_size, true);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(config.threshold, net, num_pairs)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_shamir(config.batch_size, &mut protocol)?;
        poseidon2.shamir_permutation_in_place_with_precomputation_packed(
            &mut share,
            &mut precomp,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        net = protocol.into_network();
    }

    sleep(SLEEP);
    print_runtimes(
        preprocess_times,
        config.network.my_id,
        format!(
            "Poseidon2 shamir with precomp packed n={} -- rand_generation",
            config.batch_size
        )
        .as_str(),
    );
    print_runtimes(
        times,
        config.network.my_id,
        format!(
            "Poseidon2 shamir with precomp packed n={} -- online",
            config.batch_size
        )
        .as_str(),
    );

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_mt_shamir<
    F: PrimeField,
    const T: usize,
    const D: u64,
    const ARITY: usize,
    const COMPRESSION_MODE: bool,
>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let mut rng = rand::thread_rng();
    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);

    let size = next_power_of_n(config.merkle_size, ARITY);
    let num_hashes = (size - 1) / (ARITY - 1);

    // connect to network
    let mut net = ShamirMpcNet::new(config.network.to_owned().try_into()?)?;

    for _ in 0..config.runs {
        let share =
            share_random_input_shamir::<F, T, _>(&mut net, config.threshold, size, &mut rng)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(num_hashes, true);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(config.threshold, net, num_pairs)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        if COMPRESSION_MODE {
            poseidon2.merkle_tree_compression_shamir::<ARITY, _>(share, &mut protocol)?;
        } else {
            poseidon2.merkle_tree_sponge_shamir::<ARITY, _>(share, &mut protocol)?;
        }
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        net = protocol.into_network();
    }

    sleep(SLEEP);
    print_runtimes(
        preprocess_times,
        config.network.my_id,
        format!(
            "Poseidon2 shamir with MT ({}:1, n={}) -- rand_generation",
            ARITY, config.merkle_size
        )
        .as_str(),
    );
    print_runtimes(
        times,
        config.network.my_id,
        format!(
            "Poseidon2 shamir with MT ({}:1, n={}) -- online",
            ARITY, config.merkle_size
        )
        .as_str(),
    );

    Ok(ExitCode::SUCCESS)
}
