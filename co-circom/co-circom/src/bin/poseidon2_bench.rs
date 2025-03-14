use ark_ff::PrimeField;
use clap::{value_parser, Parser};
use color_eyre::eyre::{self, eyre, Context};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::{
        rep3::{self, Rep3PartyId, Rep3PrimeFieldShare, Rep3State, PARTY_0, PARTY_1, PARTY_2},
        shamir::{self, ShamirPreprocessing, ShamirPrimeFieldShare, ShamirProtocol},
    },
};
use mpc_engine::{Address, Network, TcpNetwork};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
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
    /// Our id in the network.
    #[arg(long)]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub id: Option<usize>,
    #[arg(long)]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    /// The [SocketAddr] we bind to.
    pub bind_addr: Option<SocketAddr>,
    #[arg(long, value_delimiter = ',', value_parser = value_parser!(Address))]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    /// Party addresses (including own and in order of id).
    pub party_addrs: Option<Vec<Address>>,
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
    /// Our id in the network.
    pub id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// Party addresses (including own and in order of id).
    pub party_addrs: Vec<Address>,
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
            eyre::bail!("Unsupported statesize: {}", t);
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
    if config.party_addrs.len() == 3 && config.threshold == 1 {
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
    if config.party_addrs.len() == 3 && config.threshold == 1 {
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
    if config.party_addrs.len() == 3 && config.threshold == 1 {
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

    print_runtimes(times, config.id, "Poseidon2 plain");
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
        config.id,
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
        config.id,
        format!("Poseidon2 plain MT ({}:1, n={})", ARITY, config.merkle_size).as_str(),
    );
    sleep(SLEEP);

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn share_random_input_rep3<F: PrimeField, const T: usize, R: Rng + CryptoRng, N: Network>(
    num_elements: usize,
    rng: &mut R,
    net: &N,
) -> color_eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let share = match net.id() {
        PARTY_0 => {
            let input: Vec<F> = (0..num_elements).map(|_| F::rand(rng)).collect();
            let shares = rep3::share_field_elements(&input, rng);
            let shares = shares
                .into_iter()
                .map(|s| s.into_iter().collect::<Vec<_>>())
                .collect::<Vec<_>>();

            rep3::network::send_next_many(net, &shares[1])?;
            rep3::network::send_many(net, net.id().prev(), &shares[2])?;
            shares[0].clone()
        }
        PARTY_1 => rep3::network::recv_prev_many(net)?,
        PARTY_2 => rep3::network::recv_many(net, net.id().next())?,
        _ => unreachable!(),
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
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    if config.threshold != 1 {
        eyre::bail!("Threshold must be 1 for rep3");
    }

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    let mut state = Rep3State::new(&net)?;
    for _ in 0..config.runs {
        let mut share = share_random_input_rep3::<F, T, _, _>(T, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        poseidon2.rep3_permutation_in_place(
            share.as_mut_slice().try_into().unwrap(),
            &net,
            &mut state,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(times, config.id, "Poseidon2 rep3");

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_rep3_with_precomp<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    if config.threshold != 1 {
        eyre::bail!("Threshold must be 1 for rep3");
    }

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    let mut state = Rep3State::new(&net)?;

    for _ in 0..config.runs {
        let mut share = share_random_input_rep3::<F, T, _, _>(T, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_rep3(1, &net, &mut state)?;
        poseidon2.rep3_permutation_in_place_with_precomputation(
            share.as_mut_slice().try_into().unwrap(),
            &mut precomp,
            &net,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(times, id, "Poseidon2 rep3 with precomp");

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_rep3_with_precomp_additive<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    if config.threshold != 1 {
        eyre::bail!("Threshold must be 1 for rep3");
    }

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    let mut state = Rep3State::new(&net)?;

    for _ in 0..config.runs {
        let mut share = share_random_input_rep3::<F, T, _, _>(T, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_rep3_additive(1, &net, &mut state)?;
        poseidon2.rep3_permutation_additive_in_place_with_precomputation(
            share.as_mut_slice().try_into().unwrap(),
            &mut precomp,
            &net,
            &mut state,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(times, id, "Poseidon2 rep3 with precomp (additive)");

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_rep3_with_precomp_packed<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let batch_size = config.batch_size;
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    if config.threshold != 1 {
        eyre::bail!("Threshold must be 1 for rep3");
    }

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    let mut state = Rep3State::new(&net)?;

    for _ in 0..config.runs {
        let mut share = share_random_input_rep3::<F, T, _, _>(batch_size * T, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_rep3(batch_size, &net, &mut state)?;
        poseidon2.rep3_permutation_in_place_with_precomputation_packed(
            &mut share,
            &mut precomp,
            &net,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(
        times,
        id,
        format!("Poseidon2 rep3 with precomp packed n={batch_size}").as_str(),
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
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    if config.threshold != 1 {
        eyre::bail!("Threshold must be 1 for rep3");
    }

    let mut rng = rand::thread_rng();
    let mut times = Vec::with_capacity(config.runs);

    let size = next_power_of_n(config.merkle_size, ARITY);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    let mut state = Rep3State::new(&net)?;

    for _ in 0..config.runs {
        let share = share_random_input_rep3::<F, T, _, _>(size, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        let start = Instant::now();
        if COMPRESSION_MODE {
            poseidon2.merkle_tree_compression_rep3::<ARITY, _>(share, &net, &mut state)?;
        } else {
            poseidon2.merkle_tree_sponge_rep3::<ARITY, _>(share, &net, &mut state)?;
        }
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(
        times,
        id,
        format!("Poseidon2 rep3 MT ({}:1, n={})", ARITY, config.merkle_size).as_str(),
    );

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn share_random_input_shamir<F: PrimeField, const T: usize, R: Rng + CryptoRng, N: Network>(
    num_parties: usize,
    threshold: usize,
    num_elements: usize,
    rng: &mut R,
    net: &N,
) -> color_eyre::Result<Vec<ShamirPrimeFieldShare<F>>> {
    let share = if net.id() == PARTY_0 {
        let input: Vec<F> = (0..num_elements).map(|_| F::rand(rng)).collect();
        let shares = shamir::share_field_elements(&input, threshold, num_parties, rng);
        let myshare = shares[0].clone();
        for (i, val) in shares.into_iter().enumerate().skip(1) {
            shamir::network::send_many(net, i, &val)?;
        }
        myshare
    } else {
        shamir::network::recv_many(net, 0)?
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
    let n = config.party_addrs.len();
    let t = config.threshold;
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    for _ in 0..config.runs {
        let mut share = share_random_input_shamir::<F, T, _, _>(n, t, T, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(1, false);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(n, t, num_pairs, &net)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        poseidon2.shamir_permutation_in_place(
            share.as_mut_slice().try_into().unwrap(),
            &net,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(preprocess_times, id, "Poseidon2 shamir-- rand_generation");
    print_runtimes(times, id, "Poseidon2 shamir -- online");

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_shamir_with_precomp<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let n = config.party_addrs.len();
    let t = config.threshold;
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    for _ in 0..config.runs {
        let mut share = share_random_input_shamir::<F, T, _, _>(n, t, T, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(1, true);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(n, t, num_pairs, &net)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_shamir(1, &net, &mut protocol)?;
        poseidon2.shamir_permutation_in_place_with_precomputation(
            share.as_mut_slice().try_into().unwrap(),
            &mut precomp,
            &net,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(
        preprocess_times,
        id,
        "Poseidon2 shamir with precomp -- rand_generation",
    );
    print_runtimes(times, id, "Poseidon2 shamir with precomp -- online");

    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn poseidon2_shamir_with_precomp_packed<F: PrimeField, const T: usize, const D: u64>(
    config: &Config,
) -> color_eyre::Result<ExitCode>
where
    Poseidon2<F, T, D>: Default,
{
    let n = config.party_addrs.len();
    let t = config.threshold;
    let batch_size = config.batch_size;
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    let mut rng = rand::thread_rng();

    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    for _ in 0..config.runs {
        let mut share =
            share_random_input_shamir::<F, T, _, _>(n, t, batch_size * T, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(batch_size, true);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(n, t, num_pairs, &net)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        let mut precomp = poseidon2.precompute_shamir(batch_size, &net, &mut protocol)?;
        poseidon2.shamir_permutation_in_place_with_precomputation_packed(
            &mut share,
            &mut precomp,
            &net,
            &mut protocol,
        )?;
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(
        preprocess_times,
        id,
        format!("Poseidon2 shamir with precomp packed n={batch_size} -- rand_generation").as_str(),
    );
    print_runtimes(
        times,
        id,
        format!("Poseidon2 shamir with precomp packed n={batch_size} -- online").as_str(),
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
    let n = config.party_addrs.len();
    let t = config.threshold;
    let id = config.id;
    let bind_addr = config.bind_addr;
    let party_addrs = &config.party_addrs;

    let mut rng = rand::thread_rng();
    let mut times = Vec::with_capacity(config.runs);
    let mut preprocess_times = Vec::with_capacity(config.runs);

    let size = next_power_of_n(config.merkle_size, ARITY);
    let num_hashes = (size - 1) / (ARITY - 1);

    // connect to network
    let net = TcpNetwork::networks(id, bind_addr, party_addrs, 1)?
        .pop()
        .unwrap();

    for _ in 0..config.runs {
        let share = share_random_input_shamir::<F, T, _, _>(n, t, size, &mut rng, &net)?;

        let poseidon2 = Poseidon2::<F, T, D>::default();

        // init MPC protocol
        let num_pairs = poseidon2.rand_required(num_hashes, true);
        let start = Instant::now();
        let preprocessing = ShamirPreprocessing::new(n, t, num_pairs, &net)?;
        let duration = start.elapsed().as_micros() as f64;
        preprocess_times.push(duration);
        let mut protocol = ShamirProtocol::from(preprocessing);

        let start = Instant::now();
        if COMPRESSION_MODE {
            poseidon2.merkle_tree_compression_shamir::<ARITY, _>(share, &net, &mut protocol)?;
        } else {
            poseidon2.merkle_tree_sponge_shamir::<ARITY, _>(share, &net, &mut protocol)?;
        }
        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);
    }

    sleep(SLEEP);
    print_runtimes(
        preprocess_times,
        id,
        format!(
            "Poseidon2 shamir with MT ({}:1, n={}) -- rand_generation",
            ARITY, config.merkle_size
        )
        .as_str(),
    );
    print_runtimes(
        times,
        id,
        format!(
            "Poseidon2 shamir with MT ({}:1, n={}) -- online",
            ARITY, config.merkle_size
        )
        .as_str(),
    );

    Ok(ExitCode::SUCCESS)
}
