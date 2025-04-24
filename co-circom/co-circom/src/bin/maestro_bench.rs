use ark_ff::PrimeField;
use clap::Parser;
use co_circom::PartyID;
use color_eyre::eyre::{eyre, Context};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use mpc_core::protocols::{
    rep3::{
        self,
        network::{IoContext, Rep3MpcNet, Rep3Network},
        Rep3PrimeFieldShare,
    },
    rep3_ring::{
        self,
        ring::{bit::Bit, int_ring::IntRing2k},
        Rep3RingShare,
    },
};
use mpc_net::config::NetworkConfigFile;
use num_bigint::BigUint;
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

    /// The size of the array in 2^k
    #[arg(short, long, default_value_t = 10)]
    pub k: usize,
}

/// Config
#[derive(Debug, Deserialize)]
pub struct Config {
    /// The number of testruns
    pub runs: usize,
    /// The size of the array in 2^k
    pub k: usize,
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

fn main() -> color_eyre::Result<ExitCode> {
    install_tracing();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("Could not install default rustls crypto provider"))?;

    let cli = Cli::parse();
    let config = Config::parse(cli).context("while parsing config")?;

    type F = ark_bn254::Fr;

    benches::<F>(&config)?;

    Ok(ExitCode::SUCCESS)
}

fn benches<F: PrimeField>(config: &Config) -> color_eyre::Result<ExitCode> {
    maestro_bench::<F>(config)?;

    a2b_sequential_internal::<F>(config)?;
    Ok(ExitCode::SUCCESS)
}

#[allow(dead_code)]
fn share_random_index_rep3<F: PrimeField, R: Rng + CryptoRng>(
    net: &mut Rep3MpcNet,
    k: usize,
    rng: &mut R,
) -> color_eyre::Result<Rep3PrimeFieldShare<F>> {
    let elements = 1 << k;
    let share = match net.get_id() {
        PartyID::ID0 => {
            let index = rng.gen_range(0..elements);
            let index_f = F::from(index as u64);
            let shares = rep3::share_field_element(index_f, rng);

            net.send_next(shares[1])?;
            net.send(net.get_id().prev_id(), shares[2])?;
            shares[0]
        }
        PartyID::ID1 => net.recv_prev()?,
        PartyID::ID2 => net.recv(net.get_id().next_id())?,
    };

    Ok(share)
}

fn maestro_bench<F: PrimeField>(config: &Config) -> color_eyre::Result<ExitCode> {
    if config.k == 1 {
        maestro_bench_internal::<Bit, F>(config)
    } else if config.k <= 8 {
        maestro_bench_internal::<u8, F>(config)
    } else if config.k <= 16 {
        maestro_bench_internal::<u16, F>(config)
    } else if config.k <= 32 {
        maestro_bench_internal::<u32, F>(config)
    } else {
        panic!("Table is too large")
    }
}

fn maestro_bench_internal<T: IntRing2k, F: PrimeField>(
    config: &Config,
) -> color_eyre::Result<ExitCode> {
    let mut rng = rand::thread_rng();
    let mut times = Vec::with_capacity(config.runs);

    // connect to network
    let net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
    // init MPC protocol
    let mut protocol = IoContext::init(net)?;

    for _ in 0..config.runs {
        let index = share_random_index_rep3::<F, _>(&mut protocol.network, config.k, &mut rng)?;

        let start = Instant::now();

        let index_bin = rep3::conversion::a2b_selector(index, &mut protocol)?;
        let a = T::cast_from_biguint(&index_bin.a);
        let b = T::cast_from_biguint(&index_bin.b);
        let share = Rep3RingShare::new(a, b);
        let ohv = rep3_ring::gadgets::ohv::ohv(config.k, share, &mut protocol)?;

        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        // Check results
        let opened_index = rep3::arithmetic::open(index, &mut protocol)?;
        let ohv_opened = rep3_ring::arithmetic::open_vec(&ohv, &mut protocol)?;
        assert!(opened_index < F::from(1 << config.k));
        let index: BigUint = opened_index.into();
        let index = index.iter_u64_digits().next().unwrap_or_default();
        assert_eq!(opened_index, F::from(index));

        for (i, bit) in ohv_opened.into_iter().enumerate() {
            if i as u64 == index {
                assert!(bit.convert().convert(), "i = {}, index = {}", i, index);
            } else {
                assert!(!bit.convert().convert(), "i = {}, index = {}", i, index);
            }
        }
    }

    sleep(SLEEP);
    print_runtimes(
        times,
        config.network.my_id,
        format!("MAESTRO (2^{})", config.k).as_str(),
    );

    Ok(ExitCode::SUCCESS)
}

fn a2b_sequential_internal<F: PrimeField>(config: &Config) -> color_eyre::Result<ExitCode> {
    let mut rng = rand::thread_rng();
    let mut times = Vec::with_capacity(config.runs);

    let elements = (1 << config.k) as u64;

    // connect to network
    let net = Rep3MpcNet::new(config.network.to_owned().try_into()?)?;
    // init MPC protocol
    let mut protocol = IoContext::init(net)?;

    for _ in 0..config.runs {
        let index = share_random_index_rep3::<F, _>(&mut protocol.network, config.k, &mut rng)?;

        let start = Instant::now();

        let mut ohv = Vec::with_capacity(elements as usize);
        for i in 0..elements {
            let diff = rep3::arithmetic::add_public(index, -F::from(i), protocol.id);
            let diff_bin = rep3::conversion::a2b_selector(diff, &mut protocol)?;

            let is_zero = rep3::binary::is_zero(&diff_bin, &mut protocol)?;
            let is_zero = rep3_ring::Rep3RingShare::new(
                Bit::cast_from_biguint(&is_zero.a),
                Bit::cast_from_biguint(&is_zero.b),
            );
            ohv.push(is_zero);
        }

        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        // Check results
        let opened_index = rep3::arithmetic::open(index, &mut protocol)?;
        let ohv_opened = rep3_ring::arithmetic::open_vec(&ohv, &mut protocol)?;
        assert!(opened_index < F::from(elements));
        let index: BigUint = opened_index.into();
        let index = index.iter_u64_digits().next().unwrap_or_default();
        assert_eq!(opened_index, F::from(index));

        for (i, bit) in ohv_opened.into_iter().enumerate() {
            if i as u64 == index {
                assert!(bit.convert().convert(), "i = {}, index = {}", i, index);
            } else {
                assert!(!bit.convert().convert(), "i = {}, index = {}", i, index);
            }
        }
    }

    sleep(SLEEP);
    print_runtimes(
        times,
        config.network.my_id,
        format!("A2B Sequential (2^{})", config.k).as_str(),
    );

    Ok(ExitCode::SUCCESS)
}
