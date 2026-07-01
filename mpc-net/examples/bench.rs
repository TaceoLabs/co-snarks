//! Benchmark different message sizes and round-trip counts over a loopback TCP network.

use std::{net::SocketAddr, time::Instant};

use bytes::Bytes;
use color_eyre::Result;
use mpc_net::{
    Network as _,
    config::Address,
    tcp::{NetworkConfig, NetworkParty, TcpNetwork},
};

const N: usize = 3;
const BASE_PORT: u16 = 11000;

// (message size in bytes, round-trip count)
const CASES: [(usize, usize); 8] = [
    (64, 10_000),
    (1_024, 5_000),
    (16 * 1_024, 1_000),
    (256 * 1_024, 200),
    (1_024 * 1_024, 50),
    (16 * 1_024 * 1_024, 10),
    (64 * 1_024 * 1_024, 10),
    (256 * 1_024 * 1_024, 10),
];

fn make_config(my_id: usize) -> NetworkConfig {
    let parties = (0..N)
        .map(|i| {
            NetworkParty::new(
                i,
                Address::new("127.0.0.1".to_string(), BASE_PORT + i as u16),
            )
        })
        .collect();
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", BASE_PORT + my_id as u16)
        .parse()
        .expect("valid addr");
    NetworkConfig::new(my_id, bind_addr, parties, None, Some(usize::MAX))
}

fn run_party(my_id: usize, msg_size: usize, rounds: usize) -> Result<()> {
    let network = TcpNetwork::new(make_config(my_id))?;
    let others: Vec<usize> = (0..N).filter(|&i| i != my_id).collect();

    // warmup
    for &peer in &others {
        network.send(peer, Bytes::from(vec![0u8; 4096]))?;
    }
    for &peer in &others {
        network.recv(peer)?;
    }
    network.flush()?;

    let payload = Bytes::from(vec![my_id as u8; msg_size]);

    let start = Instant::now();
    for _ in 0..rounds {
        for &peer in &others {
            network.send(peer, payload.clone())?;
        }
        for &peer in &others {
            network.recv(peer)?;
        }
    }
    network.flush()?;
    let elapsed = start.elapsed();

    if my_id == 0 {
        // bytes sent + received by party 0 across all peers
        let total = msg_size * rounds * others.len() * 2;
        let mbs = total as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        println!(
            "{:<12}  {:>8}  {:>12.2}  {:>10.2} MB/s",
            fmt_size(msg_size),
            rounds,
            elapsed.as_secs_f64() * 1000.0,
            mbs,
        );
    }

    Ok(())
}

fn fmt_size(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{} MiB", n / (1024 * 1024))
    } else if n >= 1024 {
        format!("{} KiB", n / 1024)
    } else {
        format!("{} B", n)
    }
}

fn main() -> Result<()> {
    println!(
        "{:<12}  {:>8}  {:>12}  {:>13}",
        "msg_size", "rounds", "time_ms", "throughput"
    );
    println!("{}", "-".repeat(52));
    std::thread::scope(|s| {
        for id in 0..N {
            s.spawn(move || {
                for (msg_size, rounds) in CASES {
                    run_party(id, msg_size, rounds).expect("does not panic");
                }
            });
        }
        Ok(())
    })
}
