//! Shared helpers for spinning up real networked backends (TCP/TLS/QUIC) in tests.
#![allow(dead_code)]

use std::net::ToSocketAddrs;
use std::time::Duration;

use bytes::Bytes;
use mpc_net::Network;
use mpc_net::config::{Address, NetworkConfig, NetworkConfigBuilder, NetworkParty, TlsConfig};
use reserve_port::ReservedPort;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

pub fn configs(num_parties: usize) -> Vec<NetworkConfig> {
    let ports = (0..num_parties)
        .map(|_| ReservedPort::random_permanently_reserved().unwrap())
        .collect::<Vec<_>>();
    let parties: Vec<NetworkParty> = ports
        .iter()
        .enumerate()
        .map(|(id, port)| NetworkParty::new(id, Address::new("127.0.0.1".to_string(), *port)))
        .collect();
    let certified_keys: Vec<_> = (0..num_parties)
        .map(|_| rcgen::generate_simple_self_signed(["127.0.0.1".to_string()]).unwrap())
        .collect();
    let certs: Vec<_> = certified_keys
        .iter()
        .map(|ck| ck.cert.der().clone())
        .collect();
    let tls_configs: Vec<_> = certified_keys
        .into_iter()
        .map(|ck| {
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
            TlsConfig::new(key, certs.clone())
        })
        .collect();
    parties
        .iter()
        .enumerate()
        .map(|(id, party)| {
            NetworkConfigBuilder::new(
                id,
                party.dns_name.to_socket_addrs().unwrap().next().unwrap(),
                parties.clone(),
            )
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .tls_config(tls_configs[id].clone())
            .build()
        })
        .collect()
}

/// Install the default `rustls` crypto provider, required once per process before building any
/// TLS or QUIC config. Safe to call from multiple tests/threads.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("no other provider installed yet");
    });
}

pub fn round_trip<N: Network>(network: &N) -> eyre::Result<()> {
    let my_id = network.id();
    for id in 0..3 {
        if id != my_id {
            network.send(id, Bytes::from(vec![my_id as u8; 1024]))?;
        }
    }
    for id in 0..3 {
        if id != my_id {
            let buf = network.recv(id)?;
            assert!(buf.iter().all(|&b| b == id as u8));
        }
    }
    network.flush()?;
    let stats = network.get_connection_stats();
    for id in 0..3 {
        if id != my_id {
            assert_eq!(stats.get(id), Some((1024, 1024)));
        }
    }
    Ok(())
}
