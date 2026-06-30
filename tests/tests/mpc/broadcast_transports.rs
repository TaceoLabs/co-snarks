//! Large-payload `broadcast_many` over the real TCP / TLS / QUIC transports.
//!
//! Guards the `broadcast_many` reorder (send-all-then-recv-all): the payloads are
//! deliberately larger than a kernel socket buffer, so each `send_many` must make
//! progress *while the peer is still in its own send phase*. The pre-reorder code
//! relied on `mpc_net::join` to avoid a ring deadlock here; this test fails (hangs)
//! if someone reverts to an interleaved `send;recv;send;recv` ordering.

use std::net::{SocketAddr, TcpListener, UdpSocket};

use ark_bn254::Fr;
use ark_ff::Zero;
use mpc_core::protocols::rep3::network::Rep3NetworkExt;
use mpc_net::{config::Address, Network};

/// ~9.6 MB serialized (32 bytes/elem) — comfortably exceeds default socket buffers.
const BIG_LEN: usize = 300_000;

/// Each party broadcasts a vector tagged with its own id, then verifies it got the
/// expected vectors back from its `prev` and `next` neighbours.
fn assert_broadcast<N: Network>(net: &N) -> eyre::Result<()> {
    let my = net.id();
    let tag = Fr::from((my + 1) as u64);
    let data = vec![tag; BIG_LEN];

    let (prev_res, next_res) = net.broadcast_many(&data)?;
    // Confirm all buffered sends have been handed off to the OS (no-op on backends
    // that write inline; drains the writer thread on TCP/TLS).
    net.flush()?;

    let prev = (my + 2) % 3;
    let next = (my + 1) % 3;
    assert_eq!(prev_res.len(), BIG_LEN);
    assert_eq!(next_res.len(), BIG_LEN);
    assert!(prev_res.iter().all(|&x| x == Fr::from((prev + 1) as u64)));
    assert!(next_res.iter().all(|&x| x == Fr::from((next + 1) as u64)));
    assert!(!tag.is_zero()); // sanity
    Ok(())
}

/// Build all three party networks concurrently (each constructor blocks on the
/// connection handshake), then run the broadcast round on each.
fn run_round<N: Network>(builders: Vec<Box<dyn FnOnce() -> eyre::Result<N> + Send>>) {
    std::thread::scope(|s| {
        let handles: Vec<_> = builders
            .into_iter()
            .map(|build| {
                s.spawn(move || -> eyre::Result<()> {
                    let net = build()?;
                    assert_broadcast(&net)
                })
            })
            .collect();
        for h in handles {
            h.join()
                .expect("party thread panicked")
                .expect("broadcast round failed");
        }
    });
}

/// Reserve `n` free TCP ports on loopback (released as the listeners drop).
fn free_tcp_addrs(n: usize) -> Vec<SocketAddr> {
    let ls: Vec<_> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    ls.iter().map(|l| l.local_addr().unwrap()).collect()
}

/// Reserve `n` free UDP ports on loopback (for QUIC).
fn free_udp_addrs(n: usize) -> Vec<SocketAddr> {
    let ss: Vec<_> = (0..n)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    ss.iter().map(|s| s.local_addr().unwrap()).collect()
}

fn install_crypto_provider() {
    // Idempotent across tests in the same process; ignore "already installed".
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[test]
fn tcp_large_broadcast() {
    use mpc_net::tcp::{NetworkConfig, NetworkParty, TcpNetwork};

    let addrs = free_tcp_addrs(3);
    let parties: Vec<_> = addrs
        .iter()
        .enumerate()
        .map(|(id, a)| NetworkParty::new(id, Address::new("127.0.0.1".into(), a.port())))
        .collect();

    let builders = (0..3)
        .map(|id| {
            let parties = parties.clone();
            let bind = addrs[id];
            Box::new(move || TcpNetwork::new(NetworkConfig::new(id, bind, parties, None, None)))
                as Box<dyn FnOnce() -> eyre::Result<TcpNetwork> + Send>
        })
        .collect();

    run_round(builders);
}

#[test]
fn tls_large_broadcast() {
    use mpc_net::tls::{NetworkConfig, NetworkParty, TlsNetwork};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    install_crypto_provider();
    let addrs = free_tcp_addrs(3);

    // One self-signed cert+key per party; SAN must cover what we connect to.
    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for _ in 0..3 {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        certs.push(ck.cert.der().clone());
        keys.push(ck.key_pair.serialize_der());
    }

    let parties: Vec<_> = addrs
        .iter()
        .enumerate()
        .map(|(id, a)| {
            NetworkParty::new(
                id,
                Address::new("127.0.0.1".into(), a.port()),
                certs[id].clone(),
            )
        })
        .collect();

    let builders = (0..3)
        .map(|id| {
            let parties = parties.clone();
            let bind = addrs[id];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keys[id].clone()));
            Box::new(move || {
                TlsNetwork::new(NetworkConfig::new(id, bind, key, parties, None, None))
            }) as Box<dyn FnOnce() -> eyre::Result<TlsNetwork> + Send>
        })
        .collect();

    run_round(builders);
}

#[test]
fn quic_large_broadcast() {
    use mpc_net::quic::{NetworkConfig, NetworkParty, QuicNetwork};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    install_crypto_provider();
    let addrs = free_udp_addrs(3);

    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for _ in 0..3 {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        certs.push(ck.cert.der().clone());
        keys.push(ck.key_pair.serialize_der());
    }

    let parties: Vec<_> = addrs
        .iter()
        .enumerate()
        .map(|(id, a)| {
            NetworkParty::new(
                id,
                Address::new("127.0.0.1".into(), a.port()),
                certs[id].clone(),
            )
        })
        .collect();

    let builders = (0..3)
        .map(|id| {
            let parties = parties.clone();
            let bind = addrs[id];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keys[id].clone()));
            Box::new(move || {
                QuicNetwork::new(NetworkConfig::new(id, bind, key, parties, None, None))
            }) as Box<dyn FnOnce() -> eyre::Result<QuicNetwork> + Send>
        })
        .collect();

    run_round(builders);
}
