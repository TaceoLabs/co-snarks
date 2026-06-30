//! `Network` round-trips over the real TCP / TLS / QUIC transports.
//!
//! Two shapes are exercised per transport:
//! - `*_large_broadcast`: one ~9.6 MB `broadcast_many` per party. Guards the
//!   `broadcast_many` reorder and the large-frame paths (incl. the vectored-write
//!   partial-write fallback in the blocking core).
//! - `*_many_small_frames`: thousands of tiny back-to-back frames in a ring. Guards
//!   framing correctness across the vectored send path and sequential reads.

use std::net::{SocketAddr, TcpListener, UdpSocket};

use ark_bn254::Fr;
use ark_ff::Zero;
use mpc_core::protocols::rep3::network::Rep3NetworkExt;
use mpc_net::{config::Address, Network};

/// ~9.6 MB serialized (32 bytes/elem) — comfortably exceeds default socket buffers.
const BIG_LEN: usize = 300_000;
/// Number of tiny frames each party streams to its neighbour.
const N_FRAMES: usize = 1000;

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

/// Stream `N_FRAMES` tiny frames to `next` while receiving from `prev` in lockstep,
/// verifying every frame's content and order.
fn assert_many_frames<N: Network>(net: &N) -> eyre::Result<()> {
    let my = net.id();
    let next = (my + 1) % 3;
    let prev = (my + 2) % 3;
    for k in 0..N_FRAMES {
        net.send(next, format!("{my}:{k}").into_bytes().into())?;
        let got = net.recv(prev)?;
        assert_eq!(&got[..], format!("{prev}:{k}").as_bytes());
    }
    net.flush()?;
    Ok(())
}

/// Exchange one frame, then perform a coordinated graceful `shutdown`. `shutdown` must
/// drain every peer (flush + sentinel barrier) and return without hanging.
fn assert_shutdown<N: Network>(net: &N) -> eyre::Result<()> {
    let my = net.id();
    let next = (my + 1) % 3;
    let prev = (my + 2) % 3;
    net.send(next, vec![my as u8; 64].into())?;
    let got = net.recv(prev)?;
    assert_eq!(got.len(), 64);
    net.shutdown()?;
    Ok(())
}

/// Build all three party networks concurrently (each constructor blocks on the
/// connection handshake), then run `body` on each.
fn run_round<N: Network>(
    builders: Vec<Box<dyn FnOnce() -> eyre::Result<N> + Send>>,
    body: fn(&N) -> eyre::Result<()>,
) {
    std::thread::scope(|s| {
        let handles: Vec<_> = builders
            .into_iter()
            .map(|build| {
                s.spawn(move || -> eyre::Result<()> {
                    let net = build()?;
                    body(&net)
                })
            })
            .collect();
        for h in handles {
            h.join()
                .expect("party thread panicked")
                .expect("transport test body failed");
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

fn tcp_builders() -> Vec<Box<dyn FnOnce() -> eyre::Result<mpc_net::tcp::TcpNetwork> + Send>> {
    use mpc_net::tcp::{NetworkConfig, NetworkParty, TcpNetwork};

    let addrs = free_tcp_addrs(3);
    let parties: Vec<_> = addrs
        .iter()
        .enumerate()
        .map(|(id, a)| NetworkParty::new(id, Address::new("127.0.0.1".into(), a.port())))
        .collect();

    (0..3)
        .map(|id| {
            let parties = parties.clone();
            let bind = addrs[id];
            Box::new(move || TcpNetwork::new(NetworkConfig::new(id, bind, parties, None, None)))
                as Box<dyn FnOnce() -> eyre::Result<TcpNetwork> + Send>
        })
        .collect()
}

fn tls_builders() -> Vec<Box<dyn FnOnce() -> eyre::Result<mpc_net::tls::TlsNetwork> + Send>> {
    use mpc_net::tls::{NetworkConfig, NetworkParty, TlsNetwork};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    install_crypto_provider();
    let addrs = free_tcp_addrs(3);

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

    (0..3)
        .map(|id| {
            let parties = parties.clone();
            let bind = addrs[id];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keys[id].clone()));
            Box::new(move || {
                TlsNetwork::new(NetworkConfig::new(id, bind, key, parties, None, None))
            }) as Box<dyn FnOnce() -> eyre::Result<TlsNetwork> + Send>
        })
        .collect()
}

fn quic_builders() -> Vec<Box<dyn FnOnce() -> eyre::Result<mpc_net::quic::QuicNetwork> + Send>> {
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

    (0..3)
        .map(|id| {
            let parties = parties.clone();
            let bind = addrs[id];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keys[id].clone()));
            Box::new(move || {
                QuicNetwork::new(NetworkConfig::new(id, bind, key, parties, None, None))
            }) as Box<dyn FnOnce() -> eyre::Result<QuicNetwork> + Send>
        })
        .collect()
}

#[test]
fn tcp_large_broadcast() {
    run_round(tcp_builders(), assert_broadcast);
}

#[test]
fn tls_large_broadcast() {
    run_round(tls_builders(), assert_broadcast);
}

#[test]
fn quic_large_broadcast() {
    run_round(quic_builders(), assert_broadcast);
}

#[test]
fn tcp_many_small_frames() {
    run_round(tcp_builders(), assert_many_frames);
}

#[test]
fn tls_many_small_frames() {
    run_round(tls_builders(), assert_many_frames);
}

#[test]
fn tcp_graceful_shutdown() {
    run_round(tcp_builders(), assert_shutdown);
}

#[test]
fn tls_graceful_shutdown() {
    run_round(tls_builders(), assert_shutdown);
}

#[test]
fn quic_graceful_shutdown() {
    run_round(quic_builders(), assert_shutdown);
}
