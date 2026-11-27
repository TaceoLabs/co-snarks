//! Tests for `mpc_net::quic::QuicNetwork`.
#![cfg(feature = "quic")]

use mpc_net::{join3, quic::QuicNetwork};

mod common;

#[test]
fn three_party_network_round_trip_and_stats() {
    common::install_crypto_provider();
    let configs = common::configs(3);
    let [c0, c1, c2] = <[_; 3]>::try_from(configs).unwrap();

    let (n0, n1, n2) = join3(
        move || QuicNetwork::new(c0).unwrap(),
        move || QuicNetwork::new(c1).unwrap(),
        move || QuicNetwork::new(c2).unwrap(),
    );

    let (r0, r1, r2) = join3(
        move || common::round_trip(&n0),
        move || common::round_trip(&n1),
        move || common::round_trip(&n2),
    );
    r0.unwrap();
    r1.unwrap();
    r2.unwrap();
}

#[test]
fn fork_creates_a_usable_second_pair_of_streams() {
    common::install_crypto_provider();
    let configs = common::configs(3);
    let [c0, c1, c2] = <[_; 3]>::try_from(configs).unwrap();

    let (n0, n1, n2) = join3(
        move || QuicNetwork::new(c0).unwrap(),
        move || QuicNetwork::new(c1).unwrap(),
        move || QuicNetwork::new(c2).unwrap(),
    );

    let (f0, f1, f2) = join3(
        || n0.fork().unwrap(),
        || n1.fork().unwrap(),
        || n2.fork().unwrap(),
    );

    let (r0, r1, r2) = join3(
        move || common::round_trip(&f0),
        move || common::round_trip(&f1),
        move || common::round_trip(&f2),
    );
    r0.unwrap();
    r1.unwrap();
    r2.unwrap();

    let (r0, r1, r2) = join3(
        move || common::round_trip(&n0),
        move || common::round_trip(&n1),
        move || common::round_trip(&n2),
    );
    r0.unwrap();
    r1.unwrap();
    r2.unwrap();
}

/// Party 1 uses party 2's key and certificate (a trusted root), so the TLS handshakes succeed,
/// but the certificate does not match the claimed party id.
#[test]
fn party_with_wrong_certificate_is_rejected() {
    common::install_crypto_provider();
    let mut configs = common::configs(3);
    let mut tls = configs[2].tls.clone().unwrap();
    tls.certs[1] = tls.certs[2].clone();
    configs[1].tls = Some(tls);
    for c in &mut configs {
        c.connect_timeout = Some(std::time::Duration::from_secs(3));
    }
    let [c0, c1, c2] = <[_; 3]>::try_from(configs).unwrap();

    let (n0, n1, n2) = join3(
        move || QuicNetwork::new(c0),
        move || QuicNetwork::new(c1),
        move || QuicNetwork::new(c2),
    );
    // party 0 accepts the connection of the impostor, whose certificate is not the one of party 1
    let err = format!("{:?}", n0.err().unwrap());
    assert!(err.contains("does not match"), "{err}");
    // the other two do not get a network either
    assert!(n1.is_err());
    assert!(n2.is_err());
}
