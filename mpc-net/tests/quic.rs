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
