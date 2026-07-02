//! Tests for `mpc_net::tcp::TcpNetwork`.
#![cfg(feature = "tcp")]

use mpc_net::{join3, tcp::TcpNetwork};

mod common;

#[test]
fn three_party_network_round_trip_and_stats() {
    let configs = common::configs(3);
    let [c0, c1, c2] = <[_; 3]>::try_from(configs).unwrap();

    let (n0, n1, n2) = join3(
        move || TcpNetwork::new(c0).unwrap(),
        move || TcpNetwork::new(c1).unwrap(),
        move || TcpNetwork::new(c2).unwrap(),
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
