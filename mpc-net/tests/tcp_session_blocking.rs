//! Tests for `mpc_net::tcp_session_blocking`.
#![cfg(feature = "tcp-session-blocking")]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use mpc_net::{
    DEFAULT_MAX_FRAME_LENGTH, join, join3,
    tcp_session_blocking::{NetworkConfig, TcpNetwork, TcpNetworkHandler},
};
use reserve_port::ReservedPort;

mod common;

fn handlers(n: usize) -> Vec<TcpNetworkHandler> {
    let ports: Vec<_> = (0..n)
        .map(|_| ReservedPort::random_permanently_reserved().unwrap())
        .collect();
    let addrs: Vec<String> = ports
        .iter()
        .map(|port| format!("127.0.0.1:{port}"))
        .collect();
    (0..n)
        .map(|id| {
            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ports[id]);
            TcpNetworkHandler::new(NetworkConfig {
                party_id: id,
                bind_addr,
                node_addrs: addrs.clone(),
                init_session_timeout: None,
                timeout: None,
                flush_timeout: None,
                time_to_idle: Duration::from_secs(60),
                max_frame_length: DEFAULT_MAX_FRAME_LENGTH,
            })
            .unwrap()
        })
        .collect()
}

#[test]
fn three_party_session_round_trip() {
    let handlers = handlers(3);

    let (n0, n1, n2): (TcpNetwork, TcpNetwork, TcpNetwork) = join3(
        || handlers[0].init_session(1).unwrap(),
        || handlers[1].init_session(1).unwrap(),
        || handlers[2].init_session(1).unwrap(),
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
fn distinct_session_ids_do_not_interfere_with_each_other() {
    let handlers = handlers(3);

    let ((a0, a1, a2), (b0, b1, b2)): (
        (TcpNetwork, TcpNetwork, TcpNetwork),
        (TcpNetwork, TcpNetwork, TcpNetwork),
    ) = join(
        || {
            join3(
                || handlers[0].init_session(1).unwrap(),
                || handlers[1].init_session(1).unwrap(),
                || handlers[2].init_session(1).unwrap(),
            )
        },
        || {
            join3(
                || handlers[0].init_session(2).unwrap(),
                || handlers[1].init_session(2).unwrap(),
                || handlers[2].init_session(2).unwrap(),
            )
        },
    );

    let ((ra0, ra1, ra2), (rb0, rb1, rb2)) = join(
        move || {
            join3(
                move || common::round_trip(&a0),
                move || common::round_trip(&a1),
                move || common::round_trip(&a2),
            )
        },
        move || {
            join3(
                move || common::round_trip(&b0),
                move || common::round_trip(&b1),
                move || common::round_trip(&b2),
            )
        },
    );
    ra0.unwrap();
    ra1.unwrap();
    rb0.unwrap();
    rb1.unwrap();
    ra2.unwrap();
    rb2.unwrap();
}
