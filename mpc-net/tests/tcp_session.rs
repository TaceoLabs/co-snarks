//! Tests for `mpc_net::tcp_session`.
#![cfg(feature = "tcp-session")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use mpc_net::{
    join, join3,
    tcp_session::{TcpNetwork, TcpNetworkHandler, TcpNetworkHandlerBuilder},
};
use reserve_port::ReservedPort;

mod common;

async fn handlers(n: usize) -> Vec<TcpNetworkHandler> {
    let ports: Vec<_> = (0..n)
        .map(|_| ReservedPort::random_permanently_reserved().unwrap())
        .collect();
    let addrs: Vec<String> = ports
        .iter()
        .map(|port| format!("127.0.0.1:{port}"))
        .collect();
    futures::future::join_all((0..n).map(|id| {
        let addrs = addrs.clone();
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ports[id]);
        async move {
            TcpNetworkHandlerBuilder::new(id, bind_addr, addrs)
                .build()
                .await
                .unwrap()
        }
    }))
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_party_session_round_trip() {
    let handlers = handlers(3).await;

    let networks = futures::future::join_all(handlers.iter().map(|h| h.init_session(1))).await;
    let [n0, n1, n2]: [TcpNetwork; 3] = networks
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let (r0, r1, r2) = tokio::task::block_in_place(|| {
        join3(
            move || common::round_trip(&n0),
            move || common::round_trip(&n1),
            move || common::round_trip(&n2),
        )
    });
    r0.unwrap();
    r1.unwrap();
    r2.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn distinct_session_ids_do_not_interfere_with_each_other() {
    let handlers = handlers(3).await;

    let (networks_a, networks_b) = tokio::join!(
        futures::future::join_all(handlers.iter().map(|h| h.init_session(1))),
        futures::future::join_all(handlers.iter().map(|h| h.init_session(2))),
    );
    let [a0, a1, a2]: [TcpNetwork; 3] = networks_a
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let [b0, b1, b2]: [TcpNetwork; 3] = networks_b
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let ((ra0, ra1, ra2), (rb0, rb1, rb2)) = tokio::task::block_in_place(|| {
        join(
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
        )
    });
    ra0.unwrap();
    ra1.unwrap();
    rb0.unwrap();
    rb1.unwrap();
    ra2.unwrap();
    rb2.unwrap();
}
