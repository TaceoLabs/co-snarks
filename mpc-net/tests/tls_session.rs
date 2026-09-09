//! Tests for `mpc_net::tls_session`.
#![cfg(feature = "tls-session")]

use std::time::Duration;

use mpc_net::{
    DEFAULT_MAX_FRAME_LENGTH,
    config::NetworkConfig as BaseConfig,
    join, join3,
    tls_session::{NetworkConfig, TlsNetwork, TlsNetworkHandler},
};

mod common;

async fn handlers(n: usize) -> Vec<TlsNetworkHandler> {
    handlers_from(common::configs(n)).await
}

async fn handlers_from(configs: Vec<BaseConfig>) -> Vec<TlsNetworkHandler> {
    common::install_crypto_provider();
    let node_addrs: Vec<_> = configs[0]
        .parties
        .iter()
        .map(|p| p.dns_name.clone())
        .collect();
    futures::future::join_all(configs.into_iter().map(|c| {
        let node_addrs = node_addrs.clone();
        async move {
            TlsNetworkHandler::new(NetworkConfig {
                party_id: c.my_id,
                bind_addr: c.bind_addr,
                node_addrs,
                tls: c.tls,
                init_session_timeout: c.connect_timeout,
                timeout: c.timeout,
                flush_timeout: None,
                time_to_idle: Duration::from_secs(60),
                max_frame_length: DEFAULT_MAX_FRAME_LENGTH,
            })
            .await
            .unwrap()
        }
    }))
    .await
}

fn unwrap3(networks: Vec<eyre::Result<TlsNetwork>>) -> [TlsNetwork; 3] {
    networks
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_party_session_round_trip() {
    let handlers = handlers(3).await;

    let networks = futures::future::join_all(handlers.iter().map(|h| h.init_session(1))).await;
    let [n0, n1, n2] = unwrap3(networks);

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

/// Party 1 uses party 2's key and certificate (a trusted root), so the TLS handshakes succeed,
/// but the certificate does not match the claimed party id.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn party_with_wrong_certificate_is_rejected() {
    let mut configs = common::configs(3);
    let mut tls = configs[2].tls.clone().unwrap();
    tls.certs[1] = tls.certs[2].clone();
    configs[1].tls = Some(tls);
    for c in &mut configs {
        c.connect_timeout = Some(Duration::from_secs(3));
    }
    let handlers = handlers_from(configs).await;

    let networks = futures::future::join_all(handlers.iter().map(|h| h.init_session(1))).await;
    for (id, net) in networks.iter().enumerate() {
        assert!(net.is_err(), "party {id} should fail");
    }
    // party 2 connects to the impostor and sees the wrong certificate directly
    let err = networks[2].as_ref().err().unwrap().to_string();
    assert!(err.contains("does not match"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn distinct_session_ids_do_not_interfere_with_each_other() {
    let handlers = handlers(3).await;

    let (networks_a, networks_b) = tokio::join!(
        futures::future::join_all(handlers.iter().map(|h| h.init_session(1))),
        futures::future::join_all(handlers.iter().map(|h| h.init_session(2))),
    );
    let [a0, a1, a2] = unwrap3(networks_a);
    let [b0, b1, b2] = unwrap3(networks_b);
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
    ra2.unwrap();
    rb0.unwrap();
    rb1.unwrap();
    rb2.unwrap();
}
