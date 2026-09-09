//! Tests for `mpc_net::tls_session_blocking`.
#![cfg(feature = "tls-session-blocking")]

use std::time::Duration;

use mpc_net::{
    DEFAULT_MAX_FRAME_LENGTH,
    config::NetworkConfig as BaseConfig,
    join, join3,
    tls_session_blocking::{NetworkConfig, TlsNetwork, TlsNetworkHandler},
};

mod common;

fn handlers(n: usize) -> Vec<TlsNetworkHandler> {
    handlers_from(common::configs(n))
}

fn handlers_from(configs: Vec<BaseConfig>) -> Vec<TlsNetworkHandler> {
    common::install_crypto_provider();
    let node_addrs: Vec<_> = configs[0]
        .parties
        .iter()
        .map(|p| p.dns_name.clone())
        .collect();
    configs
        .into_iter()
        .map(|c| {
            TlsNetworkHandler::new(NetworkConfig {
                party_id: c.my_id,
                bind_addr: c.bind_addr,
                node_addrs: node_addrs.clone(),
                tls: c.tls,
                init_session_timeout: c.connect_timeout,
                timeout: c.timeout,
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

    let (n0, n1, n2): (TlsNetwork, TlsNetwork, TlsNetwork) = join3(
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

/// Party 1 uses party 2's key and certificate (a trusted root), so the TLS handshakes succeed,
/// but the certificate does not match the claimed party id.
#[test]
fn party_with_wrong_certificate_is_rejected() {
    let mut configs = common::configs(3);
    let mut tls = configs[2].tls.clone().unwrap();
    tls.certs[1] = tls.certs[2].clone();
    configs[1].tls = Some(tls);
    for c in &mut configs {
        c.connect_timeout = Some(Duration::from_secs(3));
    }
    let handlers = handlers_from(configs);

    let (n0, n1, n2) = join3(
        || handlers[0].init_session(1),
        || handlers[1].init_session(1),
        || handlers[2].init_session(1),
    );
    assert!(n0.is_err());
    assert!(n1.is_err());
    // party 2 connects to the impostor and sees the wrong certificate directly
    let err = n2.err().unwrap().to_string();
    assert!(err.contains("does not match"), "{err}");
}

#[test]
fn distinct_session_ids_do_not_interfere_with_each_other() {
    let handlers = handlers(3);

    let ((a0, a1, a2), (b0, b1, b2)): (
        (TlsNetwork, TlsNetwork, TlsNetwork),
        (TlsNetwork, TlsNetwork, TlsNetwork),
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
    ra2.unwrap();
    rb0.unwrap();
    rb1.unwrap();
    rb2.unwrap();
}
