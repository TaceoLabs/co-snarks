//! Tests for `mpc_net::tcp::TcpNetwork`.
#![cfg(feature = "tcp")]

use byteorder::{BigEndian, WriteBytesExt as _};
use mpc_net::{join3, tcp::TcpNetwork};
use std::{net::TcpStream, time::Duration};

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

/// Connects to the last of three parties and sends the given network index and party id for each of the two connections it accepts.
fn accept_with_handshakes(handshakes: [(u64, u64); 2]) -> eyre::Result<TcpNetwork> {
    let config = common::configs(3).pop().unwrap();
    let addr = config.bind_addr;
    let acceptor = std::thread::spawn(move || TcpNetwork::new(config));

    let mut streams = Vec::new();
    for (network_index, party_id) in handshakes {
        // The acceptor stops listening once it rejects a handshake
        let stream = loop {
            if acceptor.is_finished() {
                break None;
            }
            if let Ok(stream) = TcpStream::connect(addr) {
                break Some(stream);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let Some(mut stream) = stream else { break };
        // The writes fail if the acceptor is already gone, which is fine
        let _ = stream.write_u64::<BigEndian>(network_index);
        let _ = stream.write_u64::<BigEndian>(party_id);
        streams.push(stream);
    }
    acceptor.join().expect("the acceptor must not panic")
}

#[test]
fn accepts_expected_handshakes() {
    accept_with_handshakes([(0, 0), (0, 1)]).unwrap();
}

#[test]
fn invalid_network_index_is_rejected() {
    assert!(accept_with_handshakes([(1, 0), (0, 1)]).is_err());
    assert!(accept_with_handshakes([(u64::MAX, 0), (0, 1)]).is_err());
}

#[test]
fn invalid_party_id_is_rejected() {
    // Only parties with a lower id connect to us
    assert!(accept_with_handshakes([(0, 2), (0, 1)]).is_err());
    assert!(accept_with_handshakes([(0, 7), (0, 1)]).is_err());
}

#[test]
fn duplicate_party_id_is_rejected() {
    assert!(accept_with_handshakes([(0, 0), (0, 0)]).is_err());
}
