//! Tests for `mpc_net::config`.

use std::str::FromStr;

use mpc_net::config::{Address, ParseAddressError};

#[test]
fn address_parses_hostname_and_port() {
    let addr: Address = "example.com:1234".parse().unwrap();
    assert_eq!(addr.hostname, "example.com");
    assert_eq!(addr.port, 1234);
}

#[test]
fn address_rejects_missing_port() {
    let err = Address::from_str("example.com").unwrap_err();
    assert_eq!(err, ParseAddressError::InvalidFormat);
}

#[test]
fn address_rejects_too_many_colons() {
    // e.g. an unbracketed IPv6 address
    let err = Address::from_str("::1:1234").unwrap_err();
    assert_eq!(err, ParseAddressError::InvalidFormat);
}

#[test]
fn address_rejects_non_numeric_port() {
    let err = Address::from_str("example.com:not-a-port").unwrap_err();
    assert!(matches!(err, ParseAddressError::InvalidPort(_)));
}

#[test]
fn address_display_matches_hostname_colon_port() {
    let addr = Address::new("example.com".to_string(), 1234);
    assert_eq!(addr.to_string(), "example.com:1234");
}

#[test]
fn address_display_and_parse_roundtrip() {
    let addr = Address::new("localhost".to_string(), 8080);
    let roundtripped: Address = addr.to_string().parse().unwrap();
    assert_eq!(addr, roundtripped);
}
