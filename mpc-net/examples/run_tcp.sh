#!/usr/bin/env bash
cargo run --example three_party_tcp --features tcp -- -c examples/config_party1.toml &
cargo run --example three_party_tcp --features tcp -- -c examples/config_party2.toml &
cargo run --example three_party_tcp --features tcp -- -c examples/config_party3.toml 
