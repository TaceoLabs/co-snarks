#!/usr/bin/env bash
mkdir -p data
[[ -f "data/key0.der" ]] || cargo run --bin gen_cert -- -k data/key0.der -c data/cert0.der -s localhost -s ip6-localhost -s party0
[[ -f "data/key1.der" ]] || cargo run --bin gen_cert -- -k data/key1.der -c data/cert1.der -s localhost -s ip6-localhost -s party1
[[ -f "data/key2.der" ]] || cargo run --bin gen_cert -- -k data/key2.der -c data/cert2.der -s localhost -s ip6-localhost -s party2
cargo run --example three_party -- -c examples/config_party1.toml &
cargo run --example three_party -- -c examples/config_party2.toml &
cargo run --example three_party -- -c examples/config_party3.toml 
