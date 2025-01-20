#!/usr/bin/env bash
mkdir -p data
[[ -f "data/key0.pem" ]] || cargo run --bin gen_cert -- -k data/key0.pem -c data/cert0.pem -s localhost -s ip6-localhost -s 127.0.0.1 -s party0
[[ -f "data/key1.pem" ]] || cargo run --bin gen_cert -- -k data/key1.pem -c data/cert1.pem -s localhost -s ip6-localhost -s 127.0.0.1 -s party1
[[ -f "data/key2.pem" ]] || cargo run --bin gen_cert -- -k data/key2.pem -c data/cert2.pem -s localhost -s ip6-localhost -s 127.0.0.1 -s party2
cargo run --example three_party -- -c examples/config_party1.toml &
cargo run --example three_party -- -c examples/config_party2.toml &
cargo run --example three_party -- -c examples/config_party3.toml 
