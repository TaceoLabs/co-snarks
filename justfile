lint:
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -q -- -D warnings
  RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps

test-all:
  cargo test --release --all-features

test-examples:
  cd co-circom/co-circom/examples/groth16 && ./run.sh
  cd co-circom/co-circom/examples/plonk && ./run.sh
  cd co-noir/co-noir/examples && ./run.sh

check-pr: lint test-all test-examples

# check that every feature combination of mpc-core and mpc-net compiles on its own (requires `cargo install cargo-all-features`)
check-features:
  cd mpc-core && cargo all-features check -q
  cd mpc-net && cargo all-features check -q

test-circom:
  cargo test --release --all-features --package tests --test circom

test-noir:
  cargo test --release --all-features --package tests --test noir
