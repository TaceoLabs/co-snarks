lint:
  cargo fmt --all -- --check
  cargo clippy --workspace --tests --examples --benches -q -- -D warnings
  RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps

test-all:
  cargo test --release --all-features

test-examples:
  cd co-circom/co-circom/examples/groth16 && ./run.sh
  cd co-circom/co-circom/examples/plonk && ./run.sh

check-pr: lint test-all test-examples

test-circom:
  cargo test --release --all-features --package tests --test circom

test-noir:
  cargo test --release --all-features --package tests --test noir