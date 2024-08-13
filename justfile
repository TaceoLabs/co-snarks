lint:
  cargo fmt --all -- --check
  cargo clippy --workspace --tests --examples --benches -q -- -D warnings
  RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps

test-all:
  cargo test --release --all-features

check-pr: lint test-all