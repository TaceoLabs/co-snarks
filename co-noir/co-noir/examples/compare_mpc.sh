export CARGO_TERM_QUIET=true
BARRETENBERG_BINARY=~/.bb/bb  ##specify the $BARRETENBERG_BINARY path here

NARGO_VERSION=0.39.0 ##specify the desired nargo version here
BARRETENBERG_VERSION=0.63.1 ##specify the desired barretenberg version here or use the corresponding one for this nargo version
PLAINDRIVER="../../../target/release/plaindriver"
exit_code=0

REMOVE_OUTPUT=1
PIPE=""
if [[ $REMOVE_OUTPUT -eq 1 ]];
then
    PIPE=" > /dev/null 2>&1"
fi

# build the plaindriver binary
cargo build --release --bin co-noir

## install noirup: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
r=$(bash -c "nargo --version")
if  [[ $r != "nargo version = $NARGO_VERSION"* ]];
then
    bash -c "noirup -v ${NARGO_VERSION}"
fi

## use one of these two methods
## install bbup: curl -L bbup.dev | bash
# bash -c "bbup -nv 0.${NARGO_VERSION}.0"
r=$(bash -c "$BARRETENBERG_BINARY --version")
if  [[ $r != "$BARRETENBERG_VERSION" ]];
then
    bash -c "bbup -v ${BARRETENBERG_VERSION}"
fi

echo "Using nargo version $NARGO_VERSION"
echo "Using bb version $BARRETENBERG_VERSION"
echo ""

test_cases=("add3u64" "mul3u64" "assert" "get_bytes" "if_then" "negative" "poseidon_assert" "quantized")

run_proof_verification() {
  local name=$1
  local algorithm=$2

  if [[ "$algorithm" == "poseidon" ]]; then
    proof_file="proof.bb${BARRETENBERG_VERSION}.poseidon"
    vk_file="vk.bb${BARRETENBERG_VERSION}.poseidon"
    prove_command="prove_ultra_honk"
    write_command="write_vk_ultra_honk"
    verify_command="verify_ultra_honk"
  else
    proof_file="proof.bb${BARRETENBERG_VERSION}.keccak"
    vk_file="vk.bb${BARRETENBERG_VERSION}.keccak"
    prove_command="prove_ultra_keccak_honk"
    write_command="write_vk_ultra_keccak_honk"
    verify_command="verify_ultra_keccak_honk"
  fi

  echo "comparing" $name "with bb and $algorithm transcript"

  bash -c "$BARRETENBERG_BINARY $prove_command -b test_vectors/${name}/target/${name}.json -w test_vectors/${name}/target/${name}.gz -o test_vectors/${name}/${proof_file} $PIPE"

  diff test_vectors/${name}/${proof_file} test_vectors/${name}/proof
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name diff check of proofs failed"
  fi

  bash -c "$BARRETENBERG_BINARY $write_command -b test_vectors/${name}/target/${name}.json -o test_vectors/${name}/${vk_file} $PIPE"

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -k test_vectors/${name}/vk"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and our key failed"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -k test_vectors/${name}/${vk_file}"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and their key failed"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/${proof_file} -k test_vectors/${name}/vk"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and our key failed"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/${proof_file} -k test_vectors/${name}/${vk_file}"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and their key failed"
  fi
  return $exit_code
}

# comparing works with all test scripts where "run_full_" is followed by the precise test case name
for f in "${test_cases[@]}"; do
  echo "running ultrahonk example" $f

  failed=0

  # compile witnesses and bytecode with specified nargo version
  echo "computing witnesses with nargo"
  bash -c "(cd test_vectors/${f} && nargo execute) $PIPE"

  # -e to exit on first error
  # split input into shares
  bash -c "cargo run --release --bin co-noir -- split-input --circuit test_vectors/${f}/target/${f}.json --input test_vectors/${f}/Prover.toml --protocol REP3 --out-dir test_vectors/${f} $PIPE"  || failed=1
  # run witness extension in MPC
  cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.0.shared --circuit test_vectors/${f}/target/${f}.json --protocol REP3 --config configs/party1.toml --out test_vectors/${f}/${f}.gz.0.shared &
  cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.1.shared --circuit test_vectors/${f}/target/${f}.json --protocol REP3 --config configs/party2.toml --out test_vectors/${f}/${f}.gz.1.shared &
  cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.2.shared --circuit test_vectors/${f}/target/${f}.json --protocol REP3 --config configs/party3.toml --out test_vectors/${f}/${f}.gz.2.shared 
 wait $(jobs -p)
    # run proving in MPC
  cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.0.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher POSEIDON --config configs/party1.toml --out test_vectors/${f}/proof --public-input public_input.json &
  cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.1.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher POSEIDON --config configs/party2.toml --out test_vectors/${f}/proof.1.proof  &
  cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.2.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher POSEIDON --config configs/party3.toml --out test_vectors/${f}/proof.2.proof 
  wait $(jobs -p)
   # Create verification key
  bash -c "cargo run --release --bin co-noir -- create-vk --circuit test_vectors/${f}/${f}.json --crs test_vectors/bn254_g1.dat --hasher POSEIDON --vk test_vectors/${f}/vk "  
  # verify proof
  bash -c "cargo run --release --bin co-noir -- verify --proof proof.0.proof --vk test_vectors/${f}/vk --hasher POSEIDON --crs test_vectors/bn254_g2.dat"  

  # if [ "$failed" -ne 0 ]
  # then
  #   exit_code=1
  #   echo "::error::" $f "failed"
  # fi
  run_proof_verification "$f" "poseidon"
  bash cleanup.sh

  # split input into shares
  bash -c "cargo run --release --bin co-noir -- split-input --circuit test_vectors/${f}/${f}.json --input test_vectors/${f}/Prover.toml --protocol REP3 --out-dir test_vectors/${f} $PIPE"  || failed=1
  # run witness extension in MPC
cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.0.shared --circuit test_vectors/${f}/${f}.json --protocol REP3 --config configs/party1.toml --out test_vectors/${f}/${f}.gz.0.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.1.shared --circuit test_vectors/${f}/${f}.json --protocol REP3 --config configs/party2.toml --out test_vectors/${f}/${f}.gz.1.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.2.shared --circuit test_vectors/${f}/${f}.json --protocol REP3 --config configs/party3.toml --out test_vectors/${f}/${f}.gz.2.shared
 wait $(jobs -p)
  # run proving in MPC
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.0.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher KECCAK --config configs/party1.toml --out test_vectors/${f}/proof --public-input public_input.json&
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.1.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher KECCAK --config configs/party2.toml --out test_vectors/${f}/proof.1.proof  &
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.2.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher KECCAK --config configs/party3.toml --out test_vectors/${f}/proof.2.proof
 wait $(jobs -p)
  # Create verification key
  bash -c "cargo run --release --bin co-noir -- create-vk --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --hasher KECCAK --vk test_vectors/${f}/vk" 
  # verify proof
  bash -c "cargo run --release --bin co-noir -- verify --proof test_vectors/${f}/proof --vk test_vectors/${f}/vk --hasher KECCAK --crs test_vectors/bn254_g2.dat "  

  # if [ "$failed" -ne 0 ]
  # then
  #   exit_code=1
  #   echo "::error::" $f "failed"
  # fi
  run_proof_verification "$f" "keccak"
  bash cleanup.sh
  echo ""
done

exit "$exit_code"