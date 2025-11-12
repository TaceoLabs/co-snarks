export CARGO_TERM_QUIET=true
export RAYON_NUM_THREADS=$(($(nproc --all)/3)) # Limit the number of threads to prevent parties stealing from each other
BARRETENBERG_BINARY=~/.bb/bb  ##specify the $BARRETENBERG_BINARY path here

NARGO_VERSION=1.0.0-beta.15 ##specify the desired nargo version here
BARRETENBERG_VERSION=3.0.0-nightly.20251104 ##specify the desired barretenberg version here or use the corresponding one for this nargo version

exit_code=0

REMOVE_OUTPUT=1
TEST_SLOWER_CIRCUITS=0 ## this is a flag to also run the slower test cases
PIPE=""
if [[ $REMOVE_OUTPUT -eq 1 ]];
then
    PIPE=" > /dev/null 2>&1"
fi

# build the co-noir binary
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
# If bb is causing problems, run this:
# curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
# bbup
r=$(bash -c "$BARRETENBERG_BINARY --version 2> /dev/null")
if  [[ $r != "$BARRETENBERG_VERSION" ]];
then
    bash -c "bbup -v ${BARRETENBERG_VERSION}"
fi

echo "Using nargo version $NARGO_VERSION"
echo "Using bb version $BARRETENBERG_VERSION"
echo ""

test_cases=("add3u64" "mul3u64" "assert" "get_bytes" "if_then" "negative" "poseidon_assert" "quantized" "add3" "add3_assert" "poseidon" "poseidon_input2" "approx_sigmoid" "addition_multiplication" "unconstrained_fn" "unconstrained_fn_field" "blackbox_not" "blackbox_and" "blackbox_xor" "ram" "rom_shared" "poseidon2" "blackbox_poseidon2" "assert_max_bit_size" "pedersen_hash" "pedersen_commitment" "blake2s" "blake3" "embedded_curve_add")

slow_test_cases=("aes128" "bb_sha256_compression")

run_proof_verification() {
  local name=$1
  local algorithm=$2

 if [[ "$algorithm" == "poseidon" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash poseidon2 --disable_zk"
    write_command="write_vk --scheme ultra_honk --oracle_hash poseidon2 --disable_zk"
    verify_command="verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk"
  elif [[ "$algorithm" == "keccak" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash keccak --disable_zk"
    write_command="write_vk --scheme ultra_honk --oracle_hash keccak --disable_zk"
    verify_command="verify --scheme ultra_honk --oracle_hash keccak --disable_zk"
  elif [[ "$algorithm" == "poseidon_zk" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash poseidon2"
    write_command="write_vk --scheme ultra_honk --oracle_hash poseidon2"
    verify_command="verify --scheme ultra_honk --oracle_hash poseidon2"
  else
    prove_command="prove --scheme ultra_honk --oracle_hash keccak"
    write_command="write_vk --scheme ultra_honk --oracle_hash keccak"
    verify_command="verify --scheme ultra_honk --oracle_hash keccak"
  fi

  echo "comparing" $name "with bb and $algorithm transcript"

  bash -c "$BARRETENBERG_BINARY $write_command -b test_vectors/${name}/target/${name}.json -o test_vectors/${name}/ $PIPE"

  bash -c "$BARRETENBERG_BINARY $prove_command -b test_vectors/${name}/target/${name}.json -w test_vectors/${name}/target/${name}.gz -k test_vectors/${name}/vk -o test_vectors/${name}/ $PIPE"

   if [[ "$algorithm" == "poseidon" ]] || [[ "$algorithm" == "keccak" ]]; then
    diff test_vectors/${name}/proof test_vectors/${name}/cosnark_proof
    if [[ $? -ne 0 ]]; then
      exit_code=1
      echo "::error:: $name diff check of proofs failed (with: $algorithm)"
    fi
  fi

    diff test_vectors/${name}/public_inputs test_vectors/${name}/cosnark_public_input
    if [[ $? -ne 0 ]]; then
      exit_code=1
      echo "::error:: $name diff check of public inputs failed (with: $algorithm)"
    fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/cosnark_proof -i test_vectors/${name}/public_inputs -k test_vectors/${name}/cosnark_vk $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error:: $name verifying with bb, our proof and our key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/cosnark_proof -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error:: $name verifying with bb, our proof and their key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -i test_vectors/${name}/public_inputs -k test_vectors/${name}/cosnark_vk $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error:: $name verifying with bb, their proof and our key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error:: $name verifying with bb, their proof and their key failed (with: $algorithm)"
  fi
  return $exit_code
}

if [[ $TEST_SLOWER_CIRCUITS -eq 1 ]];
then
  test_cases+=("${slow_test_cases[@]}")
fi

# comparing works with all test scripts where "run_full_" is followed by the precise test case name
for f in "${test_cases[@]}"; do
  echo "running ultrahonk example" $f

  failed=0

  # compile witnesses and bytecode with specified nargo version
  echo "compiling circuits with nargo"
  bash -c "(cd test_vectors/${f} && nargo execute) $PIPE"

  echo "computing witnesses, proofs and verification with co-noir"
  # -e to exit on first error
  # split input into shares
  bash -c "cargo run --release --bin co-noir -- split-input --circuit test_vectors/${f}/target/${f}.json --input test_vectors/${f}/Prover.toml --protocol REP3 --out-dir test_vectors/${f} $PIPE"  || failed=1
  # run witness extension in MPC
  bash -c "cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.0.shared --circuit test_vectors/${f}/target/${f}.json --protocol REP3 --config configs/party1.toml --out test_vectors/${f}/${f}.gz.0.shared $PIPE"  || failed=1 &
  bash -c "cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.1.shared --circuit test_vectors/${f}/target/${f}.json --protocol REP3 --config configs/party2.toml --out test_vectors/${f}/${f}.gz.1.shared $PIPE"  || failed=1 &
  bash -c "cargo run --release --bin co-noir -- generate-witness --input test_vectors/${f}/Prover.toml.2.shared --circuit test_vectors/${f}/target/${f}.json --protocol REP3 --config configs/party3.toml --out test_vectors/${f}/${f}.gz.2.shared $PIPE"  || failed=1 &
   wait $(jobs -p)
  # Create verification key
  bash -c "cargo run --release --bin co-noir -- create-vk --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --hasher poseidon2 --vk test_vectors/${f}/cosnark_vk --fields-as-json $PIPE"  || failed=1
  # run proving in MPC
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.0.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher poseidon2 --config configs/party1.toml --out test_vectors/${f}/cosnark_proof --public-input test_vectors/${f}/cosnark_public_input --vk test_vectors/${f}/cosnark_vk --fields-as-json $PIPE"  || failed=1&
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.1.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher poseidon2 --config configs/party2.toml --out test_vectors/${f}/cosnark_proof.1.proof --vk test_vectors/${f}/cosnark_vk  $PIPE"  || failed=1&
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.2.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher poseidon2 --config configs/party3.toml --out test_vectors/${f}/cosnark_proof.2.proof --vk test_vectors/${f}/cosnark_vk $PIPE"  || failed=1
  wait $(jobs -p)
  # verify proof
  bash -c "cargo run --release --bin co-noir -- verify --proof test_vectors/${f}/cosnark_proof --vk test_vectors/${f}/cosnark_vk --public-input test_vectors/${f}/cosnark_public_input --hasher poseidon2 --crs test_vectors/bn254_g2.dat$PIPE"  || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed with poseidon"
  fi

    run_proof_verification "$f" "poseidon"

  echo "proving and verifying with ZK in co-noir and poseidon transcript"
  # run proving in MPC with ZK
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.0.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher poseidon2 --config configs/party1.toml --out test_vectors/${f}/cosnark_proof --public-input test_vectors/${f}/cosnark_public_input --zk --vk test_vectors/${f}/cosnark_vk $PIPE"  || failed=1&
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.1.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher poseidon2 --config configs/party2.toml --out test_vectors/${f}/zk_proof.1.proof --zk --vk test_vectors/${f}/cosnark_vk $PIPE"  || failed=1&
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.2.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher poseidon2 --config configs/party3.toml --out test_vectors/${f}/zk_proof.2.proof --zk --vk test_vectors/${f}/cosnark_vk $PIPE"  || failed=1
  wait $(jobs -p)
  # verify proof
  bash -c "cargo run --release --bin co-noir -- verify --proof test_vectors/${f}/cosnark_proof --vk test_vectors/${f}/cosnark_vk --public-input test_vectors/${f}/cosnark_public_input --hasher poseidon2 --crs test_vectors/bn254_g2.dat --has-zk $PIPE"  || failed=1

   if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed with poseidon and ZK"
  fi

  run_proof_verification "$f" "poseidon_zk"

  # Create verification key
  bash -c "cargo run --release --bin co-noir -- create-vk --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --hasher keccak --vk test_vectors/${f}/cosnark_vk --fields-as-json $PIPE"  || failed=1
  # run proving in MPC
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.0.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party1.toml --out test_vectors/${f}/cosnark_proof --vk test_vectors/${f}/cosnark_vk --public-input test_vectors/${f}/cosnark_public_input --fields-as-json $PIPE"  || failed=1&
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.1.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party2.toml --out test_vectors/${f}/cosnark_proof.1.proof --vk test_vectors/${f}/cosnark_vk  $PIPE"  || failed=1&
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.2.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party3.toml --out test_vectors/${f}/cosnark_proof.2.proof --vk test_vectors/${f}/cosnark_vk $PIPE"  || failed=1
  wait $(jobs -p)
  # verify proof
  bash -c "cargo run --release --bin co-noir -- verify --proof test_vectors/${f}/cosnark_proof --vk test_vectors/${f}/cosnark_vk --public-input test_vectors/${f}/cosnark_public_input --hasher keccak --crs test_vectors/bn254_g2.dat $PIPE"  || failed=1

    if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed with keccak"
  fi

  run_proof_verification "$f" "keccak"

  echo "proving and verifying with ZK in co-noir and keccak transcript"
  # run proving in MPC with ZK
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.0.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party1.toml --out test_vectors/${f}/cosnark_proof --public-input test_vectors/${f}/cosnark_public_input --vk test_vectors/${f}/cosnark_vk --zk $PIPE"  || failed=1&
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.1.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party2.toml --out test_vectors/${f}/cosnark_proof.1.proof --vk test_vectors/${f}/cosnark_vk --zk $PIPE"  || failed=1&
  bash -c "cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/${f}/${f}.gz.2.shared --circuit test_vectors/${f}/target/${f}.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party3.toml --out test_vectors/${f}/cosnark_proof.2.proof --vk test_vectors/${f}/cosnark_vk --zk $PIPE"  || failed=1
  wait $(jobs -p)
  # verify proof
  bash -c "cargo run --release --bin co-noir -- verify --proof test_vectors/${f}/cosnark_proof --vk test_vectors/${f}/cosnark_vk --public-input test_vectors/${f}/cosnark_public_input --hasher keccak --crs test_vectors/bn254_g2.dat --has-zk $PIPE"  || failed=1

    if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed with keccak and zk"
  fi
  run_proof_verification "$f" "keccak_zk"

  bash cleanup.sh
  echo ""
done

exit "$exit_code"