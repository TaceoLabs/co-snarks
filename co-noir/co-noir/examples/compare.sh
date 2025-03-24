export CARGO_TERM_QUIET=true
BARRETENBERG_BINARY=~/.bb/bb  ##specify the $BARRETENBERG_BINARY path here

NARGO_VERSION=1.0.0-beta.6 ##specify the desired nargo version here
BARRETENBERG_VERSION=0.86.0 ##specify the desired barretenberg version here or use the corresponding one for this nargo version
PLAINDRIVER="../../../target/release/plaindriver"
exit_code=0

REMOVE_OUTPUT=1
PIPE=""
if [[ $REMOVE_OUTPUT -eq 1 ]];
then
    PIPE=" > /dev/null 2>&1"
fi

# build the plaindriver binary
cargo build --release --bin plaindriver

## install noirup: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
r=$(bash -c "nargo --version")
if  [[ $r != "nargo version = $NARGO_VERSION"* ]];
then
    bash -c "noirup -v ${NARGO_VERSION}"
fi

## use one of these two methods
## install bbup: curl -L bbup.dev | bash
# bash -c "bbup -nv 0.${NARGO_VERSION}.0"
r=$(bash -c "$BARRETENBERG_BINARY --version 2> /dev/null")
if  [[ $r != "$BARRETENBERG_VERSION" ]];
then
    bash -c "bbup -v ${BARRETENBERG_VERSION}"
fi

echo "Using nargo version $NARGO_VERSION"
echo "Using bb version $BARRETENBERG_VERSION"
echo ""

test_cases=("add3u64" "mul3u64" "assert" "get_bytes" "if_then" "negative" "poseidon_assert" "quantized" "add3" "add3_assert" "poseidon" "poseidon_input2" "approx_sigmoid" "addition_multiplication" "unconstrained_fn" "unconstrained_fn_field" "blackbox_not" "blackbox_and" "blackbox_xor" "ram" "rom_shared" "poseidon2" "blackbox_poseidon2" "assert_max_bit_size" "pedersen_hash" "pedersen_commitment" "bb_sha256_compression" "blake2s" "blake3" "embedded_curve_add" "aes128")

run_proof_verification() {
  local name=$1
  local algorithm=$2

  if [[ "$algorithm" == "poseidon" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash poseidon2"
    write_command="write_vk --scheme ultra_honk --oracle_hash poseidon2"
    verify_command="verify --scheme ultra_honk --oracle_hash poseidon2"
  elif [[ "$algorithm" == "keccak" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash keccak"
    write_command="write_vk --scheme ultra_honk --oracle_hash keccak"
    verify_command="verify --scheme ultra_honk --oracle_hash keccak"
  elif [[ "$algorithm" == "poseidon_zk" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash poseidon2 --zk"
    write_command="write_vk --scheme ultra_honk --oracle_hash poseidon2"
    verify_command="verify --scheme ultra_honk --oracle_hash poseidon2 --zk"
  else
    prove_command="prove --scheme ultra_honk --oracle_hash keccak --zk"
    write_command="write_vk --scheme ultra_honk --oracle_hash keccak"
    verify_command="verify --scheme ultra_honk --oracle_hash keccak --zk"
  fi

  echo "comparing" $name "with bb and $algorithm transcript"

  bash -c "$BARRETENBERG_BINARY $prove_command -b test_vectors/${name}/target/${name}.json -w test_vectors/${name}/target/${name}.gz -o test_vectors/${name}/ $PIPE"


  if [[ "$algorithm" == "poseidon" ]] || [[ "$algorithm" == "keccak" ]]; then
    diff test_vectors/${name}/proof test_vectors/${name}/proof_plaindriver
    if [[ $? -ne 0 ]]; then
      exit_code=1
      echo "::error::$name diff check of proofs failed (with: $algorithm)"
    fi
  fi

  diff test_vectors/${name}/public_inputs test_vectors/${name}/public_inputs_plaindriver
    if [[ $? -ne 0 ]]; then
      exit_code=1
      echo "::error::$name diff check of public_inputs failed (with: $algorithm)"
    fi

  bash -c "$BARRETENBERG_BINARY $write_command -b test_vectors/${name}/target/${name}.json -o test_vectors/${name}/ $PIPE"

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof_plaindriver -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk_plaindriver $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and our key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof_plaindriver -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and their key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk_plaindriver $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and our key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and their key failed (with: $algorithm)"
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
  bash -c "${PLAINDRIVER} --prover-crs test_vectors/bn254_g1.dat --verifier-crs test_vectors/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher poseidon2 --out-dir test_vectors/${f} $PIPE" || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed"
  fi
  run_proof_verification "$f" "poseidon"

  # Run with ZK:
  bash -c "${PLAINDRIVER} --prover-crs test_vectors/bn254_g1.dat --verifier-crs test_vectors/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher poseidon2 --out-dir test_vectors/${f} --zk $PIPE" || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed with ZK"
  fi
  # Note: ZK proofs are not (yet) possible with Poseidon in Barretenberg
  # run_proof_verification "$f" "poseidon_zk"
  bash cleanup.sh

   # -e to exit on first error
  bash -c "${PLAINDRIVER} --prover-crs test_vectors/bn254_g1.dat --verifier-crs test_vectors/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher keccak --out-dir test_vectors/${f} $PIPE"  || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed"
  fi
  run_proof_verification "$f" "keccak"
   bash cleanup.sh
  # Run with ZK:
  bash -c "${PLAINDRIVER} --prover-crs test_vectors/bn254_g1.dat --verifier-crs test_vectors/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher keccak --out-dir test_vectors/${f} --zk $PIPE" || failed=1
  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed with ZK"
  fi
  run_proof_verification "$f" "keccak_zk"
  bash cleanup.sh
  echo ""
done

exit "$exit_code"
