export CARGO_TERM_QUIET=true
BARRETENBERG_BINARY= ##specify the $BARRETENBERG_BINARY path here

NARGO_VERSION=38 ##specify the desired nargo version here
BARRETENBERG_VERSION=62 ##specify the desired barretenberg version here or use the corresponding one for this nargo version
PLAINDRIVER="../../../target/release/plaindriver"
exit_code=0
bash -c "noirup -v 0.${NARGO_VERSION}.0"

## use one of these two methods
bash -c "bbup -nv 0.${NARGO_VERSION}.0"
# bash -c "bbup -v 0.${BARRETENBERG_VERSION}.0" 

test_cases=("add3" "add3_assert" "add3u64" "mul3u64" "poseidon" "poseidon_input2")


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

 echo "comparing" $name "with bb version:" $BARRETENBERG_VERSION " and $algorithm transcript"

    $BARRETENBERG_BINARY $prove_command -b test_vectors/${name}/target/${name}.json -w test_vectors/${name}/target/${name}.gz -o test_vectors/${name}/${proof_file}

    diff test_vectors/${name}/${proof_file} test_vectors/${name}/proof
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name diff check of proofs failed"
  fi

    $BARRETENBERG_BINARY $write_command -b test_vectors/${name}/target/${name}.json -o test_vectors/${name}/${vk_file}

    $BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -k test_vectors/${name}/vk
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and our key failed"
  fi

    $BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -k test_vectors/${name}/${vk_file}
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and their key failed"
  fi

    $BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/${proof_file} -k test_vectors/${name}/vk
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and our key failed"
    fi
  $BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/${proof_file} -k test_vectors/${name}/${vk_file}
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
  bash -c "(cd test_vectors/${f} && nargo execute)" 

  # -e to exit on first error
  bash -c "${PLAINDRIVER} --prover-crs test_vectors/bn254_g1.dat --verifier-crs test_vectors/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher POSEIDON --out-dir test_vectors/${f}" || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed"
  fi
  run_proof_verification "$f" "poseidon"
  bash cleanup.sh

   # -e to exit on first error
  bash -c "${PLAINDRIVER} --prover-crs test_vectors/bn254_g1.dat --verifier-crs test_vectors/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher KECCAK --out-dir test_vectors/${f}" || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed"
  fi
  run_proof_verification "$f" "keccak"
  bash cleanup.sh
done
find test_vectors/ -type d -name "target" -exec rm -rf {} +
exit "$exit_code"
