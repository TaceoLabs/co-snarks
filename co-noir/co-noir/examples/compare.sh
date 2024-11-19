export CARGO_TERM_QUIET=true
BARRETENBERG_VERSION=62 ##specify the desired barretenberg version here

exit_code=0
bash -c "bbup -v 0.${BARRETENBERG_VERSION}.0"

# comparing works with all test scripts where "run_full_" is followed by the precise test case name
for f in run_full*.sh; do
  echo "running ultrahonk example" $f


 if [[ "$f" == *"_with"* ]]; then

    name="${f#*full_}"   
    name="${name%%_with*}" 
    echo "$name"
  else

    name="${f#*full_}"   
    name="${name%.sh}"      
     echo "$name"
    fi



  failed=0

  # -e to exit on first error
  bash -e "$f" || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed"
  fi
  if [ "$f" = *with_poseidon.sh ]; then
    echo "comparing" $f  "with bb version:" $BARRETENBERG_VERSION " and poseidon transcript"
    bb prove_ultra_honk -b test_vectors/${name}/${name}.json -w test_vectors/${name}/${name}.gz -o test_vectors/${name}/proof.bb${BARRETENBERG_VERSION}.poseidon

    diff test_vectors/${name}/proof.bb${BARRETENBERG_VERSION}.poseidon proof.0.proof
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name diff check of proofs failed"
  fi

    bb write_vk_ultra_honk -b test_vectors/${name}/${name}.json -o test_vectors/${name}/vk.bb${BARRETENBERG_VERSION}.poseidon

    bb verify_ultra_honk -p proof.0.proof -k test_vectors/${name}/verification_key
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and our key failed"
  fi

    bb verify_ultra_honk -p proof.0.proof -k test_vectors/${name}/vk.bb${BARRETENBERG_VERSION}.poseidon
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and their key failed"
  fi

    bb verify_ultra_honk -p test_vectors/${name}/proof.bb${BARRETENBERG_VERSION}.poseidon -k test_vectors/${name}/verification_key
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and our key failed"
  fi
  bb verify_ultra_honk -p test_vectors/${name}/proof.bb${BARRETENBERG_VERSION}.poseidon -k test_vectors/${name}/vk.bb${BARRETENBERG_VERSION}.poseidon
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and their key failed"
  fi

  else

    echo "comparing" $f  "with bb version: " $BARRETENBERG_VERSION " and keccak transcript"
    bb prove_ultra_keccak_honk -b test_vectors/${name}/${name}.json -w test_vectors/${name}/${name}.gz -o test_vectors/${name}/proof.bb${BARRETENBERG_VERSION}.keccak

    diff test_vectors/${name}/proof.bb${BARRETENBERG_VERSION}.keccak proof.0.proof
     if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name diff check of proofs failed"
  fi

    bb write_vk_ultra_keccak_honk -b test_vectors/${name}/${name}.json -o test_vectors/${name}/vk.bb${BARRETENBERG_VERSION}.keccak

    bb verify_ultra_keccak_honk -p proof.0.proof -k test_vectors/${name}/verification_key
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and our key failed"
  fi

    bb verify_ultra_keccak_honk -p proof.0.proof -k test_vectors/${name}/vk.bb${BARRETENBERG_VERSION}.keccak
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, our proof and their key failed"
  fi

    bb verify_ultra_keccak_honk -p test_vectors/${name}/proof.bb${BARRETENBERG_VERSION}.keccak -k test_vectors/${name}/verification_key
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and our key failed"
  fi
    bb verify_ultra_keccak_honk -p test_vectors/${name}/proof.bb${BARRETENBERG_VERSION}.keccak -k test_vectors/${name}/vk.bb${BARRETENBERG_VERSION}.keccak
    if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name verifying with bb, their proof and their key failed"
  fi



  fi


   bash cleanup.sh
done

exit "$exit_code"

