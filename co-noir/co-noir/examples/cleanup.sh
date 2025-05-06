# rm all proof files
find . -name "*.proof" -type f -delete
# delete all shared files
find . -name "*.shared" -type f -delete
# delete public input file
rm -rf public_input.json
find . -name "public_input*" -type f -delete
find . -name "verification_key" -type f -delete
# delete all bb proof files
find . -name "proof.bb*" -type f -delete
# delete all bb vk files
find . -name "vk.bb*" -type f -delete
# delete all proofs and vks in test_vectors files
cd test_vectors
find . -name "vk*" -type f -delete
find . -name "proof*" -type f -delete
find . -name "zk_proof" -type f -delete
find . -name "cosnark_vk*" -type f -delete
find . -name "cosnark_proof*" -type f -delete
find . -name "cosnark_zk_proof*" -type f -delete
find . -name "cosnark_public_input*" -type f -delete
