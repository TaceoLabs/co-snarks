# rm all proof files
rm -rf proof.0.proof proof.1.proof proof.2.proof
# delete all shared files
find . -name "*.shared" -type f -delete
# delete public input file
rm -rf public_input.json
find . -name "verification_key" -type f -delete
