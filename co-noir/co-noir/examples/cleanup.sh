# rm all proof files
rm proof.0.proof proof.1.proof proof.2.proof
# delete all shared files
find . -name "*.shared" -type f -delete
# delete public input file
rm public_input.json
find . -name "verification_key" -type f -delete
