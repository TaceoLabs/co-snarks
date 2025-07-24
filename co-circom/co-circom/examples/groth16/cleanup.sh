# rm all proof files
rm -rf proof.0.json proof.1.json proof.2.json public_input.json
# delete all shared files
find . -name "*.shared" -type f -delete
