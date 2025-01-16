global SIZE_OF_PROOF_IF_LOGN_IS_28: u32 = 463;
global HONK_IDENTIFIER: u32 = 1;
fn main(
    verification_key: [Field; 128],
    public_inputs: pub [Field; 3],
    key_hash: Field,
    proof: [Field; SIZE_OF_PROOF_IF_LOGN_IS_28],
) -> pub u64 {
    // verify sum so far was computed correctly
    std::verify_proof_with_type(
        verification_key,
        proof,
        public_inputs,
        key_hash,
        HONK_IDENTIFIER,
    );
    // Take output of previous proof and add another number to it.
    public_inputs[2] as u64 + public_inputs[1] as u64
}
