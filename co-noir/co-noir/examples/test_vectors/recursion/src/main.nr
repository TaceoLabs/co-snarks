global HONK_VK_SIZE: u32 = 115;
global HONK_PROOF_SIZE: u32 = 410;
global HONK_IDENTIFIER: u32 = 0;

fn main(
    verification_key: [Field; HONK_VK_SIZE],
    proof: [Field; HONK_PROOF_SIZE],
    vk_hash: Field,
    public_inputs: pub [Field; 3],
) {
    std::verify_proof_with_type(verification_key, proof, public_inputs, vk_hash, HONK_IDENTIFIER);
}
