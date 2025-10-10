use crate::honk_curve::HonkCurve;
use crate::{mpc::NoirUltraHonkProver, transcript::TranscriptHasher};
use ark_ff::PrimeField;
use mpc_net::Network;
use noir_types::SerializeF;
use sha3::{Digest, Keccak256};

impl<F: PrimeField, U: NoirUltraHonkProver<C>, C: HonkCurve<F>> TranscriptHasher<F, U, C>
    for Keccak256
{
    fn hash(buffer: Vec<F>) -> F {
        // Losing 2 bits of this is not an issue -> we can just reduce mod p

        let vec = SerializeF::to_buffer(&buffer, false);
        let mut hasher = Keccak256::default();
        hasher.update(vec);
        let hash_result = hasher.finalize();

        let mut offset = 0;
        SerializeF::read_field_element(&hash_result, &mut offset)
    }

    fn hash_rep3<N: Network>(
        _buffer: Vec<U::ArithmeticShare>,
        _net: &N,
        _mpc_state: &mut U::State,
    ) -> eyre::Result<U::ArithmeticShare> {
        unimplemented!("Keccak does not support MPC transcript hashing")
    }
}
