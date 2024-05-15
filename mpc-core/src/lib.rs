pub mod protocols;
pub mod traits;

pub(crate) type RngType = rand_chacha::ChaCha12Rng;
pub(crate) const SEED_SIZE: usize = std::mem::size_of::<<RngType as rand::SeedableRng>::Seed>();
