use crate::{
    gadgets::poseidon2::Poseidon2,
    protocols::shamir::{network::ShamirNetwork, ShamirPrimeFieldShare, ShamirProtocol},
};
use ark_ff::{PrimeField, Zero};

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2<F, T, D> {
    /// Create a Merkle tree with a given arity using Poseidon2 in sponge mode and with the Shamir MPC protocol.
    pub fn merkle_tree_sponge_shamir<const ARITY: usize, N: ShamirNetwork>(
        &self,
        input_: Vec<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<ShamirPrimeFieldShare<F>> {
        assert!(T > ARITY);
        let mut len = input_.len();
        let log = len.ilog(ARITY);
        assert_eq!(len, ARITY.pow(log));

        let num_hashes = (len - 1) / (ARITY - 1);
        driver.buffer_triples(self.rand_required(num_hashes, true))?;
        let mut precomp = self.precompute_shamir(num_hashes, driver)?;

        // Prepare for sponge mode
        let mut input = Vec::with_capacity(T * len / ARITY);
        for inp in input_.chunks_exact(ARITY) {
            for i in inp {
                input.push(*i);
            }
            for _ in inp.len()..T {
                input.push(ShamirPrimeFieldShare::zero());
            }
        }

        while len > 1 {
            debug_assert_eq!(len % ARITY, 0);
            len /= ARITY;
            // Sponge mode
            self.shamir_permutation_in_place_with_precomputation_packed(
                &mut input[..T * len],
                &mut precomp,
                driver,
            )?;
            // Only take first element as output and pad with 0 for sponge
            for i in 0..len / ARITY {
                for j in 0..ARITY {
                    input[T * i + j] = input[T * ARITY * i + j * T];
                }
                for j in ARITY..T {
                    input[T * i + j] = ShamirPrimeFieldShare::zero();
                }
            }
        }
        debug_assert_eq!(precomp.offset, precomp.r.len());
        Ok(input[0])
    }

    /// Create a Merkle tree with a given arity using Poseidon2 in compression mode and with the Shamir MPC protocol.
    pub fn merkle_tree_compression_shamir<const ARITY: usize, N: ShamirNetwork>(
        &self,
        input_: Vec<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<ShamirPrimeFieldShare<F>> {
        assert!(T >= ARITY);
        let mut len = input_.len();
        let log = len.ilog(ARITY);
        assert_eq!(len, ARITY.pow(log));

        let num_hashes = (len - 1) / (ARITY - 1);
        driver.buffer_triples(self.rand_required(num_hashes, true))?;
        let mut precomp = self.precompute_shamir(num_hashes, driver)?;

        // Prepare padding
        let mut input = if T == ARITY {
            input_
        } else {
            let mut input = Vec::with_capacity(T * len / ARITY);
            for inp in input_.chunks_exact(ARITY) {
                for i in inp {
                    input.push(*i);
                }
                for _ in inp.len()..T {
                    input.push(ShamirPrimeFieldShare::zero());
                }
            }
            input
        };

        while len > 1 {
            debug_assert_eq!(len % ARITY, 0);
            len /= ARITY;
            let ff = input.clone();
            // Compression mode
            self.shamir_permutation_in_place_with_precomputation_packed(
                &mut input[..T * len],
                &mut precomp,
                driver,
            )?;
            // Feedforward
            for i in 0..len {
                input[T * i] += ff[T * i];
            }
            // Only take first element as output and pad with 0 for compression
            for i in 0..len / ARITY {
                for j in 0..ARITY {
                    input[T * i + j] = input[T * ARITY * i + j * T];
                }
                for j in ARITY..T {
                    input[T * i + j] = ShamirPrimeFieldShare::zero();
                }
            }
        }
        debug_assert_eq!(precomp.offset, precomp.r.len());
        Ok(input[0])
    }
}
