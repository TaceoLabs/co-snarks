use crate::gadgets::poseidon2::Poseidon2;
use ark_ff::PrimeField;
use std::cmp::Ordering;

/// A witness of proving one layer in a Merkle tree.
pub struct MerkleWitnessElement<F> {
    /// Determines all other values required to compute the hash for the next layer.
    pub other: Vec<F>,
    /// Determines the position for the prove element in the hash for current layer.
    pub position: usize, // Index of the prove element
}

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2<F, T, D> {
    /// Create a Merkle tree with a given arity using Poseidon2 in sponge mode.
    pub fn merkle_tree_sponge<const ARITY: usize>(&self, input_: Vec<F>) -> F {
        assert!(T > ARITY);
        let mut len = input_.len();
        let log = len.ilog(ARITY);
        assert_eq!(len, ARITY.pow(log));

        // Prepare for sponge mode
        let mut input = Vec::with_capacity(T * len / ARITY);
        for inp in input_.chunks_exact(ARITY) {
            for i in inp {
                input.push(*i);
            }
            for _ in inp.len()..T {
                input.push(F::zero());
            }
        }

        while len > 1 {
            debug_assert_eq!(len % ARITY, 0);
            len /= ARITY;
            for inp in input.chunks_exact_mut(T).take(len) {
                // Sponge mode
                self.permutation_in_place(inp.try_into().unwrap());
            }
            // Only take first element as output and pad with 0 for sponge
            for i in 0..len / ARITY {
                for j in 0..ARITY {
                    input[T * i + j] = input[T * ARITY * i + j * T];
                }
                for j in ARITY..T {
                    input[T * i + j] = F::zero();
                }
            }
        }
        input[0]
    }

    /// Create a Merkle tree with a given arity using Poseidon2 in sponge mode while also producing a witness for the input at index i.
    pub fn merkle_tree_sponge_with_witness<const ARITY: usize>(
        &self,
        input_: Vec<F>,
        mut i: usize,
    ) -> (F, Vec<MerkleWitnessElement<F>>) {
        assert!(T > ARITY);
        let mut len = input_.len();
        let log = len.ilog(ARITY);
        assert_eq!(len, ARITY.pow(log));
        let mut witness = Vec::with_capacity(log as usize);

        // Prepare for sponge mode
        let mut input = Vec::with_capacity(T * len / ARITY);
        for inp in input_.chunks_exact(ARITY) {
            for i in inp {
                input.push(*i);
            }
            for _ in inp.len()..T {
                input.push(F::zero());
            }
        }

        while len > 1 {
            debug_assert_eq!(len % ARITY, 0);
            len /= ARITY;

            // Witness
            let position = i % ARITY;
            let mut witness_value = Vec::with_capacity(ARITY - 1);
            let witness_index = (i / ARITY) * T;
            for (j, el) in input.iter().skip(witness_index).take(ARITY).enumerate() {
                if j != position {
                    witness_value.push(*el);
                }
            }
            witness.push(MerkleWitnessElement {
                other: witness_value,
                position,
            });
            i /= ARITY;

            for inp in input.chunks_exact_mut(T).take(len) {
                // Sponge mode
                self.permutation_in_place(inp.try_into().unwrap());
            }
            // Only take first element as output and pad with 0 for sponge
            for i in 0..len / ARITY {
                for j in 0..ARITY {
                    input[T * i + j] = input[T * ARITY * i + j * T];
                }
                for j in ARITY..T {
                    input[T * i + j] = F::zero();
                }
            }
        }
        debug_assert_eq!(i, 0);
        (input[0], witness)
    }

    /// Create a Merkle tree with a given arity using Poseidon2 in compression mode.
    pub fn merkle_tree_compression<const ARITY: usize>(&self, input_: Vec<F>) -> F {
        assert!(T >= ARITY);
        let mut len = input_.len();
        let log = len.ilog(ARITY);
        assert_eq!(len, ARITY.pow(log));

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
                    input.push(F::zero());
                }
            }
            input
        };

        while len > 1 {
            debug_assert_eq!(len % ARITY, 0);
            len /= ARITY;
            for inp in input.chunks_exact_mut(T).take(len) {
                // Compression mode
                let feed_forward = inp[0];
                self.permutation_in_place(inp.try_into().unwrap());
                inp[0] += feed_forward;
            }
            // Only take first element as output and pad with 0 for compression
            for i in 0..len / ARITY {
                for j in 0..ARITY {
                    input[T * i + j] = input[T * ARITY * i + j * T];
                }
                for j in ARITY..T {
                    input[T * i + j] = F::zero();
                }
            }
        }
        input[0]
    }

    /// Create a Merkle tree with a given arity using Poseidon2 in compression mode while also producing a witness for the input at index i.
    pub fn merkle_tree_compression_with_witness<const ARITY: usize>(
        &self,
        input_: Vec<F>,
        mut i: usize,
    ) -> (F, Vec<MerkleWitnessElement<F>>) {
        assert!(T >= ARITY);
        let mut len = input_.len();
        let log = len.ilog(ARITY);
        assert_eq!(len, ARITY.pow(log));
        let mut witness = Vec::with_capacity(log as usize);

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
                    input.push(F::zero());
                }
            }
            input
        };

        while len > 1 {
            debug_assert_eq!(len % ARITY, 0);
            len /= ARITY;

            // Witness
            let position = i % ARITY;
            let mut witness_value = Vec::with_capacity(ARITY - 1);
            let witness_index = (i / ARITY) * T;
            for (j, el) in input.iter().skip(witness_index).take(ARITY).enumerate() {
                if j != position {
                    witness_value.push(*el);
                }
            }
            witness.push(MerkleWitnessElement {
                other: witness_value,
                position,
            });
            i /= ARITY;

            for inp in input.chunks_exact_mut(T).take(len) {
                // Compression mode
                let feed_forward = inp[0];
                self.permutation_in_place(inp.try_into().unwrap());
                inp[0] += feed_forward;
            }
            // Only take first element as output and pad with 0 for compression
            for i in 0..len / ARITY {
                for j in 0..ARITY {
                    input[T * i + j] = input[T * ARITY * i + j * T];
                }
                for j in ARITY..T {
                    input[T * i + j] = F::zero();
                }
            }
        }
        debug_assert_eq!(i, 0);
        (input[0], witness)
    }

    /// Verify a Merkle path with a given root, leaf, and witness using Poseidon2 in sponge mode.
    pub fn verifiy_merkle_path_sponge(
        &self,
        root: F,
        mut leaf: F,
        witness: Vec<MerkleWitnessElement<F>>,
    ) -> bool {
        let arity = witness[0].other.len() + 1;
        assert!(T > arity);

        for wit in witness {
            if wit.other.len() != arity - 1 {
                return false;
            }
            if wit.position >= arity {
                return false;
            }

            let mut perm = [F::zero(); T];
            for (i, des) in perm.iter_mut().take(arity).enumerate() {
                match i.cmp(&wit.position) {
                    Ordering::Less => *des = wit.other[i],
                    Ordering::Equal => *des = leaf,
                    Ordering::Greater => *des = wit.other[i - 1],
                }
            }
            // sponge
            self.permutation_in_place(&mut perm);
            leaf = perm[0];
        }

        root == leaf
    }

    /// Verify a Merkle path with a given root, leaf, and witness using Poseidon2 in compression mode.
    pub fn verifiy_merkle_path_compression(
        &self,
        root: F,
        mut leaf: F,
        witness: Vec<MerkleWitnessElement<F>>,
    ) -> bool {
        let arity = witness[0].other.len() + 1;
        assert!(T >= arity);

        for wit in witness {
            if wit.other.len() != arity - 1 {
                return false;
            }
            if wit.position >= arity {
                return false;
            }

            let mut perm = [F::zero(); T];
            for (i, des) in perm.iter_mut().take(arity).enumerate() {
                match i.cmp(&wit.position) {
                    Ordering::Less => *des = wit.other[i],
                    Ordering::Equal => *des = leaf,
                    Ordering::Greater => *des = wit.other[i - 1],
                }
            }
            // compression
            let feed_forward = perm[0];
            self.permutation_in_place(&mut perm);
            leaf = perm[0] + feed_forward;
        }

        root == leaf
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{Rng, thread_rng};

    fn next_power_of_n(size: usize, n: usize) -> usize {
        let log = size.ilog(n);
        if size == n.pow(log) {
            size
        } else {
            n.pow(log + 1)
        }
    }

    fn trivial_merkle_tree_sponge<
        F: PrimeField,
        const T: usize,
        const D: u64,
        const ARITY: usize,
    >(
        poseidon2: &Poseidon2<F, T, D>,
        mut input: Vec<F>,
    ) -> F {
        assert!(T > ARITY);
        let size_ = next_power_of_n(input.len(), ARITY);
        if size_ != input.len() {
            input.resize(size_, F::zero());
        }

        while input.len() > 1 {
            let mut output = Vec::with_capacity(input.len() / ARITY);
            for inp in input.chunks_exact(ARITY) {
                let mut perm = [F::zero(); T];
                for (i, p) in inp.iter().enumerate() {
                    perm[i] = *p;
                }
                poseidon2.permutation_in_place(&mut perm);
                output.push(perm[0]);
            }
            input = output;
        }

        input[0]
    }

    fn trivial_merkle_tree_compression<
        F: PrimeField,
        const T: usize,
        const D: u64,
        const ARITY: usize,
    >(
        poseidon2: &Poseidon2<F, T, D>,
        mut input: Vec<F>,
    ) -> F {
        assert!(T >= ARITY);
        let size_ = next_power_of_n(input.len(), ARITY);
        if size_ != input.len() {
            input.resize(size_, F::zero());
        }

        while input.len() > 1 {
            let mut output = Vec::with_capacity(input.len() / ARITY);
            for inp in input.chunks_exact(ARITY) {
                let mut perm = [F::zero(); T];
                for (i, p) in inp.iter().enumerate() {
                    perm[i] = *p;
                }
                let feed_forward = perm[0];
                poseidon2.permutation_in_place(&mut perm);
                output.push(perm[0] + feed_forward);
            }
            input = output;
        }

        input[0]
    }

    fn compression_test<F: PrimeField, const DEPTH: usize, const ARITY: usize, const T: usize>() {
        const D: u64 = 5;
        let num_elements = ARITY.pow(DEPTH as u32);

        let mut rng = thread_rng();
        let input = (0..num_elements)
            .map(|_| F::rand(&mut rng))
            .collect::<Vec<_>>();
        let index = rng.gen_range(0..num_elements);
        let leaf = input[index].to_owned();

        let poseidon2 = Poseidon2::<F, T, D>::default();
        let expected = trivial_merkle_tree_compression::<F, T, D, ARITY>(&poseidon2, input.clone());
        let result = poseidon2.merkle_tree_compression::<ARITY>(input.clone());
        assert_eq!(expected, result);

        let (root, witness) = poseidon2.merkle_tree_compression_with_witness::<ARITY>(input, index);
        assert_eq!(root, expected);
        let verified = poseidon2.verifiy_merkle_path_compression(root, leaf, witness);
        assert!(verified);
    }

    fn sponge_test<F: PrimeField, const DEPTH: usize, const ARITY: usize, const T: usize>() {
        const D: u64 = 5;
        let num_elements = ARITY.pow(DEPTH as u32);

        let mut rng = thread_rng();
        let input = (0..num_elements)
            .map(|_| F::rand(&mut rng))
            .collect::<Vec<_>>();
        let index = rng.gen_range(0..num_elements);
        let leaf = input[index].to_owned();

        let poseidon2 = Poseidon2::<F, T, D>::default();
        let expected = trivial_merkle_tree_sponge::<F, T, D, ARITY>(&poseidon2, input.clone());
        let result = poseidon2.merkle_tree_sponge::<ARITY>(input.clone());
        assert_eq!(expected, result);

        let (root, witness) = poseidon2.merkle_tree_sponge_with_witness::<ARITY>(input, index);
        assert_eq!(root, expected);
        let verified = poseidon2.verifiy_merkle_path_sponge(root, leaf, witness);
        assert!(verified);
    }

    #[test]
    fn test_poseidon2_t2_merkle_2_1_compression() {
        const DEPTH: usize = 5;
        const ARITY: usize = 2;
        const T: usize = 2;
        compression_test::<ark_bn254::Fr, DEPTH, ARITY, T>();
    }

    #[test]
    fn test_poseidon2_t3_merkle_2_1_sponge() {
        const DEPTH: usize = 5;
        const ARITY: usize = 2;
        const T: usize = 3;
        sponge_test::<ark_bn254::Fr, DEPTH, ARITY, T>();
    }

    #[test]
    fn test_poseidon2_t3_merkle_2_1_compression() {
        const DEPTH: usize = 5;
        const ARITY: usize = 2;
        const T: usize = 3;
        compression_test::<ark_bn254::Fr, DEPTH, ARITY, T>();
    }

    #[test]
    fn test_poseidon2_t4_merkle_2_1_sponge() {
        const DEPTH: usize = 5;
        const ARITY: usize = 2;
        const T: usize = 4;
        sponge_test::<ark_bn254::Fr, DEPTH, ARITY, T>();
    }

    #[test]
    fn test_poseidon2_t4_merkle_2_1_compression() {
        const DEPTH: usize = 5;
        const ARITY: usize = 2;
        const T: usize = 4;
        compression_test::<ark_bn254::Fr, DEPTH, ARITY, T>();
    }

    #[test]
    fn test_poseidon2_t4_merkle_4_1_compression() {
        const DEPTH: usize = 5;
        const ARITY: usize = 4;
        const T: usize = 4;
        compression_test::<ark_bn254::Fr, DEPTH, ARITY, T>();
    }
}
