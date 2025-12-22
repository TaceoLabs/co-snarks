use super::Poseidon2;
use crate::gadgets::poseidon2::{
    poseidon2_bn254_t2::{WITNESS_INDICES_SIZE_T2, WITNESS_INDICES_T2},
    poseidon2_bn254_t3::{WITNESS_INDICES_SIZE_T3, WITNESS_INDICES_T3},
    poseidon2_bn254_t4::{WITNESS_INDICES_SIZE_T4, WITNESS_INDICES_T4},
};
use ark_ff::PrimeField;

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2<F, T, D> {
    /// Performs the Poseidon2 Permutation on the given state, returning intermediate values needed for Circom WitExt.
    pub fn permutation_in_place_intermediate(&self, state: &mut [F; T]) -> eyre::Result<Vec<F>> {
        assert!(T == 2 || T == 3 || T == 4);

        // Precompute the maximum number of elements needed for each vector
        let num_states = match T {
            2 => {
                T * (self.params.rounds_f_beginning - 1)
                    + T * self.params.rounds_f_end
                    + self.params.rounds_p
            }
            3 => {
                T * (self.params.rounds_f_beginning - 1)
                    + T * self.params.rounds_f_end
                    + self.params.rounds_p
            }
            4 => {
                T * (self.params.rounds_f_beginning - 1) + T * self.params.rounds_f_end - 1
                    + self.params.rounds_p
            }
            _ => 0,
        };

        let mut final_mul = None;
        let mut squares_1 = Vec::with_capacity(T * self.params.rounds_f_beginning);
        let mut quads_1 = Vec::with_capacity(T * self.params.rounds_f_beginning);
        let mut squares_2 = Vec::with_capacity(self.params.rounds_p);
        let mut quads_2 = Vec::with_capacity(self.params.rounds_p);
        let mut squares_3 = Vec::with_capacity(T * self.params.rounds_f_end);
        let mut quads_3 = Vec::with_capacity(T * self.params.rounds_f_end);
        let mut states = Vec::with_capacity(num_states);

        let mut trace = if T == 2 {
            [F::default(); WITNESS_INDICES_SIZE_T2].to_vec()
        } else if T == 3 {
            [F::default(); WITNESS_INDICES_SIZE_T3].to_vec()
        } else {
            [F::default(); WITNESS_INDICES_SIZE_T4].to_vec()
        };

        // Linear layer at beginning
        Self::matmul_external(state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            let (squares_, quads_) = self.external_round_intermediate(state, r)?;
            if r != self.params.rounds_f_beginning - 1 || T != 4 {
                states.extend_from_slice(state);
            } else if r == self.params.rounds_f_beginning - 1 && T == 4 {
                states.push(state[0]);
                states.push(state[3]);
            }
            squares_1.extend(squares_);
            quads_1.extend(quads_);
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            let (sum, squares_, quads_) = self.internal_round_intermediate(state, r)?;
            squares_2.push(squares_);
            quads_2.push(quads_);
            if T == 4 && r == self.params.rounds_p - 1 {
                final_mul = sum;
            }
            if T != 4 {
                states.push(*state.first().unwrap());
            } else if T == 4 && (r < self.params.rounds_p - 2) {
                states.push(*state.last().unwrap());
            } else if T == 4 && r == self.params.rounds_p - 2 {
                states.push(state[1]);
                states.push(state[2]);
                states.push(state[3]);
            }
        }

        let wtns_indices: &[u16] = match T {
            2 => WITNESS_INDICES_T2,
            3 => WITNESS_INDICES_T3,
            4 => WITNESS_INDICES_T4,
            _ => {
                return Err(eyre::eyre!(
                    "Current implementation does not support state size {T}"
                ));
            }
        };
        let mut wtns_indices_iter = wtns_indices.iter().copied();

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (squares_, quads_) = self.external_round_intermediate(state, r)?;
            squares_3.extend(squares_);
            quads_3.extend(quads_);
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                break;
            }
            states.extend_from_slice(state);
        }

        for s in &states {
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = *s;
            }
        }
        for (sq, qu) in squares_1.into_iter().zip(quads_1.into_iter()) {
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = sq;
            }
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = qu;
            }
        }
        for (sq, qu) in squares_3.into_iter().zip(quads_3.into_iter()) {
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = sq;
            }
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = qu;
            }
        }
        for (sq, qu) in squares_2.into_iter().zip(quads_2.into_iter()) {
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = sq;
            }
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = qu;
            }
        }
        if T == 4
            && let (Some(idx), Some(val)) = (wtns_indices_iter.next(), final_mul)
        {
            trace[idx as usize] = val;
        }

        Ok(trace)
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    pub fn external_round_intermediate(
        &self,
        state: &mut [F; T],
        r: usize,
    ) -> eyre::Result<(Vec<F>, Vec<F>)> {
        self.add_rc_internal(state, r);
        let (squares, quads) = Self::sbox_intermediate(state)?;
        Self::matmul_external(state);
        Ok((squares, quads))
    }

    fn sbox_intermediate(input: &mut [F; T]) -> eyre::Result<(Vec<F>, Vec<F>)> {
        assert_eq!(D, 5);

        let mut squares = Vec::with_capacity(input.len());
        let mut quads = Vec::with_capacity(input.len());
        for el in input.iter_mut() {
            let input2 = el.square();
            let input4 = input2.square();
            *el *= input4;

            squares.push(input2);
            quads.push(input4);
        }

        Ok((squares, quads))
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    pub fn internal_round_intermediate(
        &self,
        state: &mut [F; T],
        r: usize,
    ) -> eyre::Result<(Option<F>, F, F)> {
        self.add_rc_internal(state, r);
        let (squares, quads) = Self::single_sbox_intermediate(&mut state[0])?;
        let sum = if T >= 4 {
            Some(self.matmul_internal_return_sum(state))
        } else {
            self.matmul_internal(state);
            None
        };
        Ok((sum, squares, quads))
    }

    /// The matrix multiplication in the internal rounds of the Poseidon2 permutation. Implemented for the Rep3 MPC protocol.
    pub fn matmul_internal_return_sum(&self, input: &mut [F; T]) -> F {
        debug_assert!(T >= 4); // We only need the sum for T >= 4
        // Compute input sum
        let mut sum = input[0];
        for el in input.iter().skip(1) {
            sum += el;
        }
        // Add sum + diag entry * element to each element

        for (s, m) in input
            .iter_mut()
            .zip(self.params.mat_internal_diag_m_1.iter())
        {
            *s *= *m;
            *s += sum;
        }
        sum
    }

    fn single_sbox_intermediate(input: &mut F) -> eyre::Result<(F, F)> {
        assert_eq!(D, 5);
        let input2 = input.square();
        let input4 = input2.square();
        *input *= input4;

        Ok((input2, input4))
    }
}
