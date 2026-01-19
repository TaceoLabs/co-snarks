use std::array;

use super::{Poseidon2, Poseidon2Precomputations};
use crate::{
    gadgets::poseidon2::{
        poseidon2_bn254_t2::{WITNESS_INDICES_SIZE_T2, WITNESS_INDICES_T2},
        poseidon2_bn254_t3::{WITNESS_INDICES_SIZE_T3, WITNESS_INDICES_T3},
        poseidon2_bn254_t4::{WITNESS_INDICES_SIZE_T4, WITNESS_INDICES_T4},
        poseidon2_bn254_t16::{WITNESS_INDICES_SIZE_T16, WITNESS_INDICES_T16},
    },
    protocols::rep3::{self, Rep3PrimeFieldShare, arithmetic, id::PartyID},
};
use ark_ff::PrimeField;
use itertools::izip;
use mpc_net::Network;

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2<F, T, D> {
    fn sbox_rep3_precomp_post_intermediate(
        y: &F,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        precomp_offset: usize,
        id: PartyID,
    ) -> (
        Rep3PrimeFieldShare<F>,
        Rep3PrimeFieldShare<F>,
        Rep3PrimeFieldShare<F>,
    ) {
        assert_eq!(D, 5);
        let (r, r2, r3, r4, r5) = precomp.get(precomp_offset);

        let y2 = y.square();
        let y3 = y2 * y;
        let y4 = y2.square();
        let five = F::from(5u64);
        let ten = F::from(10u64);
        let two = F::from(2u64);
        let four = F::from(4u64);
        let six = F::from(6u64);

        // Trace
        let input_square = rep3::arithmetic::add_public(*r2 + r * *y * two, y2, id);
        let input_quad = rep3::arithmetic::add_public(
            *r4 + *r3 * *y * four + r2 * y2 * six + r * y3 * four,
            y4,
            id,
        );

        let mut res = *r5;
        res += r4 * (five * y);
        res += r3 * (ten * y2);
        res += r2 * (ten * y3);
        res += r * (five * y4);

        if id == PartyID::ID0 {
            let y5 = y4 * y;
            res.a += y5;
        } else if id == PartyID::ID1 {
            let y5 = y4 * y;
            res.b += y5;
        }
        (res, input_square, input_quad)
    }

    /// Computes the Poseidon2 permuation using the Rep3 MPC protocol while overwriting the input. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn rep3_permutation_in_place_with_precomputation_intermediate<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
        assert!(T == 2 || T == 3 || T == 4 || T == 16);
        let offset = precomp.offset;

        // Precompute the maximum number of elements needed for each vector
        let num_states = match T {
            2 | 3 => {
                T * (self.params.rounds_f_beginning - 1)
                    + T * self.params.rounds_f_end
                    + self.params.rounds_p
            }
            4 | 16 => {
                T * (self.params.rounds_f_beginning - 1) + T * self.params.rounds_f_end - 1
                    + self.params.rounds_p
            }
            _ => 0,
        };

        let mut final_mul = [None, None];
        let mut squares_1 = Vec::with_capacity(T * self.params.rounds_f_beginning);
        let mut quads_1 = Vec::with_capacity(T * self.params.rounds_f_beginning);
        let mut squares_2 = Vec::with_capacity(self.params.rounds_p);
        let mut quads_2 = Vec::with_capacity(self.params.rounds_p);
        let mut squares_3 = Vec::with_capacity(T * self.params.rounds_f_end);
        let mut quads_3 = Vec::with_capacity(T * self.params.rounds_f_end);
        let mut states = Vec::with_capacity(num_states);

        let mut trace = if T == 2 {
            vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T2]
        } else if T == 3 {
            vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T3]
        } else if T == 4 {
            vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T4]
        } else {
            vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16]
        };

        // Linear layer at beginning
        Self::matmul_external_rep3(state);

        states.push(state[1]);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            let (squares_, quads_, res) = if r == self.params.rounds_f_beginning - 1 && T == 16 {
                self.rep3_external_round_precomp_matmul_intermediate(state, r, precomp, net)?
            } else {
                self.rep3_external_round_precomp_intermediate(state, r, precomp, net)?
            };

            if r != self.params.rounds_f_beginning - 1 || (T != 4 && T != 16) {
                states.extend_from_slice(state);
            } else if r == self.params.rounds_f_beginning - 1 && T == 4 {
                states.push(state[0]);
                states.push(state[3]);
            } else if r == self.params.rounds_f_beginning - 1 && T == 16 {
                squares_1.push(res);
                quads_1.push(Rep3PrimeFieldShare::<F>::default());
            }
            squares_1.extend(squares_);
            quads_1.extend(quads_);
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            let (sum, squares_, quads_) =
                self.rep3_internal_round_precomp_intermediate(state, r, precomp, net)?;
            squares_2.push(squares_);
            quads_2.push(quads_);
            if T == 16 && r == 0 {
                final_mul[0] = sum;
            }
            if (T == 4 || T == 16) && r == self.params.rounds_p - 1 {
                final_mul[1] = sum;
            }
            if T != 4 && T != 16 {
                states.push(*state.first().unwrap());
            } else if (T == 4 || T == 16) && (r < self.params.rounds_p - 2) {
                states.push(*state.last().unwrap());
            } else if (T == 4 || T == 16) && r == self.params.rounds_p - 2 {
                states.extend_from_slice(&state[1..]);
            }
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (squares_, quads_, sbox_0) =
                self.rep3_external_round_precomp_intermediate(state, r, precomp, net)?;
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                squares_3.push(sbox_0);
                quads_3.push(Rep3PrimeFieldShare::<F>::default());
            }
            squares_3.extend(squares_);
            quads_3.extend(quads_);
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                break;
            }
            states.extend_from_slice(state);
        }

        let wtns_indices: &[u16] = match T {
            2 => WITNESS_INDICES_T2,
            3 => WITNESS_INDICES_T3,
            4 => WITNESS_INDICES_T4,
            16 => WITNESS_INDICES_T16,
            _ => {
                return Err(eyre::eyre!(
                    "Current implementation does not support state size {T}"
                ));
            }
        };
        let mut wtns_indices_iter = wtns_indices.iter().copied();

        for s in &states {
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = *s;
            }
        }

        for (sq, qu) in squares_1
            .into_iter()
            .zip(quads_1.into_iter())
            .chain(squares_3.into_iter().zip(quads_3.into_iter()))
            .chain(squares_2.into_iter().zip(quads_2.into_iter()))
        {
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = sq;
            }
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = qu;
            }
        }
        if T == 16
            && let (Some(first_idx), Some(second_idx), Some(first_val), Some(second_val)) = (
                wtns_indices_iter.next(),
                wtns_indices_iter.next(),
                final_mul[0],
                final_mul[1],
            )
        {
            trace[first_idx as usize] = first_val;
            trace[second_idx as usize] = second_val;
        }

        if T == 4
            && let (Some(idx), Some(val)) = (wtns_indices_iter.next(), final_mul[1])
        {
            trace[idx as usize] = val;
        }

        debug_assert_eq!(precomp.offset - offset, self.num_sbox());
        Ok(trace)
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol. Returns a value needed for the trace when T > 4.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_intermediate<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Rep3PrimeFieldShare<F>,
    )> {
        let id = PartyID::try_from(net.id())?;
        self.add_rc_external_rep3(state, r, id);
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate(state, precomp, net)?;
        let sbox_0 = state[0];
        Self::matmul_external_rep3(state);
        Ok((squares, quads, sbox_0))
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_matmul_intermediate<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Rep3PrimeFieldShare<F>,
    )> {
        assert!(T == 8 || T == 12 || T == 16 || T == 20 || T == 24);
        let id = PartyID::try_from(net.id())?;
        self.add_rc_external_rep3(state, r, id);
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate(state, precomp, net)?;
        let res = Self::matmul_external_rep3_intermediate(state);
        Ok((squares, quads, res))
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_intermediate_packed<N: Network, const BATCH_SIZE: usize>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
        [Rep3PrimeFieldShare<F>; BATCH_SIZE],
    )> {
        assert!(state.len().is_multiple_of(T));
        let id = PartyID::try_from(net.id())?;
        for s in state.chunks_exact_mut(T) {
            self.add_rc_external_rep3(s.try_into().expect("we checked sizes"), r, id);
        }
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate_packed(state, precomp, net)?;
        let sboxes_0: [_; BATCH_SIZE] = array::from_fn(|i| state[i * T]);
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().expect("we checked sizes"));
        }
        Ok((squares, quads, sboxes_0))
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_matmul_intermediate_packed<
        N: Network,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
        [Rep3PrimeFieldShare<F>; BATCH_SIZE],
    )> {
        assert!(state.len().is_multiple_of(T));
        let id = PartyID::try_from(net.id())?;
        for s in state.chunks_exact_mut(T) {
            self.add_rc_external_rep3(s.try_into().expect("we checked sizes"), r, id);
        }
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate_packed(state, precomp, net)?;
        let mut matmul_results = Vec::with_capacity(BATCH_SIZE);
        for s in state.chunks_exact_mut(T) {
            matmul_results.push(Self::matmul_external_rep3_intermediate(
                s.try_into().expect("we checked sizes"),
            ));
        }
        Ok((
            squares,
            quads,
            matmul_results.try_into().expect("we checked sizes"),
        ))
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_intermediate_vec<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        assert!(state.len().is_multiple_of(T));
        let id = PartyID::try_from(net.id())?;
        for s in state.chunks_exact_mut(T) {
            self.add_rc_external_rep3(s.try_into().expect("we checked sizes"), r, id);
        }
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate_vec(state, precomp, net)?;
        let sboxes_0 = state.iter().step_by(T).cloned().collect::<Vec<_>>();
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().expect("we checked sizes"));
        }
        Ok((squares, quads, sboxes_0))
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_matmul_intermediate_vec<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        assert!(state.len().is_multiple_of(T));
        let id = PartyID::try_from(net.id())?;
        for s in state.chunks_exact_mut(T) {
            self.add_rc_external_rep3(s.try_into().expect("we checked sizes"), r, id);
        }
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate_vec(state, precomp, net)?;
        let mut matmul_results = Vec::with_capacity(state.len() / T);
        for s in state.chunks_exact_mut(T) {
            matmul_results.push(Self::matmul_external_rep3_intermediate(
                s.try_into().expect("we checked sizes"),
            ));
        }
        Ok((squares, quads, matmul_results))
    }

    #[expect(clippy::type_complexity)]
    fn sbox_rep3_precomp_intermediate<N: Network>(
        input: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(Vec<Rep3PrimeFieldShare<F>>, Vec<Rep3PrimeFieldShare<F>>)> {
        assert_eq!(D, 5);
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let id = PartyID::try_from(net.id())?;

        let mut squares = Vec::with_capacity(input.len());
        let mut quads = Vec::with_capacity(input.len());
        let mut squ;
        let mut quad;
        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            (*inp, squ, quad) =
                Self::sbox_rep3_precomp_post_intermediate(&y, precomp, precomp.offset + i, id);
            squares.push(squ);
            quads.push(quad);
        }

        precomp.offset += input.len();

        Ok((squares, quads))
    }

    #[expect(clippy::type_complexity)]
    fn sbox_rep3_precomp_intermediate_packed<N: Network, const BATCH_SIZE: usize>(
        input: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
    )> {
        assert!(input.len().is_multiple_of(T));
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let id = PartyID::try_from(net.id())?;

        let mut squares: [_; BATCH_SIZE] = array::from_fn(|_| Vec::with_capacity(input.len()));
        let mut quads: [_; BATCH_SIZE] = array::from_fn(|_| Vec::with_capacity(input.len()));
        let mut squ;
        let mut quad;
        let mut count = 0;
        for (inp, y, squares_, quads_) in izip!(
            input.chunks_exact_mut(T),
            y.chunks_exact(T),
            squares.iter_mut(),
            quads.iter_mut()
        ) {
            for (inp, y) in inp.iter_mut().zip(y) {
                (*inp, squ, quad) = Self::sbox_rep3_precomp_post_intermediate(
                    y,
                    precomp,
                    precomp.offset + count,
                    id,
                );
                squares_.push(squ);
                quads_.push(quad);
                count += 1;
            }
        }

        precomp.offset += input.len();

        Ok((squares, quads))
    }

    #[expect(clippy::type_complexity)]
    fn sbox_rep3_precomp_intermediate_vec<N: Network>(
        input: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
    )> {
        let t2 = input.len() / T;
        assert!(input.len().is_multiple_of(T));
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let id = PartyID::try_from(net.id())?;

        let mut squares = vec![Vec::with_capacity(input.len()); t2];
        let mut quads = vec![Vec::with_capacity(input.len()); t2];
        let mut squ;
        let mut quad;
        let mut count = 0;
        for (inp, y, squares_, quads_) in izip!(
            input.chunks_exact_mut(T),
            y.chunks_exact(T),
            squares.iter_mut(),
            quads.iter_mut()
        ) {
            for (inp, y) in inp.iter_mut().zip(y) {
                (*inp, squ, quad) = Self::sbox_rep3_precomp_post_intermediate(
                    y,
                    precomp,
                    precomp.offset + count,
                    id,
                );
                squares_.push(squ);
                quads_.push(quad);
                count += 1;
            }
        }

        precomp.offset += input.len();

        Ok((squares, quads))
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_internal_round_precomp_intermediate<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Option<Rep3PrimeFieldShare<F>>,
        Rep3PrimeFieldShare<F>,
        Rep3PrimeFieldShare<F>,
    )> {
        let id = PartyID::try_from(net.id())?;
        if id == PartyID::ID0 {
            state[0].a += self.params.round_constants_internal[r];
        } else if id == PartyID::ID1 {
            state[0].b += self.params.round_constants_internal[r];
        }
        let (squares, quads) =
            Self::single_sbox_rep3_precomp_intermediate(&mut state[0], precomp, net)?;
        let sum = if T >= 4 {
            Some(self.matmul_internal_rep3_return_sum(state))
        } else {
            self.matmul_internal_rep3(state);
            None
        };
        Ok((sum, squares, quads))
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_internal_round_precomp_intermediate_packed<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Option<Vec<Rep3PrimeFieldShare<F>>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        let id = PartyID::try_from(net.id())?;
        let t2 = state.len() / T;
        for inp in state.iter_mut().step_by(T) {
            if id == PartyID::ID0 {
                inp.a += self.params.round_constants_internal[r];
            } else if id == PartyID::ID1 {
                inp.b += self.params.round_constants_internal[r];
            }
        }
        let mut vec = state.iter().cloned().step_by(T).collect::<Vec<_>>();
        let (squares, quads) =
            Self::single_sbox_rep3_precomp_intermediate_packed::<N>(&mut vec, precomp, net)?;
        for (inp, r) in state.iter_mut().step_by(T).zip(vec) {
            *inp = r;
        }
        let sum = if T >= 4 {
            let mut sum = Vec::with_capacity(t2);
            for state_chunk in state.chunks_exact_mut(T) {
                sum.push(self.matmul_internal_rep3_return_sum(
                    state_chunk.try_into().expect("Chunk size checked"),
                ));
            }
            Some(sum)
        } else {
            for state_chunk in state.chunks_exact_mut(T) {
                self.matmul_internal_rep3(state_chunk.try_into().expect("Chunk size checked"));
            }
            None
        };
        Ok((sum, squares, quads))
    }

    /// The matrix multiplication in the internal rounds of the Poseidon2 permutation. Implemented for the Rep3 MPC protocol.
    pub fn matmul_internal_rep3_return_sum(
        &self,
        input: &mut [Rep3PrimeFieldShare<F>; T],
    ) -> Rep3PrimeFieldShare<F> {
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

    fn single_sbox_rep3_precomp_intermediate<N: Network>(
        input: &mut Rep3PrimeFieldShare<F>,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(Rep3PrimeFieldShare<F>, Rep3PrimeFieldShare<F>)> {
        assert_eq!(D, 5);
        let r = precomp.get_r(precomp.offset);

        *input -= *r;

        let id = PartyID::try_from(net.id())?;

        // Open
        let y = arithmetic::open(*input, net)?;
        let squ;
        let quad;
        (*input, squ, quad) =
            Self::sbox_rep3_precomp_post_intermediate(&y, precomp, precomp.offset, id);
        precomp.offset += 1;

        Ok((squ, quad))
    }

    #[expect(clippy::type_complexity)]
    fn single_sbox_rep3_precomp_intermediate_packed<N: Network>(
        input: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(Vec<Rep3PrimeFieldShare<F>>, Vec<Rep3PrimeFieldShare<F>>)> {
        let num_parallel = input.len() / T;
        assert_eq!(D, 5);

        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= *precomp.get_r(precomp.offset + i);
        }

        let id = PartyID::try_from(net.id())?;

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let mut squares = Vec::with_capacity(num_parallel);
        let mut quads = Vec::with_capacity(num_parallel);
        let mut squ;
        let mut quad;
        for (i, (inp, y)) in izip!(input.iter_mut(), y.iter()).enumerate() {
            (*inp, squ, quad) =
                Self::sbox_rep3_precomp_post_intermediate(y, precomp, precomp.offset + i, id);
            squares.push(squ);
            quads.push(quad);
        }

        precomp.offset += input.len();

        Ok((squares, quads))
    }

    /// The matrix multiplication in the external rounds of the Poseidon2 permutation. Implemented for the Rep3 MPC protocol. Returns a value needed for the trace when T > 4.
    pub fn matmul_external_rep3_intermediate(
        input: &mut [Rep3PrimeFieldShare<F>; T],
    ) -> Rep3PrimeFieldShare<F> {
        assert!(T == 8 || T == 12 || T == 16 || T == 20 || T == 24);
        match T {
            8 | 12 | 16 | 20 | 24 => {
                // Applying cheap 4x4 MDS matrix to each 4-element part of the state
                for state in input.chunks_exact_mut(4) {
                    Self::matmul_m4_rep3(state.try_into().unwrap());
                }

                let result = input[0].to_owned();

                // Applying second cheap matrix for t > 4
                let mut stored = [Rep3PrimeFieldShare::default(); 4];
                for l in 0..4 {
                    stored[l] = input[l].to_owned();
                    for j in 1..T / 4 {
                        stored[l] += input[4 * j + l];
                    }
                }
                for i in 0..T {
                    input[i] += stored[i % 4];
                }
                result
            }
            _ => {
                panic!("Invalid Statesize");
            }
        }
    }
}

/// A trait for computing the trace of a Circom hash component with public inputs (i.e. in plain).
pub trait CircomTracePlainHasher<F: PrimeField, const T: usize> {
    /// Computes the intermediate values needed for the witness extension for Circom.
    fn plain_permutation_intermediate(&self, state: [F; T]) -> eyre::Result<([F; T], Vec<F>)>;
}
impl<F: PrimeField, const T: usize> Poseidon2<F, T, 5> {
    fn external_round_intermediate(&self, state: &mut [F; T], r: usize) -> (Vec<F>, Vec<F>, F) {
        self.add_rc_external(state, r);
        let (squares, quads) = Self::sbox_plain_intermediate(state);
        let sbox_0 = state[0];
        Self::matmul_external(state);
        (squares, quads, sbox_0)
    }

    fn external_round_matmul_intermediate(
        &self,
        state: &mut [F; T],
        r: usize,
    ) -> (Vec<F>, Vec<F>, F) {
        self.add_rc_external(state, r);
        let (squares, quads) = Self::sbox_plain_intermediate(state);
        let result = Self::matmul_external_intermediate(state);
        (squares, quads, result)
    }

    /// The matrix multiplication in the external rounds of the Poseidon2 permutation, returning a value needed for the trace when T > 4.
    pub fn matmul_external_intermediate(input: &mut [F; T]) -> F {
        assert!(T == 8 || T == 12 || T == 16 || T == 20 || T == 24);
        match T {
            8 | 12 | 16 | 20 | 24 => {
                // Applying cheap 4x4 MDS matrix to each 4-element part of the state
                for state in input.chunks_exact_mut(4) {
                    Self::matmul_m4(state.try_into().unwrap());
                }

                let result = input[0];

                // Applying second cheap matrix for t > 4
                let mut stored = [F::zero(); 4];
                for l in 0..4 {
                    stored[l] = input[l];
                    for j in 1..T / 4 {
                        stored[l] += input[4 * j + l];
                    }
                }
                for i in 0..T {
                    input[i] += stored[i % 4];
                }
                result
            }
            _ => {
                panic!("Invalid Statesize");
            }
        }
    }

    fn sbox_plain_intermediate(state: &mut [F; T]) -> (Vec<F>, Vec<F>) {
        let mut squares = Vec::with_capacity(T);
        let mut quads = Vec::with_capacity(T);
        for s in state.iter_mut() {
            let (input2, input4) = Self::single_sbox_plain_intermediate(s);

            squares.push(input2);
            quads.push(input4);
        }
        (squares, quads)
    }

    fn plain_internal_round_intermediate(&self, state: &mut [F; T], r: usize) -> (Option<F>, F, F) {
        state[0] += self.params.round_constants_internal[r];
        let (squares, quads) = Self::single_sbox_plain_intermediate(&mut state[0]);
        let sum = if T >= 4 {
            Some(self.matmul_internal_return_sum(state))
        } else {
            self.matmul_internal(state);
            None
        };
        (sum, squares, quads)
    }

    fn single_sbox_plain_intermediate(input: &mut F) -> (F, F) {
        let input_square = input.square();
        let input_quad = input_square.square();
        *input *= input_quad;

        (input_square, input_quad)
    }
    fn matmul_internal_return_sum(&self, input: &mut [F; T]) -> F {
        debug_assert!(T >= 4); // We only need the sum for T >= 4
        // Compute input sum
        let mut sum = input[0];
        for el in input.iter().skip(1) {
            sum += *el;
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
}

impl<F: PrimeField, const T: usize> CircomTracePlainHasher<F, T> for Poseidon2<F, T, 5> {
    fn plain_permutation_intermediate(&self, state: [F; T]) -> eyre::Result<([F; T], Vec<F>)> {
        assert!(T == 2 || T == 3 || T == 4 || T == 16);
        let mut state = state;
        // Precompute the maximum number of elements needed for each vector
        let num_states = match T {
            2 | 3 => {
                T * (self.params.rounds_f_beginning - 1)
                    + T * self.params.rounds_f_end
                    + self.params.rounds_p
            }
            4 | 16 => {
                T * (self.params.rounds_f_beginning - 1) + T * self.params.rounds_f_end - 1
                    + self.params.rounds_p
            }
            _ => 0,
        };

        let mut final_mul = [None, None];
        let mut squares_1 = Vec::with_capacity(T * self.params.rounds_f_beginning);
        let mut quads_1 = Vec::with_capacity(T * self.params.rounds_f_beginning);
        let mut squares_2 = Vec::with_capacity(self.params.rounds_p);
        let mut quads_2 = Vec::with_capacity(self.params.rounds_p);
        let mut squares_3 = Vec::with_capacity(T * self.params.rounds_f_end);
        let mut quads_3 = Vec::with_capacity(T * self.params.rounds_f_end);
        let mut states = Vec::with_capacity(num_states);

        let mut trace = if T == 2 {
            vec![F::default(); WITNESS_INDICES_SIZE_T2]
        } else if T == 3 {
            vec![F::default(); WITNESS_INDICES_SIZE_T3]
        } else if T == 4 {
            vec![F::default(); WITNESS_INDICES_SIZE_T4]
        } else {
            vec![F::default(); WITNESS_INDICES_SIZE_T16]
        };

        // Linear layer at beginning
        Self::matmul_external(&mut state);

        states.push(state[1]);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            let (squares_, quads_, res) = if r == self.params.rounds_f_beginning - 1 && T == 16 {
                self.external_round_matmul_intermediate(&mut state, r)
            } else {
                self.external_round_intermediate(&mut state, r)
            };

            if r != self.params.rounds_f_beginning - 1 || (T != 4 && T != 16) {
                states.extend_from_slice(&state);
            } else if r == self.params.rounds_f_beginning - 1 && T == 4 {
                states.push(state[0]);
                states.push(state[3]);
            } else if r == self.params.rounds_f_beginning - 1 && T == 16 {
                squares_1.push(res);
                quads_1.push(F::default());
            }
            squares_1.extend(squares_);
            quads_1.extend(quads_);
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            let (sum, squares_, quads_) = self.plain_internal_round_intermediate(&mut state, r);
            squares_2.push(squares_);
            quads_2.push(quads_);
            if T == 16 && r == 0 {
                final_mul[0] = sum;
            }
            if (T == 4 || T == 16) && r == self.params.rounds_p - 1 {
                final_mul[1] = sum;
            }
            if T != 4 && T != 16 {
                states.push(*state.first().unwrap());
            } else if (T == 4 || T == 16) && (r < self.params.rounds_p - 2) {
                states.push(*state.last().unwrap());
            } else if (T == 4 || T == 16) && r == self.params.rounds_p - 2 {
                states.extend_from_slice(&state[1..]);
            }
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (squares_, quads_, sbox_0) = self.external_round_intermediate(&mut state, r);
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                squares_3.push(sbox_0);
                quads_3.push(F::zero());
            }
            squares_3.extend(squares_);
            quads_3.extend(quads_);
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                break;
            }
            states.extend_from_slice(&state);
        }

        let wtns_indices: &[u16] = match T {
            2 => WITNESS_INDICES_T2,
            3 => WITNESS_INDICES_T3,
            4 => WITNESS_INDICES_T4,
            16 => WITNESS_INDICES_T16,
            _ => {
                return Err(eyre::eyre!(
                    "Current implementation does not support state size {T}"
                ));
            }
        };
        let mut wtns_indices_iter = wtns_indices.iter().copied();

        for s in &states {
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = *s;
            }
        }

        for (sq, qu) in squares_1
            .into_iter()
            .zip(quads_1.into_iter())
            .chain(squares_3.into_iter().zip(quads_3.into_iter()))
            .chain(squares_2.into_iter().zip(quads_2.into_iter()))
        {
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = sq;
            }
            if let Some(idx) = wtns_indices_iter.next() {
                trace[idx as usize] = qu;
            }
        }
        if T == 16
            && let (Some(first_idx), Some(second_idx), Some(first_val), Some(second_val)) = (
                wtns_indices_iter.next(),
                wtns_indices_iter.next(),
                final_mul[0],
                final_mul[1],
            )
        {
            trace[first_idx as usize] = first_val;
            trace[second_idx as usize] = second_val;
        }

        if T == 4
            && let (Some(idx), Some(val)) = (wtns_indices_iter.next(), final_mul[1])
        {
            trace[idx as usize] = val;
        }

        Ok((state, trace))
    }
}

/// A trait for computing the trace of a Circom hash component in a batched MPC setting.
pub trait CircomTraceBatchedHasher<F: PrimeField, const T: usize> {
    /// The type holding data required for preprocessing the Sbox of the permutation.
    type Precomputation;

    #[expect(clippy::type_complexity)]
    /// Computes the intermediate values needed for the witness extension for Circom in a batched MPC setting.
    fn rep3_permutation_in_place_with_precomputation_intermediate_packed<
        N: Network,
        const T2: usize,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: [Rep3PrimeFieldShare<F>; T2],
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<(
        [Rep3PrimeFieldShare<F>; T2],
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
    )>;

    #[expect(clippy::type_complexity)]
    /// Computes the intermediate values needed for the witness extension for Circom in a batched MPC setting, where the size of the batch is dynamic.
    fn rep3_permutation_in_place_with_precomputation_intermediate_vec<N: Network>(
        &self,
        state: Vec<Rep3PrimeFieldShare<F>>,
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<(
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
    )>;
}

impl<F: PrimeField, const T: usize> CircomTraceBatchedHasher<F, T> for Poseidon2<F, T, 5> {
    type Precomputation = Poseidon2Precomputations<Rep3PrimeFieldShare<F>>;

    fn rep3_permutation_in_place_with_precomputation_intermediate_packed<
        N: Network,
        const T2: usize,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: [Rep3PrimeFieldShare<F>; T2],
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<(
        [Rep3PrimeFieldShare<F>; T2],
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
    )> {
        assert!(T == 2 || T == 3 || T == 4 || T == 16);
        assert!(T2 == T * BATCH_SIZE);
        let mut state = state;
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
            4 | 16 => {
                T * (self.params.rounds_f_beginning - 1) + T * self.params.rounds_f_end - 1
                    + self.params.rounds_p
            }
            _ => 0,
        };
        let mut final_mul: [[Option<Rep3PrimeFieldShare<F>>; 2]; BATCH_SIZE] =
            array::from_fn(|_| [None, None]);
        let mut squares_1: [_; BATCH_SIZE] =
            array::from_fn(|_| Vec::with_capacity(T * self.params.rounds_f_beginning));
        let mut quads_1: [_; BATCH_SIZE] =
            array::from_fn(|_| Vec::with_capacity(T * self.params.rounds_f_beginning));
        let mut squares_2: [_; BATCH_SIZE] =
            array::from_fn(|_| Vec::with_capacity(self.params.rounds_p));
        let mut quads_2: [_; BATCH_SIZE] =
            array::from_fn(|_| Vec::with_capacity(self.params.rounds_p));
        let mut squares_3: [_; BATCH_SIZE] =
            array::from_fn(|_| Vec::with_capacity(T * self.params.rounds_f_end));
        let mut quads_3: [_; BATCH_SIZE] =
            array::from_fn(|_| Vec::with_capacity(T * self.params.rounds_f_end));
        let mut states: [_; BATCH_SIZE] = array::from_fn(|_| Vec::with_capacity(num_states));

        let mut traces: [_; BATCH_SIZE] = array::from_fn(|_| {
            if T == 2 {
                vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T2]
            } else if T == 3 {
                vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T3]
            } else if T == 4 {
                vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T4]
            } else {
                vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16]
            }
        });

        // Linear layer at beginning
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().unwrap());
        }

        for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
            states_.push(state_[1]);
        }

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            let (squares_, quads_, res): ([_; BATCH_SIZE], [_; BATCH_SIZE], [_; BATCH_SIZE]) = if r
                == self.params.rounds_f_beginning - 1
                && T == 16
            {
                self.rep3_external_round_precomp_matmul_intermediate_packed(
                    &mut state, r, precomp, net,
                )?
            } else {
                self.rep3_external_round_precomp_intermediate_packed(&mut state, r, precomp, net)?
            };
            if r != self.params.rounds_f_beginning - 1 || (T != 4 && T != 16) {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.extend_from_slice(state_);
                }
            } else if r == self.params.rounds_f_beginning - 1 && T == 4 {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.push(state_[0]);
                    states_.push(state_[3]);
                }
            } else if r == self.params.rounds_f_beginning - 1 && T == 16 {
                for (squares_1_, res_, quads_1_) in
                    izip!(squares_1.iter_mut(), res.iter(), quads_1.iter_mut(),)
                {
                    squares_1_.push(*res_);
                    quads_1_.push(Rep3PrimeFieldShare::<F>::default());
                }
            }
            for (squares_1_, squares__, quads_1_, quads__) in izip!(
                squares_1.iter_mut(),
                squares_.iter(),
                quads_1.iter_mut(),
                quads_.iter()
            ) {
                squares_1_.extend(squares__);
                quads_1_.extend(quads__);
            }
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            let (sum, squares_, quads_) = self
                .rep3_internal_round_precomp_intermediate_packed::<N>(
                    &mut state, r, precomp, net,
                )?;
            for (squares_2_, squares__, quads_2_, quads__) in izip!(
                squares_2.iter_mut(),
                squares_.iter(),
                quads_2.iter_mut(),
                quads_.iter()
            ) {
                squares_2_.push(*squares__);
                quads_2_.push(*quads__);
            }

            let set_first = T == 16 && r == 0;
            let set_last = (T == 4 || T == 16) && r == self.params.rounds_p - 1;

            if set_first || set_last {
                let sum_vec = sum.as_ref().expect("T >= 4 means sum should be Some");
                for (final_mul, sum_) in final_mul.iter_mut().zip(sum_vec.iter()) {
                    if set_first {
                        final_mul[0] = Some(*sum_);
                    }
                    if set_last {
                        final_mul[1] = Some(*sum_);
                    }
                }
            }

            if T != 4 && T != 16 {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.push(*state_.first().unwrap());
                }
            } else if (T == 4 || T == 16) && (r < self.params.rounds_p - 2) {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.push(*state_.last().unwrap());
                }
            } else if (T == 4 || T == 16) && r == self.params.rounds_p - 2 {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.extend_from_slice(&state_[1..]);
                }
            }
        }

        let wtns_indices: &[u16] = match T {
            2 => WITNESS_INDICES_T2,
            3 => WITNESS_INDICES_T3,
            4 => WITNESS_INDICES_T4,
            16 => WITNESS_INDICES_T16,
            _ => {
                return Err(eyre::eyre!(
                    "Current implementation does not support state size {T}"
                ));
            }
        };

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (squares_, quads_, sboxes_0): ([_; BATCH_SIZE], [_; BATCH_SIZE], [_; BATCH_SIZE]) =
                self.rep3_external_round_precomp_intermediate_packed(&mut state, r, precomp, net)?;
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                for (squares_3_, sbox_0) in squares_3.iter_mut().zip(sboxes_0.iter()) {
                    squares_3_.push(*sbox_0);
                }
                for quads_3_ in quads_3.iter_mut() {
                    quads_3_.push(Rep3PrimeFieldShare::<F>::default());
                }
            }
            for (squares_3_, squares__, quads_3_, quads__) in izip!(
                squares_3.iter_mut(),
                squares_.iter(),
                quads_3.iter_mut(),
                quads_.iter()
            ) {
                squares_3_.extend(squares__);
                quads_3_.extend(quads__);
            }
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                break;
            }
            for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                states_.extend_from_slice(state_);
            }
        }

        let mut counter = 0;
        for (i, state) in states.iter().enumerate() {
            for (j, s) in state.iter().enumerate() {
                traces[i][wtns_indices[j] as usize] = *s;
            }
        }
        counter += states[0].len();

        for (i, (squares_1_, quads_1_)) in izip!(squares_1.iter(), quads_1.iter()).enumerate() {
            for (j, (sq, qu)) in squares_1_.iter().zip(quads_1_.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_1[0].len();

        for (i, (squares_3_, quads_3_)) in izip!(squares_3.iter(), quads_3.iter()).enumerate() {
            for (j, (sq, qu)) in squares_3_.iter().zip(quads_3_.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_3[0].len();

        for (i, (squares_2_, quads_2_)) in izip!(squares_2.iter(), quads_2.iter()).enumerate() {
            for (j, (sq, qu)) in squares_2_.iter().zip(quads_2_.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_2[0].len();

        if T == 16 {
            for (i, final_mul_) in final_mul.iter().enumerate() {
                if let (Some(first_val), Some(second_val)) = (final_mul_[0], final_mul_[1]) {
                    traces[i][wtns_indices[counter] as usize] = first_val;
                    traces[i][wtns_indices[counter + 1] as usize] = second_val;
                }
            }
        }

        if T == 4 {
            for (i, final_mul_) in final_mul.iter().enumerate() {
                if let Some(val) = final_mul_[1] {
                    traces[i][wtns_indices[counter] as usize] = val;
                }
            }
        }

        Ok((state, traces))
    }

    fn rep3_permutation_in_place_with_precomputation_intermediate_vec<N: Network>(
        &self,
        state: Vec<Rep3PrimeFieldShare<F>>,
        precomp: &mut Self::Precomputation,
        net: &N,
    ) -> eyre::Result<(
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
    )> {
        assert!(T == 2 || T == 3 || T == 4 || T == 16);
        let t2 = state.len();

        let mut state = state;
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
            4 | 16 => {
                T * (self.params.rounds_f_beginning - 1) + T * self.params.rounds_f_end - 1
                    + self.params.rounds_p
            }
            _ => 0,
        };
        let mut final_mul = vec![[None, None]; t2];
        let mut squares_1 = vec![Vec::with_capacity(T * self.params.rounds_f_beginning); t2];
        let mut quads_1 = vec![Vec::with_capacity(T * self.params.rounds_f_beginning); t2];
        let mut squares_2 = vec![Vec::with_capacity(self.params.rounds_p); t2];
        let mut quads_2 = vec![Vec::with_capacity(self.params.rounds_p); t2];
        let mut squares_3 = vec![Vec::with_capacity(T * self.params.rounds_f_end); t2];
        let mut quads_3 = vec![Vec::with_capacity(T * self.params.rounds_f_end); t2];
        let mut states = vec![Vec::with_capacity(num_states); t2];

        let mut traces = if T == 2 {
            vec![vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T2]; t2]
        } else if T == 3 {
            vec![vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T3]; t2]
        } else if T == 4 {
            vec![vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T4]; t2]
        } else {
            vec![vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16]; t2]
        };

        // Linear layer at beginning
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().unwrap());
        }

        for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
            states_.push(state_[1]);
        }

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            let (squares_, quads_, res) = if r == self.params.rounds_f_beginning - 1 && T == 16 {
                self.rep3_external_round_precomp_matmul_intermediate_vec(
                    &mut state, r, precomp, net,
                )?
            } else {
                self.rep3_external_round_precomp_intermediate_vec(&mut state, r, precomp, net)?
            };
            if r != self.params.rounds_f_beginning - 1 || (T != 4 && T != 16) {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.extend_from_slice(state_);
                }
            } else if r == self.params.rounds_f_beginning - 1 && T == 4 {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.push(state_[0]);
                    states_.push(state_[3]);
                }
            } else if r == self.params.rounds_f_beginning - 1 && T == 16 {
                for (squares_1_, res_, quads_1_) in
                    izip!(squares_1.iter_mut(), res.iter(), quads_1.iter_mut(),)
                {
                    squares_1_.push(*res_);
                    quads_1_.push(Rep3PrimeFieldShare::<F>::default());
                }
            }
            for (squares_1_, squares__, quads_1_, quads__) in izip!(
                squares_1.iter_mut(),
                squares_.iter(),
                quads_1.iter_mut(),
                quads_.iter()
            ) {
                squares_1_.extend(squares__);
                quads_1_.extend(quads__);
            }
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            let (sum, squares_, quads_) = self
                .rep3_internal_round_precomp_intermediate_packed::<N>(
                    &mut state, r, precomp, net,
                )?;
            for (squares_2_, squares__, quads_2_, quads__) in izip!(
                squares_2.iter_mut(),
                squares_.iter(),
                quads_2.iter_mut(),
                quads_.iter()
            ) {
                squares_2_.push(*squares__);
                quads_2_.push(*quads__);
            }

            let set_first = T == 16 && r == 0;
            let set_last = (T == 4 || T == 16) && r == self.params.rounds_p - 1;

            if set_first || set_last {
                let sum_vec = sum.as_ref().expect("T >= 4 means sum should be Some");
                for (final_mul, sum_) in final_mul.iter_mut().zip(sum_vec.iter()) {
                    if set_first {
                        final_mul[0] = Some(*sum_);
                    }
                    if set_last {
                        final_mul[1] = Some(*sum_);
                    }
                }
            }

            if T != 4 && T != 16 {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.push(*state_.first().unwrap());
                }
            } else if (T == 4 || T == 16) && (r < self.params.rounds_p - 2) {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.push(*state_.last().unwrap());
                }
            } else if (T == 4 || T == 16) && r == self.params.rounds_p - 2 {
                for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                    states_.extend_from_slice(&state_[1..]);
                }
            }
        }

        let wtns_indices: &[u16] = match T {
            2 => WITNESS_INDICES_T2,
            3 => WITNESS_INDICES_T3,
            4 => WITNESS_INDICES_T4,
            16 => WITNESS_INDICES_T16,
            _ => {
                return Err(eyre::eyre!(
                    "Current implementation does not support state size {T}"
                ));
            }
        };

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (squares_, quads_, sboxes_0) =
                self.rep3_external_round_precomp_intermediate_vec(&mut state, r, precomp, net)?;
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                for (squares_3_, sbox_0) in squares_3.iter_mut().zip(sboxes_0.iter()) {
                    squares_3_.push(*sbox_0);
                }
                for quads_3_ in quads_3.iter_mut() {
                    quads_3_.push(Rep3PrimeFieldShare::<F>::default());
                }
            }
            for (squares_3_, squares__, quads_3_, quads__) in izip!(
                squares_3.iter_mut(),
                squares_.iter(),
                quads_3.iter_mut(),
                quads_.iter()
            ) {
                squares_3_.extend(squares__);
                quads_3_.extend(quads__);
            }
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                break;
            }
            for (states_, state_) in states.iter_mut().zip(state.chunks(T)) {
                states_.extend_from_slice(state_);
            }
        }

        let mut counter = 0;
        for (i, state) in states.iter().enumerate() {
            for (j, s) in state.iter().enumerate() {
                traces[i][wtns_indices[j] as usize] = *s;
            }
        }
        counter += states[0].len();

        for (i, (squares_1_, quads_1_)) in izip!(squares_1.iter(), quads_1.iter()).enumerate() {
            for (j, (sq, qu)) in squares_1_.iter().zip(quads_1_.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_1[0].len();

        for (i, (squares_3_, quads_3_)) in izip!(squares_3.iter(), quads_3.iter()).enumerate() {
            for (j, (sq, qu)) in squares_3_.iter().zip(quads_3_.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_3[0].len();

        for (i, (squares_2_, quads_2_)) in izip!(squares_2.iter(), quads_2.iter()).enumerate() {
            for (j, (sq, qu)) in squares_2_.iter().zip(quads_2_.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_2[0].len();

        if T == 16 {
            for (i, final_mul_) in final_mul.iter().enumerate() {
                if let (Some(first_val), Some(second_val)) = (final_mul_[0], final_mul_[1]) {
                    traces[i][wtns_indices[counter] as usize] = first_val;
                    traces[i][wtns_indices[counter + 1] as usize] = second_val;
                }
            }
        }

        if T == 4 {
            for (i, final_mul_) in final_mul.iter().enumerate() {
                if let Some(val) = final_mul_[1] {
                    traces[i][wtns_indices[counter] as usize] = val;
                }
            }
        }

        Ok((state, traces))
    }
}
