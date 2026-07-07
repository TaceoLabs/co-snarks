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
    /// The matrix multiplication in the external rounds of the Poseidon2 permutation. Implemented for the Rep3 MPC protocol.
    pub fn matmul_external_rep3_intermediate_t16(
        input: &mut [Rep3PrimeFieldShare<F>; T],
    ) -> [Rep3PrimeFieldShare<F>; T] {
        match T {
            16 => {
                let mut res = [Rep3PrimeFieldShare::default(); T];
                let mut idx = 0;
                // Applying cheap 4x4 MDS matrix to each 4-element part of the state
                for state in input.chunks_exact_mut(4) {
                    Self::matmul_m4_rep3(state.try_into().unwrap());
                }

                // Applying second cheap matrix for t > 4
                let mut stored = [Rep3PrimeFieldShare::default(); 4];
                for l in 0..4 {
                    stored[l] = input[l].to_owned();
                    res[idx] = input[l];
                    idx += 1;
                    for j in 1..T / 4 {
                        res[idx] = input[4 * j + l];
                        idx += 1;
                        stored[l] += input[4 * j + l];
                    }
                }
                for i in 0..T {
                    input[i] += stored[i % 4];
                }
                res
            }
            _ => {
                panic!("Invalid state size, this function is only implemented for T=16");
            }
        }
    }

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

    /// Computes the Poseidon2 permutation using the Rep3 MPC protocol while overwriting the input. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn rep3_permutation_in_place_with_precomputation_intermediate<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
        assert!(T == 2 || T == 3 || T == 4 || T == 16);
        if T == 16 {
            return self.rep3_permutation_in_place_with_precomputation_intermediate_t16_fast(
                state, precomp, net,
            );
        }

        // Fast path for T in {2, 3, 4}: the destination index of every state/square/quad value
        // in `trace` is a deterministic function of T and the (compile-time-fixed) round counts,
        // so we write directly into `trace` instead of buffering into per-round Vecs and
        // reassembling them afterwards. The flattened layout (matching the buffering order the
        // slow path used to produce) is:
        // [states] [squares_1/quads_1] [squares_3/quads_3] [squares_2/quads_2] [final_mul (T=4 only)]
        let offset = precomp.offset;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let (wtns_indices, trace_size): (&[u16], usize) = match T {
            2 => (WITNESS_INDICES_T2, WITNESS_INDICES_SIZE_T2),
            3 => (WITNESS_INDICES_T3, WITNESS_INDICES_SIZE_T3),
            4 => (WITNESS_INDICES_T4, WITNESS_INDICES_SIZE_T4),
            _ => {
                return Err(eyre::eyre!(
                    "Current implementation does not support state size {T}"
                ));
            }
        };
        let mut trace = vec![Rep3PrimeFieldShare::<F>::default(); trace_size];

        let states_len = if T == 4 {
            T * (f1 + f2 - 1) + p + 3
        } else {
            T * (f1 + f2) + p
        };
        let sq1_len = f1 * T;
        let sq3_len = f2 * T + 1;

        let mut idx_states = 0usize;
        let mut idx_sq1 = states_len;
        let mut idx_sq3 = idx_sq1 + 2 * sq1_len;
        let mut idx_sq2 = idx_sq3 + 2 * sq3_len;

        macro_rules! put {
            ($idx:expr, $val:expr) => {{
                trace[wtns_indices[$idx] as usize] = $val;
                $idx += 1;
            }};
        }

        // Linear layer at beginning
        Self::matmul_external_rep3(state);
        for s in state.iter() {
            put!(idx_states, *s);
        }

        // First set of external rounds
        for r in 0..f1 {
            let (squares_, quads_, _, _, _) =
                self.rep3_external_round_precomp_intermediate(state, r, precomp, net)?;
            if r != f1 - 1 || T != 4 {
                for s in state.iter() {
                    put!(idx_states, *s);
                }
            } else {
                put!(idx_states, state[0]);
                put!(idx_states, state[3]);
            }
            for (sq, qu) in squares_.into_iter().zip(quads_) {
                put!(idx_sq1, sq);
                put!(idx_sq1, qu);
            }
        }

        // Internal rounds
        let mut final_mul = None;
        for r in 0..p {
            let (sum, squares_, quads_) =
                self.rep3_internal_round_precomp_intermediate(state, r, precomp, net)?;
            put!(idx_sq2, squares_);
            put!(idx_sq2, quads_);
            if T == 4 && r == p - 1 {
                final_mul = sum;
            }
            if T != 4 {
                put!(idx_states, *state.first().unwrap());
            } else if r < p - 2 {
                put!(idx_states, *state.last().unwrap());
            } else if r == p - 2 {
                for s in &state[1..] {
                    put!(idx_states, *s);
                }
            }
        }

        // Remaining external rounds
        for r in f1..f1 + f2 {
            let (squares_, quads_, sbox_0, sbox_1, _) =
                self.rep3_external_round_precomp_intermediate(state, r, precomp, net)?;
            let is_last = r == f1 + f2 - 1;
            if is_last {
                put!(idx_sq3, sbox_0);
                put!(idx_sq3, sbox_1);
            }
            for (sq, qu) in squares_.into_iter().zip(quads_) {
                put!(idx_sq3, sq);
                put!(idx_sq3, qu);
            }
            if is_last {
                break;
            }
            for s in state.iter() {
                put!(idx_states, *s);
            }
        }

        if T == 4
            && let Some(val) = final_mul
        {
            trace[wtns_indices[idx_sq2] as usize] = val;
        }

        debug_assert_eq!(precomp.offset - offset, self.num_sbox());
        Ok(trace)
    }

    /// Fast path for T = 16: same direct-write technique as the T in {2,3,4} path above, but with
    /// the additional matmul-external and last-matmul-external sections that only exist for T=16.
    /// Section lengths were derived empirically (cross-checked against `WITNESS_INDICES_T16` via
    /// the KAT/random tests) rather than by closed-form arithmetic, since T=16's extra branches
    /// make hand-derivation error-prone.
    fn rep3_permutation_in_place_with_precomputation_intermediate_t16_fast<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
        assert_eq!(T, 16);
        let offset = precomp.offset;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let wtns_indices = WITNESS_INDICES_T16;
        let mut trace = vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16];

        let states_len = T * (f1 + f2 - 1) + p + T - 3;
        let sq1_len = f1 * T + 1;
        let sq3_len = f2 * T + 1;

        let mut idx_states = 0usize;
        let mut idx_matmul_ext = states_len;
        let mut idx_sq1 = idx_matmul_ext + T;
        let mut idx_sq3 = idx_sq1 + 2 * sq1_len;
        let mut idx_sq2 = idx_sq3 + 2 * sq3_len;

        macro_rules! put {
            ($idx:expr, $val:expr) => {{
                trace[wtns_indices[$idx] as usize] = $val;
                $idx += 1;
            }};
        }

        // Linear layer at beginning
        let matmul_ext_vec = Self::matmul_external_rep3_intermediate_t16(state);
        for s in state.iter() {
            put!(idx_states, *s);
        }
        for s in matmul_ext_vec {
            put!(idx_matmul_ext, s);
        }

        // First set of external rounds
        for r in 0..f1 {
            if r == f1 - 1 {
                let (squares_, quads_, res) =
                    self.rep3_external_round_precomp_matmul_intermediate(state, r, precomp, net)?;
                put!(idx_sq1, res);
                put!(idx_sq1, Rep3PrimeFieldShare::<F>::default());
                for (sq, qu) in squares_.into_iter().zip(quads_) {
                    put!(idx_sq1, sq);
                    put!(idx_sq1, qu);
                }
            } else {
                let (squares_, quads_, _, _, _) =
                    self.rep3_external_round_precomp_intermediate(state, r, precomp, net)?;
                for s in state.iter() {
                    put!(idx_states, *s);
                }
                for (sq, qu) in squares_.into_iter().zip(quads_) {
                    put!(idx_sq1, sq);
                    put!(idx_sq1, qu);
                }
            }
        }

        // Internal rounds
        let mut final_mul = [None, None];
        for r in 0..p {
            let (sum, squares_, quads_) =
                self.rep3_internal_round_precomp_intermediate(state, r, precomp, net)?;
            put!(idx_sq2, squares_);
            put!(idx_sq2, quads_);
            if r == 0 {
                final_mul[0] = sum;
            }
            if r == p - 1 {
                final_mul[1] = sum;
            }
            if r < p - 2 {
                put!(idx_states, *state.last().unwrap());
            } else if r == p - 2 {
                for s in &state[1..] {
                    put!(idx_states, *s);
                }
            }
        }

        // Remaining external rounds
        let mut last_matmul_ext = None;
        for r in f1..f1 + f2 {
            let (squares_, quads_, sbox_0, sbox_1, matmul_external) =
                self.rep3_external_round_precomp_intermediate(state, r, precomp, net)?;
            let is_last = r == f1 + f2 - 1;
            if is_last {
                put!(idx_sq3, sbox_0);
                put!(idx_sq3, sbox_1);
            }
            for (sq, qu) in squares_.into_iter().zip(quads_) {
                put!(idx_sq3, sq);
                put!(idx_sq3, qu);
            }
            if is_last {
                last_matmul_ext = matmul_external;
                break;
            }
            for s in state.iter() {
                put!(idx_states, *s);
            }
        }

        if let (Some(v0), Some(v1)) = (final_mul[0], final_mul[1]) {
            trace[wtns_indices[idx_sq2] as usize] = v0;
            trace[wtns_indices[idx_sq2 + 1] as usize] = v1;
        }
        let mut idx_last_matmul = idx_sq2 + 2;

        if let Some(lme) = last_matmul_ext {
            for s in lme {
                put!(idx_last_matmul, s);
            }
        }

        debug_assert_eq!(precomp.offset - offset, self.num_sbox());
        Ok(trace)
    }

    /// One external round of the Poseidon2 permutation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol. Returns a value needed for the trace when T > 4.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_intermediate<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [Rep3PrimeFieldShare<F>; T],
        [Rep3PrimeFieldShare<F>; T],
        Rep3PrimeFieldShare<F>,
        Rep3PrimeFieldShare<F>,
        Option<[Rep3PrimeFieldShare<F>; T]>,
    )> {
        let id = PartyID::try_from(net.id())?;
        self.add_rc_external_rep3(state, r, id);
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate(state, precomp, net)?;
        let sbox_0 = state[0];
        let sbox_1 = state[1];
        let matmul_external = if T == 16 {
            Some(Self::matmul_external_rep3_intermediate_t16(state))
        } else {
            Self::matmul_external_rep3(state);
            None
        };
        Ok((squares, quads, sbox_0, sbox_1, matmul_external))
    }

    /// One external round of the Poseidon2 permutation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_matmul_intermediate<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [Rep3PrimeFieldShare<F>; T],
        [Rep3PrimeFieldShare<F>; T],
        Rep3PrimeFieldShare<F>,
    )> {
        assert!(T == 8 || T == 12 || T == 16 || T == 20 || T == 24);
        let id = PartyID::try_from(net.id())?;
        self.add_rc_external_rep3(state, r, id);
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate(state, precomp, net)?;
        let res = Self::matmul_external_rep3_intermediate(state);
        Ok((squares, quads, res))
    }

    /// One external round of the Poseidon2 permutation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_intermediate_packed<N: Network, const BATCH_SIZE: usize>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE],
        [[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE],
        [Rep3PrimeFieldShare<F>; BATCH_SIZE],
        [Rep3PrimeFieldShare<F>; BATCH_SIZE],
        Option<[[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE]>,
    )> {
        assert!(state.len().is_multiple_of(T));
        let id = PartyID::try_from(net.id())?;
        for s in state.chunks_exact_mut(T) {
            self.add_rc_external_rep3(s.try_into().expect("we checked sizes"), r, id);
        }
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate_packed(state, precomp, net)?;
        let sboxes_0: [_; BATCH_SIZE] = array::from_fn(|i| state[i * T]);
        let sboxes_1: [_; BATCH_SIZE] = array::from_fn(|i| state[i * T + 1]);
        let matmul_external = if T == 16 {
            let mut res = [[Rep3PrimeFieldShare::<F>::default(); T]; BATCH_SIZE];
            for (out, state_chunk) in res.iter_mut().zip(state.chunks_exact_mut(T)) {
                *out = Self::matmul_external_rep3_intermediate_t16(
                    state_chunk.try_into().expect("Chunk size checked"),
                );
            }
            Some(res)
        } else {
            for state_chunk in state.chunks_exact_mut(T) {
                Self::matmul_external_rep3(state_chunk.try_into().expect("Chunk size checked"));
            }
            None
        };
        Ok((squares, quads, sboxes_0, sboxes_1, matmul_external))
    }

    /// One external round of the Poseidon2 permutation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
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
        [[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE],
        [[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE],
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

    /// One external round of the Poseidon2 permutation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_intermediate_vec<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Option<Vec<[Rep3PrimeFieldShare<F>; T]>>,
    )> {
        assert!(state.len().is_multiple_of(T));
        let id = PartyID::try_from(net.id())?;
        for s in state.chunks_exact_mut(T) {
            self.add_rc_external_rep3(s.try_into().expect("we checked sizes"), r, id);
        }
        let (squares, quads) = Self::sbox_rep3_precomp_intermediate_vec(state, precomp, net)?;
        let sboxes_0 = state.iter().step_by(T).cloned().collect::<Vec<_>>();
        let sboxes_1 = state.iter().skip(1).step_by(T).cloned().collect::<Vec<_>>();
        let matmul_external = if T == 16 {
            let mut res = Vec::with_capacity(state.len() / T);
            for state_chunk in state.chunks_exact_mut(T) {
                res.push(Self::matmul_external_rep3_intermediate_t16(
                    state_chunk.try_into().expect("Chunk size checked"),
                ));
            }
            Some(res)
        } else {
            for state_chunk in state.chunks_exact_mut(T) {
                Self::matmul_external_rep3(state_chunk.try_into().expect("Chunk size checked"));
            }
            None
        };
        Ok((squares, quads, sboxes_0, sboxes_1, matmul_external))
    }

    /// One external round of the Poseidon2 permutation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    #[expect(clippy::type_complexity)]
    pub fn rep3_external_round_precomp_matmul_intermediate_vec<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
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
        input: &mut [Rep3PrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<([Rep3PrimeFieldShare<F>; T], [Rep3PrimeFieldShare<F>; T])> {
        assert_eq!(D, 5);
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let id = PartyID::try_from(net.id())?;

        let mut squares = [Rep3PrimeFieldShare::<F>::default(); T];
        let mut quads = [Rep3PrimeFieldShare::<F>::default(); T];
        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            (*inp, squares[i], quads[i]) =
                Self::sbox_rep3_precomp_post_intermediate(&y, precomp, precomp.offset + i, id);
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
        [[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE],
        [[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE],
    )> {
        assert!(input.len().is_multiple_of(T));
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let id = PartyID::try_from(net.id())?;

        let mut squares = [[Rep3PrimeFieldShare::<F>::default(); T]; BATCH_SIZE];
        let mut quads = [[Rep3PrimeFieldShare::<F>::default(); T]; BATCH_SIZE];
        let mut count = 0;
        for (inp, y, squares_, quads_) in izip!(
            input.chunks_exact_mut(T),
            y.chunks_exact(T),
            squares.iter_mut(),
            quads.iter_mut()
        ) {
            for (j, (inp, y)) in inp.iter_mut().zip(y).enumerate() {
                (*inp, squares_[j], quads_[j]) = Self::sbox_rep3_precomp_post_intermediate(
                    y,
                    precomp,
                    precomp.offset + count,
                    id,
                );
                count += 1;
            }
        }

        precomp.offset += input.len();

        Ok((squares, quads))
    }

    #[expect(clippy::type_complexity)]
    /// Flat-buffer variant: returns squares/quads as a single `Vec` of length `input.len()`
    /// (batch item `b`'s values live at `[b*T, (b+1)*T)`) instead of one `Vec` per batch item,
    /// cutting the allocation count from `2*batch` down to `2` regardless of batch size.
    fn sbox_rep3_precomp_intermediate_vec<N: Network>(
        input: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(Vec<Rep3PrimeFieldShare<F>>, Vec<Rep3PrimeFieldShare<F>>)> {
        assert!(input.len().is_multiple_of(T));
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let id = PartyID::try_from(net.id())?;

        let mut squares = vec![Rep3PrimeFieldShare::<F>::default(); input.len()];
        let mut quads = vec![Rep3PrimeFieldShare::<F>::default(); input.len()];
        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            (*inp, squares[i], quads[i]) =
                Self::sbox_rep3_precomp_post_intermediate(&y, precomp, precomp.offset + i, id);
        }

        precomp.offset += input.len();

        Ok((squares, quads))
    }

    /// One internal round of the Poseidon2 permutation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
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

    /// One internal round of the Poseidon2 permutation using Poseidon2Precomputations. Implemented
    /// for the Rep3 MPC protocol. Writes into caller-provided scratch buffers instead of
    /// allocating fresh `Vec`s every round: since a single permutation call invokes this in a loop
    /// (`rounds_p` times) with the same batch size each time, the caller allocates `gather_buf`/
    /// `squares_buf`/`quads_buf`/`sum_buf` once before the loop and reuses them across all
    /// iterations, dropping the allocation count from up to `4 * rounds_p` down to `4` total.
    #[expect(clippy::too_many_arguments)]
    pub fn rep3_internal_round_precomp_intermediate_packed<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
        gather_buf: &mut Vec<Rep3PrimeFieldShare<F>>,
        squares_buf: &mut Vec<Rep3PrimeFieldShare<F>>,
        quads_buf: &mut Vec<Rep3PrimeFieldShare<F>>,
        sum_buf: &mut Vec<Rep3PrimeFieldShare<F>>,
    ) -> eyre::Result<bool> {
        let id = PartyID::try_from(net.id())?;
        for inp in state.iter_mut().step_by(T) {
            if id == PartyID::ID0 {
                inp.a += self.params.round_constants_internal[r];
            } else if id == PartyID::ID1 {
                inp.b += self.params.round_constants_internal[r];
            }
        }
        gather_buf.clear();
        gather_buf.extend(state.iter().cloned().step_by(T));
        Self::single_sbox_rep3_precomp_intermediate_packed::<N>(
            gather_buf,
            precomp,
            net,
            squares_buf,
            quads_buf,
        )?;
        for (inp, r) in state.iter_mut().step_by(T).zip(gather_buf.iter()) {
            *inp = *r;
        }
        let has_sum = T >= 4;
        if has_sum {
            sum_buf.clear();
            for state_chunk in state.chunks_exact_mut(T) {
                sum_buf.push(self.matmul_internal_rep3_return_sum(
                    state_chunk.try_into().expect("Chunk size checked"),
                ));
            }
        } else {
            for state_chunk in state.chunks_exact_mut(T) {
                self.matmul_internal_rep3(state_chunk.try_into().expect("Chunk size checked"));
            }
        }
        Ok(has_sum)
    }

    /// Fixed-`BATCH_SIZE` counterpart to [`Self::rep3_internal_round_precomp_intermediate_packed`]
    /// for callers where the batch size is known at compile time, avoiding the two per-round heap
    /// allocations (the gathered `state[0]`-per-item buffer, and the `sum` buffer for T >= 4).
    #[expect(clippy::type_complexity)]
    pub fn rep3_internal_round_precomp_intermediate_fixed<N: Network, const BATCH_SIZE: usize>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Option<[Rep3PrimeFieldShare<F>; BATCH_SIZE]>,
        [Rep3PrimeFieldShare<F>; BATCH_SIZE],
        [Rep3PrimeFieldShare<F>; BATCH_SIZE],
    )> {
        let id = PartyID::try_from(net.id())?;
        for inp in state.iter_mut().step_by(T) {
            if id == PartyID::ID0 {
                inp.a += self.params.round_constants_internal[r];
            } else if id == PartyID::ID1 {
                inp.b += self.params.round_constants_internal[r];
            }
        }
        let mut arr: [Rep3PrimeFieldShare<F>; BATCH_SIZE] = array::from_fn(|i| state[i * T]);
        let (squares, quads) = Self::single_sbox_rep3_precomp_intermediate_fixed::<N, BATCH_SIZE>(
            &mut arr, precomp, net,
        )?;
        for (inp, v) in state.iter_mut().step_by(T).zip(arr) {
            *inp = v;
        }
        let sum = if T >= 4 {
            let mut sum = [Rep3PrimeFieldShare::<F>::default(); BATCH_SIZE];
            for (out, state_chunk) in sum.iter_mut().zip(state.chunks_exact_mut(T)) {
                *out = self.matmul_internal_rep3_return_sum(
                    state_chunk.try_into().expect("Chunk size checked"),
                );
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

    fn single_sbox_rep3_precomp_intermediate_packed<N: Network>(
        input: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
        squares: &mut Vec<Rep3PrimeFieldShare<F>>,
        quads: &mut Vec<Rep3PrimeFieldShare<F>>,
    ) -> eyre::Result<()> {
        assert_eq!(D, 5);

        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= *precomp.get_r(precomp.offset + i);
        }

        let id = PartyID::try_from(net.id())?;

        // Open
        let y = arithmetic::open_vec(input, net)?;
        squares.clear();
        quads.clear();
        for (i, (inp, y)) in izip!(input.iter_mut(), y.iter()).enumerate() {
            let (res, squ, quad) =
                Self::sbox_rep3_precomp_post_intermediate(y, precomp, precomp.offset + i, id);
            *inp = res;
            squares.push(squ);
            quads.push(quad);
        }

        precomp.offset += input.len();

        Ok(())
    }

    /// Fixed-`BATCH_SIZE` counterpart to [`Self::single_sbox_rep3_precomp_intermediate_packed`]
    /// for callers where the batch size is known at compile time, avoiding the heap allocation.
    #[expect(clippy::type_complexity)]
    fn single_sbox_rep3_precomp_intermediate_fixed<N: Network, const BATCH_SIZE: usize>(
        input: &mut [Rep3PrimeFieldShare<F>; BATCH_SIZE],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [Rep3PrimeFieldShare<F>; BATCH_SIZE],
        [Rep3PrimeFieldShare<F>; BATCH_SIZE],
    )> {
        assert_eq!(D, 5);

        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= *precomp.get_r(precomp.offset + i);
        }

        let id = PartyID::try_from(net.id())?;

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let mut squares = [Rep3PrimeFieldShare::<F>::default(); BATCH_SIZE];
        let mut quads = [Rep3PrimeFieldShare::<F>::default(); BATCH_SIZE];
        for (i, (inp, y)) in izip!(input.iter_mut(), y.iter()).enumerate() {
            (*inp, squares[i], quads[i]) =
                Self::sbox_rep3_precomp_post_intermediate(y, precomp, precomp.offset + i, id);
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
    /// The matrix multiplication in the external rounds of the Poseidon2 permutation for T=16, returning the ordered intermediate values used by the Circom trace.
    pub fn matmul_external_intermediate_t16(input: &mut [F; T]) -> Vec<F> {
        match T {
            16 => {
                let mut res = Vec::with_capacity(T);
                // Applying cheap 4x4 MDS matrix to each 4-element part of the state
                for state in input.chunks_exact_mut(4) {
                    Self::matmul_m4(state.try_into().unwrap());
                }

                // Applying second cheap matrix for t > 4
                let mut stored = [F::zero(); 4];
                for l in 0..4 {
                    stored[l] = input[l];
                    res.push(input[l]);
                    for j in 1..T / 4 {
                        res.push(input[4 * j + l]);
                        stored[l] += input[4 * j + l];
                    }
                }
                for i in 0..T {
                    input[i] += stored[i % 4];
                }
                res
            }
            _ => {
                panic!("Invalid state size, this function is only implemented for T=16");
            }
        }
    }

    fn external_round_intermediate(
        &self,
        state: &mut [F; T],
        r: usize,
    ) -> (Vec<F>, Vec<F>, F, F, Option<Vec<F>>) {
        self.add_rc_external(state, r);
        let (squares, quads) = Self::sbox_plain_intermediate(state);
        let sbox_0 = state[0];
        let sbox_1 = state[1];
        let matmul_external = if T == 16 {
            Some(Self::matmul_external_intermediate_t16(state))
        } else {
            Self::matmul_external(state);
            None
        };
        (squares, quads, sbox_0, sbox_1, matmul_external)
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
        let matmul_external = if T == 16 {
            let res = Self::matmul_external_intermediate_t16(&mut state);
            Some(res)
        } else {
            Self::matmul_external(&mut state);
            None
        };

        states.extend(state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            let (squares_, quads_, res) = if r == self.params.rounds_f_beginning - 1 && T == 16 {
                self.external_round_matmul_intermediate(&mut state, r)
            } else {
                let (squares_, quads_, res, _, _) = self.external_round_intermediate(&mut state, r);
                (squares_, quads_, res)
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

        let mut last_matmul_external = None;

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (squares_, quads_, sbox_0, sbox_1, matmul_external) =
                self.external_round_intermediate(&mut state, r);

            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                squares_3.push(sbox_0);
                quads_3.push(sbox_1);
            }
            squares_3.extend(squares_);
            quads_3.extend(quads_);
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                last_matmul_external = matmul_external;
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

        if let Some(matmul_external) = matmul_external {
            for s in &matmul_external {
                if let Some(idx) = wtns_indices_iter.next() {
                    trace[idx as usize] = *s;
                }
            }
        }

        for (sq, qu) in squares_1
            .into_iter()
            .zip(quads_1)
            .chain(squares_3.into_iter().zip(quads_3))
            .chain(squares_2.into_iter().zip(quads_2))
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

        if let Some(last_matmul_external) = last_matmul_external {
            for s in &last_matmul_external {
                if let Some(idx) = wtns_indices_iter.next() {
                    trace[idx as usize] = *s;
                }
            }
        }

        Ok((state, trace))
    }
}

impl<F: PrimeField, const T: usize> Poseidon2<F, T, 5> {
    /// Fast path for T in {2, 3, 4}: same layout/offset derivation as
    /// `rep3_permutation_in_place_with_precomputation_intermediate`, replicated per batch item.
    #[expect(clippy::type_complexity)]
    fn rep3_permutation_in_place_with_precomputation_intermediate_packed_fast<
        N: Network,
        const T2: usize,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: [Rep3PrimeFieldShare<F>; T2],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [Rep3PrimeFieldShare<F>; T2],
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
    )> {
        let mut state = state;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let (wtns_indices, trace_size): (&[u16], usize) = match T {
            2 => (WITNESS_INDICES_T2, WITNESS_INDICES_SIZE_T2),
            3 => (WITNESS_INDICES_T3, WITNESS_INDICES_SIZE_T3),
            4 => (WITNESS_INDICES_T4, WITNESS_INDICES_SIZE_T4),
            _ => {
                return Err(eyre::eyre!(
                    "Current implementation does not support state size {T}"
                ));
            }
        };
        let mut traces: [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE] =
            array::from_fn(|_| vec![Rep3PrimeFieldShare::<F>::default(); trace_size]);

        let states_len = if T == 4 {
            T * (f1 + f2 - 1) + p + 3
        } else {
            T * (f1 + f2) + p
        };
        let sq1_len = f1 * T;
        let sq3_len = f2 * T + 1;
        let sq1_base = states_len;
        let sq3_base = sq1_base + 2 * sq1_len;
        let sq2_base = sq3_base + 2 * sq3_len;

        let mut idx_states = [0usize; BATCH_SIZE];
        let mut idx_sq1 = [sq1_base; BATCH_SIZE];
        let mut idx_sq3 = [sq3_base; BATCH_SIZE];
        let mut idx_sq2 = [sq2_base; BATCH_SIZE];

        macro_rules! put {
            ($b:expr, $idx:expr, $val:expr) => {{
                traces[$b][wtns_indices[$idx] as usize] = $val;
                $idx += 1;
            }};
        }

        // Linear layer at beginning
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().unwrap());
        }
        for (b, chunk) in state.chunks(T).enumerate() {
            for s in chunk {
                put!(b, idx_states[b], *s);
            }
        }

        // First set of external rounds
        for r in 0..f1 {
            let (squares_, quads_, _, _, _) = self
                .rep3_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                    &mut state, r, precomp, net,
                )?;
            if r != f1 - 1 || T != 4 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in chunk {
                        put!(b, idx_states[b], *s);
                    }
                }
            } else {
                for (b, chunk) in state.chunks(T).enumerate() {
                    put!(b, idx_states[b], chunk[0]);
                    put!(b, idx_states[b], chunk[3]);
                }
            }
            for b in 0..BATCH_SIZE {
                for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                    put!(b, idx_sq1[b], *sq);
                    put!(b, idx_sq1[b], *qu);
                }
            }
        }

        // Internal rounds
        let mut final_mul = [None; BATCH_SIZE];
        for r in 0..p {
            let (sum, squares_, quads_) = self
                .rep3_internal_round_precomp_intermediate_fixed::<N, BATCH_SIZE>(
                    &mut state, r, precomp, net,
                )?;
            for b in 0..BATCH_SIZE {
                put!(b, idx_sq2[b], squares_[b]);
                put!(b, idx_sq2[b], quads_[b]);
            }
            if T == 4 && r == p - 1 {
                let sum_vec = sum.as_ref().expect("T >= 4 means sum should be Some");
                for b in 0..BATCH_SIZE {
                    final_mul[b] = Some(sum_vec[b]);
                }
            }
            if T != 4 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    put!(b, idx_states[b], *chunk.first().unwrap());
                }
            } else if r < p - 2 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    put!(b, idx_states[b], *chunk.last().unwrap());
                }
            } else if r == p - 2 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in &chunk[1..] {
                        put!(b, idx_states[b], *s);
                    }
                }
            }
        }

        // Remaining external rounds
        for r in f1..f1 + f2 {
            let (squares_, quads_, sboxes_0, sboxes_1, _) = self
                .rep3_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                    &mut state, r, precomp, net,
                )?;
            let is_last = r == f1 + f2 - 1;
            if is_last {
                for b in 0..BATCH_SIZE {
                    put!(b, idx_sq3[b], sboxes_0[b]);
                    put!(b, idx_sq3[b], sboxes_1[b]);
                }
            }
            for b in 0..BATCH_SIZE {
                for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                    put!(b, idx_sq3[b], *sq);
                    put!(b, idx_sq3[b], *qu);
                }
            }
            if is_last {
                break;
            }
            for (b, chunk) in state.chunks(T).enumerate() {
                for s in chunk {
                    put!(b, idx_states[b], *s);
                }
            }
        }

        if T == 4 {
            for b in 0..BATCH_SIZE {
                if let Some(val) = final_mul[b] {
                    traces[b][wtns_indices[idx_sq2[b]] as usize] = val;
                }
            }
        }

        Ok((state, traces))
    }

    /// Fast path for T = 16: same direct-write technique and section lengths as
    /// `rep3_permutation_in_place_with_precomputation_intermediate_t16_fast`, replicated per batch
    /// item.
    #[expect(clippy::type_complexity)]
    fn rep3_permutation_in_place_with_precomputation_intermediate_packed_t16_fast<
        N: Network,
        const T2: usize,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: [Rep3PrimeFieldShare<F>; T2],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        [Rep3PrimeFieldShare<F>; T2],
        [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE],
    )> {
        assert_eq!(T, 16);
        let mut state = state;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let wtns_indices = WITNESS_INDICES_T16;
        let mut traces: [Vec<Rep3PrimeFieldShare<F>>; BATCH_SIZE] =
            array::from_fn(|_| vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16]);

        let states_len = T * (f1 + f2 - 1) + p + T - 3;
        let sq1_len = f1 * T + 1;
        let sq3_len = f2 * T + 1;

        let mut idx_states = [0usize; BATCH_SIZE];
        let mut idx_matmul_ext = [states_len; BATCH_SIZE];
        let mut idx_sq1 = [states_len + T; BATCH_SIZE];
        let mut idx_sq3 = [states_len + T + 2 * sq1_len; BATCH_SIZE];
        let mut idx_sq2 = [states_len + T + 2 * sq1_len + 2 * sq3_len; BATCH_SIZE];

        macro_rules! put {
            ($b:expr, $idx:expr, $val:expr) => {{
                traces[$b][wtns_indices[$idx] as usize] = $val;
                $idx += 1;
            }};
        }

        // Linear layer at beginning
        for (b, s) in state.chunks_exact_mut(T).enumerate() {
            let chunk: &mut [Rep3PrimeFieldShare<F>; T] = s.try_into().unwrap();
            let matmul_ext_vec = Self::matmul_external_rep3_intermediate_t16(chunk);
            for s in matmul_ext_vec {
                put!(b, idx_matmul_ext[b], s);
            }
        }

        for (b, chunk) in state.chunks(T).enumerate() {
            for s in chunk {
                put!(b, idx_states[b], *s);
            }
        }

        // First set of external rounds
        for r in 0..f1 {
            if r == f1 - 1 {
                let (squares_, quads_, res): (
                    [[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE],
                    [[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE],
                    [Rep3PrimeFieldShare<F>; BATCH_SIZE],
                ) = self.rep3_external_round_precomp_matmul_intermediate_packed::<N, BATCH_SIZE>(
                    &mut state, r, precomp, net,
                )?;
                for b in 0..BATCH_SIZE {
                    put!(b, idx_sq1[b], res[b]);
                    put!(b, idx_sq1[b], Rep3PrimeFieldShare::<F>::default());
                    for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                        put!(b, idx_sq1[b], *sq);
                        put!(b, idx_sq1[b], *qu);
                    }
                }
            } else {
                let (squares_, quads_, _, _, _) = self
                    .rep3_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                        &mut state, r, precomp, net,
                    )?;
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in chunk {
                        put!(b, idx_states[b], *s);
                    }
                }
                for b in 0..BATCH_SIZE {
                    for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                        put!(b, idx_sq1[b], *sq);
                        put!(b, idx_sq1[b], *qu);
                    }
                }
            }
        }

        // Internal rounds
        let mut final_mul = [[None, None]; BATCH_SIZE];
        for r in 0..p {
            let (sum, squares_, quads_) = self
                .rep3_internal_round_precomp_intermediate_fixed::<N, BATCH_SIZE>(
                    &mut state, r, precomp, net,
                )?;
            for b in 0..BATCH_SIZE {
                put!(b, idx_sq2[b], squares_[b]);
                put!(b, idx_sq2[b], quads_[b]);
            }
            if r == 0 {
                let sum_vec = sum.as_ref().expect("T=16 sum should be Some");
                for b in 0..BATCH_SIZE {
                    final_mul[b][0] = Some(sum_vec[b]);
                }
            }
            if r == p - 1 {
                let sum_vec = sum.as_ref().expect("T=16 sum should be Some");
                for b in 0..BATCH_SIZE {
                    final_mul[b][1] = Some(sum_vec[b]);
                }
            }
            if r < p - 2 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    put!(b, idx_states[b], *chunk.last().unwrap());
                }
            } else if r == p - 2 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in &chunk[1..] {
                        put!(b, idx_states[b], *s);
                    }
                }
            }
        }

        // Remaining external rounds
        let mut last_matmul_ext: Option<[[Rep3PrimeFieldShare<F>; T]; BATCH_SIZE]> = None;
        for r in f1..f1 + f2 {
            let (squares_, quads_, sboxes_0, sboxes_1, matmul_external) = self
                .rep3_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                    &mut state, r, precomp, net,
                )?;
            let is_last = r == f1 + f2 - 1;
            if is_last {
                for b in 0..BATCH_SIZE {
                    put!(b, idx_sq3[b], sboxes_0[b]);
                    put!(b, idx_sq3[b], sboxes_1[b]);
                }
            }
            for b in 0..BATCH_SIZE {
                for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                    put!(b, idx_sq3[b], *sq);
                    put!(b, idx_sq3[b], *qu);
                }
            }
            if is_last {
                last_matmul_ext = matmul_external;
                break;
            }
            for (b, chunk) in state.chunks(T).enumerate() {
                for s in chunk {
                    put!(b, idx_states[b], *s);
                }
            }
        }

        let mut idx_last_matmul = [0usize; BATCH_SIZE];
        for b in 0..BATCH_SIZE {
            if let (Some(v0), Some(v1)) = (final_mul[b][0], final_mul[b][1]) {
                traces[b][wtns_indices[idx_sq2[b]] as usize] = v0;
                traces[b][wtns_indices[idx_sq2[b] + 1] as usize] = v1;
            }
            idx_last_matmul[b] = idx_sq2[b] + 2;
        }

        if let Some(lme) = last_matmul_ext {
            for b in 0..BATCH_SIZE {
                for s in lme[b].iter() {
                    put!(b, idx_last_matmul[b], *s);
                }
            }
        }

        Ok((state, traces))
    }

    /// Fast path for T in {2, 3, 4}: same layout/offset derivation as
    /// `rep3_permutation_in_place_with_precomputation_intermediate`, replicated per batch item,
    /// with a runtime-determined batch size.
    #[expect(clippy::type_complexity)]
    fn rep3_permutation_in_place_with_precomputation_intermediate_vec_fast<N: Network>(
        &self,
        state: Vec<Rep3PrimeFieldShare<F>>,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
    )> {
        let mut state = state;
        let batch = state.len() / T;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let (wtns_indices, trace_size): (&[u16], usize) = match T {
            2 => (WITNESS_INDICES_T2, WITNESS_INDICES_SIZE_T2),
            3 => (WITNESS_INDICES_T3, WITNESS_INDICES_SIZE_T3),
            4 => (WITNESS_INDICES_T4, WITNESS_INDICES_SIZE_T4),
            _ => {
                return Err(eyre::eyre!(
                    "Current implementation does not support state size {T}"
                ));
            }
        };
        let mut traces: Vec<Vec<Rep3PrimeFieldShare<F>>> =
            vec![vec![Rep3PrimeFieldShare::<F>::default(); trace_size]; batch];

        let states_len = if T == 4 {
            T * (f1 + f2 - 1) + p + 3
        } else {
            T * (f1 + f2) + p
        };
        let sq1_len = f1 * T;
        let sq3_len = f2 * T + 1;
        let sq1_base = states_len;
        let sq3_base = sq1_base + 2 * sq1_len;
        let sq2_base = sq3_base + 2 * sq3_len;

        let mut idx_states = vec![0usize; batch];
        let mut idx_sq1 = vec![sq1_base; batch];
        let mut idx_sq3 = vec![sq3_base; batch];
        let mut idx_sq2 = vec![sq2_base; batch];

        macro_rules! put {
            ($b:expr, $idx:expr, $val:expr) => {{
                traces[$b][wtns_indices[$idx] as usize] = $val;
                $idx += 1;
            }};
        }

        // Linear layer at beginning
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().unwrap());
        }
        for (b, chunk) in state.chunks(T).enumerate() {
            for s in chunk {
                put!(b, idx_states[b], *s);
            }
        }

        // First set of external rounds
        for r in 0..f1 {
            let (squares_, quads_, _, _, _) =
                self.rep3_external_round_precomp_intermediate_vec(&mut state, r, precomp, net)?;
            if r != f1 - 1 || T != 4 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in chunk {
                        put!(b, idx_states[b], *s);
                    }
                }
            } else {
                for (b, chunk) in state.chunks(T).enumerate() {
                    put!(b, idx_states[b], chunk[0]);
                    put!(b, idx_states[b], chunk[3]);
                }
            }
            for b in 0..batch {
                for (sq, qu) in squares_[b * T..(b + 1) * T]
                    .iter()
                    .zip(quads_[b * T..(b + 1) * T].iter())
                {
                    put!(b, idx_sq1[b], *sq);
                    put!(b, idx_sq1[b], *qu);
                }
            }
        }

        // Internal rounds
        let mut final_mul = vec![None; batch];
        let mut gather_buf = Vec::with_capacity(batch);
        let mut squares_buf = Vec::with_capacity(batch);
        let mut quads_buf = Vec::with_capacity(batch);
        let mut sum_buf = Vec::with_capacity(batch);
        for r in 0..p {
            let has_sum = self.rep3_internal_round_precomp_intermediate_packed::<N>(
                &mut state,
                r,
                precomp,
                net,
                &mut gather_buf,
                &mut squares_buf,
                &mut quads_buf,
                &mut sum_buf,
            )?;
            for b in 0..batch {
                put!(b, idx_sq2[b], squares_buf[b]);
                put!(b, idx_sq2[b], quads_buf[b]);
            }
            if T == 4 && r == p - 1 {
                debug_assert!(has_sum, "T >= 4 means sum should be populated");
                for b in 0..batch {
                    final_mul[b] = Some(sum_buf[b]);
                }
            }
            if T != 4 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    put!(b, idx_states[b], *chunk.first().unwrap());
                }
            } else if r < p - 2 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    put!(b, idx_states[b], *chunk.last().unwrap());
                }
            } else if r == p - 2 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in &chunk[1..] {
                        put!(b, idx_states[b], *s);
                    }
                }
            }
        }

        // Remaining external rounds
        for r in f1..f1 + f2 {
            let (squares_, quads_, sboxes_0, sboxes_1, _) =
                self.rep3_external_round_precomp_intermediate_vec(&mut state, r, precomp, net)?;
            let is_last = r == f1 + f2 - 1;
            if is_last {
                for b in 0..batch {
                    put!(b, idx_sq3[b], sboxes_0[b]);
                    put!(b, idx_sq3[b], sboxes_1[b]);
                }
            }
            for b in 0..batch {
                for (sq, qu) in squares_[b * T..(b + 1) * T]
                    .iter()
                    .zip(quads_[b * T..(b + 1) * T].iter())
                {
                    put!(b, idx_sq3[b], *sq);
                    put!(b, idx_sq3[b], *qu);
                }
            }
            if is_last {
                break;
            }
            for (b, chunk) in state.chunks(T).enumerate() {
                for s in chunk {
                    put!(b, idx_states[b], *s);
                }
            }
        }

        if T == 4 {
            for b in 0..batch {
                if let Some(val) = final_mul[b] {
                    traces[b][wtns_indices[idx_sq2[b]] as usize] = val;
                }
            }
        }

        Ok((state, traces))
    }

    /// Fast path for T = 16: same direct-write technique and section lengths as
    /// `rep3_permutation_in_place_with_precomputation_intermediate_t16_fast`, replicated per batch
    /// item, with a runtime-determined batch size.
    #[expect(clippy::type_complexity)]
    fn rep3_permutation_in_place_with_precomputation_intermediate_vec_t16_fast<N: Network>(
        &self,
        state: Vec<Rep3PrimeFieldShare<F>>,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<(
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Vec<Rep3PrimeFieldShare<F>>>,
    )> {
        assert_eq!(T, 16);
        let mut state = state;
        let batch = state.len() / T;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let wtns_indices = WITNESS_INDICES_T16;
        let mut traces: Vec<Vec<Rep3PrimeFieldShare<F>>> =
            vec![vec![Rep3PrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16]; batch];

        let states_len = T * (f1 + f2 - 1) + p + T - 3;
        let sq1_len = f1 * T + 1;
        let sq3_len = f2 * T + 1;

        let mut idx_states = vec![0usize; batch];
        let mut idx_matmul_ext = vec![states_len; batch];
        let mut idx_sq1 = vec![states_len + T; batch];
        let mut idx_sq3 = vec![states_len + T + 2 * sq1_len; batch];
        let mut idx_sq2 = vec![states_len + T + 2 * sq1_len + 2 * sq3_len; batch];

        macro_rules! put {
            ($b:expr, $idx:expr, $val:expr) => {{
                traces[$b][wtns_indices[$idx] as usize] = $val;
                $idx += 1;
            }};
        }

        // Linear layer at beginning
        for (b, s) in state.chunks_exact_mut(T).enumerate() {
            let chunk: &mut [Rep3PrimeFieldShare<F>; T] = s.try_into().unwrap();
            let matmul_ext_vec = Self::matmul_external_rep3_intermediate_t16(chunk);
            for s in matmul_ext_vec {
                put!(b, idx_matmul_ext[b], s);
            }
        }
        for (b, chunk) in state.chunks(T).enumerate() {
            for s in chunk {
                put!(b, idx_states[b], *s);
            }
        }

        // First set of external rounds
        for r in 0..f1 {
            if r == f1 - 1 {
                let (squares_, quads_, res) = self
                    .rep3_external_round_precomp_matmul_intermediate_vec(
                        &mut state, r, precomp, net,
                    )?;
                for b in 0..batch {
                    put!(b, idx_sq1[b], res[b]);
                    put!(b, idx_sq1[b], Rep3PrimeFieldShare::<F>::default());
                    for (sq, qu) in squares_[b * T..(b + 1) * T]
                        .iter()
                        .zip(quads_[b * T..(b + 1) * T].iter())
                    {
                        put!(b, idx_sq1[b], *sq);
                        put!(b, idx_sq1[b], *qu);
                    }
                }
            } else {
                let (squares_, quads_, _, _, _) =
                    self.rep3_external_round_precomp_intermediate_vec(&mut state, r, precomp, net)?;
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in chunk {
                        put!(b, idx_states[b], *s);
                    }
                }
                for b in 0..batch {
                    for (sq, qu) in squares_[b * T..(b + 1) * T]
                        .iter()
                        .zip(quads_[b * T..(b + 1) * T].iter())
                    {
                        put!(b, idx_sq1[b], *sq);
                        put!(b, idx_sq1[b], *qu);
                    }
                }
            }
        }

        // Internal rounds
        let mut final_mul = vec![[None, None]; batch];
        let mut gather_buf = Vec::with_capacity(batch);
        let mut squares_buf = Vec::with_capacity(batch);
        let mut quads_buf = Vec::with_capacity(batch);
        let mut sum_buf = Vec::with_capacity(batch);
        for r in 0..p {
            let has_sum = self.rep3_internal_round_precomp_intermediate_packed::<N>(
                &mut state,
                r,
                precomp,
                net,
                &mut gather_buf,
                &mut squares_buf,
                &mut quads_buf,
                &mut sum_buf,
            )?;
            for b in 0..batch {
                put!(b, idx_sq2[b], squares_buf[b]);
                put!(b, idx_sq2[b], quads_buf[b]);
            }
            if r == 0 {
                debug_assert!(has_sum, "T=16 sum should be populated");
                for b in 0..batch {
                    final_mul[b][0] = Some(sum_buf[b]);
                }
            }
            if r == p - 1 {
                debug_assert!(has_sum, "T=16 sum should be populated");
                for b in 0..batch {
                    final_mul[b][1] = Some(sum_buf[b]);
                }
            }
            if r < p - 2 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    put!(b, idx_states[b], *chunk.last().unwrap());
                }
            } else if r == p - 2 {
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in &chunk[1..] {
                        put!(b, idx_states[b], *s);
                    }
                }
            }
        }

        // Remaining external rounds
        let mut last_matmul_ext: Option<Vec<[Rep3PrimeFieldShare<F>; T]>> = None;
        for r in f1..f1 + f2 {
            let (squares_, quads_, sboxes_0, sboxes_1, matmul_external) =
                self.rep3_external_round_precomp_intermediate_vec(&mut state, r, precomp, net)?;
            let is_last = r == f1 + f2 - 1;
            if is_last {
                for b in 0..batch {
                    put!(b, idx_sq3[b], sboxes_0[b]);
                    put!(b, idx_sq3[b], sboxes_1[b]);
                }
            }
            for b in 0..batch {
                for (sq, qu) in squares_[b * T..(b + 1) * T]
                    .iter()
                    .zip(quads_[b * T..(b + 1) * T].iter())
                {
                    put!(b, idx_sq3[b], *sq);
                    put!(b, idx_sq3[b], *qu);
                }
            }
            if is_last {
                last_matmul_ext = matmul_external;
                break;
            }
            for (b, chunk) in state.chunks(T).enumerate() {
                for s in chunk {
                    put!(b, idx_states[b], *s);
                }
            }
        }

        let mut idx_last_matmul = vec![0usize; batch];
        for b in 0..batch {
            if let (Some(v0), Some(v1)) = (final_mul[b][0], final_mul[b][1]) {
                traces[b][wtns_indices[idx_sq2[b]] as usize] = v0;
                traces[b][wtns_indices[idx_sq2[b] + 1] as usize] = v1;
            }
            idx_last_matmul[b] = idx_sq2[b] + 2;
        }

        if let Some(lme) = last_matmul_ext {
            for b in 0..batch {
                for s in lme[b].iter() {
                    put!(b, idx_last_matmul[b], *s);
                }
            }
        }

        Ok((state, traces))
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
        if T == 16 {
            return self
                .rep3_permutation_in_place_with_precomputation_intermediate_packed_t16_fast::<
                    N,
                    T2,
                    BATCH_SIZE,
                >(state, precomp, net);
        }
        self.rep3_permutation_in_place_with_precomputation_intermediate_packed_fast::<
            N,
            T2,
            BATCH_SIZE,
        >(state, precomp, net)
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
        if T == 16 {
            return self.rep3_permutation_in_place_with_precomputation_intermediate_vec_t16_fast(
                state, precomp, net,
            );
        }
        self.rep3_permutation_in_place_with_precomputation_intermediate_vec_fast(
            state, precomp, net,
        )
    }
}
