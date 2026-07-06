use std::array;

use super::{Poseidon2, Poseidon2Precomputations};
use crate::{
    gadgets::poseidon2::{
        poseidon2_bn254_t2::{WITNESS_INDICES_SIZE_T2, WITNESS_INDICES_T2},
        poseidon2_bn254_t3::{WITNESS_INDICES_SIZE_T3, WITNESS_INDICES_T3},
        poseidon2_bn254_t4::{WITNESS_INDICES_SIZE_T4, WITNESS_INDICES_T4},
        poseidon2_bn254_t16::{WITNESS_INDICES_SIZE_T16, WITNESS_INDICES_T16},
    },
    protocols::shamir::{ShamirPrimeFieldShare, ShamirState, arithmetic},
};
use ark_ff::PrimeField;
use itertools::izip;
use mpc_net::Network;

impl<F: PrimeField, const T: usize> Poseidon2<F, T, 5> {
    fn matmul_m4_shamir(input: &mut [ShamirPrimeFieldShare<F>; 4]) {
        let two = F::from(2u64);
        let four = F::from(4u64);
        let t_0 = input[0] + input[1];
        let t_1 = input[2] + input[3];
        let t_2 = input[1] * two + t_1;
        let t_3 = input[3] * two + t_0;
        let t_4 = t_1 * four + t_3;
        let t_5 = t_0 * four + t_2;
        let t_6 = t_3 + t_5;
        let t_7 = t_2 + t_4;
        input[0] = t_6;
        input[1] = t_5;
        input[2] = t_7;
        input[3] = t_4;
    }

    fn matmul_external_shamir_shares(input: &mut [ShamirPrimeFieldShare<F>; T]) {
        match T {
            2 => {
                let sum = input[0] + input[1];
                input[0] += &sum;
                input[1] += sum;
            }
            3 => {
                let sum = input[0] + input[1] + input[2];
                input[0] += &sum;
                input[1] += &sum;
                input[2] += sum;
            }
            4 => {
                Self::matmul_m4_shamir(input.as_mut_slice().try_into().unwrap());
            }
            8 | 12 | 16 | 20 | 24 => {
                for s in input.chunks_exact_mut(4) {
                    Self::matmul_m4_shamir(s.try_into().unwrap());
                }
                let mut stored = [ShamirPrimeFieldShare::default(); 4];
                for l in 0..4 {
                    stored[l] = input[l];
                    for j in 1..T / 4 {
                        stored[l] += input[4 * j + l];
                    }
                }
                for i in 0..T {
                    input[i] += stored[i % 4];
                }
            }
            _ => panic!("Invalid state size"),
        }
    }

    fn matmul_external_shamir_intermediate_t16(
        input: &mut [ShamirPrimeFieldShare<F>; T],
    ) -> [ShamirPrimeFieldShare<F>; T] {
        assert_eq!(T, 16);
        let mut res = [ShamirPrimeFieldShare::default(); T];
        let mut idx = 0;
        for s in input.chunks_exact_mut(4) {
            Self::matmul_m4_shamir(s.try_into().unwrap());
        }
        let mut stored = [ShamirPrimeFieldShare::default(); 4];
        for l in 0..4 {
            stored[l] = input[l];
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

    fn matmul_external_shamir_intermediate(
        input: &mut [ShamirPrimeFieldShare<F>; T],
    ) -> ShamirPrimeFieldShare<F> {
        assert!(T == 8 || T == 12 || T == 16 || T == 20 || T == 24);
        for s in input.chunks_exact_mut(4) {
            Self::matmul_m4_shamir(s.try_into().unwrap());
        }
        let result = input[0];
        let mut stored = [ShamirPrimeFieldShare::default(); 4];
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

    fn matmul_internal_shamir_shares(&self, input: &mut [ShamirPrimeFieldShare<F>; T]) {
        let two = F::from(2u64);
        match T {
            2 => {
                let sum = input[0] + input[1];
                input[0] += &sum;
                input[1] = input[1] * two + sum;
            }
            3 => {
                let sum = input[0] + input[1] + input[2];
                input[0] += &sum;
                input[1] += &sum;
                input[2] = input[2] * two + sum;
            }
            _ => {
                let mut sum = input[0];
                for el in input.iter().skip(1) {
                    sum += el;
                }
                for (s, &m) in input
                    .iter_mut()
                    .zip(self.params.mat_internal_diag_m_1.iter())
                {
                    *s *= m;
                    *s += sum;
                }
            }
        }
    }

    fn matmul_internal_shamir_return_sum(
        &self,
        input: &mut [ShamirPrimeFieldShare<F>; T],
    ) -> ShamirPrimeFieldShare<F> {
        debug_assert!(T >= 4);
        let mut sum = input[0];
        for el in input.iter().skip(1) {
            sum += el;
        }
        for (s, &m) in input
            .iter_mut()
            .zip(self.params.mat_internal_diag_m_1.iter())
        {
            *s *= m;
            *s += sum;
        }
        sum
    }

    fn sbox_shamir_precomp_post_intermediate(
        y: &F,
        r: &ShamirPrimeFieldShare<F>,
        r2: &ShamirPrimeFieldShare<F>,
        r3: &ShamirPrimeFieldShare<F>,
        r4: &ShamirPrimeFieldShare<F>,
        r5: &ShamirPrimeFieldShare<F>,
    ) -> (
        ShamirPrimeFieldShare<F>,
        ShamirPrimeFieldShare<F>,
        ShamirPrimeFieldShare<F>,
    ) {
        let y2 = y.square();
        let y3 = y2 * y;
        let y4 = y2.square();
        let y5 = y4 * y;
        let two = F::from(2u64);
        let four = F::from(4u64);
        let five = F::from(5u64);
        let six = F::from(6u64);
        let ten = F::from(10u64);

        // x^2 = (r+y)^2; all Shamir parties add the public y-polynomial terms directly
        // (correct because sum_i lambda_i = 1 in Lagrange interpolation)
        let input_square = *r2 + *r * (two * *y) + y2;
        let input_quad = *r4 + *r3 * (four * *y) + *r2 * (six * y2) + *r * (four * y3) + y4;

        let mut res = *r5;
        res += *r4 * (five * *y);
        res += *r3 * (ten * y2);
        res += *r2 * (ten * y3);
        res += *r * (five * y4);
        res += y5;

        (res, input_square, input_quad)
    }

    #[expect(clippy::type_complexity)]
    /// Same as [`Self::sbox_shamir_precomp_intermediate`] but for the fixed-length (`T`-sized)
    /// external-round case, avoiding the heap allocation.
    fn sbox_shamir_precomp_intermediate_fixed_t<N: Network>(
        input: &mut [ShamirPrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<([ShamirPrimeFieldShare<F>; T], [ShamirPrimeFieldShare<F>; T])> {
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        let y = arithmetic::open_vec(input, net, shamir_state)?;

        let mut squares = [ShamirPrimeFieldShare::<F>::default(); T];
        let mut quads = [ShamirPrimeFieldShare::<F>::default(); T];
        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            let (r, r2, r3, r4, r5) = precomp.get(precomp.offset + i);
            let (res, squ, quad) =
                Self::sbox_shamir_precomp_post_intermediate(&y, r, r2, r3, r4, r5);
            *inp = res;
            squares[i] = squ;
            quads[i] = quad;
        }

        precomp.offset += input.len();
        Ok((squares, quads))
    }

    /// General (dynamic-length) sbox, used by the internal-round packed/vec batching path where
    /// the collected "one element per batch item" buffer's length is not known at compile time.
    #[expect(clippy::type_complexity)]
    fn sbox_shamir_precomp_intermediate<N: Network>(
        input: &mut [ShamirPrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(Vec<ShamirPrimeFieldShare<F>>, Vec<ShamirPrimeFieldShare<F>>)> {
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        let y = arithmetic::open_vec(input, net, shamir_state)?;

        let mut squares = Vec::with_capacity(input.len());
        let mut quads = Vec::with_capacity(input.len());
        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            let (r, r2, r3, r4, r5) = precomp.get(precomp.offset + i);
            let (res, squ, quad) =
                Self::sbox_shamir_precomp_post_intermediate(&y, r, r2, r3, r4, r5);
            *inp = res;
            squares.push(squ);
            quads.push(quad);
        }

        precomp.offset += input.len();
        Ok((squares, quads))
    }

    fn single_sbox_shamir_precomp_intermediate<N: Network>(
        input: &mut ShamirPrimeFieldShare<F>,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(ShamirPrimeFieldShare<F>, ShamirPrimeFieldShare<F>)> {
        let (r, r2, r3, r4, r5) = precomp.get(precomp.offset);
        *input -= *r;
        let y = arithmetic::open(*input, net, shamir_state)?;
        let (res, squ, quad) = Self::sbox_shamir_precomp_post_intermediate(&y, r, r2, r3, r4, r5);
        *input = res;
        precomp.offset += 1;
        Ok((squ, quad))
    }

    #[expect(clippy::type_complexity)]
    fn sbox_shamir_precomp_intermediate_packed<N: Network, const BATCH_SIZE: usize>(
        input: &mut [ShamirPrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE],
        [[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE],
    )> {
        assert!(input.len().is_multiple_of(T));
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }
        let y = arithmetic::open_vec(input, net, shamir_state)?;
        let mut squares = [[ShamirPrimeFieldShare::<F>::default(); T]; BATCH_SIZE];
        let mut quads = [[ShamirPrimeFieldShare::<F>::default(); T]; BATCH_SIZE];
        let mut count = 0;
        for (inp, y_chunk, sq, qu) in izip!(
            input.chunks_exact_mut(T),
            y.chunks_exact(T),
            squares.iter_mut(),
            quads.iter_mut()
        ) {
            for (j, (inp, y)) in inp.iter_mut().zip(y_chunk).enumerate() {
                let (r, r2, r3, r4, r5) = precomp.get(precomp.offset + count);
                let (res, squ, quad) =
                    Self::sbox_shamir_precomp_post_intermediate(y, r, r2, r3, r4, r5);
                *inp = res;
                sq[j] = squ;
                qu[j] = quad;
                count += 1;
            }
        }
        precomp.offset += input.len();
        Ok((squares, quads))
    }

    #[expect(clippy::type_complexity)]
    fn sbox_shamir_precomp_intermediate_vec<N: Network>(
        input: &mut [ShamirPrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
    )> {
        let t2 = input.len() / T;
        assert!(input.len().is_multiple_of(T));
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }
        let y = arithmetic::open_vec(input, net, shamir_state)?;
        let mut squares = vec![Vec::with_capacity(T); t2];
        let mut quads = vec![Vec::with_capacity(T); t2];
        let mut count = 0;
        for (inp, y_chunk, sq, qu) in izip!(
            input.chunks_exact_mut(T),
            y.chunks_exact(T),
            squares.iter_mut(),
            quads.iter_mut()
        ) {
            for (inp, y) in inp.iter_mut().zip(y_chunk) {
                let (r, r2, r3, r4, r5) = precomp.get(precomp.offset + count);
                let (res, squ, quad) =
                    Self::sbox_shamir_precomp_post_intermediate(y, r, r2, r3, r4, r5);
                *inp = res;
                sq.push(squ);
                qu.push(quad);
                count += 1;
            }
        }
        precomp.offset += input.len();
        Ok((squares, quads))
    }

    #[expect(clippy::type_complexity)]
    fn shamir_external_round_precomp_intermediate<N: Network>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [ShamirPrimeFieldShare<F>; T],
        [ShamirPrimeFieldShare<F>; T],
        ShamirPrimeFieldShare<F>,
        ShamirPrimeFieldShare<F>,
        Option<[ShamirPrimeFieldShare<F>; T]>,
    )> {
        for (s, &rc) in state
            .iter_mut()
            .zip(self.params.round_constants_external[r].iter())
        {
            *s += rc;
        }
        let (squares, quads) =
            Self::sbox_shamir_precomp_intermediate_fixed_t(state, precomp, net, shamir_state)?;
        let sbox_0 = state[0];
        let sbox_1 = state[1];
        let matmul_external = if T == 16 {
            Some(Self::matmul_external_shamir_intermediate_t16(state))
        } else {
            Self::matmul_external_shamir_shares(state);
            None
        };
        Ok((squares, quads, sbox_0, sbox_1, matmul_external))
    }

    #[expect(clippy::type_complexity)]
    fn shamir_external_round_precomp_matmul_intermediate<N: Network>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [ShamirPrimeFieldShare<F>; T],
        [ShamirPrimeFieldShare<F>; T],
        ShamirPrimeFieldShare<F>,
    )> {
        for (s, &rc) in state
            .iter_mut()
            .zip(self.params.round_constants_external[r].iter())
        {
            *s += rc;
        }
        let (squares, quads) =
            Self::sbox_shamir_precomp_intermediate_fixed_t(state, precomp, net, shamir_state)?;
        let res = Self::matmul_external_shamir_intermediate(state);
        Ok((squares, quads, res))
    }

    #[expect(clippy::type_complexity)]
    fn shamir_internal_round_precomp_intermediate<N: Network>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Option<ShamirPrimeFieldShare<F>>,
        ShamirPrimeFieldShare<F>,
        ShamirPrimeFieldShare<F>,
    )> {
        state[0] += self.params.round_constants_internal[r];
        let (squ, quad) = Self::single_sbox_shamir_precomp_intermediate(
            &mut state[0],
            precomp,
            net,
            shamir_state,
        )?;
        let sum = if T >= 4 {
            Some(self.matmul_internal_shamir_return_sum(state))
        } else {
            self.matmul_internal_shamir_shares(state);
            None
        };
        Ok((sum, squ, quad))
    }

    #[expect(clippy::type_complexity)]
    fn shamir_external_round_precomp_intermediate_packed<N: Network, const BATCH_SIZE: usize>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE],
        [[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE],
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
        Option<[[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE]>,
    )> {
        assert!(state.len().is_multiple_of(T));
        for chunk in state.chunks_exact_mut(T) {
            let chunk: &mut [ShamirPrimeFieldShare<F>; T] = chunk.try_into().unwrap();
            for (s, &rc) in chunk
                .iter_mut()
                .zip(self.params.round_constants_external[r].iter())
            {
                *s += rc;
            }
        }
        let (squares, quads) = Self::sbox_shamir_precomp_intermediate_packed::<N, BATCH_SIZE>(
            state,
            precomp,
            net,
            shamir_state,
        )?;
        let sboxes_0: [_; BATCH_SIZE] = array::from_fn(|i| state[i * T]);
        let sboxes_1: [_; BATCH_SIZE] = array::from_fn(|i| state[i * T + 1]);
        let matmul_external = if T == 16 {
            let mut me = [[ShamirPrimeFieldShare::<F>::default(); T]; BATCH_SIZE];
            for (out, chunk) in me.iter_mut().zip(state.chunks_exact_mut(T)) {
                *out = Self::matmul_external_shamir_intermediate_t16(
                    chunk.try_into().expect("we checked sizes"),
                );
            }
            Some(me)
        } else {
            for chunk in state.chunks_exact_mut(T) {
                Self::matmul_external_shamir_shares(chunk.try_into().expect("we checked sizes"));
            }
            None
        };
        Ok((squares, quads, sboxes_0, sboxes_1, matmul_external))
    }

    #[expect(clippy::type_complexity)]
    fn shamir_external_round_precomp_matmul_intermediate_packed<
        N: Network,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE],
        [[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE],
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
    )> {
        assert!(state.len().is_multiple_of(T));
        for chunk in state.chunks_exact_mut(T) {
            let chunk: &mut [ShamirPrimeFieldShare<F>; T] = chunk.try_into().unwrap();
            for (s, &rc) in chunk
                .iter_mut()
                .zip(self.params.round_constants_external[r].iter())
            {
                *s += rc;
            }
        }
        let (squares, quads) = Self::sbox_shamir_precomp_intermediate_packed::<N, BATCH_SIZE>(
            state,
            precomp,
            net,
            shamir_state,
        )?;
        let mut matmul_results = Vec::with_capacity(BATCH_SIZE);
        for chunk in state.chunks_exact_mut(T) {
            matmul_results.push(Self::matmul_external_shamir_intermediate(
                chunk.try_into().expect("we checked sizes"),
            ));
        }
        Ok((
            squares,
            quads,
            matmul_results.try_into().expect("we checked sizes"),
        ))
    }

    #[expect(clippy::type_complexity)]
    fn shamir_internal_round_precomp_intermediate_packed<N: Network>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Option<Vec<ShamirPrimeFieldShare<F>>>,
        Vec<ShamirPrimeFieldShare<F>>,
        Vec<ShamirPrimeFieldShare<F>>,
    )> {
        let t2 = state.len() / T;
        for inp in state.iter_mut().step_by(T) {
            *inp += self.params.round_constants_internal[r];
        }
        let mut first_elems: Vec<ShamirPrimeFieldShare<F>> =
            state.iter().cloned().step_by(T).collect();
        let (squares, quads) =
            Self::sbox_shamir_precomp_intermediate(&mut first_elems, precomp, net, shamir_state)?;
        for (inp, val) in state.iter_mut().step_by(T).zip(first_elems) {
            *inp = val;
        }
        let sum = if T >= 4 {
            let mut sums = Vec::with_capacity(t2);
            for chunk in state.chunks_exact_mut(T) {
                sums.push(self.matmul_internal_shamir_return_sum(
                    chunk.try_into().expect("Chunk size checked"),
                ));
            }
            Some(sums)
        } else {
            for chunk in state.chunks_exact_mut(T) {
                self.matmul_internal_shamir_shares(chunk.try_into().expect("Chunk size checked"));
            }
            None
        };
        Ok((sum, squares, quads))
    }

    /// Fixed-`BATCH_SIZE` counterpart to
    /// [`Self::sbox_shamir_precomp_intermediate`]/[`Self::shamir_internal_round_precomp_intermediate_packed`]
    /// for callers where the batch size is known at compile time, avoiding the per-round heap
    /// allocations (the gathered `state[0]`-per-item buffer, and the `sum` buffer for T >= 4).
    #[expect(clippy::type_complexity)]
    fn sbox_shamir_precomp_intermediate_fixed_batch<N: Network, const BATCH_SIZE: usize>(
        input: &mut [ShamirPrimeFieldShare<F>; BATCH_SIZE],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
    )> {
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        let y = arithmetic::open_vec(input, net, shamir_state)?;

        let mut squares = [ShamirPrimeFieldShare::<F>::default(); BATCH_SIZE];
        let mut quads = [ShamirPrimeFieldShare::<F>::default(); BATCH_SIZE];
        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            let (r, r2, r3, r4, r5) = precomp.get(precomp.offset + i);
            let (res, squ, quad) =
                Self::sbox_shamir_precomp_post_intermediate(&y, r, r2, r3, r4, r5);
            *inp = res;
            squares[i] = squ;
            quads[i] = quad;
        }

        precomp.offset += input.len();
        Ok((squares, quads))
    }

    /// Fixed-`BATCH_SIZE` counterpart to [`Self::shamir_internal_round_precomp_intermediate_packed`]
    /// for callers where the batch size is known at compile time, avoiding the two per-round heap
    /// allocations (the gathered `state[0]`-per-item buffer, and the `sum` buffer for T >= 4).
    #[expect(clippy::type_complexity)]
    pub fn shamir_internal_round_precomp_intermediate_fixed<N: Network, const BATCH_SIZE: usize>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Option<[ShamirPrimeFieldShare<F>; BATCH_SIZE]>,
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
    )> {
        for inp in state.iter_mut().step_by(T) {
            *inp += self.params.round_constants_internal[r];
        }
        let mut arr: [ShamirPrimeFieldShare<F>; BATCH_SIZE] = array::from_fn(|i| state[i * T]);
        let (squares, quads) = Self::sbox_shamir_precomp_intermediate_fixed_batch::<N, BATCH_SIZE>(
            &mut arr,
            precomp,
            net,
            shamir_state,
        )?;
        for (inp, val) in state.iter_mut().step_by(T).zip(arr) {
            *inp = val;
        }
        let sum = if T >= 4 {
            let mut sums = [ShamirPrimeFieldShare::<F>::default(); BATCH_SIZE];
            for (out, chunk) in sums.iter_mut().zip(state.chunks_exact_mut(T)) {
                *out = self.matmul_internal_shamir_return_sum(
                    chunk.try_into().expect("Chunk size checked"),
                );
            }
            Some(sums)
        } else {
            for chunk in state.chunks_exact_mut(T) {
                self.matmul_internal_shamir_shares(chunk.try_into().expect("Chunk size checked"));
            }
            None
        };
        Ok((sum, squares, quads))
    }

    #[expect(clippy::type_complexity)]
    fn shamir_external_round_precomp_intermediate_vec<N: Network>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
        Vec<ShamirPrimeFieldShare<F>>,
        Vec<ShamirPrimeFieldShare<F>>,
        Option<Vec<[ShamirPrimeFieldShare<F>; T]>>,
    )> {
        assert!(state.len().is_multiple_of(T));
        for chunk in state.chunks_exact_mut(T) {
            let chunk: &mut [ShamirPrimeFieldShare<F>; T] = chunk.try_into().unwrap();
            for (s, &rc) in chunk
                .iter_mut()
                .zip(self.params.round_constants_external[r].iter())
            {
                *s += rc;
            }
        }
        let (squares, quads) =
            Self::sbox_shamir_precomp_intermediate_vec(state, precomp, net, shamir_state)?;
        let sboxes_0 = state.iter().step_by(T).cloned().collect();
        let sboxes_1 = state.iter().skip(1).step_by(T).cloned().collect();
        let matmul_external = if T == 16 {
            let mut res = Vec::with_capacity(state.len() / T);
            for chunk in state.chunks_exact_mut(T) {
                res.push(Self::matmul_external_shamir_intermediate_t16(
                    chunk.try_into().expect("Chunk size checked"),
                ));
            }
            Some(res)
        } else {
            for chunk in state.chunks_exact_mut(T) {
                Self::matmul_external_shamir_shares(chunk.try_into().expect("Chunk size checked"));
            }
            None
        };
        Ok((squares, quads, sboxes_0, sboxes_1, matmul_external))
    }

    #[expect(clippy::type_complexity)]
    fn shamir_external_round_precomp_matmul_intermediate_vec<N: Network>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
        Vec<ShamirPrimeFieldShare<F>>,
    )> {
        assert!(state.len().is_multiple_of(T));
        for chunk in state.chunks_exact_mut(T) {
            let chunk: &mut [ShamirPrimeFieldShare<F>; T] = chunk.try_into().unwrap();
            for (s, &rc) in chunk
                .iter_mut()
                .zip(self.params.round_constants_external[r].iter())
            {
                *s += rc;
            }
        }
        let (squares, quads) =
            Self::sbox_shamir_precomp_intermediate_vec(state, precomp, net, shamir_state)?;
        let mut matmul_results = Vec::with_capacity(state.len() / T);
        for chunk in state.chunks_exact_mut(T) {
            matmul_results.push(Self::matmul_external_shamir_intermediate(
                chunk.try_into().expect("we checked sizes"),
            ));
        }
        Ok((squares, quads, matmul_results))
    }

    /// Computes the Poseidon2 permutation using the Shamir MPC protocol while overwriting the input. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn shamir_permutation_in_place_with_precomputation_intermediate<N: Network>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<Vec<ShamirPrimeFieldShare<F>>> {
        assert!(T == 2 || T == 3 || T == 4 || T == 16);
        if T == 16 {
            return self.shamir_permutation_in_place_with_precomputation_intermediate_t16_fast(
                state,
                precomp,
                net,
                shamir_state,
            );
        }

        // Fast path for T in {2, 3, 4}: see the analogous rep3 fast path in
        // poseidon2_circom_accelerator.rs for the derivation of the layout offsets.
        let offset = precomp.offset;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let (wtns_indices, trace_size): (&[u16], usize) = match T {
            2 => (WITNESS_INDICES_T2, WITNESS_INDICES_SIZE_T2),
            3 => (WITNESS_INDICES_T3, WITNESS_INDICES_SIZE_T3),
            4 => (WITNESS_INDICES_T4, WITNESS_INDICES_SIZE_T4),
            _ => return Err(eyre::eyre!("Unsupported state size {T}")),
        };
        let mut trace = vec![ShamirPrimeFieldShare::<F>::default(); trace_size];

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
        Self::matmul_external_shamir_shares(state);
        for s in state.iter() {
            put!(idx_states, *s);
        }

        // First set of external rounds
        for r in 0..f1 {
            let (squares_, quads_, _, _, _) = self.shamir_external_round_precomp_intermediate(
                state,
                r,
                precomp,
                net,
                shamir_state,
            )?;
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
            let (sum, squ, quad) = self.shamir_internal_round_precomp_intermediate(
                state,
                r,
                precomp,
                net,
                shamir_state,
            )?;
            put!(idx_sq2, squ);
            put!(idx_sq2, quad);
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
            let (squares_, quads_, sbox_0, sbox_1, _) = self
                .shamir_external_round_precomp_intermediate(state, r, precomp, net, shamir_state)?;
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
    /// Section lengths were derived empirically against the rep3 implementation (identical round
    /// structure) and cross-checked via the KAT/random tests here.
    fn shamir_permutation_in_place_with_precomputation_intermediate_t16_fast<N: Network>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<Vec<ShamirPrimeFieldShare<F>>> {
        assert_eq!(T, 16);
        let offset = precomp.offset;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let wtns_indices = WITNESS_INDICES_T16;
        let mut trace = vec![ShamirPrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16];

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
        let matmul_ext_vec = Self::matmul_external_shamir_intermediate_t16(state);
        for s in state.iter() {
            put!(idx_states, *s);
        }
        for s in matmul_ext_vec {
            put!(idx_matmul_ext, s);
        }

        // First set of external rounds
        for r in 0..f1 {
            if r == f1 - 1 {
                let (squares_, quads_, res) = self
                    .shamir_external_round_precomp_matmul_intermediate(
                        state,
                        r,
                        precomp,
                        net,
                        shamir_state,
                    )?;
                put!(idx_sq1, res);
                put!(idx_sq1, ShamirPrimeFieldShare::<F>::default());
                for (sq, qu) in squares_.into_iter().zip(quads_) {
                    put!(idx_sq1, sq);
                    put!(idx_sq1, qu);
                }
            } else {
                let (squares_, quads_, _, _, _) = self.shamir_external_round_precomp_intermediate(
                    state,
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?;
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
            let (sum, squ, quad) = self.shamir_internal_round_precomp_intermediate(
                state,
                r,
                precomp,
                net,
                shamir_state,
            )?;
            put!(idx_sq2, squ);
            put!(idx_sq2, quad);
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
            let (squares_, quads_, sbox_0, sbox_1, matmul_external) = self
                .shamir_external_round_precomp_intermediate(state, r, precomp, net, shamir_state)?;
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
}

impl<F: PrimeField, const T: usize> Poseidon2<F, T, 5> {
    /// Fast path for T in {2, 3, 4}: same layout/offset derivation as
    /// `shamir_permutation_in_place_with_precomputation_intermediate`, replicated per batch item.
    #[expect(clippy::type_complexity)]
    fn shamir_permutation_in_place_with_precomputation_intermediate_packed_fast<
        N: Network,
        const T2: usize,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: [ShamirPrimeFieldShare<F>; T2],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [ShamirPrimeFieldShare<F>; T2],
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
    )> {
        let mut state = state;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let (wtns_indices, trace_size): (&[u16], usize) = match T {
            2 => (WITNESS_INDICES_T2, WITNESS_INDICES_SIZE_T2),
            3 => (WITNESS_INDICES_T3, WITNESS_INDICES_SIZE_T3),
            4 => (WITNESS_INDICES_T4, WITNESS_INDICES_SIZE_T4),
            _ => return Err(eyre::eyre!("Unsupported state size {T}")),
        };
        let mut traces: [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE] =
            array::from_fn(|_| vec![ShamirPrimeFieldShare::<F>::default(); trace_size]);

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
            Self::matmul_external_shamir_shares(s.try_into().unwrap());
        }
        for (b, chunk) in state.chunks(T).enumerate() {
            for s in chunk {
                put!(b, idx_states[b], *s);
            }
        }

        // First set of external rounds
        for r in 0..f1 {
            let (squares_, quads_, _, _, _) = self
                .shamir_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                    &mut state,
                    r,
                    precomp,
                    net,
                    shamir_state,
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
            let (sum, squares_, quads_) = self.shamir_internal_round_precomp_intermediate_fixed::<N, BATCH_SIZE>(
                &mut state,
                r,
                precomp,
                net,
                shamir_state,
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
                .shamir_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                    &mut state,
                    r,
                    precomp,
                    net,
                    shamir_state,
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
    /// `shamir_permutation_in_place_with_precomputation_intermediate_t16_fast`, replicated per
    /// batch item.
    #[expect(clippy::type_complexity)]
    fn shamir_permutation_in_place_with_precomputation_intermediate_packed_t16_fast<
        N: Network,
        const T2: usize,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: [ShamirPrimeFieldShare<F>; T2],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [ShamirPrimeFieldShare<F>; T2],
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
    )> {
        assert_eq!(T, 16);
        let mut state = state;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let wtns_indices = WITNESS_INDICES_T16;
        let mut traces: [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE] = array::from_fn(|_| {
            vec![ShamirPrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16]
        });

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
            let chunk: &mut [ShamirPrimeFieldShare<F>; T] = s.try_into().unwrap();
            let matmul_ext_vec = Self::matmul_external_shamir_intermediate_t16(chunk);
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
                    [[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE],
                    [[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE],
                    [ShamirPrimeFieldShare<F>; BATCH_SIZE],
                ) = self
                    .shamir_external_round_precomp_matmul_intermediate_packed::<N, BATCH_SIZE>(
                        state.as_mut_slice(),
                        r,
                        precomp,
                        net,
                        shamir_state,
                    )?;
                for b in 0..BATCH_SIZE {
                    put!(b, idx_sq1[b], res[b]);
                    put!(b, idx_sq1[b], ShamirPrimeFieldShare::<F>::default());
                    for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                        put!(b, idx_sq1[b], *sq);
                        put!(b, idx_sq1[b], *qu);
                    }
                }
            } else {
                let (squares_, quads_, _, _, _) = self
                    .shamir_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                        state.as_mut_slice(),
                        r,
                        precomp,
                        net,
                        shamir_state,
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
            let (sum, squares_, quads_) = self.shamir_internal_round_precomp_intermediate_fixed::<N, BATCH_SIZE>(
                state.as_mut_slice(),
                r,
                precomp,
                net,
                shamir_state,
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
        let mut last_matmul_ext: Option<[[ShamirPrimeFieldShare<F>; T]; BATCH_SIZE]> = None;
        for r in f1..f1 + f2 {
            let (squares_, quads_, sboxes_0, sboxes_1, matmul_external) = self
                .shamir_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                    state.as_mut_slice(),
                    r,
                    precomp,
                    net,
                    shamir_state,
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
    /// `shamir_permutation_in_place_with_precomputation_intermediate`, replicated per batch item,
    /// with a runtime-determined batch size.
    #[expect(clippy::type_complexity)]
    fn shamir_permutation_in_place_with_precomputation_intermediate_vec_fast<N: Network>(
        &self,
        state: Vec<ShamirPrimeFieldShare<F>>,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Vec<ShamirPrimeFieldShare<F>>,
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
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
            _ => return Err(eyre::eyre!("Unsupported state size {T}")),
        };
        let mut traces: Vec<Vec<ShamirPrimeFieldShare<F>>> =
            vec![vec![ShamirPrimeFieldShare::<F>::default(); trace_size]; batch];

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
            Self::matmul_external_shamir_shares(s.try_into().unwrap());
        }
        for (b, chunk) in state.chunks(T).enumerate() {
            for s in chunk {
                put!(b, idx_states[b], *s);
            }
        }

        // First set of external rounds
        for r in 0..f1 {
            let (squares_, quads_, _, _, _) = self.shamir_external_round_precomp_intermediate_vec(
                &mut state,
                r,
                precomp,
                net,
                shamir_state,
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
            for b in 0..batch {
                for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                    put!(b, idx_sq1[b], *sq);
                    put!(b, idx_sq1[b], *qu);
                }
            }
        }

        // Internal rounds
        let mut final_mul = vec![None; batch];
        for r in 0..p {
            let (sum, squares_, quads_) = self.shamir_internal_round_precomp_intermediate_packed(
                &mut state,
                r,
                precomp,
                net,
                shamir_state,
            )?;
            for b in 0..batch {
                put!(b, idx_sq2[b], squares_[b]);
                put!(b, idx_sq2[b], quads_[b]);
            }
            if T == 4 && r == p - 1 {
                let sum_vec = sum.as_ref().expect("T >= 4 means sum should be Some");
                for b in 0..batch {
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
                .shamir_external_round_precomp_intermediate_vec(
                    &mut state,
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?;
            let is_last = r == f1 + f2 - 1;
            if is_last {
                for b in 0..batch {
                    put!(b, idx_sq3[b], sboxes_0[b]);
                    put!(b, idx_sq3[b], sboxes_1[b]);
                }
            }
            for b in 0..batch {
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
            for b in 0..batch {
                if let Some(val) = final_mul[b] {
                    traces[b][wtns_indices[idx_sq2[b]] as usize] = val;
                }
            }
        }

        Ok((state, traces))
    }

    /// Fast path for T = 16: same direct-write technique and section lengths as
    /// `shamir_permutation_in_place_with_precomputation_intermediate_t16_fast`, replicated per
    /// batch item, with a runtime-determined batch size.
    #[expect(clippy::type_complexity)]
    fn shamir_permutation_in_place_with_precomputation_intermediate_vec_t16_fast<N: Network>(
        &self,
        state: Vec<ShamirPrimeFieldShare<F>>,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Vec<ShamirPrimeFieldShare<F>>,
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
    )> {
        assert_eq!(T, 16);
        let mut state = state;
        let batch = state.len() / T;
        let f1 = self.params.rounds_f_beginning;
        let f2 = self.params.rounds_f_end;
        let p = self.params.rounds_p;

        let wtns_indices = WITNESS_INDICES_T16;
        let mut traces: Vec<Vec<ShamirPrimeFieldShare<F>>> =
            vec![vec![ShamirPrimeFieldShare::<F>::default(); WITNESS_INDICES_SIZE_T16]; batch];

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
            let chunk: &mut [ShamirPrimeFieldShare<F>; T] = s.try_into().unwrap();
            let matmul_ext_vec = Self::matmul_external_shamir_intermediate_t16(chunk);
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
                    .shamir_external_round_precomp_matmul_intermediate_vec(
                        &mut state,
                        r,
                        precomp,
                        net,
                        shamir_state,
                    )?;
                for b in 0..batch {
                    put!(b, idx_sq1[b], res[b]);
                    put!(b, idx_sq1[b], ShamirPrimeFieldShare::<F>::default());
                    for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                        put!(b, idx_sq1[b], *sq);
                        put!(b, idx_sq1[b], *qu);
                    }
                }
            } else {
                let (squares_, quads_, _, _, _) = self
                    .shamir_external_round_precomp_intermediate_vec(
                        &mut state,
                        r,
                        precomp,
                        net,
                        shamir_state,
                    )?;
                for (b, chunk) in state.chunks(T).enumerate() {
                    for s in chunk {
                        put!(b, idx_states[b], *s);
                    }
                }
                for b in 0..batch {
                    for (sq, qu) in squares_[b].iter().zip(quads_[b].iter()) {
                        put!(b, idx_sq1[b], *sq);
                        put!(b, idx_sq1[b], *qu);
                    }
                }
            }
        }

        // Internal rounds
        let mut final_mul = vec![[None, None]; batch];
        for r in 0..p {
            let (sum, squares_, quads_) = self.shamir_internal_round_precomp_intermediate_packed(
                &mut state,
                r,
                precomp,
                net,
                shamir_state,
            )?;
            for b in 0..batch {
                put!(b, idx_sq2[b], squares_[b]);
                put!(b, idx_sq2[b], quads_[b]);
            }
            if r == 0 {
                let sum_vec = sum.as_ref().expect("T=16 sum should be Some");
                for b in 0..batch {
                    final_mul[b][0] = Some(sum_vec[b]);
                }
            }
            if r == p - 1 {
                let sum_vec = sum.as_ref().expect("T=16 sum should be Some");
                for b in 0..batch {
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
        let mut last_matmul_ext: Option<Vec<[ShamirPrimeFieldShare<F>; T]>> = None;
        for r in f1..f1 + f2 {
            let (squares_, quads_, sboxes_0, sboxes_1, matmul_external) = self
                .shamir_external_round_precomp_intermediate_vec(
                    &mut state,
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?;
            let is_last = r == f1 + f2 - 1;
            if is_last {
                for b in 0..batch {
                    put!(b, idx_sq3[b], sboxes_0[b]);
                    put!(b, idx_sq3[b], sboxes_1[b]);
                }
            }
            for b in 0..batch {
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
pub trait CircomTraceShamirHasher<F: PrimeField, const T: usize> {
    /// The type holding data required for preprocessing the Sbox of the permutation.
    type Precomputation;

    #[expect(clippy::type_complexity)]
    /// Computes the intermediate values needed for the witness extension for Circom in a batched MPC setting.
    fn shamir_permutation_in_place_with_precomputation_intermediate_packed<
        N: Network,
        const T2: usize,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: [ShamirPrimeFieldShare<F>; T2],
        precomp: &mut Self::Precomputation,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [ShamirPrimeFieldShare<F>; T2],
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
    )>;

    #[expect(clippy::type_complexity)]
    /// Computes the intermediate values needed for the witness extension for Circom in a batched MPC setting, where the size of the batch is dynamic.
    fn shamir_permutation_in_place_with_precomputation_intermediate_vec<N: Network>(
        &self,
        state: Vec<ShamirPrimeFieldShare<F>>,
        precomp: &mut Self::Precomputation,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Vec<ShamirPrimeFieldShare<F>>,
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
    )>;
}

impl<F: PrimeField, const T: usize> CircomTraceShamirHasher<F, T> for Poseidon2<F, T, 5> {
    type Precomputation = Poseidon2Precomputations<ShamirPrimeFieldShare<F>>;

    fn shamir_permutation_in_place_with_precomputation_intermediate_packed<
        N: Network,
        const T2: usize,
        const BATCH_SIZE: usize,
    >(
        &self,
        state: [ShamirPrimeFieldShare<F>; T2],
        precomp: &mut Self::Precomputation,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        [ShamirPrimeFieldShare<F>; T2],
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
    )> {
        assert!(T == 2 || T == 3 || T == 4 || T == 16);
        assert_eq!(T2, T * BATCH_SIZE);
        if T == 16 {
            return self
                .shamir_permutation_in_place_with_precomputation_intermediate_packed_t16_fast::<
                    N,
                    T2,
                    BATCH_SIZE,
                >(state, precomp, net, shamir_state);
        }
        self.shamir_permutation_in_place_with_precomputation_intermediate_packed_fast::<
            N,
            T2,
            BATCH_SIZE,
        >(state, precomp, net, shamir_state)
    }

    fn shamir_permutation_in_place_with_precomputation_intermediate_vec<N: Network>(
        &self,
        state: Vec<ShamirPrimeFieldShare<F>>,
        precomp: &mut Self::Precomputation,
        net: &N,
        shamir_state: &mut ShamirState<F>,
    ) -> eyre::Result<(
        Vec<ShamirPrimeFieldShare<F>>,
        Vec<Vec<ShamirPrimeFieldShare<F>>>,
    )> {
        assert!(T == 2 || T == 3 || T == 4 || T == 16);
        if T == 16 {
            return self.shamir_permutation_in_place_with_precomputation_intermediate_vec_t16_fast(
                state,
                precomp,
                net,
                shamir_state,
            );
        }
        self.shamir_permutation_in_place_with_precomputation_intermediate_vec_fast(
            state,
            precomp,
            net,
            shamir_state,
        )
    }
}
