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
    fn num_witness_states(&self) -> usize {
        match T {
            2 | 3 => {
                T * (self.params.rounds_f_beginning - 1)
                    + T * self.params.rounds_f_end
                    + self.params.rounds_p
            }
            _ => {
                T * (self.params.rounds_f_beginning - 1) + T * self.params.rounds_f_end - 1
                    + self.params.rounds_p
            }
        }
    }

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
    ) -> Vec<ShamirPrimeFieldShare<F>> {
        assert_eq!(T, 16);
        let mut res = Vec::with_capacity(T);
        for s in input.chunks_exact_mut(4) {
            Self::matmul_m4_shamir(s.try_into().unwrap());
        }
        let mut stored = [ShamirPrimeFieldShare::default(); 4];
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
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
    )> {
        assert!(input.len().is_multiple_of(T));
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }
        let y = arithmetic::open_vec(input, net, shamir_state)?;
        let mut squares: [_; BATCH_SIZE] = array::from_fn(|_| Vec::with_capacity(T));
        let mut quads: [_; BATCH_SIZE] = array::from_fn(|_| Vec::with_capacity(T));
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
        Vec<ShamirPrimeFieldShare<F>>,
        Vec<ShamirPrimeFieldShare<F>>,
        ShamirPrimeFieldShare<F>,
        ShamirPrimeFieldShare<F>,
        Option<Vec<ShamirPrimeFieldShare<F>>>,
    )> {
        for (s, &rc) in state
            .iter_mut()
            .zip(self.params.round_constants_external[r].iter())
        {
            *s += rc;
        }
        let (squares, quads) =
            Self::sbox_shamir_precomp_intermediate(state, precomp, net, shamir_state)?;
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
        Vec<ShamirPrimeFieldShare<F>>,
        Vec<ShamirPrimeFieldShare<F>>,
        ShamirPrimeFieldShare<F>,
    )> {
        for (s, &rc) in state
            .iter_mut()
            .zip(self.params.round_constants_external[r].iter())
        {
            *s += rc;
        }
        let (squares, quads) =
            Self::sbox_shamir_precomp_intermediate(state, precomp, net, shamir_state)?;
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
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
        [ShamirPrimeFieldShare<F>; BATCH_SIZE],
        Option<[Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE]>,
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
            let mut me = Vec::with_capacity(BATCH_SIZE);
            for chunk in state.chunks_exact_mut(T) {
                me.push(Self::matmul_external_shamir_intermediate_t16(
                    chunk.try_into().expect("we checked sizes"),
                ));
            }
            Some(me.try_into().expect("we checked sizes"))
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
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
        [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE],
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
        Option<Vec<Vec<ShamirPrimeFieldShare<F>>>>,
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
        let offset = precomp.offset;

        let num_states = self.num_witness_states();

        let mut final_mul = [None, None];
        let mut squares_1 = Vec::with_capacity(T * self.params.rounds_f_beginning);
        let mut quads_1 = Vec::with_capacity(T * self.params.rounds_f_beginning);
        let mut squares_2 = Vec::with_capacity(self.params.rounds_p);
        let mut quads_2 = Vec::with_capacity(self.params.rounds_p);
        let mut squares_3 = Vec::with_capacity(T * self.params.rounds_f_end);
        let mut quads_3 = Vec::with_capacity(T * self.params.rounds_f_end);
        let mut states: Vec<ShamirPrimeFieldShare<F>> = Vec::with_capacity(num_states);

        let mut trace = if T == 2 {
            vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T2]
        } else if T == 3 {
            vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T3]
        } else if T == 4 {
            vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T4]
        } else {
            vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T16]
        };

        let matmul_external = if T == 16 {
            Some(Self::matmul_external_shamir_intermediate_t16(state))
        } else {
            Self::matmul_external_shamir_shares(state);
            None
        };

        states.extend_from_slice(state);

        for r in 0..self.params.rounds_f_beginning {
            let (squares_, quads_, sbox_0) = if r == self.params.rounds_f_beginning - 1 && T == 16 {
                self.shamir_external_round_precomp_matmul_intermediate(
                    state,
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?
            } else {
                let (sq, qu, s0, _, _) = self.shamir_external_round_precomp_intermediate(
                    state,
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?;
                (sq, qu, s0)
            };

            if r != self.params.rounds_f_beginning - 1 || (T != 4 && T != 16) {
                states.extend_from_slice(state);
            } else if r == self.params.rounds_f_beginning - 1 && T == 4 {
                states.push(state[0]);
                states.push(state[3]);
            } else if r == self.params.rounds_f_beginning - 1 && T == 16 {
                squares_1.push(sbox_0);
                quads_1.push(ShamirPrimeFieldShare::default());
            }
            squares_1.extend(squares_);
            quads_1.extend(quads_);
        }

        for r in 0..self.params.rounds_p {
            let (sum, squ, quad) = self.shamir_internal_round_precomp_intermediate(
                state,
                r,
                precomp,
                net,
                shamir_state,
            )?;
            squares_2.push(squ);
            quads_2.push(quad);
            if T == 16 && r == 0 {
                final_mul[0] = sum;
            }
            if (T == 4 || T == 16) && r == self.params.rounds_p - 1 {
                final_mul[1] = sum;
            }
            if T != 4 && T != 16 {
                states.push(*state.first().unwrap());
            } else if (T == 4 || T == 16) && r < self.params.rounds_p - 2 {
                states.push(*state.last().unwrap());
            } else if (T == 4 || T == 16) && r == self.params.rounds_p - 2 {
                states.extend_from_slice(&state[1..]);
            }
        }

        let mut last_matmul_external = None;
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (sq, qu, sbox_0, sbox_1, me) = self.shamir_external_round_precomp_intermediate(
                state,
                r,
                precomp,
                net,
                shamir_state,
            )?;
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                squares_3.push(sbox_0);
                quads_3.push(sbox_1);
                squares_3.extend(sq);
                quads_3.extend(qu);
                last_matmul_external = me;
                break;
            }
            squares_3.extend(sq);
            quads_3.extend(qu);
            states.extend_from_slice(state);
        }

        let wtns_indices: &[u16] = match T {
            2 => WITNESS_INDICES_T2,
            3 => WITNESS_INDICES_T3,
            4 => WITNESS_INDICES_T4,
            16 => WITNESS_INDICES_T16,
            _ => return Err(eyre::eyre!("Unsupported state size {T}")),
        };
        let mut it = wtns_indices.iter().copied();

        for s in &states {
            if let Some(idx) = it.next() {
                trace[idx as usize] = *s;
            }
        }
        if let Some(me) = matmul_external {
            for s in &me {
                if let Some(idx) = it.next() {
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
            if let Some(idx) = it.next() {
                trace[idx as usize] = sq;
            }
            if let Some(idx) = it.next() {
                trace[idx as usize] = qu;
            }
        }
        if T == 16
            && let (Some(i0), Some(i1), Some(v0), Some(v1)) =
                (it.next(), it.next(), final_mul[0], final_mul[1])
        {
            trace[i0 as usize] = v0;
            trace[i1 as usize] = v1;
        }
        if T == 4
            && let (Some(idx), Some(val)) = (it.next(), final_mul[1])
        {
            trace[idx as usize] = val;
        }
        if let Some(lme) = last_matmul_external {
            for s in &lme {
                if let Some(idx) = it.next() {
                    trace[idx as usize] = *s;
                }
            }
        }

        debug_assert_eq!(precomp.offset - offset, self.num_sbox());
        Ok(trace)
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
        let mut state = state;

        let num_states = self.num_witness_states();

        let mut final_mul: [[Option<ShamirPrimeFieldShare<F>>; 2]; BATCH_SIZE] =
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
        let mut per_states: [_; BATCH_SIZE] = array::from_fn(|_| Vec::with_capacity(num_states));

        let mut traces: [Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE] = array::from_fn(|_| {
            if T == 2 {
                vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T2]
            } else if T == 3 {
                vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T3]
            } else if T == 4 {
                vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T4]
            } else {
                vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T16]
            }
        });

        let wtns_indices: &[u16] = match T {
            2 => WITNESS_INDICES_T2,
            3 => WITNESS_INDICES_T3,
            4 => WITNESS_INDICES_T4,
            16 => WITNESS_INDICES_T16,
            _ => return Err(eyre::eyre!("Unsupported state size {T}")),
        };

        let matmul_external: Option<[Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE]> = if T == 16 {
            let mut me = Vec::with_capacity(BATCH_SIZE);
            for chunk in state.chunks_exact_mut(T) {
                me.push(Self::matmul_external_shamir_intermediate_t16(
                    chunk.try_into().expect("we checked sizes"),
                ));
            }
            Some(me.try_into().expect("we checked sizes"))
        } else {
            for chunk in state.chunks_exact_mut(T) {
                Self::matmul_external_shamir_shares(chunk.try_into().expect("we checked sizes"));
            }
            None
        };

        for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
            ps.extend_from_slice(chunk);
        }

        for r in 0..self.params.rounds_f_beginning {
            let (sq_, qu_, res): ([_; BATCH_SIZE], [_; BATCH_SIZE], [_; BATCH_SIZE]) =
                if r == self.params.rounds_f_beginning - 1 && T == 16 {
                    self.shamir_external_round_precomp_matmul_intermediate_packed::<N, BATCH_SIZE>(
                        state.as_mut_slice(),
                        r,
                        precomp,
                        net,
                        shamir_state,
                    )?
                } else {
                    let (sq, qu, res, _, _) = self
                        .shamir_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                            state.as_mut_slice(),
                            r,
                            precomp,
                            net,
                            shamir_state,
                        )?;
                    (sq, qu, res)
                };

            if r != self.params.rounds_f_beginning - 1 || (T != 4 && T != 16) {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.extend_from_slice(chunk);
                }
            } else if r == self.params.rounds_f_beginning - 1 && T == 4 {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.push(chunk[0]);
                    ps.push(chunk[3]);
                }
            } else if r == self.params.rounds_f_beginning - 1 && T == 16 {
                for (sq1, r_, qu1) in izip!(squares_1.iter_mut(), res.iter(), quads_1.iter_mut()) {
                    sq1.push(*r_);
                    qu1.push(ShamirPrimeFieldShare::default());
                }
            }
            for (sq1, sq, qu1, qu) in izip!(
                squares_1.iter_mut(),
                sq_.iter(),
                quads_1.iter_mut(),
                qu_.iter()
            ) {
                sq1.extend(sq);
                qu1.extend(qu);
            }
        }

        for r in 0..self.params.rounds_p {
            let (sum, sq_, qu_) = self.shamir_internal_round_precomp_intermediate_packed(
                state.as_mut_slice(),
                r,
                precomp,
                net,
                shamir_state,
            )?;
            for (sq2, sq, qu2, qu) in izip!(
                squares_2.iter_mut(),
                sq_.iter(),
                quads_2.iter_mut(),
                qu_.iter()
            ) {
                sq2.push(*sq);
                qu2.push(*qu);
            }
            let set_first = T == 16 && r == 0;
            let set_last = (T == 4 || T == 16) && r == self.params.rounds_p - 1;
            if set_first || set_last {
                let sv = sum.as_ref().expect("T >= 4 means sum should be Some");
                for (fm, s) in final_mul.iter_mut().zip(sv.iter()) {
                    if set_first {
                        fm[0] = Some(*s);
                    }
                    if set_last {
                        fm[1] = Some(*s);
                    }
                }
            }
            if T != 4 && T != 16 {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.push(*chunk.first().unwrap());
                }
            } else if (T == 4 || T == 16) && r < self.params.rounds_p - 2 {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.push(*chunk.last().unwrap());
                }
            } else if (T == 4 || T == 16) && r == self.params.rounds_p - 2 {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.extend_from_slice(&chunk[1..]);
                }
            }
        }

        let mut last_matmul_external: Option<[Vec<ShamirPrimeFieldShare<F>>; BATCH_SIZE]> = None;
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (sq_, qu_, sboxes_0, sboxes_1, me) = self
                .shamir_external_round_precomp_intermediate_packed::<N, BATCH_SIZE>(
                    state.as_mut_slice(),
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?;
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                for (sq3, s0) in squares_3.iter_mut().zip(sboxes_0.iter()) {
                    sq3.push(*s0);
                }
                for (qu3, s1) in quads_3.iter_mut().zip(sboxes_1.iter()) {
                    qu3.push(*s1);
                }
                for (sq3, sq, qu3, qu) in izip!(
                    squares_3.iter_mut(),
                    sq_.iter(),
                    quads_3.iter_mut(),
                    qu_.iter()
                ) {
                    sq3.extend(sq);
                    qu3.extend(qu);
                }
                last_matmul_external = me;
                break;
            }
            for (sq3, sq, qu3, qu) in izip!(
                squares_3.iter_mut(),
                sq_.iter(),
                quads_3.iter_mut(),
                qu_.iter()
            ) {
                sq3.extend(sq);
                qu3.extend(qu);
            }
            for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                ps.extend_from_slice(chunk);
            }
        }

        // Fill traces
        let mut counter = 0;
        for (i, ps) in per_states.iter().enumerate() {
            for (j, s) in ps.iter().enumerate() {
                traces[i][wtns_indices[j] as usize] = *s;
            }
        }
        counter += per_states[0].len();

        if let Some(ref me) = matmul_external {
            for (i, me_) in me.iter().enumerate() {
                for (j, s) in me_.iter().enumerate() {
                    traces[i][wtns_indices[counter + j] as usize] = *s;
                }
            }
            counter += me[0].len();
        }

        for (i, (sq1, qu1)) in izip!(squares_1.iter(), quads_1.iter()).enumerate() {
            for (j, (sq, qu)) in sq1.iter().zip(qu1.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_1[0].len();

        for (i, (sq3, qu3)) in izip!(squares_3.iter(), quads_3.iter()).enumerate() {
            for (j, (sq, qu)) in sq3.iter().zip(qu3.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_3[0].len();

        for (i, (sq2, qu2)) in izip!(squares_2.iter(), quads_2.iter()).enumerate() {
            for (j, (sq, qu)) in sq2.iter().zip(qu2.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_2[0].len();

        if T == 16 {
            for (i, fm) in final_mul.iter().enumerate() {
                if let (Some(v0), Some(v1)) = (fm[0], fm[1]) {
                    traces[i][wtns_indices[counter] as usize] = v0;
                    traces[i][wtns_indices[counter + 1] as usize] = v1;
                }
            }
            counter += 2;
        }
        if T == 4 {
            for (i, fm) in final_mul.iter().enumerate() {
                if let Some(val) = fm[1] {
                    traces[i][wtns_indices[counter] as usize] = val;
                }
            }
            counter += 1;
        }

        if let Some(lme) = last_matmul_external {
            for (i, lme_) in lme.iter().enumerate() {
                for (j, s) in lme_.iter().enumerate() {
                    traces[i][wtns_indices[counter + j] as usize] = *s;
                }
            }
        }

        Ok((state, traces))
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
        let t2 = state.len() / T;
        let mut state = state;

        let num_states = self.num_witness_states();

        let mut final_mul = vec![[None::<ShamirPrimeFieldShare<F>>, None]; t2];
        let mut squares_1 = vec![Vec::with_capacity(T * self.params.rounds_f_beginning); t2];
        let mut quads_1 = vec![Vec::with_capacity(T * self.params.rounds_f_beginning); t2];
        let mut squares_2 = vec![Vec::with_capacity(self.params.rounds_p); t2];
        let mut quads_2 = vec![Vec::with_capacity(self.params.rounds_p); t2];
        let mut squares_3 = vec![Vec::with_capacity(T * self.params.rounds_f_end); t2];
        let mut quads_3 = vec![Vec::with_capacity(T * self.params.rounds_f_end); t2];
        let mut per_states = vec![Vec::with_capacity(num_states); t2];

        let mut traces: Vec<Vec<ShamirPrimeFieldShare<F>>> = if T == 2 {
            vec![vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T2]; t2]
        } else if T == 3 {
            vec![vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T3]; t2]
        } else if T == 4 {
            vec![vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T4]; t2]
        } else {
            vec![vec![ShamirPrimeFieldShare::default(); WITNESS_INDICES_SIZE_T16]; t2]
        };

        let wtns_indices: &[u16] = match T {
            2 => WITNESS_INDICES_T2,
            3 => WITNESS_INDICES_T3,
            4 => WITNESS_INDICES_T4,
            16 => WITNESS_INDICES_T16,
            _ => return Err(eyre::eyre!("Unsupported state size {T}")),
        };

        let matmul_external: Option<Vec<Vec<ShamirPrimeFieldShare<F>>>> = if T == 16 {
            Some(
                state
                    .chunks_exact_mut(T)
                    .map(|chunk| {
                        Self::matmul_external_shamir_intermediate_t16(
                            chunk.try_into().expect("we checked sizes"),
                        )
                    })
                    .collect(),
            )
        } else {
            for chunk in state.chunks_exact_mut(T) {
                Self::matmul_external_shamir_shares(chunk.try_into().expect("we checked sizes"));
            }
            None
        };

        for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
            ps.extend_from_slice(chunk);
        }

        for r in 0..self.params.rounds_f_beginning {
            let (sq_, qu_, res) = if r == self.params.rounds_f_beginning - 1 && T == 16 {
                self.shamir_external_round_precomp_matmul_intermediate_vec(
                    &mut state,
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?
            } else {
                let (sq, qu, res, _, _) = self.shamir_external_round_precomp_intermediate_vec(
                    &mut state,
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?;
                (sq, qu, res)
            };

            if r != self.params.rounds_f_beginning - 1 || (T != 4 && T != 16) {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.extend_from_slice(chunk);
                }
            } else if r == self.params.rounds_f_beginning - 1 && T == 4 {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.push(chunk[0]);
                    ps.push(chunk[3]);
                }
            } else if r == self.params.rounds_f_beginning - 1 && T == 16 {
                for (sq1, r_, qu1) in izip!(squares_1.iter_mut(), res.iter(), quads_1.iter_mut()) {
                    sq1.push(*r_);
                    qu1.push(ShamirPrimeFieldShare::default());
                }
            }
            for (sq1, sq, qu1, qu) in izip!(
                squares_1.iter_mut(),
                sq_.iter(),
                quads_1.iter_mut(),
                qu_.iter()
            ) {
                sq1.extend(sq);
                qu1.extend(qu);
            }
        }

        for r in 0..self.params.rounds_p {
            let (sum, sq_, qu_) = self.shamir_internal_round_precomp_intermediate_packed(
                &mut state,
                r,
                precomp,
                net,
                shamir_state,
            )?;
            for (sq2, sq, qu2, qu) in izip!(
                squares_2.iter_mut(),
                sq_.iter(),
                quads_2.iter_mut(),
                qu_.iter()
            ) {
                sq2.push(*sq);
                qu2.push(*qu);
            }
            let set_first = T == 16 && r == 0;
            let set_last = (T == 4 || T == 16) && r == self.params.rounds_p - 1;
            if set_first || set_last {
                let sv = sum.as_ref().expect("T >= 4 means sum should be Some");
                for (fm, s) in final_mul.iter_mut().zip(sv.iter()) {
                    if set_first {
                        fm[0] = Some(*s);
                    }
                    if set_last {
                        fm[1] = Some(*s);
                    }
                }
            }
            if T != 4 && T != 16 {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.push(*chunk.first().unwrap());
                }
            } else if (T == 4 || T == 16) && r < self.params.rounds_p - 2 {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.push(*chunk.last().unwrap());
                }
            } else if (T == 4 || T == 16) && r == self.params.rounds_p - 2 {
                for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                    ps.extend_from_slice(&chunk[1..]);
                }
            }
        }

        let mut last_matmul_external = None;
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            let (sq_, qu_, sboxes_0, sboxes_1, me) = self
                .shamir_external_round_precomp_intermediate_vec(
                    &mut state,
                    r,
                    precomp,
                    net,
                    shamir_state,
                )?;
            if r == self.params.rounds_f_beginning + self.params.rounds_f_end - 1 {
                for (sq3, s0) in squares_3.iter_mut().zip(sboxes_0.iter()) {
                    sq3.push(*s0);
                }
                for (qu3, s1) in quads_3.iter_mut().zip(sboxes_1.iter()) {
                    qu3.push(*s1);
                }
                for (sq3, sq, qu3, qu) in izip!(
                    squares_3.iter_mut(),
                    sq_.iter(),
                    quads_3.iter_mut(),
                    qu_.iter()
                ) {
                    sq3.extend(sq);
                    qu3.extend(qu);
                }
                last_matmul_external = me;
                break;
            }
            for (sq3, sq, qu3, qu) in izip!(
                squares_3.iter_mut(),
                sq_.iter(),
                quads_3.iter_mut(),
                qu_.iter()
            ) {
                sq3.extend(sq);
                qu3.extend(qu);
            }
            for (ps, chunk) in per_states.iter_mut().zip(state.chunks(T)) {
                ps.extend_from_slice(chunk);
            }
        }

        let mut counter = 0;
        for (i, ps) in per_states.iter().enumerate() {
            for (j, s) in ps.iter().enumerate() {
                traces[i][wtns_indices[j] as usize] = *s;
            }
        }
        counter += per_states[0].len();

        if let Some(ref me) = matmul_external {
            for (i, me_) in me.iter().enumerate() {
                for (j, s) in me_.iter().enumerate() {
                    traces[i][wtns_indices[counter + j] as usize] = *s;
                }
            }
            counter += me[0].len();
        }

        for (i, (sq1, qu1)) in izip!(squares_1.iter(), quads_1.iter()).enumerate() {
            for (j, (sq, qu)) in sq1.iter().zip(qu1.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_1[0].len();

        for (i, (sq3, qu3)) in izip!(squares_3.iter(), quads_3.iter()).enumerate() {
            for (j, (sq, qu)) in sq3.iter().zip(qu3.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_3[0].len();

        for (i, (sq2, qu2)) in izip!(squares_2.iter(), quads_2.iter()).enumerate() {
            for (j, (sq, qu)) in sq2.iter().zip(qu2.iter()).enumerate() {
                let idx = counter + 2 * j;
                traces[i][wtns_indices[idx] as usize] = *sq;
                traces[i][wtns_indices[idx + 1] as usize] = *qu;
            }
        }
        counter += 2 * squares_2[0].len();

        if T == 16 {
            for (i, fm) in final_mul.iter().enumerate() {
                if let (Some(v0), Some(v1)) = (fm[0], fm[1]) {
                    traces[i][wtns_indices[counter] as usize] = v0;
                    traces[i][wtns_indices[counter + 1] as usize] = v1;
                }
            }
            counter += 2;
        }
        if T == 4 {
            for (i, fm) in final_mul.iter().enumerate() {
                if let Some(val) = fm[1] {
                    traces[i][wtns_indices[counter] as usize] = val;
                }
            }
            counter += 1;
        }

        if let Some(lme) = last_matmul_external {
            for (i, lme_) in lme.iter().enumerate() {
                for (j, s) in lme_.iter().enumerate() {
                    traces[i][wtns_indices[counter + j] as usize] = *s;
                }
            }
        }

        Ok((state, traces))
    }
}
