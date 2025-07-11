use std::array;

use super::{Poseidon2, Poseidon2Precomputations};
use crate::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State, arithmetic, id::PartyID, network::Rep3NetworkExt,
};
use ark_ff::PrimeField;
use mpc_net::Network;

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2<F, T, D> {
    /// Create Poseidon2Precomputations for the Rep3 MPC protocol.
    pub fn precompute_rep3<N: Network>(
        &self,
        num_poseidon: usize,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Poseidon2Precomputations<Rep3PrimeFieldShare<F>>> {
        assert_eq!(D, 5);

        let num_sbox = self.num_sbox() * num_poseidon;

        let mut r = Vec::with_capacity(num_sbox);
        for _ in 0..num_sbox {
            r.push(arithmetic::rand(state));
        }
        let r2 = arithmetic::mul_vec(&r, &r, net, state)?;
        let r4 = arithmetic::mul_vec(&r2, &r2, net, state)?;

        let mut lhs = Vec::with_capacity(num_sbox * 2);
        let mut rhs = Vec::with_capacity(num_sbox * 2);
        for (r, r2) in r.iter().cloned().zip(r2.iter().cloned()) {
            lhs.push(r);
            rhs.push(r2);
        }
        for (r, r4) in r.iter().cloned().zip(r4.iter().cloned()) {
            lhs.push(r);
            rhs.push(r4);
        }

        let mut r3 = arithmetic::mul_vec(&lhs, &rhs, net, state)?;
        let r5 = r3.split_off(num_sbox);

        Ok(Poseidon2Precomputations {
            r,
            r2,
            r3,
            r4,
            r5,
            offset: 0,
        })
    }

    /// Create Poseidon2Precomputations for the Rep3 MPC protocol, but only save the additive shares.
    pub fn precompute_rep3_additive<N: Network>(
        &self,
        num_poseidon: usize,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Poseidon2Precomputations<F>> {
        let res = self.precompute_rep3(num_poseidon, net, state)?;
        Ok(Poseidon2Precomputations {
            r: res.r.into_iter().map(|x| x.a).collect(),
            r2: res.r2.into_iter().map(|x| x.a).collect(),
            r3: res.r3.into_iter().map(|x| x.a).collect(),
            r4: res.r4.into_iter().map(|x| x.a).collect(),
            r5: res.r5.into_iter().map(|x| x.a).collect(),
            offset: res.offset,
        })
    }

    /**
     * hardcoded algorithm that evaluates matrix multiplication using the following MDS matrix:
     * /         \
     * | 5 7 1 3 |
     * | 4 6 1 1 |
     * | 1 3 5 7 |
     * | 1 1 4 6 |
     * \         /
     *
     * Algorithm is taken directly from the Poseidon2 paper.
     */
    fn matmul_m4_rep3(input: &mut [Rep3PrimeFieldShare<F>; 4]) {
        let t_0 = input[0] + input[1]; // A + B
        let t_1 = input[2] + input[3]; // C + D
        let t_2 = input[1].double() + t_1; // 2B + C + D
        let t_3 = input[3].double() + t_0; // A + B + 2D
        let t_4 = t_1.double().double() + t_3; // A + B + 4C + 6D
        let t_5 = t_0.double().double() + t_2; // 4A + 6B + C + D
        let t_6 = t_3 + t_5; // 5A + 7B + C + 3D
        let t_7 = t_2 + t_4; // A + 3B + 5C + 7D
        input[0] = t_6;
        input[1] = t_5;
        input[2] = t_7;
        input[3] = t_4;
    }

    /// The matrix multiplication in the external rounds of the Poseidon2 permutation. Implemented for the Rep3 MPC protocol.
    pub fn matmul_external_rep3(input: &mut [Rep3PrimeFieldShare<F>; T]) {
        match T {
            2 => {
                // Matrix circ(2, 1)
                let sum = input[0] + input[1];
                input[0] += &sum;
                input[1] += sum;
            }
            3 => {
                // Matrix circ(2, 1, 1)
                let sum = input[0] + input[1] + input[2];
                input[0] += &sum;
                input[1] += &sum;
                input[2] += sum;
            }
            4 => {
                Self::matmul_m4_rep3(input.as_mut_slice().try_into().unwrap());
            }
            8 | 12 | 16 | 20 | 24 => {
                // Applying cheap 4x4 MDS matrix to each 4-element part of the state
                for state in input.chunks_exact_mut(4) {
                    Self::matmul_m4_rep3(state.try_into().unwrap());
                }

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
            }
            _ => {
                panic!("Invalid Statesize");
            }
        }
    }

    fn matmul_internal_rep3(&self, input: &mut [Rep3PrimeFieldShare<F>; T]) {
        match T {
            2 => {
                // Matrix [[2, 1], [1, 3]]
                debug_assert_eq!(self.params.mat_internal_diag_m_1[0], F::one());
                debug_assert_eq!(self.params.mat_internal_diag_m_1[1], F::from(2u64));
                let sum = input[0] + input[1];
                input[0] += &sum;
                input[1].double_in_place();
                input[1] += sum;
            }
            3 => {
                // Matrix [[2, 1, 1], [1, 2, 1], [1, 1, 3]]
                debug_assert_eq!(self.params.mat_internal_diag_m_1[0], F::one());
                debug_assert_eq!(self.params.mat_internal_diag_m_1[1], F::one());
                debug_assert_eq!(self.params.mat_internal_diag_m_1[2], F::from(2u64));
                let sum = input[0] + input[1] + input[2];
                input[0] += &sum;
                input[1] += &sum;
                input[2].double_in_place();
                input[2] += sum;
            }
            _ => {
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
            }
        }
    }

    fn add_rc_external_rep3(
        &self,
        input: &mut [Rep3PrimeFieldShare<F>; T],
        rc_offset: usize,
        id: PartyID,
    ) {
        if id == PartyID::ID0 {
            for (s, rc) in input
                .iter_mut()
                .zip(self.params.round_constants_external[rc_offset].iter())
            {
                s.a += rc;
            }
        } else if id == PartyID::ID1 {
            for (s, rc) in input
                .iter_mut()
                .zip(self.params.round_constants_external[rc_offset].iter())
            {
                s.b += rc;
            }
        }
    }

    fn reshare_state_rep3<N: Network>(
        input: &mut [F; T],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<[Rep3PrimeFieldShare<F>; T]> {
        input.iter_mut().for_each(|x| {
            *x += state.rngs.rand.masking_field_element::<F>();
        });
        let b = net.reshare_many(input)?;
        let shares = array::from_fn(|i| Rep3PrimeFieldShare::new(input[i], b[i]));

        Ok(shares)
    }

    fn sbox_rep3_precomp<N: Network>(
        input: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        assert_eq!(D, 5);
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        // Open
        let y = arithmetic::open_vec(input, net)?;
        let id = PartyID::try_from(net.id())?;

        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            let (r, r2, r3, r4, r5) = precomp.get(precomp.offset + i);

            *inp = Self::sbox_rep3_precomp_post(&y, r, r2, r3, r4, r5, id);
        }

        precomp.offset += input.len();

        Ok(())
    }

    fn sbox_rep3_precomp_additive<N: Network>(
        input: &mut [F],
        precomp: &mut Poseidon2Precomputations<F>,
        net: &N,
    ) -> eyre::Result<()> {
        assert_eq!(D, 5);
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= precomp.r[precomp.offset + i];
        }

        let id = PartyID::try_from(net.id())?;

        // Open
        let (b, c) = net.broadcast_many(input)?;
        let mut y = b;
        for (y, (c, i)) in y.iter_mut().zip(c.into_iter().zip(input.iter())) {
            *y += c + i;
        }

        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            let (r, r2, r3, r4, r5) = precomp.get(precomp.offset + i);

            *inp = Self::sbox_rep3_precomp_post_additive(&y, r, r2, r3, r4, r5, id);
        }

        precomp.offset += input.len();

        Ok(())
    }

    fn single_sbox_rep3_precomp<N: Network>(
        input: &mut Rep3PrimeFieldShare<F>,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        assert_eq!(D, 5);
        let (r, r2, r3, r4, r5) = precomp.get(precomp.offset);

        *input -= *r;

        let id = PartyID::try_from(net.id())?;

        // Open
        let y = arithmetic::open(*input, net)?;

        *input = Self::sbox_rep3_precomp_post(&y, r, r2, r3, r4, r5, id);
        precomp.offset += 1;

        Ok(())
    }

    fn single_sbox_rep3_precomp_packed<N: Network>(
        input: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        debug_assert_eq!(input.len() % T, 0);
        let mut vec = input.iter().cloned().step_by(T).collect::<Vec<_>>();
        Self::sbox_rep3_precomp(&mut vec, precomp, net)?;

        for (inp, r) in input.iter_mut().step_by(T).zip(vec) {
            *inp = r;
        }

        Ok(())
    }

    fn single_sbox_rep3<N: Network>(
        input: &mut F,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()> {
        assert_eq!(D, 5);
        // Reshare (with re-randomization):
        let input_a = input.to_owned() + state.rngs.rand.masking_field_element::<F>();
        let input_b = net.reshare(input_a.to_owned())?;
        let share = Rep3PrimeFieldShare::new(input_a, input_b);

        // Square
        let sq = arithmetic::mul(share, share, net, state)?;

        // Quad
        let qu = arithmetic::mul(sq, sq, net, state)?;

        // Quint
        *input = qu * share;

        Ok(())
    }

    fn single_sbox_rep3_precomp_additive<N: Network>(
        input: &mut F,
        precomp: &mut Poseidon2Precomputations<F>,
        net: &N,
    ) -> eyre::Result<()> {
        assert_eq!(D, 5);
        let (r, r2, r3, r4, r5) = precomp.get(precomp.offset);

        *input -= r;

        let id = PartyID::try_from(net.id())?;

        // Open
        let (b, c) = net.broadcast(*input)?;
        let mut y = b;
        y += c + *input;

        *input = Self::sbox_rep3_precomp_post_additive(&y, r, r2, r3, r4, r5, id);
        precomp.offset += 1;

        Ok(())
    }

    fn sbox_rep3_precomp_post(
        y: &F,
        r: &Rep3PrimeFieldShare<F>,
        r2: &Rep3PrimeFieldShare<F>,
        r3: &Rep3PrimeFieldShare<F>,
        r4: &Rep3PrimeFieldShare<F>,
        r5: &Rep3PrimeFieldShare<F>,
        id: PartyID,
    ) -> Rep3PrimeFieldShare<F> {
        assert_eq!(D, 5);
        let y2 = y.square();
        let y3 = y2 * y;
        let y4 = y2.square();
        let five = F::from(5u64);
        let ten = F::from(10u64);

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
        res
    }

    fn sbox_rep3_precomp_post_additive(
        y: &F,
        r: &F,
        r2: &F,
        r3: &F,
        r4: &F,
        r5: &F,
        id: PartyID,
    ) -> F {
        assert_eq!(D, 5);
        let y2 = y.square();
        let y3 = y2 * y;
        let y4 = y2.square();
        let five = F::from(5u64);
        let ten = F::from(10u64);

        let mut res = *r5;
        res += *y * r4 * five;
        res += y2 * r3 * ten;
        res += y3 * r2 * ten;
        res += y4 * r * five;

        if id == PartyID::ID0 {
            let y5 = y4 * y;
            res += y5;
        }
        res
    }

    fn sbox_rep3<N: Network>(
        input: &mut [F; T],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()> {
        let shares = Self::reshare_state_rep3(input, net, state)?;
        *input = Self::sbox_rep3_first(&shares, net, state)?;

        Ok(())
    }

    fn sbox_rep3_first<N: Network>(
        input: &[Rep3PrimeFieldShare<F>; T],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<[F; T]> {
        assert_eq!(D, 5);
        // Square
        let sq: Vec<Rep3PrimeFieldShare<F>> = arithmetic::mul_vec(input, input, net, state)?;

        // Quad
        let qu = arithmetic::mul_vec(&sq, &sq, net, state)?;

        // Quint
        let res = array::from_fn(|i| qu[i] * input[i]);
        Ok(res)
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    fn rep3_external_round_precomp_additive<N: Network>(
        &self,
        state: &mut [F; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<F>,
        net: &N,
    ) -> eyre::Result<()> {
        let id = PartyID::try_from(net.id())?;
        if id == PartyID::ID0 {
            self.add_rc_external(state, r);
        }
        Self::sbox_rep3_precomp_additive(state, precomp, net)?;
        Self::matmul_external(state);
        Ok(())
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    fn rep3_internal_round_precomp_additive<N: Network>(
        &self,
        state: &mut [F; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<F>,
        net: &N,
    ) -> eyre::Result<()> {
        let id = PartyID::try_from(net.id())?;
        if id == PartyID::ID0 {
            self.add_rc_internal(state, r);
        }
        Self::single_sbox_rep3_precomp_additive(&mut state[0], precomp, net)?;
        self.matmul_internal(state);
        Ok(())
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    pub fn rep3_external_round_precomp<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        let id = PartyID::try_from(net.id())?;
        self.add_rc_external_rep3(state, r, id);
        Self::sbox_rep3_precomp(state, precomp, net)?;
        Self::matmul_external_rep3(state);
        Ok(())
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    pub fn rep3_internal_round_precomp<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        let id = PartyID::try_from(net.id())?;
        if id == PartyID::ID0 {
            state[0].a += self.params.round_constants_internal[r];
        } else if id == PartyID::ID1 {
            state[0].b += self.params.round_constants_internal[r];
        }
        Self::single_sbox_rep3_precomp(&mut state[0], precomp, net)?;
        self.matmul_internal_rep3(state);
        Ok(())
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    fn rep3_external_round_precomp_packed<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        debug_assert_eq!(state.len() % T, 0);
        let id = PartyID::try_from(net.id())?;
        if id == PartyID::ID0 {
            for state in state.chunks_exact_mut(T) {
                for (s, rc) in state
                    .iter_mut()
                    .zip(self.params.round_constants_external[r].iter())
                {
                    s.a += rc;
                }
            }
        } else if id == PartyID::ID1 {
            for state in state.chunks_exact_mut(T) {
                for (s, rc) in state
                    .iter_mut()
                    .zip(self.params.round_constants_external[r].iter())
                {
                    s.b += rc;
                }
            }
        }
        Self::sbox_rep3_precomp(state, precomp, net)?;
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().unwrap());
        }
        Ok(())
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Rep3 MPC protocol.
    fn rep3_internal_round_precomp_packed<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        debug_assert_eq!(state.len() % T, 0);
        let id = PartyID::try_from(net.id())?;
        if id == PartyID::ID0 {
            for s in state.chunks_exact_mut(T) {
                s[0].a += self.params.round_constants_internal[r];
            }
        } else if id == PartyID::ID1 {
            for s in state.chunks_exact_mut(T) {
                s[0].b += self.params.round_constants_internal[r];
            }
        }
        Self::single_sbox_rep3_precomp_packed(state, precomp, net)?;
        for s in state.chunks_exact_mut(T) {
            self.matmul_internal_rep3(s.try_into().unwrap());
        }
        Ok(())
    }

    /// One external round of the Poseidon2 permuation. Implemented for the Rep3 MPC protocol.
    fn rep3_external_round<N: Network>(
        &self,
        state: &mut [F; T],
        r: usize,
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        let id = PartyID::try_from(net.id())?;
        if id == PartyID::ID0 {
            self.add_rc_external(state, r);
        }
        Self::sbox_rep3(state, net, rep3_state)?;
        Self::matmul_external(state);
        Ok(())
    }

    /// One internal round of the Poseidon2 permuation. Implemented for the Rep3 MPC protocol.
    fn rep3_internal_round<N: Network>(
        &self,
        state: &mut [F; T],
        r: usize,
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        let id = PartyID::try_from(net.id())?;
        if id == PartyID::ID0 {
            self.add_rc_internal(state, r);
        }
        Self::single_sbox_rep3(&mut state[0], net, rep3_state)?;
        self.matmul_internal(state);
        Ok(())
    }

    /// Computes multiple Poseidon2 permuations in parallel using the Rep3 MPC protocol while overwriting the input. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn rep3_permutation_in_place_with_precomputation_packed<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        assert_eq!(state.len() % T, 0);

        let num_poseidon = state.len() / T;
        let offset = precomp.offset;
        // let mut precomp = self.precompute_rep3(num_poseidon, driver)?;

        // Linear layer at beginning
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external_rep3(s.try_into().unwrap());
        }

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.rep3_external_round_precomp_packed(state, r, precomp, net)?;
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.rep3_internal_round_precomp_packed(state, r, precomp, net)?;
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.rep3_external_round_precomp_packed(state, r, precomp, net)?;
        }

        debug_assert_eq!(precomp.offset - offset, self.num_sbox() * num_poseidon);
        Ok(())
    }

    /// Computes the Poseidon2 permuation using the Rep3 MPC protocol while overwriting the input. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn rep3_permutation_in_place_with_precomputation<N: Network>(
        &self,
        state: &mut [Rep3PrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<()> {
        let offset = precomp.offset;
        // let mut precomp = self.precompute_rep3(1, driver)?;

        // Linear layer at beginning
        Self::matmul_external_rep3(state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.rep3_external_round_precomp(state, r, precomp, net)?;
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.rep3_internal_round_precomp(state, r, precomp, net)?;
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.rep3_external_round_precomp(state, r, precomp, net)?;
        }

        debug_assert_eq!(precomp.offset - offset, self.num_sbox());
        Ok(())
    }

    /// Computes the Poseidon2 permuation using the Rep3 MPC protocol while overwriting the input. Thereby, a preprocessing technique is used to reduce the depth of the computation. Furthermore, the whole state is processed as additive shares, i.e., less CPU at the cost of more network communication.
    pub fn rep3_permutation_additive_in_place_with_precomputation<N: Network>(
        &self,
        state_: &mut [Rep3PrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<F>,
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        let offset = precomp.offset;
        // let mut precomp = self.precompute_rep3_additive(1, driver)?;

        // Just use a
        let mut state = array::from_fn(|i| state_[i].a);

        // Linear layer at beginning
        Self::matmul_external(&mut state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.rep3_external_round_precomp_additive(&mut state, r, precomp, net)?;
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.rep3_internal_round_precomp_additive(&mut state, r, precomp, net)?;
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.rep3_external_round_precomp_additive(&mut state, r, precomp, net)?;
        }

        *state_ = Self::reshare_state_rep3(&mut state, net, rep3_state)?;

        debug_assert_eq!(precomp.offset - offset, self.num_sbox());
        Ok(())
    }

    /// Computes the Poseidon2 permuation using the Rep3 MPC protocol while overwriting the input.
    pub fn rep3_permutation_in_place<N: Network>(
        &self,
        state_: &mut [Rep3PrimeFieldShare<F>; T],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        // Linear layer at beginning
        Self::matmul_external_rep3(state_);

        let id = PartyID::try_from(net.id())?;

        // First round:
        self.add_rc_external_rep3(state_, 0, id);
        let mut state = Self::sbox_rep3_first(state_, net, rep3_state)?;
        Self::matmul_external(&mut state);

        // First set of external rounds
        for r in 1..self.params.rounds_f_beginning {
            self.rep3_external_round(&mut state, r, net, rep3_state)?;
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.rep3_internal_round(&mut state, r, net, rep3_state)?;
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.rep3_external_round(&mut state, r, net, rep3_state)?;
        }

        *state_ = Self::reshare_state_rep3(&mut state, net, rep3_state)?;

        Ok(())
    }

    /// Computes the Poseidon2 permuation using the Rep3 MPC protocol.
    pub fn rep3_permutation<N: Network>(
        &self,
        state: &[Rep3PrimeFieldShare<F>; T],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<[Rep3PrimeFieldShare<F>; T]> {
        let mut state = state.to_owned();
        self.rep3_permutation_in_place(&mut state, net, rep3_state)?;
        Ok(state)
    }

    /// Computes the Poseidon2 permuation using the Rep3 MPC protocol. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn rep3_permutation_with_precomputation<N: Network>(
        &self,
        state: &[Rep3PrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<[Rep3PrimeFieldShare<F>; T]> {
        assert_eq!(D, 5);
        let mut state = state.to_owned();
        self.rep3_permutation_in_place_with_precomputation(&mut state, precomp, net)?;
        Ok(state)
    }

    /// Computes multiple Poseidon2 permuations in paralllel using the Rep3 MPC protocol. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn rep3_permutation_with_precomputation_packed<N: Network>(
        &self,
        state: &[Rep3PrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
        assert_eq!(D, 5);
        let mut state = state.to_owned();
        self.rep3_permutation_in_place_with_precomputation_packed(&mut state, precomp, net)?;
        Ok(state)
    }

    /// Computes the Poseidon2 permuation using the Rep3 MPC protocol. Thereby, a preprocessing technique is used to reduce the depth of the computation. Furthermore, the whole state is processed as additive shares, i.e., less CPU at the cost of more network communication.
    pub fn rep3_permutation_additive_with_precomputation<N: Network>(
        &self,
        state: &[Rep3PrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<F>,
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<[Rep3PrimeFieldShare<F>; T]> {
        assert_eq!(D, 5);
        let mut state = state.to_owned();
        self.rep3_permutation_additive_in_place_with_precomputation(
            &mut state, precomp, net, rep3_state,
        )?;
        Ok(state)
    }
}
