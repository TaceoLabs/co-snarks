use super::{Poseidon2, Poseidon2Precomputations};
use crate::protocols::shamir::{
    ShamirPrimeFieldShare, ShamirProtocol, arithmetic, network::ShamirNetwork,
};
use ark_ff::PrimeField;

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2<F, T, D> {
    fn transmute_shamir_state(state: &mut [ShamirPrimeFieldShare<F>; T]) -> &mut [F; T] {
        // SAFETY: ShamirPrimeFieldShare has repr(transparent)
        unsafe { &mut *(state.as_mut() as *mut [ShamirPrimeFieldShare<F>] as *mut [F; T]) }
    }

    /// Returns how much preprocessed randomness is required for num_poseidon Poseidon2 permutations. Thereby, it distinguishes between whether the depth-reducing preprocessing step is used or not.
    pub fn rand_required(&self, num_poseidon: usize, precomputation: bool) -> usize {
        assert_eq!(D, 5);
        let num_sbox = self.num_sbox();
        let mut mult_per_sbox = 3;

        if precomputation {
            mult_per_sbox += 2;
        }

        num_sbox * mult_per_sbox * num_poseidon
    }

    /// The matrix multiplication in the external rounds of the Poseidon2 permutation. Implemented for the Shamir MPC protocol.
    pub fn matmul_external_shamir(state: &mut [ShamirPrimeFieldShare<F>; T]) -> &mut [F; T] {
        let state = Self::transmute_shamir_state(state);
        Self::matmul_external(state);
        state
    }

    /// Create Poseidon2Precomputations for the Shamir MPC protocol.
    pub fn precompute_shamir<N: ShamirNetwork>(
        &self,
        num_poseidon: usize,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<Poseidon2Precomputations<ShamirPrimeFieldShare<F>>> {
        assert_eq!(D, 5);
        let num_sbox = self.num_sbox() * num_poseidon;

        let mut r = Vec::with_capacity(num_sbox);
        for _ in 0..num_sbox {
            r.push(driver.rand()?);
        }
        let r2 = arithmetic::mul_vec(&r, &r, driver)?;
        let r4 = arithmetic::mul_vec(&r2, &r2, driver)?;

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

        let mut r3 = arithmetic::mul_vec(&lhs, &rhs, driver)?;
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

    fn sbox_shamir_precomp<N: ShamirNetwork>(
        input: &mut [F],
        driver: &mut ShamirProtocol<F, N>,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
    ) -> std::io::Result<()> {
        assert_eq!(D, 5);
        for (i, inp) in input.iter_mut().enumerate() {
            *inp -= &precomp.r[precomp.offset + i].a;
        }

        let y = arithmetic::open_vec(ShamirPrimeFieldShare::convert_slice_rev(&*input), driver)?;

        for (i, (inp, y)) in input.iter_mut().zip(y).enumerate() {
            let (r, r2, r3, r4, r5) = precomp.get(precomp.offset + i);

            *inp = Self::sbox_shamir_precomp_post(&y, &r.a, &r2.a, &r3.a, &r4.a, &r5.a);
        }

        precomp.offset += input.len();

        Ok(())
    }

    fn single_sbox_shamir_precomp<N: ShamirNetwork>(
        input: &mut F,
        driver: &mut ShamirProtocol<F, N>,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
    ) -> std::io::Result<()> {
        assert_eq!(D, 5);
        let (r, r2, r3, r4, r5) = precomp.get(precomp.offset);

        *input -= &r.a;
        let y = arithmetic::open(ShamirPrimeFieldShare::new(*input), driver)?;
        *input = Self::sbox_shamir_precomp_post(&y, &r.a, &r2.a, &r3.a, &r4.a, &r5.a);
        precomp.offset += 1;

        Ok(())
    }

    fn single_sbox_shamir_precomp_packed<N: ShamirNetwork>(
        input: &mut [F],
        driver: &mut ShamirProtocol<F, N>,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
    ) -> std::io::Result<()> {
        debug_assert_eq!(input.len() % T, 0);
        let mut vec = input.iter().cloned().step_by(T).collect::<Vec<_>>();
        Self::sbox_shamir_precomp(&mut vec, driver, precomp)?;

        for (inp, r) in input.iter_mut().step_by(T).zip(vec) {
            *inp = r;
        }

        Ok(())
    }

    fn sbox_shamir_precomp_post(y: &F, r: &F, r2: &F, r3: &F, r4: &F, r5: &F) -> F {
        assert_eq!(D, 5);
        let y2 = y.square();
        let y3 = y2 * y;
        let y4 = y2.square();
        let y5 = y4 * y;
        let five = F::from(5u64);
        let ten = F::from(10u64);

        let mut res = y5;
        res += y4 * r * five;
        res += y3 * r2 * ten;
        res += y2 * r3 * ten;
        res += *y * r4 * five;
        res += r5;
        res
    }

    fn sbox_shamir<N: ShamirNetwork>(
        input: &mut [F; T],
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        assert_eq!(D, 5);
        // Square
        let inp = input.iter().map(|i| i.square()).collect();
        let mut sq = ShamirPrimeFieldShare::convert_vec(driver.degree_reduce_vec(inp)?);

        // Quad
        sq.iter_mut().for_each(|x| {
            x.square_in_place();
        });
        let mut qu = ShamirPrimeFieldShare::convert_vec(driver.degree_reduce_vec(sq)?);

        // Quint
        qu.iter_mut().zip(input.iter()).for_each(|(x, y)| *x *= y);
        let res = ShamirPrimeFieldShare::convert_vec(driver.degree_reduce_vec(qu)?);

        input.clone_from_slice(&res);
        Ok(())
    }

    fn single_sbox_shamir<N: ShamirNetwork>(
        input: &mut F,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        assert_eq!(D, 5);
        // Square
        let mut sq = driver.degree_reduce(input.square())?.a;

        // Quad
        sq.square_in_place();
        let mut qu = driver.degree_reduce(sq)?.a;

        // Quint
        qu *= &*input;
        *input = driver.degree_reduce(qu)?.a;

        Ok(())
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Shamir MPC protocol.
    #[inline(always)]
    pub fn shamir_external_round_precomp<N: ShamirNetwork>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        let state = Self::transmute_shamir_state(state);
        self.shamir_external_round_precomp_inner(state, r, precomp, driver)
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Shamir MPC protocol.
    fn shamir_external_round_precomp_inner<N: ShamirNetwork>(
        &self,
        state: &mut [F; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        self.add_rc_external(state, r);
        Self::sbox_shamir_precomp(state, driver, precomp)?;
        Self::matmul_external(state);
        Ok(())
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Shamir MPC protocol.
    #[inline(always)]
    pub fn shamir_internal_round_precomp<N: ShamirNetwork>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        let state = Self::transmute_shamir_state(state);
        self.shamir_internal_round_precomp_inner(state, r, precomp, driver)
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Shamir MPC protocol.
    fn shamir_internal_round_precomp_inner<N: ShamirNetwork>(
        &self,
        state: &mut [F; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        self.add_rc_internal(state, r);
        Self::single_sbox_shamir_precomp(&mut state[0], driver, precomp)?;
        self.matmul_internal(state);
        Ok(())
    }

    /// One external round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Shamir MPC protocol.
    fn shamir_external_round_precomp_inner_packed<N: ShamirNetwork>(
        &self,
        state: &mut [F],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        debug_assert_eq!(state.len() % T, 0);
        for s in state.chunks_exact_mut(T) {
            self.add_rc_external(s.try_into().unwrap(), r);
        }
        Self::sbox_shamir_precomp(state, driver, precomp)?;
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external(s.try_into().unwrap());
        }
        Ok(())
    }

    /// One internal round of the Poseidon2 permuation using Poseidon2Precomputations. Implemented for the Shamir MPC protocol.
    fn shamir_internal_round_precomp_inner_packed<N: ShamirNetwork>(
        &self,
        state: &mut [F],
        r: usize,
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        debug_assert_eq!(state.len() % T, 0);
        for s in state.chunks_exact_mut(T) {
            self.add_rc_internal(s.try_into().unwrap(), r);
        }
        Self::single_sbox_shamir_precomp_packed(state, driver, precomp)?;
        for s in state.chunks_exact_mut(T) {
            self.matmul_internal(s.try_into().unwrap());
        }
        Ok(())
    }

    /// One external round of the Poseidon2 permuation. Implemented for the Shamir MPC protocol.
    fn shamir_external_round<N: ShamirNetwork>(
        &self,
        state: &mut [F; T],
        r: usize,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        self.add_rc_external(state, r);
        Self::sbox_shamir(state, driver)?;
        Self::matmul_external(state);
        Ok(())
    }

    /// One internal round of the Poseidon2 permuation. Implemented for the Shamir MPC protocol.
    fn shamir_internal_round<N: ShamirNetwork>(
        &self,
        state: &mut [F; T],
        r: usize,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        self.add_rc_internal(state, r);
        Self::single_sbox_shamir(&mut state[0], driver)?;
        self.matmul_internal(state);
        Ok(())
    }

    /// Computes multiple Poseidon2 permuations in parallel using the Shamir MPC protocol while overwriting the input. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn shamir_permutation_in_place_with_precomputation_packed<N: ShamirNetwork>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        assert_eq!(state.len() % T, 0);

        let num_poseidon = state.len() / T;
        let offset = precomp.offset;
        // let mut precomp = self.precompute_shamir(num_poseidon, driver)?;

        // Linear layer at beginning
        let state = ShamirPrimeFieldShare::convert_mut(state);
        for s in state.chunks_exact_mut(T) {
            Self::matmul_external(s.try_into().unwrap());
        }

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.shamir_external_round_precomp_inner_packed(state, r, precomp, driver)?;
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.shamir_internal_round_precomp_inner_packed(state, r, precomp, driver)?;
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.shamir_external_round_precomp_inner_packed(state, r, precomp, driver)?;
        }

        debug_assert_eq!(precomp.offset - offset, self.num_sbox() * num_poseidon);
        Ok(())
    }

    /// Computes the Poseidon2 permuation using the Shamir MPC protocol while overwriting the input. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn shamir_permutation_in_place_with_precomputation<N: ShamirNetwork>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        let offset = precomp.offset;
        // let mut precomp = self.precompute_shamir(1, driver)?;

        // Linear layer at beginning
        let state = Self::matmul_external_shamir(state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.shamir_external_round_precomp_inner(state, r, precomp, driver)?;
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.shamir_internal_round_precomp_inner(state, r, precomp, driver)?;
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.shamir_external_round_precomp_inner(state, r, precomp, driver)?;
        }

        debug_assert_eq!(precomp.offset - offset, self.num_sbox());
        Ok(())
    }

    /// Computes the Poseidon2 permuation using the Shamir MPC protocol while overwriting the input.
    pub fn shamir_permutation_in_place<N: ShamirNetwork>(
        &self,
        state: &mut [ShamirPrimeFieldShare<F>; T],
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<()> {
        // Linear layer at beginning
        let state = Self::matmul_external_shamir(state);

        // First set of external rounds
        for r in 0..self.params.rounds_f_beginning {
            self.shamir_external_round(state, r, driver)?;
        }

        // Internal rounds
        for r in 0..self.params.rounds_p {
            self.shamir_internal_round(state, r, driver)?;
        }

        // Remaining external rounds
        for r in self.params.rounds_f_beginning
            ..self.params.rounds_f_beginning + self.params.rounds_f_end
        {
            self.shamir_external_round(state, r, driver)?;
        }

        Ok(())
    }

    /// Computes the Poseidon2 permuation using the Shamir MPC protocol.
    pub fn shamir_permutation<N: ShamirNetwork>(
        &self,
        state: &[ShamirPrimeFieldShare<F>; T],
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<[ShamirPrimeFieldShare<F>; T]> {
        let mut state = state.to_owned();
        self.shamir_permutation_in_place(&mut state, driver)?;
        Ok(state)
    }

    /// Computes the Poseidon2 permuation using the Shamir MPC protocol. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn shamir_permutation_with_precomputation<N: ShamirNetwork>(
        &self,
        state: &[ShamirPrimeFieldShare<F>; T],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<[ShamirPrimeFieldShare<F>; T]> {
        let mut state = state.to_owned();
        self.shamir_permutation_in_place_with_precomputation(&mut state, precomp, driver)?;
        Ok(state)
    }

    /// Computes multiple Poseidon2 permuations in parallel using the Shamir MPC protocol. Thereby, a preprocessing technique is used to reduce the depth of the computation.
    pub fn shamir_permutation_with_precomputation_packed<N: ShamirNetwork>(
        &self,
        state: &[ShamirPrimeFieldShare<F>],
        precomp: &mut Poseidon2Precomputations<ShamirPrimeFieldShare<F>>,
        driver: &mut ShamirProtocol<F, N>,
    ) -> std::io::Result<Vec<ShamirPrimeFieldShare<F>>> {
        let mut state = state.to_owned();
        self.shamir_permutation_in_place_with_precomputation_packed(&mut state, precomp, driver)?;
        Ok(state)
    }
}
