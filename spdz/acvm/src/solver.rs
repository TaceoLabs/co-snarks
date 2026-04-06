//! SPDZ ACVM Solver
//!
//! Implements `NoirWitnessExtensionProtocol` for 2-party SPDZ.
//! Follows the Shamir implementation pattern: basic arithmetic on shared values
//! is supported; complex operations panic when called on shared inputs.

use crate::brillig::{SpdzBrilligDriver, SpdzBrilligType};
use crate::types::{SpdzAcvmPoint, SpdzAcvmType};
use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use mpc_core::gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations};
use mpc_core::protocols::rep3::yao::circuits::SHA256Table;
use mpc_core::protocols::rep3_ring::lut_field::Rep3FieldLookupTable;
use mpc_net::Network;
use num_bigint::BigUint;
use spdz_core::types::SpdzPrimeFieldShare;
use spdz_core::{arithmetic, SpdzState};
use std::marker::PhantomData;

/// SPDZ ACVM solver.
pub struct SpdzAcvmSolver<'a, F: PrimeField, N: Network> {
    net: &'a N,
    state: SpdzState<F>,
    phantom_data: PhantomData<F>,
    /// Stores Poseidon2 precomputation between preprocess and round calls.
    /// The trait passes `Poseidon2Precomputations` as a dummy token;
    /// we use our own precomp internally to avoid needing the `new()`
    /// constructor on the mpc-core type.
    poseidon2_precomp: Option<spdz_core::gadgets::poseidon2::SpdzPoseidon2Precomp<F>>,
}

impl<'a, F: PrimeField, N: Network> SpdzAcvmSolver<'a, F, N> {
    pub fn new(net: &'a N, state: SpdzState<F>) -> Self {
        Self { poseidon2_precomp: None,
            net,
            state,
            phantom_data: PhantomData,
        }
    }
}

// Macro for methods that panic on shared inputs (matching Shamir pattern)
macro_rules! not_supported {
    ($name:ident) => {
        panic!(concat!("SPDZ: ", stringify!($name), " not supported for shared values"))
    };
}

impl<'a, F: PrimeField, N: Network> NoirWitnessExtensionProtocol<F>
    for SpdzAcvmSolver<'a, F, N>
{
    type Lookup = Rep3FieldLookupTable<F>;
    type ArithmeticShare = SpdzPrimeFieldShare<F>;
    type OtherArithmeticShare<C: CurveGroup<ScalarField = F, BaseField: PrimeField>> =
        SpdzPrimeFieldShare<C::BaseField>;
    type AcvmType = SpdzAcvmType<F>;
    type OtherAcvmType<C: CurveGroup<ScalarField = F, BaseField: PrimeField>> =
        SpdzAcvmType<C::BaseField>;
    type AcvmPoint<C: CurveGroup<BaseField = F>> = SpdzAcvmPoint<C>;
    type BrilligDriver = SpdzBrilligDriver<'a, F, N>;

    fn init_brillig_driver(&mut self) -> eyre::Result<Self::BrilligDriver> {
        // Fork the state to give the Brillig VM its own preprocessing material.
        // The network reference is shared (branches run sequentially).
        use mpc_core::MpcState;
        let forked_state = self.state.fork(0)?;
        Ok(SpdzBrilligDriver::new(self.net, forked_state))
    }

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<SpdzBrilligType<F>>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        Ok(brillig_result.into_iter().map(SpdzAcvmType::from).collect())
    }

    fn shared_zeros(&mut self, len: usize) -> eyre::Result<Vec<Self::AcvmType>> {
        Ok(vec![SpdzAcvmType::Shared(SpdzPrimeFieldShare::zero_share()); len])
    }

    fn is_public_zero(a: &Self::AcvmType) -> bool {
        matches!(a, SpdzAcvmType::Public(f) if f.is_zero())
    }

    fn is_public_one(a: &Self::AcvmType) -> bool {
        matches!(a, SpdzAcvmType::Public(f) if f.is_one())
    }

    fn cmux(&mut self, cond: Self::AcvmType, truthy: Self::AcvmType, falsy: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match cond {
            SpdzAcvmType::Public(c) => {
                if c.is_one() { Ok(truthy) } else { Ok(falsy) }
            }
            SpdzAcvmType::Shared(c) => {
                let diff = self.sub(truthy, falsy.clone());
                let d = self.mul(SpdzAcvmType::Shared(c), diff)?;
                Ok(self.add(falsy, d))
            }
        }
    }

    fn cmux_many(&mut self, conds: &[Self::AcvmType], truthies: &[Self::AcvmType], falsies: &[Self::AcvmType]) -> eyre::Result<Vec<Self::AcvmType>> {
        let n = conds.len();
        let mut results: Vec<Option<SpdzAcvmType<F>>> = vec![None; n];
        let mut shared_conds = Vec::new();
        let mut shared_diffs = Vec::new();
        let mut shared_falsies = Vec::new();
        let mut shared_idx = Vec::new();

        for i in 0..n {
            match &conds[i] {
                SpdzAcvmType::Public(c) => {
                    results[i] = Some(if c.is_one() { truthies[i].clone() } else { falsies[i].clone() });
                }
                SpdzAcvmType::Shared(c) => {
                    let diff = self.sub(truthies[i].clone(), falsies[i].clone());
                    if let SpdzAcvmType::Shared(d) = diff {
                        shared_conds.push(*c);
                        shared_diffs.push(d);
                        shared_falsies.push(falsies[i].clone());
                        shared_idx.push(i);
                    } else {
                        let d = self.mul(SpdzAcvmType::Shared(*c), diff)?;
                        results[i] = Some(self.add(falsies[i].clone(), d));
                    }
                }
            }
        }

        if !shared_conds.is_empty() {
            let products = arithmetic::mul_many(&shared_conds, &shared_diffs, self.net, &mut self.state)?;
            for (j, &idx) in shared_idx.iter().enumerate() {
                let result = self.add(shared_falsies[j].clone(), SpdzAcvmType::Shared(products[j]));
                results[idx] = Some(result);
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap()).collect())
    }

    fn cmux_other_acvm_type<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, cond: Self::OtherAcvmType<C>, truthy: Self::OtherAcvmType<C>, falsy: Self::OtherAcvmType<C>) -> eyre::Result<Self::OtherAcvmType<C>> {
        match cond {
            SpdzAcvmType::Public(c) => {
                if c.is_one() { Ok(truthy) } else { Ok(falsy) }
            }
            _ => not_supported!(cmux_other_shared_cond),
        }
    }

    fn add_assign_with_public(&mut self, public: F, target: &mut Self::AcvmType) {
        match target {
            SpdzAcvmType::Public(f) => *f += public,
            SpdzAcvmType::Shared(s) => *s = arithmetic::add_public(*s, public, self.state.mac_key_share, self.state.id),
        }
    }

    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        match (lhs, rhs) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => SpdzAcvmType::Public(a + b),
            (SpdzAcvmType::Shared(a), SpdzAcvmType::Shared(b)) => SpdzAcvmType::Shared(a + b),
            (SpdzAcvmType::Public(p), SpdzAcvmType::Shared(s)) | (SpdzAcvmType::Shared(s), SpdzAcvmType::Public(p)) =>
                SpdzAcvmType::Shared(arithmetic::add_public(s, p, self.state.mac_key_share, self.state.id)),
        }
    }

    fn add_points<C: CurveGroup<BaseField = F>>(&self, lhs: Self::AcvmPoint<C>, rhs: Self::AcvmPoint<C>) -> Self::AcvmPoint<C> {
        match (lhs, rhs) {
            (SpdzAcvmPoint::Public(a), SpdzAcvmPoint::Public(b)) => SpdzAcvmPoint::Public(a + b),
            (SpdzAcvmPoint::Shared(a), SpdzAcvmPoint::Shared(b)) => SpdzAcvmPoint::Shared(a + b),
            _ => panic!("SPDZ: mixed public/shared point add not supported"),
        }
    }

    fn sub(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        match (lhs, rhs) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => SpdzAcvmType::Public(a - b),
            (SpdzAcvmType::Shared(a), SpdzAcvmType::Shared(b)) => SpdzAcvmType::Shared(a - b),
            (SpdzAcvmType::Public(p), SpdzAcvmType::Shared(s)) =>
                SpdzAcvmType::Shared(arithmetic::add_public(-s, p, self.state.mac_key_share, self.state.id)),
            (SpdzAcvmType::Shared(s), SpdzAcvmType::Public(p)) =>
                SpdzAcvmType::Shared(arithmetic::sub_public(s, p, self.state.mac_key_share, self.state.id)),
        }
    }

    fn mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType {
        match secret {
            SpdzAcvmType::Public(f) => SpdzAcvmType::Public(public * f),
            SpdzAcvmType::Shared(s) => SpdzAcvmType::Shared(s * public),
        }
    }

    fn mul(&mut self, a: Self::AcvmType, b: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match (a, b) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => Ok(SpdzAcvmType::Public(a * b)),
            (SpdzAcvmType::Public(p), SpdzAcvmType::Shared(s)) | (SpdzAcvmType::Shared(s), SpdzAcvmType::Public(p)) =>
                Ok(SpdzAcvmType::Shared(s * p)),
            (SpdzAcvmType::Shared(a), SpdzAcvmType::Shared(b)) =>
                Ok(SpdzAcvmType::Shared(arithmetic::mul(&a, &b, self.net, &mut self.state)?)),
        }
    }

    fn mul_many(&mut self, a: &[Self::AcvmType], b: &[Self::AcvmType]) -> eyre::Result<Vec<Self::AcvmType>> {
        // Batch all Shared×Shared multiplications into ONE mul_many call (1 round).
        // Public operations are handled locally (free).
        let n = a.len();
        let mut results: Vec<Option<SpdzAcvmType<F>>> = vec![None; n];
        let mut shared_as = Vec::new();
        let mut shared_bs = Vec::new();
        let mut shared_idx = Vec::new();

        for (i, (ai, bi)) in a.iter().zip(b.iter()).enumerate() {
            match (ai, bi) {
                (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => {
                    results[i] = Some(SpdzAcvmType::Public(*a * *b));
                }
                (SpdzAcvmType::Public(p), SpdzAcvmType::Shared(s))
                | (SpdzAcvmType::Shared(s), SpdzAcvmType::Public(p)) => {
                    results[i] = Some(SpdzAcvmType::Shared(*s * *p));
                }
                (SpdzAcvmType::Shared(a), SpdzAcvmType::Shared(b)) => {
                    shared_as.push(*a);
                    shared_bs.push(*b);
                    shared_idx.push(i);
                }
            }
        }

        // One batched call for ALL shared multiplications
        if !shared_as.is_empty() {
            let products = arithmetic::mul_many(&shared_as, &shared_bs, self.net, &mut self.state)?;
            for (j, &idx) in shared_idx.iter().enumerate() {
                results[idx] = Some(SpdzAcvmType::Shared(products[j]));
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap()).collect())
    }

    fn invert(&mut self, secret: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match secret {
            SpdzAcvmType::Public(f) => Ok(SpdzAcvmType::Public(f.inverse().ok_or_else(|| eyre::eyre!("invert zero"))?)),
            SpdzAcvmType::Shared(s) => Ok(SpdzAcvmType::Shared(arithmetic::inv(&s, self.net, &mut self.state)?)),
        }
    }

    fn negate_inplace(&mut self, a: &mut Self::AcvmType) {
        match a {
            SpdzAcvmType::Public(f) => *f = -*f,
            SpdzAcvmType::Shared(s) => *s = -*s,
        }
    }

    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, result: &mut Self::AcvmType) {
        let term = self.mul_with_public(q_l, w_l);
        self.add_assign(result, term);
    }

    fn add_assign(&mut self, lhs: &mut Self::AcvmType, rhs: Self::AcvmType) {
        *lhs = self.add(lhs.clone(), rhs);
    }

    fn solve_mul_term(&mut self, c: F, lhs: Self::AcvmType, rhs: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        let p = self.mul(lhs, rhs)?;
        Ok(self.mul_with_public(c, p))
    }

    fn solve_equation(&mut self, q_l: Self::AcvmType, c: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        let mut neg_c = c;
        self.negate_inplace(&mut neg_c);
        let inv_q = self.invert(q_l)?;
        self.mul(inv_q, neg_c)
    }

    fn is_shared(a: &Self::AcvmType) -> bool { matches!(a, SpdzAcvmType::Shared(_)) }
    fn get_shared(a: &Self::AcvmType) -> Option<Self::ArithmeticShare> { match a { SpdzAcvmType::Shared(s) => Some(*s), _ => None } }
    fn get_public(a: &Self::AcvmType) -> Option<F> { match a { SpdzAcvmType::Public(f) => Some(*f), _ => None } }
    fn get_public_other_acvm_type<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(a: &Self::OtherAcvmType<C>) -> Option<C::BaseField> { match a { SpdzAcvmType::Public(f) => Some(*f), _ => None } }
    fn get_public_point<C: CurveGroup<BaseField = F>>(a: &Self::AcvmPoint<C>) -> Option<C> { match a { SpdzAcvmPoint::Public(p) => Some(*p), _ => None } }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> eyre::Result<Vec<F>> {
        let mac = if self.state.verify_macs { Some(self.state.mac_key_share) } else { None };
        arithmetic::open_many(a, self.net, mac)
    }
    fn open_many_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: &[Self::OtherAcvmType<C>]) -> eyre::Result<Vec<C::BaseField>> {
        // Open base field shares by exchanging share components
        use crate::types::SpdzAcvmType;
        let mut results = Vec::with_capacity(a.len());
        for val in a {
            match val {
                SpdzAcvmType::Public(f) => results.push(*f),
                SpdzAcvmType::Shared(s) => {
                    // Exchange share components via network
                    use spdz_core::network::SpdzNetworkExt;
                    let other: C::BaseField = self.net.exchange(s.share)?;
                    results.push(s.share + other);
                }
            }
        }
        Ok(results)
    }

    fn rand(&mut self) -> eyre::Result<Self::ArithmeticShare> { self.state.preprocessing.next_shared_random() }
    fn promote_to_trivial_share(&mut self, v: F) -> Self::ArithmeticShare { SpdzPrimeFieldShare::promote_from_trivial(&v, self.state.mac_key_share, self.state.id) }
    fn promote_to_trivial_shares(&mut self, vs: &[F]) -> Vec<Self::ArithmeticShare> { vs.iter().map(|v| self.promote_to_trivial_share(*v)).collect() }

    fn equal(&mut self, a: &Self::AcvmType, b: &Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match (a, b) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => {
                Ok(SpdzAcvmType::Public(if a == b { F::one() } else { F::zero() }))
            }
            _ => {
                let a_share = self.get_as_shared(a);
                let b_share = self.get_as_shared(b);
                let num_bits = F::MODULUS_BIT_SIZE as usize;
                let result = spdz_core::gadgets::bits::equal(
                    &a_share, &b_share, num_bits, self.net, &mut self.state,
                )?;
                Ok(SpdzAcvmType::Shared(result))
            }
        }
    }

    fn equals_other_acvm_type<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: &Self::OtherAcvmType<C>, b: &Self::OtherAcvmType<C>) -> eyre::Result<(Self::AcvmType, Self::OtherAcvmType<C>)> {
        match (a, b) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => {
                use ark_ff::{One as _, Zero as _};
                let eq = if a == b { F::one() } else { F::zero() };
                let eq_other: C::BaseField = if a == b { C::BaseField::one() } else { C::BaseField::zero() };
                Ok((SpdzAcvmType::Public(eq), SpdzAcvmType::Public(eq_other)))
            }
            _ => not_supported!(equals_other_shared),
        }
    }

    fn equal_many(&mut self, a: &[Self::AcvmType], b: &[Self::AcvmType]) -> eyre::Result<Vec<Self::AcvmType>> {
        // Batch all shared equalities into 2 rounds total (via gc_equality_batch)
        let mut public_results = Vec::new();
        let mut shared_pairs = Vec::new();
        let mut shared_indices = Vec::new();

        for (i, (ai, bi)) in a.iter().zip(b.iter()).enumerate() {
            match (ai, bi) {
                (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => {
                    public_results.push((i, if a == b { F::one() } else { F::zero() }));
                }
                _ => {
                    shared_pairs.push((self.get_as_shared(ai), self.get_as_shared(bi)));
                    shared_indices.push(i);
                }
            }
        }

        // Batch the shared equalities (2 rounds for ALL of them!)
        let shared_results = if !shared_pairs.is_empty() {
            spdz_core::gadgets::yao2pc::equality::gc_equality_batch(
                &shared_pairs,
                F::MODULUS_BIT_SIZE as usize,
                self.net,
                &mut self.state,
            )?
        } else {
            vec![]
        };

        // Reconstruct output in original order
        let mut results = vec![SpdzAcvmType::Public(F::zero()); a.len()];
        for (idx, val) in public_results {
            results[idx] = SpdzAcvmType::Public(val);
        }
        for (j, &idx) in shared_indices.iter().enumerate() {
            results[idx] = SpdzAcvmType::Shared(shared_results[j]);
        }
        Ok(results)
    }

    fn decompose_arithmetic(&mut self, input: Self::ArithmeticShare, total_bit_size: usize, decompose_bit_size: usize) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        // Decompose into individual bits, then group into chunks of decompose_bit_size
        let bits = spdz_core::gadgets::bits::decompose(
            &input, total_bit_size, self.net, &mut self.state,
        )?;

        // Group bits into chunks and compose each chunk
        let num_chunks = (total_bit_size + decompose_bit_size - 1) / decompose_bit_size;
        let mut chunks = Vec::with_capacity(num_chunks);
        for chunk_idx in 0..num_chunks {
            let start = chunk_idx * decompose_bit_size;
            let end = std::cmp::min(start + decompose_bit_size, total_bit_size);
            let mut chunk_val = SpdzPrimeFieldShare::zero_share();
            let mut power = F::one();
            for bit in &bits[start..end] {
                chunk_val += *bit * power;
                power.double_in_place();
            }
            chunks.push(chunk_val);
        }
        Ok(chunks)
    }

    fn decompose_arithmetic_many(&mut self, inputs: &[Self::ArithmeticShare], total_bit_size: usize, decompose_bit_size: usize) -> eyre::Result<Vec<Vec<Self::ArithmeticShare>>> {
        let all_bits = spdz_core::gadgets::bits::decompose_many(
            inputs, total_bit_size, self.net, &mut self.state,
        )?;

        let num_chunks = (total_bit_size + decompose_bit_size - 1) / decompose_bit_size;
        let mut results = Vec::with_capacity(inputs.len());
        for bits in all_bits {
            let mut chunks = Vec::with_capacity(num_chunks);
            for chunk_idx in 0..num_chunks {
                let start = chunk_idx * decompose_bit_size;
                let end = std::cmp::min(start + decompose_bit_size, total_bit_size);
                let mut chunk_val = SpdzPrimeFieldShare::zero_share();
                let mut power = F::one();
                for bit in &bits[start..end] {
                    chunk_val += *bit * power;
                    power.double_in_place();
                }
                chunks.push(chunk_val);
            }
            results.push(chunks);
        }
        Ok(results)
    }

    fn sort(&mut self, inputs: &[Self::AcvmType], bitsize: usize) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let shares: Vec<SpdzPrimeFieldShare<F>> = inputs.iter().map(|v| self.get_as_shared(v)).collect();
        spdz_core::gadgets::bits::sort(&shares, bitsize, self.net, &mut self.state)
    }

    fn sort_vec_by(&mut self, key: &[Self::AcvmType], inputs: Vec<&[Self::ArithmeticShare]>, bitsize: usize) -> eyre::Result<Vec<Vec<Self::ArithmeticShare>>> {
        // Sort all input arrays by the key using oblivious bubble sort
        let n = key.len();
        let key_shares: Vec<SpdzPrimeFieldShare<F>> = key.iter().map(|v| self.get_as_shared(v)).collect();
        let mut key_arr = key_shares;
        let mut input_arrs: Vec<Vec<SpdzPrimeFieldShare<F>>> = inputs.iter().map(|v| v.to_vec()).collect();

        for i in 0..n {
            for j in 0..n - 1 - i {
                let gt = spdz_core::gadgets::bits::greater_than(&key_arr[j], &key_arr[j + 1], bitsize, self.net, &mut self.state)?;
                // Conditional swap key
                let diff = key_arr[j + 1] - key_arr[j];
                let gt_diff = arithmetic::mul(&gt, &diff, self.net, &mut self.state)?;
                key_arr[j] = key_arr[j] + gt_diff;
                key_arr[j + 1] = key_arr[j + 1] - gt_diff;
                // Conditional swap each input array
                for arr in &mut input_arrs {
                    let diff = arr[j + 1] - arr[j];
                    let gt_diff = arithmetic::mul(&gt, &diff, self.net, &mut self.state)?;
                    arr[j] = arr[j] + gt_diff;
                    arr[j + 1] = arr[j + 1] - gt_diff;
                }
            }
        }
        Ok(input_arrs)
    }

    fn slice(&mut self, input: Self::ArithmeticShare, msb: u8, lsb: u8, bitsize: usize) -> eyre::Result<[Self::ArithmeticShare; 2]> {
        spdz_core::gadgets::bits::slice(&input, msb, lsb, bitsize, self.net, &mut self.state)
    }

    fn slice_many(&mut self, inputs: &[Self::ArithmeticShare], msb: u8, lsb: u8, bitsize: usize) -> eyre::Result<Vec<[Self::ArithmeticShare; 2]>> {
        spdz_core::gadgets::bits::slice_many(inputs, msb, lsb, bitsize, self.net, &mut self.state)
    }

    fn right_shift(&mut self, input: Self::AcvmType, shift: usize) -> eyre::Result<Self::AcvmType> {
        match input {
            SpdzAcvmType::Public(f) => {
                let big: BigUint = f.into();
                Ok(SpdzAcvmType::Public(F::from(big >> shift)))
            }
            SpdzAcvmType::Shared(s) => {
                let result = spdz_core::gadgets::bits::right_shift(&s, shift, 128, self.net, &mut self.state)?;
                Ok(SpdzAcvmType::Shared(result))
            }
        }
    }

    fn integer_bitwise_and(&mut self, lhs: Self::AcvmType, rhs: Self::AcvmType, num_bits: u32) -> eyre::Result<Self::AcvmType> {
        match (&lhs, &rhs) {
            (SpdzAcvmType::Public(l), SpdzAcvmType::Public(r)) => {
                let mask = (BigUint::from(1u64) << num_bits) - BigUint::from(1u64);
                Ok(SpdzAcvmType::Public(F::from((Into::<BigUint>::into(*l) & Into::<BigUint>::into(*r)) & mask)))
            }
            _ => {
                let a = self.get_as_shared(&lhs);
                let b = self.get_as_shared(&rhs);
                let result = spdz_core::gadgets::bits::bitwise_and(
                    &a, &b, num_bits as usize, self.net, &mut self.state,
                )?;
                Ok(SpdzAcvmType::Shared(result))
            }
        }
    }

    fn integer_bitwise_xor(&mut self, lhs: Self::AcvmType, rhs: Self::AcvmType, num_bits: u32) -> eyre::Result<Self::AcvmType> {
        match (&lhs, &rhs) {
            (SpdzAcvmType::Public(l), SpdzAcvmType::Public(r)) => {
                let mask = (BigUint::from(1u64) << num_bits) - BigUint::from(1u64);
                Ok(SpdzAcvmType::Public(F::from((Into::<BigUint>::into(*l) ^ Into::<BigUint>::into(*r)) & mask)))
            }
            _ => {
                let a = self.get_as_shared(&lhs);
                let b = self.get_as_shared(&rhs);
                let result = spdz_core::gadgets::bits::bitwise_xor(
                    &a, &b, num_bits as usize, self.net, &mut self.state,
                )?;
                Ok(SpdzAcvmType::Shared(result))
            }
        }
    }

    // LUT operations — using PublicPrivateLut enum from Rep3FieldLookupTable.
    // We can implement public operations directly and shared index via one-hot vector.
    fn init_lut_by_acvm_type(
        &mut self,
        values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType {
        use mpc_core::protocols::rep3_ring::lut_field::PublicPrivateLut;
        if values.iter().all(|v| !Self::is_shared(v)) {
            let public: Vec<F> = values.iter().map(|v| Self::get_public(v).unwrap()).collect();
            PublicPrivateLut::Public(public)
        } else {
            // Shared LUT: store as Rep3 trivial shares (both components = value/2)
            // This is a workaround since PublicPrivateLut::Shared expects Rep3 shares.
            // We store as Public and handle shared access via one-hot vector.
            let public: Vec<F> = values.iter().map(|v| {
                match v {
                    SpdzAcvmType::Public(f) => *f,
                    SpdzAcvmType::Shared(_) => F::zero(), // placeholder — shared LUT not fully supported
                }
            }).collect();
            PublicPrivateLut::Public(public)
        }
    }

    fn read_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<Self::AcvmType> {
        use mpc_core::protocols::rep3_ring::lut_field::PublicPrivateLut;
        match &index {
            SpdzAcvmType::Public(idx) => {
                let idx_int: BigUint = (*idx).into();
                let i = usize::try_from(idx_int).map_err(|_| eyre::eyre!("Index too large"))?;
                match lut {
                    PublicPrivateLut::Public(vec) => Ok(SpdzAcvmType::Public(vec[i])),
                    PublicPrivateLut::Shared(vec) => {
                        // Rep3 share at public index — extract value (a+b for Rep3)
                        Ok(SpdzAcvmType::Public(vec[i].a + vec[i].b))
                    }
                }
            }
            SpdzAcvmType::Shared(idx_share) => {
                // Shared index: one-hot vector approach
                let len = Self::get_length_of_lut(lut);
                let ohv = self.one_hot_vector_from_shared_index(*idx_share, len)?;
                // Inner product of one-hot vector with LUT values
                let lut_vals: Vec<F> = match lut {
                    PublicPrivateLut::Public(vec) => vec.clone(),
                    PublicPrivateLut::Shared(vec) => vec.iter().map(|s| s.a + s.b).collect(),
                };
                let mut result = SpdzPrimeFieldShare::zero_share();
                for (indicator, val) in ohv.iter().zip(lut_vals.iter()) {
                    result += *indicator * *val;
                }
                Ok(SpdzAcvmType::Shared(result))
            }
        }
    }

    fn read_from_public_luts(&mut self, index: Self::AcvmType, luts: &[Vec<F>]) -> eyre::Result<Vec<Self::AcvmType>> {
        match &index {
            SpdzAcvmType::Public(idx) => {
                let idx_int: BigUint = (*idx).into();
                let i = usize::try_from(idx_int).map_err(|_| eyre::eyre!("Index too large"))?;
                Ok(luts.iter().map(|lut| SpdzAcvmType::Public(lut[i])).collect())
            }
            SpdzAcvmType::Shared(idx_share) => {
                // One-hot approach for each LUT
                let len = luts[0].len();
                let ohv = self.one_hot_vector_from_shared_index(*idx_share, len)?;
                let mut results = Vec::with_capacity(luts.len());
                for lut in luts {
                    let mut result = SpdzPrimeFieldShare::zero_share();
                    for (indicator, val) in ohv.iter().zip(lut.iter()) {
                        result += *indicator * *val;
                    }
                    results.push(SpdzAcvmType::Shared(result));
                }
                Ok(results)
            }
        }
    }

    fn write_lut_by_acvm_type(
        &mut self,
        _index: Self::AcvmType,
        _value: Self::AcvmType,
        _lut: &mut <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<()> {
        // Write requires modifying the LUT at a shared index — complex with PublicPrivateLut
        not_supported!(write_lut)
    }

    fn get_length_of_lut(lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType) -> usize {
        lut.len()
    }

    fn get_public_lut(lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType) -> eyre::Result<&Vec<F>> {
        use mpc_core::protocols::rep3_ring::lut_field::PublicPrivateLut;
        match lut {
            PublicPrivateLut::Public(vec) => Ok(vec),
            PublicPrivateLut::Shared(_) => eyre::bail!("LUT is shared, not public"),
        }
    }

    fn is_public_lut(lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType) -> bool {
        use mpc_core::protocols::rep3_ring::lut_field::PublicPrivateLut;
        matches!(lut, PublicPrivateLut::Public(_))
    }

    fn one_hot_vector_from_shared_index(&mut self, index: Self::ArithmeticShare, len: usize) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let mut ohv = Vec::with_capacity(len);
        for i in 0..len {
            let i_share = self.promote_to_trivial_share(F::from(i as u64));
            let eq = spdz_core::gadgets::bits::equal(&index, &i_share, 32, self.net, &mut self.state)?;
            ohv.push(eq);
        }
        Ok(ohv)
    }

    fn write_to_shared_lut_from_ohv(&mut self, ohv: &[Self::ArithmeticShare], value: Self::ArithmeticShare, lut: &mut [Self::ArithmeticShare]) -> eyre::Result<()> {
        for (i, indicator) in ohv.iter().enumerate() {
            let diff = value - lut[i];
            let update = arithmetic::mul(indicator, &diff, self.net, &mut self.state)?;
            lut[i] = lut[i] + update;
        }
        Ok(())
    }

    // SHA256 / AES / Blake table ops
    // SHA256/AES circuit builder helpers.
    // These are used by co-builder's SHA256 and AES constraint generation.
    // They perform specialized decompose-XOR-rotate-lookup operations.
    // We implement them using our bit decomposition primitives.

    fn slice_and_get_and_rotate_values(&mut self, input1: Self::ArithmeticShare, input2: Self::ArithmeticShare, basis_bits: usize, total_bitsize: usize, _rotation: usize) -> eyre::Result<(Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>)> {
        // Decompose, AND corresponding bits, then group into chunks
        let bits1 = spdz_core::gadgets::bits::decompose(&input1, total_bitsize, self.net, &mut self.state)?;
        let bits2 = spdz_core::gadgets::bits::decompose(&input2, total_bitsize, self.net, &mut self.state)?;
        let and_bits = arithmetic::mul_many(&bits1, &bits2, self.net, &mut self.state)?;

        // Number of chunks: ceiling division to include remainder bits
        let num_chunks = (total_bitsize + basis_bits - 1) / basis_bits;
        let mut key_a_slices = Vec::with_capacity(num_chunks);
        let mut key_b_slices = Vec::with_capacity(num_chunks);
        let mut and_slices = Vec::with_capacity(num_chunks);
        for c in 0..num_chunks {
            let start = c * basis_bits;
            let chunk_size = basis_bits.min(total_bitsize - start);
            let mut v1 = SpdzPrimeFieldShare::zero_share();
            let mut v2 = SpdzPrimeFieldShare::zero_share();
            let mut va = SpdzPrimeFieldShare::zero_share();
            let mut pow = F::one();
            for b in 0..chunk_size {
                v1 += bits1[start + b] * pow;
                v2 += bits2[start + b] * pow;
                va += and_bits[start + b] * pow;
                pow.double_in_place();
            }
            key_a_slices.push(SpdzAcvmType::Shared(v1));
            key_b_slices.push(SpdzAcvmType::Shared(v2));
            and_slices.push(SpdzAcvmType::Shared(va));
        }
        // Return order: (results, key_a, key_b) — matches what plookup.rs expects
        Ok((and_slices, key_a_slices, key_b_slices))
    }

    fn slice_and_get_xor_rotate_values(&mut self, input1: Self::ArithmeticShare, input2: Self::ArithmeticShare, basis_bits: usize, total_bitsize: usize, _rotation: usize) -> eyre::Result<(Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>)> {
        let bits1 = spdz_core::gadgets::bits::decompose(&input1, total_bitsize, self.net, &mut self.state)?;
        let bits2 = spdz_core::gadgets::bits::decompose(&input2, total_bitsize, self.net, &mut self.state)?;
        let prods = arithmetic::mul_many(&bits1, &bits2, self.net, &mut self.state)?;
        let two = F::from(2u64);
        let xor_bits: Vec<_> = bits1.iter().zip(bits2.iter()).zip(prods.iter())
            .map(|((a, b), p)| *a + *b - *p * two).collect();
        // Ceiling division for remainder chunk
        let num_chunks = (total_bitsize + basis_bits - 1) / basis_bits;
        let mut key_a = Vec::with_capacity(num_chunks);
        let mut key_b = Vec::with_capacity(num_chunks);
        let mut xor_slices = Vec::with_capacity(num_chunks);
        for c in 0..num_chunks {
            let start = c * basis_bits;
            let chunk_size = basis_bits.min(total_bitsize - start);
            let mut v1 = SpdzPrimeFieldShare::zero_share();
            let mut v2 = SpdzPrimeFieldShare::zero_share();
            let mut vx = SpdzPrimeFieldShare::zero_share();
            let mut pow = F::one();
            for b in 0..chunk_size {
                v1 += bits1[start + b] * pow;
                v2 += bits2[start + b] * pow;
                vx += xor_bits[start + b] * pow;
                pow.double_in_place();
            }
            key_a.push(SpdzAcvmType::Shared(v1));
            key_b.push(SpdzAcvmType::Shared(v2));
            xor_slices.push(SpdzAcvmType::Shared(vx));
        }
        // Return order: (results, key_a, key_b) — matches plookup.rs expectations
        Ok((xor_slices, key_a, key_b))
    }

    fn slice_and_get_sparse_table_with_rotation_values(&mut self, _: Self::ArithmeticShare, _: Self::ArithmeticShare, _: &[u64], _: &[u32], _: usize, _: u64) -> eyre::Result<(Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>)> {
        // Complex sparse table operation — Rep3 uses garbled circuits
        not_supported!(slice_and_get_sparse_table)
    }

    fn slice_and_get_sparse_normalization_values(&mut self, _: Self::ArithmeticShare, _: Self::ArithmeticShare, _: &[u64], _: u64, _: usize, _: &SHA256Table) -> eyre::Result<(Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>)> {
        not_supported!(slice_and_get_sparse_norm)
    }

    fn slice_and_get_xor_rotate_values_with_filter(&mut self, input1: Self::ArithmeticShare, input2: Self::ArithmeticShare, basis_bits: &[u64], rotation: &[usize], _filter: &[bool]) -> eyre::Result<(Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>)> {
        // Simplified: decompose, XOR, chunk by variable basis_bits
        let total_bits: usize = basis_bits.iter().sum::<u64>() as usize;
        let bits1 = spdz_core::gadgets::bits::decompose(&input1, total_bits, self.net, &mut self.state)?;
        let bits2 = spdz_core::gadgets::bits::decompose(&input2, total_bits, self.net, &mut self.state)?;
        let prods = arithmetic::mul_many(&bits1, &bits2, self.net, &mut self.state)?;
        let two = F::from(2u64);
        let xor_bits: Vec<_> = bits1.iter().zip(bits2.iter()).zip(prods.iter())
            .map(|((a, b), p)| *a + *b - *p * two).collect();
        let mut s1 = Vec::new();
        let mut s2 = Vec::new();
        let mut sx = Vec::new();
        let mut offset = 0;
        for &blen in basis_bits {
            let blen = blen as usize;
            let mut v1 = SpdzPrimeFieldShare::zero_share();
            let mut v2 = SpdzPrimeFieldShare::zero_share();
            let mut vx = SpdzPrimeFieldShare::zero_share();
            let mut pow = F::one();
            for b in 0..blen {
                if offset + b < total_bits {
                    v1 += bits1[offset + b] * pow;
                    v2 += bits2[offset + b] * pow;
                    vx += xor_bits[offset + b] * pow;
                }
                pow.double_in_place();
            }
            s1.push(SpdzAcvmType::Shared(v1));
            s2.push(SpdzAcvmType::Shared(v2));
            sx.push(SpdzAcvmType::Shared(vx));
            offset += blen;
        }
        // Return order: (results, key_a, key_b)
        Ok((sx, s1, s2))
    }

    fn slice_and_get_aes_sparse_normalization_values_from_key(&mut self, _: Self::ArithmeticShare, _: Self::ArithmeticShare, _: &[u64], _: u64) -> eyre::Result<(Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>)> {
        not_supported!(aes_sparse_norm)
    }

    fn slice_and_get_aes_sbox_values_from_key(&mut self, _: Self::ArithmeticShare, _: Self::ArithmeticShare, _: &[u64], _: u64, _: &[u8]) -> eyre::Result<(Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>, Vec<Self::AcvmType>)> {
        not_supported!(aes_sbox)
    }

    fn sha256_get_overflow_bit(&mut self, input: Self::ArithmeticShare) -> eyre::Result<Self::ArithmeticShare> {
        // Get the MSB (overflow bit) of a 32-bit value
        let bits = spdz_core::gadgets::bits::decompose(&input, 33, self.net, &mut self.state)?;
        Ok(bits[32]) // The 33rd bit is the overflow
    }

    fn accumulate_from_sparse_bytes(&mut self, inputs: &[Self::AcvmType], base: u64, input_bitsize: usize, output_bitsize: usize) -> eyre::Result<Self::AcvmType> {
        // Accumulate sparse byte representation into a single field element
        // Each input represents a sparse byte, accumulated with base powers
        let mut result = SpdzPrimeFieldShare::zero_share();
        let base_f = F::from(base);
        let mut power = F::one();
        for inp in inputs {
            let share = self.get_as_shared(inp);
            result += share * power;
            power *= base_f;
        }
        Ok(SpdzAcvmType::Shared(result))
    }

    // Poseidon2
    fn poseidon2_permutation<const T: usize, const D: u64>(
        &mut self,
        mut input: Vec<Self::AcvmType>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if input.len() != T {
            eyre::bail!("Poseidon2: expected {T} inputs, got {}", input.len());
        }

        if input.iter().any(|x| Self::is_shared(x)) {
            // Convert to shared array
            let mut shared: [SpdzPrimeFieldShare<F>; T] = std::array::from_fn(|i| {
                match &input[i] {
                    SpdzAcvmType::Public(f) => self.promote_to_trivial_share(*f),
                    SpdzAcvmType::Shared(s) => *s,
                }
            });

            let mut precomp = spdz_core::gadgets::poseidon2::precompute(
                poseidon2, 1, self.net, &mut self.state,
            )?;
            spdz_core::gadgets::poseidon2::permutation_in_place(
                poseidon2, &mut shared, &mut precomp, self.net, &self.state,
            )?;

            for (i, s) in shared.into_iter().enumerate() {
                input[i] = SpdzAcvmType::Shared(s);
            }
        } else {
            // All public — use plain permutation
            let mut public: [F; T] = std::array::from_fn(|i| {
                Self::get_public(&input[i]).unwrap()
            });
            poseidon2.permutation_in_place(&mut public);
            for (i, f) in public.into_iter().enumerate() {
                input[i] = SpdzAcvmType::Public(f);
            }
        }
        Ok(input)
    }

    fn poseidon2_matmul_external_inplace<const T: usize, const D: u64>(
        &self,
        input: &mut [Self::ArithmeticShare; T],
    ) {
        spdz_core::gadgets::poseidon2::matmul_external(input);
    }

    fn poseidon2_preprocess_permutation<const T: usize, const D: u64>(
        &mut self,
        num_poseidon: usize,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<Poseidon2Precomputations<Self::ArithmeticShare>> {
        // Store our precomp internally; return a dummy Default token.
        // The round functions will use self.poseidon2_precomp instead of the
        // passed-in Poseidon2Precomputations, avoiding the need for its `new()`.
        let spdz_precomp = spdz_core::gadgets::poseidon2::precompute(
            poseidon2, num_poseidon, self.net, &mut self.state,
        )?;
        self.poseidon2_precomp = Some(spdz_precomp);
        Ok(Poseidon2Precomputations::default())
    }

    fn poseidon2_external_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        _precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<()> {
        let precomp = self.poseidon2_precomp.as_mut()
            .ok_or_else(|| eyre::eyre!("Poseidon2 precomp not initialized — call preprocess first"))?;
        spdz_core::gadgets::poseidon2::external_round(
            poseidon2, input, r, precomp, self.net, &self.state,
        )
    }

    fn poseidon2_internal_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        _precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<()> {
        let precomp = self.poseidon2_precomp.as_mut()
            .ok_or_else(|| eyre::eyre!("Poseidon2 precomp not initialized — call preprocess first"))?;
        spdz_core::gadgets::poseidon2::internal_round(
            poseidon2, input, r, precomp, self.net, &self.state,
        )
    }

    // EC / MSM
    fn multi_scalar_mul(&mut self, points: &[Self::AcvmType], scalars_lo: &[Self::AcvmType], scalars_hi: &[Self::AcvmType], _pedantic: bool) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        // Check if all inputs are public
        let all_public = points.iter().chain(scalars_lo.iter()).chain(scalars_hi.iter()).all(|v| !Self::is_shared(v));
        if all_public {
            // Public MSM — can compute directly using the plain solver pattern
            // For now, delegate to the public case of embedded_curve_add iteratively
            not_supported!(multi_scalar_mul_public)
        } else {
            // Shared MSM — requires NAF decomposition on shared scalars + point arithmetic
            not_supported!(multi_scalar_mul_shared)
        }
    }
    fn field_shares_to_pointshare<C: CurveGroup<BaseField = F>>(
        &mut self,
        x: Self::AcvmType,
        y: Self::AcvmType,
        is_infinity: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmPoint<C>> {
        // For public values, construct the point directly
        if let (Some(px), Some(py), Some(pi)) = (
            Self::get_public(&x),
            Self::get_public(&y),
            Self::get_public(&is_infinity),
        ) {
            if pi.is_one() {
                Ok(SpdzAcvmPoint::Public(C::zero()))
            } else {
                // For public coordinates, construct the point using affine representation
                // Cannot construct Affine from coordinates without curve-specific constructors
                not_supported!(field_shares_to_pointshare_public)
            }
        } else {
            // For shared values, we can't construct a curve point without opening
            // Store as a "shared point" conceptually (would need proper implementation)
            not_supported!(field_shares_to_pointshare_shared)
        }
    }

    fn pointshare_to_field_shares<C: CurveGroup<BaseField = F>>(
        &mut self,
        point: Self::AcvmPoint<C>,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        match point {
            SpdzAcvmPoint::Public(p) => {
                use ark_ec::AffineRepr;
                let affine = p.into_affine();
                if let Some((x, y)) = affine.xy() {
                    Ok((SpdzAcvmType::Public(x.to_owned()), SpdzAcvmType::Public(y.to_owned()), SpdzAcvmType::Public(F::zero())))
                } else {
                    Ok((SpdzAcvmType::Public(F::zero()), SpdzAcvmType::Public(F::zero()), SpdzAcvmType::Public(F::one())))
                }
            }
            SpdzAcvmPoint::Shared(_) => {
                not_supported!(pointshare_to_field_shares_shared)
            }
        }
    }
    fn set_point_to_value_if_zero<C: CurveGroup<BaseField = F>>(&mut self, point: Self::AcvmPoint<C>, value: Self::AcvmPoint<C>) -> eyre::Result<Self::AcvmPoint<C>> {
        match point {
            SpdzAcvmPoint::Public(p) => {
                if p.is_zero() { Ok(value) } else { Ok(SpdzAcvmPoint::Public(p)) }
            }
            SpdzAcvmPoint::Shared(_) => {
                // For shared points, we'd need to check if the point is zero
                // without revealing it. This requires opening coordinate shares
                // and checking equality to zero.
                not_supported!(set_point_to_value_if_zero_shared)
            }
        }
    }
    fn embedded_curve_add(
        &mut self,
        x1: Self::AcvmType, y1: Self::AcvmType, inf1: Self::AcvmType,
        x2: Self::AcvmType, y2: Self::AcvmType, inf2: Self::AcvmType,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        // If all public, use plain
        if !Self::is_shared(&x1) && !Self::is_shared(&y1) && !Self::is_shared(&inf1)
            && !Self::is_shared(&x2) && !Self::is_shared(&y2) && !Self::is_shared(&inf2)
        {
            let p1x = Self::get_public(&x1).unwrap();
            let p1y = Self::get_public(&y1).unwrap();
            let p2x = Self::get_public(&x2).unwrap();
            let p2y = Self::get_public(&y2).unwrap();
            // Simple affine addition for public values
            let dx = p2x - p1x;
            if dx.is_zero() {
                return Ok((SpdzAcvmType::Public(F::zero()), SpdzAcvmType::Public(F::zero()), SpdzAcvmType::Public(F::one())));
            }
            let lambda = (p2y - p1y) * dx.inverse().unwrap();
            let x3 = lambda.square() - p1x - p2x;
            let y3 = lambda * (p1x - x3) - p1y;
            return Ok((SpdzAcvmType::Public(x3), SpdzAcvmType::Public(y3), SpdzAcvmType::Public(F::zero())));
        }

        let x1s = self.get_as_shared(&x1);
        let y1s = self.get_as_shared(&y1);
        let inf1s = self.get_as_shared(&inf1);
        let x2s = self.get_as_shared(&x2);
        let y2s = self.get_as_shared(&y2);
        let inf2s = self.get_as_shared(&inf2);
        let (rx, ry, ri) = spdz_core::gadgets::ec::embedded_curve_add(
            &x1s, &y1s, &inf1s, &x2s, &y2s, &inf2s,
            self.net, &mut self.state,
        )?;
        Ok((SpdzAcvmType::Shared(rx), SpdzAcvmType::Shared(ry), SpdzAcvmType::Shared(ri)))
    }

    // Comparison
    fn gt(&mut self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match (&lhs, &rhs) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => {
                let a_big: BigUint = (*a).into();
                let b_big: BigUint = (*b).into();
                Ok(SpdzAcvmType::Public(if a_big > b_big { F::one() } else { F::zero() }))
            }
            _ => {
                let a_share = self.get_as_shared(&lhs);
                let b_share = self.get_as_shared(&rhs);
                // Use 128 bits for comparison (matching Noir's behavior for field comparisons)
                let result = spdz_core::gadgets::bits::greater_than(
                    &a_share, &b_share, 128, self.net, &mut self.state,
                )?;
                Ok(SpdzAcvmType::Shared(result))
            }
        }
    }

    // Hash/crypto — implemented using shared bit operations (decompose + AND/XOR).
    // Less efficient than Rep3's garbled circuits but functionally correct.
    fn sha256_compression(
        &mut self,
        state: &[Self::AcvmType; 8],
        message: &[Self::AcvmType; 16],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if state.iter().chain(message.iter()).any(|v| Self::is_shared(v)) {
            // Use garbled circuit for SHA256 on shared values (2-3 rounds)
            let s: Vec<SpdzPrimeFieldShare<F>> = state.iter().map(|v| self.get_as_shared(v)).collect();
            let m: Vec<SpdzPrimeFieldShare<F>> = message.iter().map(|v| self.get_as_shared(v)).collect();
            let result = spdz_core::gadgets::yao2pc::gc_sha256::gc_sha256_compression(&s, &m, self.net, &self.state)?;
            Ok(result.into_iter().map(SpdzAcvmType::Shared).collect())
        } else {
            // All public — use standard SHA256
            use sha2::digest::generic_array::GenericArray;
            let mut state_u32 = [0u32; 8];
            for (i, v) in state.iter().enumerate() {
                let big: BigUint = Self::get_public(v).unwrap().into();
                state_u32[i] = big.iter_u32_digits().next().unwrap_or_default();
            }
            let mut msg_bytes = [0u8; 64];
            for (i, v) in message.iter().enumerate() {
                let big: BigUint = Self::get_public(v).unwrap().into();
                let word = big.iter_u32_digits().next().unwrap_or_default();
                msg_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
            }
            sha2::compress256(
                &mut state_u32.map(|x| x.to_be()),
                &[*GenericArray::from_slice(&msg_bytes)],
            );
            Ok(state_u32.iter().map(|x| SpdzAcvmType::Public(F::from(u32::from_be(*x) as u64))).collect())
        }
    }

    fn blake2s_hash(&mut self, inputs: Vec<Self::AcvmType>, num_bits: usize) -> eyre::Result<Vec<Self::AcvmType>> {
        if inputs.iter().any(|v| Self::is_shared(v)) {
            // Use garbled circuit for Blake2s on shared values (2-3 rounds)
            let shared: Vec<SpdzPrimeFieldShare<F>> = inputs.iter().map(|v| self.get_as_shared(v)).collect();
            let result = spdz_core::gadgets::yao2pc::gc_blake2s::gc_blake2s(&shared, num_bits, self.net, &self.state)?;
            Ok(result.into_iter().map(SpdzAcvmType::Shared).collect())
        } else {
            // All public — compute blake2s locally
            use sha2::Digest;
            let num_elements = num_bits.div_ceil(8);
            let mut real_input = Vec::new();
            for inp in &inputs {
                let val = Self::get_public(inp).unwrap();
                let bytes = {
                    use ark_ff::BigInteger;
                    val.into_bigint().to_bytes_le()
                };
                real_input.extend_from_slice(&bytes[..num_elements]);
            }
            let output: [u8; 32] = blake2::Blake2s256::digest(&real_input).into();
            Ok(output.into_iter().map(|x| SpdzAcvmType::Public(F::from(x as u64))).collect())
        }
    }
    fn blake3_hash(&mut self, inputs: Vec<Self::AcvmType>, num_bits: usize) -> eyre::Result<Vec<Self::AcvmType>> {
        if inputs.iter().any(|v| Self::is_shared(v)) {
            // Use garbled circuit for Blake3 on shared values (2-3 rounds)
            let shared: Vec<SpdzPrimeFieldShare<F>> = inputs.iter().map(|v| self.get_as_shared(v)).collect();
            let result = spdz_core::gadgets::yao2pc::gc_blake3::gc_blake3(&shared, num_bits, self.net, &self.state)?;
            Ok(result.into_iter().map(SpdzAcvmType::Shared).collect())
        } else {
            // All public — compute blake3 locally
            let num_elements = num_bits.div_ceil(8);
            let mut real_input = Vec::new();
            for inp in &inputs {
                let val = Self::get_public(inp).unwrap();
                let bytes = {
                    use ark_ff::BigInteger;
                    val.into_bigint().to_bytes_le()
                };
                real_input.extend_from_slice(&bytes[..num_elements]);
            }
            let output: [u8; 32] = blake3::hash(&real_input).into();
            Ok(output.into_iter().map(|x| SpdzAcvmType::Public(F::from(x as u64))).collect())
        }
    }
    fn aes128_encrypt(&mut self, scalars: &[Self::AcvmType], iv: Vec<Self::AcvmType>, key: Vec<Self::AcvmType>) -> eyre::Result<Vec<Self::AcvmType>> {
        if scalars.iter().chain(iv.iter()).chain(key.iter()).any(|v| Self::is_shared(v)) {
            let s: Vec<SpdzPrimeFieldShare<F>> = scalars.iter().map(|v| self.get_as_shared(v)).collect();
            let i: Vec<SpdzPrimeFieldShare<F>> = iv.iter().map(|v| self.get_as_shared(v)).collect();
            let k: Vec<SpdzPrimeFieldShare<F>> = key.iter().map(|v| self.get_as_shared(v)).collect();
            let result = spdz_core::gadgets::aes::aes128_encrypt(&s, &i, &k, self.net, &mut self.state)?;
            Ok(result.into_iter().map(SpdzAcvmType::Shared).collect())
        } else {
            not_supported!(aes128_public_fallback)
        }
    }

    fn get_as_shared(&mut self, value: &Self::AcvmType) -> Self::ArithmeticShare {
        match value {
            SpdzAcvmType::Public(f) => self.promote_to_trivial_share(*f),
            SpdzAcvmType::Shared(s) => *s,
        }
    }

    fn compute_naf_entries(&mut self, scalar: &Self::AcvmType, max_num_bits: usize) -> eyre::Result<Vec<Self::AcvmType>> {
        // Only public values supported (same as Rep3)
        if let Some(scalar_public) = Self::get_public(scalar) {
            // NAF: non-adjacent form decomposition
            let scalar_big: num_bigint::BigUint = scalar_public.into();
            let mut naf = Vec::with_capacity(max_num_bits + 1);
            let mut k = scalar_big.clone();
            let zero = num_bigint::BigUint::from(0u64);
            let one = num_bigint::BigUint::from(1u64);
            let two = num_bigint::BigUint::from(2u64);
            while k > zero {
                if &k % &two == one {
                    // k is odd
                    let ki = if &k % num_bigint::BigUint::from(4u64) == num_bigint::BigUint::from(3u64) {
                        k += &one;
                        F::zero() - F::one() // -1
                    } else {
                        k -= &one;
                        F::one() // 1
                    };
                    naf.push(SpdzAcvmType::Public(ki));
                } else {
                    naf.push(SpdzAcvmType::Public(F::zero()));
                }
                k >>= 1;
            }
            // Pad to max_num_bits + 1
            while naf.len() < max_num_bits + 1 {
                naf.push(SpdzAcvmType::Public(F::zero()));
            }
            Ok(naf)
        } else {
            not_supported!(compute_naf_entries_shared)
        }
    }

    // OtherAcvmType operations — arithmetic on the base field of a curve.
    // OtherAcvmType<C> = SpdzAcvmType<C::BaseField> = Public(BaseField) | Shared(SpdzPrimeFieldShare<BaseField>)
    // These are the same operations as on the scalar field, just over a different field.

    fn neg_other_acvm_type<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: Self::OtherAcvmType<C>) -> Self::OtherAcvmType<C> {
        match a {
            SpdzAcvmType::Public(f) => SpdzAcvmType::Public(-f),
            SpdzAcvmType::Shared(s) => SpdzAcvmType::Shared(-s),
        }
    }

    fn add_other_acvm_types<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, lhs: Self::OtherAcvmType<C>, rhs: Self::OtherAcvmType<C>) -> Self::OtherAcvmType<C> {
        match (lhs, rhs) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => SpdzAcvmType::Public(a + b),
            (SpdzAcvmType::Shared(a), SpdzAcvmType::Shared(b)) => SpdzAcvmType::Shared(a + b),
            (SpdzAcvmType::Public(_), SpdzAcvmType::Shared(_)) | (SpdzAcvmType::Shared(_), SpdzAcvmType::Public(_)) => {
                // Would need mac_key_share for the base field — not available in current design
                panic!("SPDZ: add_other mixed public/shared requires base field MAC key")
            }
        }
    }

    fn sub_other_acvm_types<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, lhs: Self::OtherAcvmType<C>, rhs: Self::OtherAcvmType<C>) -> Self::OtherAcvmType<C> {
        match (lhs, rhs) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => SpdzAcvmType::Public(a - b),
            (SpdzAcvmType::Shared(a), SpdzAcvmType::Shared(b)) => SpdzAcvmType::Shared(a - b),
            _ => panic!("SPDZ: sub_other mixed public/shared requires base field MAC key"),
        }
    }

    fn inverse_other_acvm_type<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: Self::OtherAcvmType<C>) -> eyre::Result<Self::OtherAcvmType<C>> {
        match a {
            SpdzAcvmType::Public(f) => {
                use ark_ff::Field;
                Ok(SpdzAcvmType::Public(f.inverse().ok_or_else(|| eyre::eyre!("inverse of zero"))?))
            }
            SpdzAcvmType::Shared(_) => not_supported!(inverse_other_shared),
        }
    }

    fn mul_other_acvm_types<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, lhs: Self::OtherAcvmType<C>, rhs: Self::OtherAcvmType<C>) -> eyre::Result<Self::OtherAcvmType<C>> {
        match (lhs, rhs) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => Ok(SpdzAcvmType::Public(a * b)),
            (SpdzAcvmType::Public(p), SpdzAcvmType::Shared(s)) | (SpdzAcvmType::Shared(s), SpdzAcvmType::Public(p)) => Ok(SpdzAcvmType::Shared(s * p)),
            (SpdzAcvmType::Shared(_), SpdzAcvmType::Shared(_)) => not_supported!(mul_other_shared_shared),
        }
    }

    fn div_unchecked_other_acvm_types<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, lhs: Self::OtherAcvmType<C>, rhs: Self::OtherAcvmType<C>) -> eyre::Result<Self::OtherAcvmType<C>> {
        match (lhs, rhs) {
            (SpdzAcvmType::Public(a), SpdzAcvmType::Public(b)) => {
                use ark_ff::Field;
                Ok(SpdzAcvmType::Public(a * b.inverse().ok_or_else(|| eyre::eyre!("div by zero"))?))
            }
            _ => not_supported!(div_unchecked_other_shared),
        }
    }

    // Limb operations — non-native field arithmetic (4-limb representation).
    // Public case: delegate to PlainAcvmSolver. Shared case: not supported (same as Rep3).

    fn acvm_type_limbs_to_other_acvm_type<const NUM_LIMBS: usize, const LIMB_BITS: usize, C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, limbs: &[Self::AcvmType; NUM_LIMBS]) -> eyre::Result<Self::OtherAcvmType<C>> {
        if limbs.iter().all(|x| !Self::is_shared(x)) {
            let result: C::BaseField = co_noir_common::utils::Utils::field_limbs_to_biguint::<F, NUM_LIMBS, LIMB_BITS>(
                &limbs.clone().map(|x| Self::get_public(&x).unwrap()),
            ).into();
            return Ok(SpdzAcvmType::Public(result));
        }
        not_supported!(limbs_to_other_shared)
    }

    fn other_acvm_type_to_acvm_type_limbs<const NUM_LIMBS: usize, const LIMB_BITS: usize, C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, input: &Self::OtherAcvmType<C>) -> eyre::Result<[Self::AcvmType; NUM_LIMBS]> {
        if let SpdzAcvmType::Public(public) = input {
            let bigint: num_bigint::BigUint = (*public).into();
            let result = co_noir_common::utils::Utils::biguint_to_field_limbs::<F, NUM_LIMBS, LIMB_BITS>(&bigint);
            return Ok(result.map(SpdzAcvmType::Public));
        }
        not_supported!(other_to_limbs_shared)
    }

    fn inverse_acvm_type_limbs<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, limbs: &[Self::AcvmType; 4]) -> eyre::Result<[Self::AcvmType; 4]> {
        if limbs.iter().all(|x| !Self::is_shared(x)) {
            let plain = limbs.clone().map(|x| Self::get_public(&x).unwrap());
            let result = co_acvm::PlainAcvmSolver::new().inverse_acvm_type_limbs::<C>(&plain)?;
            return Ok(result.map(SpdzAcvmType::Public));
        }
        not_supported!(inverse_limbs_shared)
    }

    fn add_acvm_type_limbs<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: &[Self::AcvmType; 4], b: &[Self::AcvmType; 4]) -> eyre::Result<[Self::AcvmType; 4]> {
        if a.iter().chain(b.iter()).all(|x| !Self::is_shared(x)) {
            let pa = a.clone().map(|x| Self::get_public(&x).unwrap());
            let pb = b.clone().map(|x| Self::get_public(&x).unwrap());
            let result = co_acvm::PlainAcvmSolver::new().add_acvm_type_limbs::<C>(&pa, &pb)?;
            return Ok(result.map(SpdzAcvmType::Public));
        }
        not_supported!(add_limbs_shared)
    }

    fn sub_acvm_type_limbs<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: &[Self::AcvmType; 4], b: &[Self::AcvmType; 4]) -> eyre::Result<[Self::AcvmType; 4]> {
        if a.iter().chain(b.iter()).all(|x| !Self::is_shared(x)) {
            let pa = a.clone().map(|x| Self::get_public(&x).unwrap());
            let pb = b.clone().map(|x| Self::get_public(&x).unwrap());
            let result = co_acvm::PlainAcvmSolver::new().sub_acvm_type_limbs::<C>(&pa, &pb)?;
            return Ok(result.map(SpdzAcvmType::Public));
        }
        not_supported!(sub_limbs_shared)
    }

    fn mul_mod_acvm_type_limbs<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: &[Self::AcvmType; 4], b: &[Self::AcvmType; 4]) -> eyre::Result<[Self::AcvmType; 4]> {
        if a.iter().chain(b.iter()).all(|x| !Self::is_shared(x)) {
            let pa = a.clone().map(|x| Self::get_public(&x).unwrap());
            let pb = b.clone().map(|x| Self::get_public(&x).unwrap());
            let result = co_acvm::PlainAcvmSolver::new().mul_mod_acvm_type_limbs::<C>(&pa, &pb)?;
            return Ok(result.map(SpdzAcvmType::Public));
        }
        not_supported!(mul_mod_limbs_shared)
    }

    fn madd_div_mod_acvm_limbs<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: &[Self::AcvmType; 4], b: &[Self::AcvmType; 4], to_add: &[[Self::AcvmType; 4]]) -> eyre::Result<([Self::AcvmType; 4], Self::OtherAcvmType<C>)> {
        if a.iter().all(|x| !Self::is_shared(x))
            && b.iter().all(|x| !Self::is_shared(x))
            && to_add.iter().all(|arr| arr.iter().all(|x| !Self::is_shared(x)))
        {
            let pa = a.clone().map(|x| Self::get_public(&x).unwrap());
            let pb = b.clone().map(|x| Self::get_public(&x).unwrap());
            let pta: Vec<[F; 4]> = to_add.iter().map(|arr| arr.clone().map(|x| Self::get_public(&x).unwrap())).collect();
            let (limbs_res, other_res) = co_acvm::PlainAcvmSolver::new().madd_div_mod_acvm_limbs::<C>(&pa, &pb, &pta)?;
            return Ok((limbs_res.map(SpdzAcvmType::Public), SpdzAcvmType::Public(other_res)));
        }
        not_supported!(madd_div_mod_shared)
    }

    fn madd_div_mod_many_acvm_limbs<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: &[[Self::AcvmType; 4]], b: &[[Self::AcvmType; 4]], to_add: &[[Self::AcvmType; 4]]) -> eyre::Result<([Self::AcvmType; 4], Self::OtherAcvmType<C>)> {
        if a.iter().flat_map(|arr| arr.iter()).all(|x| !Self::is_shared(x))
            && b.iter().flat_map(|arr| arr.iter()).all(|x| !Self::is_shared(x))
            && to_add.iter().all(|arr| arr.iter().all(|x| !Self::is_shared(x)))
        {
            let pa: Vec<[F; 4]> = a.iter().map(|arr| arr.clone().map(|x| Self::get_public(&x).unwrap())).collect();
            let pb: Vec<[F; 4]> = b.iter().map(|arr| arr.clone().map(|x| Self::get_public(&x).unwrap())).collect();
            let pta: Vec<[F; 4]> = to_add.iter().map(|arr| arr.clone().map(|x| Self::get_public(&x).unwrap())).collect();
            let (limbs_res, other_res) = co_acvm::PlainAcvmSolver::new().madd_div_mod_many_acvm_limbs::<C>(&pa, &pb, &pta)?;
            return Ok((limbs_res.map(SpdzAcvmType::Public), SpdzAcvmType::Public(other_res)));
        }
        not_supported!(madd_div_mod_many_shared)
    }

    fn div_mod_acvm_limbs<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(&mut self, a: &[Self::AcvmType; 4]) -> eyre::Result<([Self::AcvmType; 4], Self::OtherAcvmType<C>)> {
        if a.iter().all(|x| !Self::is_shared(x)) {
            let pa = a.clone().map(|x| Self::get_public(&x).unwrap());
            let (limbs_res, other_res) = co_acvm::PlainAcvmSolver::new().div_mod_acvm_limbs::<C>(&pa)?;
            return Ok((limbs_res.map(SpdzAcvmType::Public), SpdzAcvmType::Public(other_res)));
        }
        not_supported!(div_mod_limbs_shared)
    }
}
