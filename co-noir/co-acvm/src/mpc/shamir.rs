use super::{plain::PlainAcvmSolver, NoirWitnessExtensionProtocol};
use ark_ff::{One, PrimeField};
use co_brillig::mpc::{ShamirBrilligDriver, ShamirBrilligType};
use mpc_core::{
    gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations},
    protocols::{
        rep3::network::Rep3MpcNet,
        rep3_ring::lut::Rep3LookupTable,
        shamir::{arithmetic, network::ShamirNetwork, ShamirPrimeFieldShare, ShamirProtocol},
    },
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{array, marker::PhantomData};

pub struct ShamirAcvmSolver<F: PrimeField, N: ShamirNetwork> {
    protocol: ShamirProtocol<F, N>,
    plain_solver: PlainAcvmSolver<F>,
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirAcvmSolver<F, N> {
    pub fn new(protocol: ShamirProtocol<F, N>) -> Self {
        let plain_solver = PlainAcvmSolver::<F>::default();
        Self {
            protocol,
            plain_solver,
            phantom_data: PhantomData,
        }
    }

    pub fn into_network(self) -> N {
        self.protocol.network
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum ShamirAcvmType<F: PrimeField> {
    Public(
        #[serde(
            serialize_with = "mpc_core::ark_se",
            deserialize_with = "mpc_core::ark_de"
        )]
        F,
    ),
    Shared(
        #[serde(
            serialize_with = "mpc_core::ark_se",
            deserialize_with = "mpc_core::ark_de"
        )]
        ShamirPrimeFieldShare<F>,
    ),
}

impl<F: PrimeField> std::fmt::Debug for ShamirAcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Shared(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for ShamirAcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.write_str(&format!("Public ({field})")),
            Self::Shared(arithmetic) => {
                f.write_str(&format!("Arithmetic ({})", arithmetic.inner()))
            }
        }
    }
}

impl<F: PrimeField> Default for ShamirAcvmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

impl<F: PrimeField> From<F> for ShamirAcvmType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<ShamirPrimeFieldShare<F>> for ShamirAcvmType<F> {
    fn from(value: ShamirPrimeFieldShare<F>) -> Self {
        Self::Shared(value)
    }
}

impl<F: PrimeField> From<ShamirAcvmType<F>> for ShamirBrilligType<F> {
    fn from(val: ShamirAcvmType<F>) -> Self {
        match val {
            ShamirAcvmType::Public(public) => ShamirBrilligType::from(public),
            ShamirAcvmType::Shared(share) => ShamirBrilligType::Shared(share),
        }
    }
}

impl<F: PrimeField> From<ShamirBrilligType<F>> for ShamirAcvmType<F> {
    fn from(value: ShamirBrilligType<F>) -> Self {
        match value {
            ShamirBrilligType::Public(public) => ShamirAcvmType::Public(public.into_field()),
            ShamirBrilligType::Shared(shared) => ShamirAcvmType::Shared(shared),
        }
    }
}

impl<F: PrimeField, N: ShamirNetwork> NoirWitnessExtensionProtocol<F> for ShamirAcvmSolver<F, N> {
    type Lookup = Rep3LookupTable<Rep3MpcNet>; // This is just a dummy and unused

    type ArithmeticShare = ShamirPrimeFieldShare<F>;

    type AcvmType = ShamirAcvmType<F>;

    type BrilligDriver = ShamirBrilligDriver<F, N>;

    fn init_brillig_driver(&mut self) -> std::io::Result<Self::BrilligDriver> {
        Ok(ShamirBrilligDriver::with_protocol(
            self.protocol.fork_with_pairs(0)?, // TODO maybe have some pairs here
        ))
    }

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<ShamirBrilligType<F>>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        Ok(brillig_result
            .into_iter()
            .map(ShamirAcvmType::from)
            .collect())
    }

    fn public_zero() -> Self::AcvmType {
        Self::AcvmType::default()
    }

    fn shared_zeros(&mut self, len: usize) -> std::io::Result<Vec<Self::AcvmType>> {
        // TODO: This is not the best implementaiton for shared zeros
        let trivial_zeros = vec![F::zero(); len];
        let res = self.protocol.degree_reduce_vec(trivial_zeros)?;
        Ok(res.into_iter().map(ShamirAcvmType::from).collect())
    }

    fn is_public_zero(a: &Self::AcvmType) -> bool {
        if let ShamirAcvmType::Public(x) = a {
            x.is_zero()
        } else {
            false
        }
    }

    fn is_public_one(a: &Self::AcvmType) -> bool {
        if let ShamirAcvmType::Public(x) = a {
            x.is_one()
        } else {
            false
        }
    }

    fn cmux(
        &mut self,
        cond: Self::AcvmType,
        truthy: Self::AcvmType,
        falsy: Self::AcvmType,
    ) -> std::io::Result<Self::AcvmType> {
        match (cond, truthy, falsy) {
            (ShamirAcvmType::Public(cond), truthy, falsy) => {
                assert!(cond.is_one() || cond.is_zero());
                if cond.is_one() {
                    Ok(truthy)
                } else {
                    Ok(falsy)
                }
            }
            (ShamirAcvmType::Shared(cond), truthy, falsy) => {
                let b_min_a = self.sub(truthy, falsy.clone());
                let d = self.mul(cond.into(), b_min_a)?;
                Ok(self.add(falsy, d))
            }
        }
    }

    fn add_assign_with_public(&mut self, public: F, target: &mut Self::AcvmType) {
        let result = match target.to_owned() {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public + secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::add_public(secret, public))
            }
        };
        *target = result;
    }

    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs + rhs)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                let result = arithmetic::add(lhs, rhs);
                ShamirAcvmType::Shared(result)
            }
        }
    }

    fn sub(&mut self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType {
        match (share_1, share_2) {
            (ShamirAcvmType::Public(share_1), ShamirAcvmType::Public(share_2)) => {
                ShamirAcvmType::Public(share_1 - share_2)
            }
            (ShamirAcvmType::Public(share_1), ShamirAcvmType::Shared(share_2)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(-share_2, share_1))
            }
            (ShamirAcvmType::Shared(share_1), ShamirAcvmType::Public(share_2)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(share_1, -share_2))
            }
            (ShamirAcvmType::Shared(share_1), ShamirAcvmType::Shared(share_2)) => {
                let result = arithmetic::sub(share_1, share_2);
                ShamirAcvmType::Shared(result)
            }
        }
    }

    fn mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType {
        match secret {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public * secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::mul_public(secret, public))
            }
        }
    }

    fn mul(
        &mut self,
        secret_1: Self::AcvmType,
        secret_2: Self::AcvmType,
    ) -> std::io::Result<Self::AcvmType> {
        match (secret_1, secret_2) {
            (ShamirAcvmType::Public(secret_1), ShamirAcvmType::Public(secret_2)) => {
                Ok(ShamirAcvmType::Public(secret_1 * secret_2))
            }
            (ShamirAcvmType::Public(secret_1), ShamirAcvmType::Shared(secret_2)) => Ok(
                ShamirAcvmType::Shared(arithmetic::mul_public(secret_2, secret_1)),
            ),
            (ShamirAcvmType::Shared(secret_1), ShamirAcvmType::Public(secret_2)) => Ok(
                ShamirAcvmType::Shared(arithmetic::mul_public(secret_1, secret_2)),
            ),
            (ShamirAcvmType::Shared(secret_1), ShamirAcvmType::Shared(secret_2)) => {
                let result = arithmetic::mul(secret_1, secret_2, &mut self.protocol)?;
                Ok(ShamirAcvmType::Shared(result))
            }
        }
    }

    fn negate_inplace(&mut self, a: &mut Self::AcvmType) {
        match a {
            ShamirAcvmType::Public(public) => {
                public.neg_in_place();
            }
            ShamirAcvmType::Shared(shared) => *shared = arithmetic::neg(*shared),
        }
    }

    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, target: &mut Self::AcvmType) {
        let result = match (w_l, target.to_owned()) {
            (ShamirAcvmType::Public(w_l), ShamirAcvmType::Public(result)) => {
                ShamirAcvmType::Public(q_l * w_l + result)
            }
            (ShamirAcvmType::Public(w_l), ShamirAcvmType::Shared(result)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(result, q_l * w_l))
            }
            (ShamirAcvmType::Shared(w_l), ShamirAcvmType::Public(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                ShamirAcvmType::Shared(arithmetic::add_public(mul, result))
            }
            (ShamirAcvmType::Shared(w_l), ShamirAcvmType::Shared(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                ShamirAcvmType::Shared(arithmetic::add(mul, result))
            }
        };
        *target = result;
    }

    fn add_assign(&mut self, target: &mut Self::AcvmType, rhs: Self::AcvmType) {
        let result = match (target.clone(), rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs + rhs)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                ShamirAcvmType::Shared(arithmetic::add(lhs, rhs))
            }
        };
        *target = result;
    }

    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
    ) -> std::io::Result<Self::AcvmType> {
        let result = match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs * rhs * c)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::mul_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                let shared_mul = arithmetic::mul(lhs, rhs, &mut self.protocol)?;
                ShamirAcvmType::Shared(arithmetic::mul_public(shared_mul, c))
            }
        };
        Ok(result)
    }

    fn solve_equation(
        &mut self,
        q_l: Self::AcvmType,
        c: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        //-c/q_l
        let result = match (q_l, c) {
            (ShamirAcvmType::Public(q_l), ShamirAcvmType::Public(c)) => {
                ShamirAcvmType::Public(self.plain_solver.solve_equation(q_l, c)?)
            }
            (ShamirAcvmType::Public(q_l), ShamirAcvmType::Shared(c)) => {
                ShamirAcvmType::Shared(arithmetic::div_shared_by_public(arithmetic::neg(c), q_l)?)
            }
            (ShamirAcvmType::Shared(q_l), ShamirAcvmType::Public(c)) => {
                let result = arithmetic::div_public_by_shared(-c, q_l, &mut self.protocol)?;
                ShamirAcvmType::Shared(result)
            }
            (ShamirAcvmType::Shared(q_l), ShamirAcvmType::Shared(c)) => {
                let result = arithmetic::div(arithmetic::neg(c), q_l, &mut self.protocol)?;
                ShamirAcvmType::Shared(result)
            }
        };
        Ok(result)
    }

    fn init_lut_by_acvm_type(
        &mut self,
        _values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType {
        panic!("init_lut_by_acvm_type: Operation atm not supported")
    }

    fn read_lut_by_acvm_type(
        &mut self,
        _index: Self::AcvmType,
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> std::io::Result<Self::AcvmType> {
        panic!("read_lut_by_acvm_type: Operation atm not supported")
    }

    fn write_lut_by_acvm_type(
        &mut self,
        _index: Self::AcvmType,
        _value: Self::AcvmType,
        _lut: &mut <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> std::io::Result<()> {
        panic!("write_lut_by_acvm_type: Operation atm not supported")
    }

    fn one_hot_vector_from_shared_index(
        &mut self,
        _index: Self::ArithmeticShare,
        _len: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        panic!("one_hot_vector_from_shared_index: Operation atm not supported")
    }

    fn write_to_shared_lut_from_ohv(
        &mut self,
        _ohv: &[Self::ArithmeticShare],
        _value: Self::ArithmeticShare,
        _lut: &mut [Self::ArithmeticShare],
    ) -> std::io::Result<()> {
        panic!("write_to_shared_lut_from_ohv: Operation atm not supported")
    }

    fn get_length_of_lut(
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> usize {
        panic!("get_length_of_lut: Operation atm not supported")
    }

    fn is_shared(a: &Self::AcvmType) -> bool {
        matches!(a, ShamirAcvmType::Shared(_))
    }

    fn get_shared(a: &Self::AcvmType) -> Option<Self::ArithmeticShare> {
        match a {
            ShamirAcvmType::Shared(shared) => Some(*shared),
            _ => None,
        }
    }

    fn get_public(a: &Self::AcvmType) -> Option<F> {
        match a {
            ShamirAcvmType::Public(public) => Some(*public),
            _ => None,
        }
    }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> std::io::Result<Vec<F>> {
        arithmetic::open_vec(a, &mut self.protocol)
    }

    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(public_value)
    }

    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare> {
        arithmetic::promote_to_trivial_shares(public_values)
    }

    fn decompose_arithmetic(
        &mut self,
        _input: Self::ArithmeticShare,
        _total_bit_size_per_field: usize,
        _decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        panic!("functionality decompose_arithmetic not feasible for Shamir")
    }
    fn decompose_arithmetic_many(
        &mut self,
        _input: &[Self::ArithmeticShare],
        _total_bit_size_per_field: usize,
        _decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>> {
        panic!("functionality decompose_arithmetic_many not feasible for Shamir")
    }

    fn sort(
        &mut self,
        _inputs: &[Self::AcvmType],
        _bitsize: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        panic!("functionality sort not feasible for Shamir")
    }

    fn slice(
        &mut self,
        _input: Self::ArithmeticShare,
        _msb: u8,
        _lsb: u8,
        _bitsize: usize,
    ) -> std::io::Result<[Self::ArithmeticShare; 3]> {
        panic!("functionality slice not feasible for Shamir")
    }

    fn integer_bitwise_and(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> std::io::Result<Self::AcvmType> {
        debug_assert!(num_bits <= 128);
        let mask = (BigUint::one() << num_bits) - BigUint::one();
        match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                let lhs: BigUint = lhs.into();
                let rhs: BigUint = rhs.into();
                let res = (lhs & rhs) & mask;
                let res = F::from(res);
                Ok(ShamirAcvmType::Public(res))
            }
            _ => panic!("functionality bitwise_and not feasible for Shamir"),
        }
    }

    fn integer_bitwise_xor(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> std::io::Result<Self::AcvmType> {
        debug_assert!(num_bits <= 128);
        let mask = (BigUint::one() << num_bits) - BigUint::one();
        match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                let lhs: BigUint = lhs.into();
                let rhs: BigUint = rhs.into();
                let res = (lhs ^ rhs) & mask;
                let res = F::from(res);
                Ok(ShamirAcvmType::Public(res))
            }
            _ => panic!("functionality bitwise_xor not feasible for Shamir"),
        }
    }

    fn slice_and_get_and_rotate_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: usize,
        _total_bitsize: usize,
        _rotation: usize,
    ) -> std::io::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!("functionality slice_and_get_and_rotate_values not feasible for Shamir")
    }

    fn slice_and_get_xor_rotate_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: usize,
        _total_bitsize: usize,
        _rotation: usize,
    ) -> std::io::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!("functionality slice_and_get_xor_rotate_values not feasible for Shamir")
    }

    fn sort_vec_by(
        &mut self,
        _key: &[Self::AcvmType],
        _inputs: Vec<&[Self::AcvmType]>,
        _bitsize: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>> {
        panic!("functionality sort_vec_by not feasible for Shamir")
    }

    fn poseidon2_permutation<const T: usize, const D: u64>(
        &mut self,
        mut input: Vec<Self::AcvmType>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<Vec<Self::AcvmType>> {
        if input.len() != T {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Expected {} values but encountered {}", T, input.len(),),
            ));
        }

        if input.iter().any(|x| Self::is_shared(x)) {
            let mut shared = array::from_fn(|i| match input[i] {
                ShamirAcvmType::Public(public) => {
                    // The initial linear layer of poseidon makes the whole state shared anyway
                    arithmetic::promote_to_trivial_share(public)
                }
                ShamirAcvmType::Shared(shared) => shared,
            });
            poseidon2
                .shamir_permutation_in_place_with_precomputation(&mut shared, &mut self.protocol)?;

            for (src, des) in shared.into_iter().zip(input.iter_mut()) {
                *des = ShamirAcvmType::Shared(src);
            }
        } else {
            let mut public = array::from_fn(|i| Self::get_public(&input[i]).unwrap());
            poseidon2.permutation_in_place(&mut public);

            for (src, des) in public.into_iter().zip(input.iter_mut()) {
                *des = ShamirAcvmType::Public(src);
            }
        }

        Ok(input)
    }

    fn poseidon2_matmul_external_inplace<const T: usize, const D: u64>(
        &self,
        input: &mut [Self::ArithmeticShare; T],
    ) {
        Poseidon2::<F, T, D>::matmul_external_shamir(input);
    }

    fn poseidon2_preprocess_permutation<const T: usize, const D: u64>(
        &mut self,
        num_poseidon: usize,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<Poseidon2Precomputations<Self::ArithmeticShare>> {
        // Prepare enough randomness
        self.protocol
            .buffer_triples(poseidon2.rand_required(num_poseidon, true))?;
        poseidon2.precompute_shamir(num_poseidon, &mut self.protocol)
    }

    fn poseidon2_external_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<()> {
        poseidon2.shamir_external_round_precomp(input, r, precomp, &mut self.protocol)
    }

    fn poseidon2_internal_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<()> {
        poseidon2.shamir_internal_round_precomp(input, r, precomp, &mut self.protocol)
    }

    fn get_public_lut(
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> std::io::Result<&Vec<F>> {
        panic!("functionality get_public_lut not feasible for Shamir")
    }

    fn is_public_lut(
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> bool {
        panic!("functionality is_public_lut not feasible for Shamir")
    }

    fn equal(
        &mut self,
        _a: &Self::AcvmType,
        _b: &Self::AcvmType,
    ) -> std::io::Result<Self::AcvmType> {
        panic!("functionality equal not feasible for Shamir")
    }
}
