use ark_ff::{One, PrimeField};
use co_brillig::mpc::{Rep3BrilligDriver, Rep3BrilligType};
use itertools::{izip, Itertools};
use mpc_core::protocols::rep3::{arithmetic, binary, conversion, yao};
use mpc_core::protocols::rep3_ring::gadgets::sort::radix_sort_fields;
use mpc_core::{
    lut::LookupTableProvider,
    protocols::rep3::{
        lut::Rep3LookupTable,
        network::{IoContext, Rep3Network},
        Rep3PrimeFieldShare,
    },
};
use num_bigint::BigUint;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::plain::PlainAcvmSolver;
use super::NoirWitnessExtensionProtocol;
type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;

macro_rules! join {
    ($t1: expr, $t2: expr) => {{
        std::thread::scope(|s| {
            let t1 = s.spawn(|| $t1);
            let t2 = $t2;
            (t1.join().expect("can join"), t2)
        })
    }};
}

pub struct Rep3AcvmSolver<F: PrimeField, N: Rep3Network> {
    lut_provider: Rep3LookupTable<N>,
    io_context0: IoContext<N>,
    io_context1: IoContext<N>,
    plain_solver: PlainAcvmSolver<F>,
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField, N: Rep3Network> Rep3AcvmSolver<F, N> {
    // TODO remove unwrap
    pub fn new(network: N) -> Self {
        let plain_solver = PlainAcvmSolver::<F>::default();
        let mut io_context = IoContext::init(network).unwrap();
        let forked = io_context.fork().unwrap();
        let forked2 = io_context.fork().unwrap();
        Self {
            lut_provider: Rep3LookupTable::new(forked),
            io_context0: io_context,
            io_context1: forked2,
            plain_solver,
            phantom_data: PhantomData,
        }
    }

    pub fn into_io_contexts(self) -> (IoContext<N>, IoContext<N>) {
        (self.io_context0, self.io_context1)
    }
}

// TODO maybe we want to merge that with the Rep3VmType?? Atm we do not need
// binary shares so maybe it is ok..
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum Rep3AcvmType<F: PrimeField> {
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
        ArithmeticShare<F>,
    ),
}

impl<F: PrimeField> std::fmt::Debug for Rep3AcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Shared(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for Rep3AcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.write_str(&format!("Public ({field})")),
            Self::Shared(arithmetic) => {
                let (a, b) = arithmetic.ab();
                f.write_str(&format!("Arithmetic (a: {}, b: {})", a, b))
            }
        }
    }
}

impl<F: PrimeField> Default for Rep3AcvmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

impl<F: PrimeField> From<F> for Rep3AcvmType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<ArithmeticShare<F>> for Rep3AcvmType<F> {
    fn from(value: ArithmeticShare<F>) -> Self {
        Self::Shared(value)
    }
}

impl<F: PrimeField> From<Rep3AcvmType<F>> for Rep3BrilligType<F> {
    fn from(val: Rep3AcvmType<F>) -> Self {
        match val {
            Rep3AcvmType::Public(public) => Rep3BrilligType::public_field(public),
            Rep3AcvmType::Shared(share) => Rep3BrilligType::shared_field(share),
        }
    }
}

impl<F: PrimeField> Rep3AcvmType<F> {
    fn from_brillig_type<N: Rep3Network>(
        value: Rep3BrilligType<F>,
        io_context: &mut IoContext<N>,
    ) -> eyre::Result<Self> {
        match value {
            Rep3BrilligType::Public(public) => Ok(Rep3AcvmType::Public(public.into_field())),
            Rep3BrilligType::Shared(shared) => {
                let shared = Rep3BrilligType::into_arithmetic_share(io_context, shared)?;
                Ok(Rep3AcvmType::Shared(shared))
            }
        }
    }
}

impl<F: PrimeField, N: Rep3Network> NoirWitnessExtensionProtocol<F> for Rep3AcvmSolver<F, N> {
    type Lookup = Rep3LookupTable<N>;

    type ArithmeticShare = Rep3PrimeFieldShare<F>;

    type AcvmType = Rep3AcvmType<F>;

    type BrilligDriver = Rep3BrilligDriver<F, N>;

    fn init_brillig_driver(&mut self) -> std::io::Result<Self::BrilligDriver> {
        Ok(Rep3BrilligDriver::with_io_context(self.io_context0.fork()?))
    }

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<Rep3BrilligType<F>>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        brillig_result
            .into_iter()
            .map(|value| Rep3AcvmType::from_brillig_type(value, &mut self.io_context0))
            .collect()
    }

    fn cmux(
        &mut self,
        cond: Self::AcvmType,
        truthy: Self::AcvmType,
        falsy: Self::AcvmType,
    ) -> std::io::Result<Self::AcvmType> {
        match (cond, truthy, falsy) {
            (Rep3AcvmType::Public(cond), truthy, falsy) => {
                assert!(cond.is_one() || cond.is_zero());
                if cond.is_one() {
                    Ok(truthy)
                } else {
                    Ok(falsy)
                }
            }
            (Rep3AcvmType::Shared(cond), truthy, falsy) => {
                let b_min_a = self.sub(truthy, falsy.clone());
                let d = self.mul(cond.into(), b_min_a)?;
                Ok(self.add(falsy, d))
            }
        }
    }

    fn shared_zeros(&mut self, len: usize) -> std::io::Result<Vec<Self::AcvmType>> {
        let a = (0..len)
            .map(|_| self.io_context0.masking_field_element())
            .collect::<Vec<_>>();
        let b = self.io_context0.network.reshare_many(&a)?;
        let result = izip!(a, b)
            .map(|(a, b)| Rep3AcvmType::Shared(Rep3PrimeFieldShare::new(a, b)))
            .collect();
        Ok(result)
    }

    fn is_public_zero(a: &Self::AcvmType) -> bool {
        if let Rep3AcvmType::Public(x) = a {
            x.is_zero()
        } else {
            false
        }
    }

    fn is_public_one(a: &Self::AcvmType) -> bool {
        if let Rep3AcvmType::Public(x) = a {
            x.is_one()
        } else {
            false
        }
    }

    fn add_assign_with_public(&mut self, public: F, target: &mut Self::AcvmType) {
        let id = self.io_context0.id;
        let result = match target.to_owned() {
            Rep3AcvmType::Public(secret) => Rep3AcvmType::Public(public + secret),
            Rep3AcvmType::Shared(secret) => {
                Rep3AcvmType::Shared(arithmetic::add_public(secret, public, id))
            }
        };
        *target = result;
    }

    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        let id = self.io_context0.id;
        match (lhs, rhs) {
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                Rep3AcvmType::Public(lhs + rhs)
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(shared, public, id))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let result = arithmetic::add(lhs, rhs);
                Rep3AcvmType::Shared(result)
            }
        }
    }

    fn sub(&mut self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType {
        let id = self.io_context0.id;

        match (share_1, share_2) {
            (Rep3AcvmType::Public(share_1), Rep3AcvmType::Public(share_2)) => {
                Rep3AcvmType::Public(share_1 - share_2)
            }
            (Rep3AcvmType::Public(share_1), Rep3AcvmType::Shared(share_2)) => {
                Rep3AcvmType::Shared(arithmetic::sub_public_by_shared(share_1, share_2, id))
            }
            (Rep3AcvmType::Shared(share_1), Rep3AcvmType::Public(share_2)) => {
                Rep3AcvmType::Shared(arithmetic::sub_shared_by_public(share_1, share_2, id))
            }
            (Rep3AcvmType::Shared(share_1), Rep3AcvmType::Shared(share_2)) => {
                let result = arithmetic::sub(share_1, share_2);
                Rep3AcvmType::Shared(result)
            }
        }
    }

    fn mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType {
        match secret {
            Rep3AcvmType::Public(secret) => Rep3AcvmType::Public(public * secret),
            Rep3AcvmType::Shared(secret) => {
                Rep3AcvmType::Shared(arithmetic::mul_public(secret, public))
            }
        }
    }

    fn mul(
        &mut self,
        secret_1: Self::AcvmType,
        secret_2: Self::AcvmType,
    ) -> std::io::Result<Self::AcvmType> {
        match (secret_1, secret_2) {
            (Rep3AcvmType::Public(secret_1), Rep3AcvmType::Public(secret_2)) => {
                Ok(Rep3AcvmType::Public(secret_1 * secret_2))
            }
            (Rep3AcvmType::Public(secret_1), Rep3AcvmType::Shared(secret_2)) => Ok(
                Rep3AcvmType::Shared(arithmetic::mul_public(secret_2, secret_1)),
            ),
            (Rep3AcvmType::Shared(secret_1), Rep3AcvmType::Public(secret_2)) => Ok(
                Rep3AcvmType::Shared(arithmetic::mul_public(secret_1, secret_2)),
            ),
            (Rep3AcvmType::Shared(secret_1), Rep3AcvmType::Shared(secret_2)) => {
                let result = arithmetic::mul(secret_1, secret_2, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
        }
    }

    fn negate_inplace(&mut self, a: &mut Self::AcvmType) {
        match a {
            Rep3AcvmType::Public(public) => {
                public.neg_in_place();
            }
            Rep3AcvmType::Shared(shared) => *shared = arithmetic::neg(*shared),
        }
    }

    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, target: &mut Self::AcvmType) {
        let id = self.io_context0.id;
        let result = match (w_l, target.to_owned()) {
            (Rep3AcvmType::Public(w_l), Rep3AcvmType::Public(result)) => {
                Rep3AcvmType::Public(q_l * w_l + result)
            }
            (Rep3AcvmType::Public(w_l), Rep3AcvmType::Shared(result)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(result, q_l * w_l, id))
            }
            (Rep3AcvmType::Shared(w_l), Rep3AcvmType::Public(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                Rep3AcvmType::Shared(arithmetic::add_public(mul, result, id))
            }
            (Rep3AcvmType::Shared(w_l), Rep3AcvmType::Shared(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                Rep3AcvmType::Shared(arithmetic::add(mul, result))
            }
        };
        *target = result;
    }

    fn add_assign(&mut self, target: &mut Self::AcvmType, rhs: Self::AcvmType) {
        let id = self.io_context0.id;
        let result = match (target.clone(), rhs) {
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                Rep3AcvmType::Public(lhs + rhs)
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(shared, public, id))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                Rep3AcvmType::Shared(arithmetic::add(lhs, rhs))
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
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                Rep3AcvmType::Public(lhs * rhs * c)
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                let mul = arithmetic::mul_public(shared, public);
                Rep3AcvmType::Shared(arithmetic::mul_public(mul, c))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let shared_mul = arithmetic::mul(lhs, rhs, &mut self.io_context0)?;
                Rep3AcvmType::Shared(arithmetic::mul_public(shared_mul, c))
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
        let io_context = &mut self.io_context0;
        let result = match (q_l, c) {
            (Rep3AcvmType::Public(q_l), Rep3AcvmType::Public(c)) => {
                Rep3AcvmType::Public(self.plain_solver.solve_equation(q_l, c)?)
            }
            (Rep3AcvmType::Public(q_l), Rep3AcvmType::Shared(c)) => {
                Rep3AcvmType::Shared(arithmetic::div_shared_by_public(arithmetic::neg(c), q_l)?)
            }
            (Rep3AcvmType::Shared(q_l), Rep3AcvmType::Public(c)) => {
                let result = arithmetic::div_public_by_shared(-c, q_l, io_context)?;
                Rep3AcvmType::Shared(result)
            }
            (Rep3AcvmType::Shared(q_l), Rep3AcvmType::Shared(c)) => {
                let result = arithmetic::div(arithmetic::neg(c), q_l, io_context)?;
                Rep3AcvmType::Shared(result)
            }
        };
        Ok(result)
    }

    fn init_lut_by_acvm_type(
        &mut self,
        values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType {
        let id = self.io_context0.id;

        if values.iter().any(|v| Self::is_shared(v)) {
            let mut shares = Vec::with_capacity(values.len());
            for val in values {
                shares.push(match val {
                    Rep3AcvmType::Public(public) => {
                        arithmetic::promote_to_trivial_share(id, public)
                    }
                    Rep3AcvmType::Shared(shared) => shared,
                });
            }
            self.lut_provider.init_private(shares)
        } else {
            let mut public = Vec::with_capacity(values.len());
            for val in values {
                public.push(Self::get_public(&val).expect("Already checked it is public"));
            }
            self.lut_provider.init_public(public)
        }
    }

    fn read_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> std::io::Result<Self::AcvmType> {
        let result = match index {
            Rep3AcvmType::Public(public) => {
                let index: BigUint = public.into();
                let index = usize::try_from(index).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Index can not be translated to usize",
                    )
                })?;

                match lut {
                    mpc_core::protocols::rep3::lut::PublicPrivateLut::Public(vec) => {
                        Self::AcvmType::from(vec[index].to_owned())
                    }
                    mpc_core::protocols::rep3::lut::PublicPrivateLut::Shared(vec) => {
                        Self::AcvmType::from(vec[index].to_owned())
                    }
                }
            }
            Rep3AcvmType::Shared(shared) => {
                Self::AcvmType::from(self.lut_provider.get_from_lut(shared, lut)?)
            }
        };
        Ok(result)
    }

    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        lut: &mut <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> std::io::Result<()> {
        let id = self.io_context0.id;
        match (index, value) {
            (Rep3AcvmType::Public(index), Rep3AcvmType::Public(value)) => {
                let index: BigUint = (index).into();
                let index = usize::try_from(index).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Index can not be translated to usize",
                    )
                })?;

                match lut {
                    mpc_core::protocols::rep3::lut::PublicPrivateLut::Public(vec) => {
                        vec[index] = value;
                    }
                    mpc_core::protocols::rep3::lut::PublicPrivateLut::Shared(vec) => {
                        vec[index] = arithmetic::promote_to_trivial_share(id, value);
                    }
                }
            }
            (Rep3AcvmType::Public(index), Rep3AcvmType::Shared(value)) => {
                let index: BigUint = (index).into();
                let index = usize::try_from(index).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Index can not be translated to usize",
                    )
                })?;

                match lut {
                    mpc_core::protocols::rep3::lut::PublicPrivateLut::Public(vec) => {
                        let mut vec = vec
                            .iter()
                            .map(|value| arithmetic::promote_to_trivial_share(id, *value))
                            .collect::<Vec<_>>();
                        vec[index] = value;
                        *lut = mpc_core::protocols::rep3::lut::PublicPrivateLut::Shared(vec);
                    }
                    mpc_core::protocols::rep3::lut::PublicPrivateLut::Shared(vec) => {
                        vec[index] = value;
                    }
                }
            }
            (Rep3AcvmType::Shared(index), Rep3AcvmType::Public(value)) => {
                // TODO there might be a more efficient implementation for this if the table is also public
                let value = arithmetic::promote_to_trivial_share(id, value);
                self.lut_provider.write_to_lut(index, value, lut)?;
            }
            (Rep3AcvmType::Shared(index), Rep3AcvmType::Shared(value)) => {
                self.lut_provider.write_to_lut(index, value, lut)?;
            }
        }
        todo!()
    }

    fn is_shared(a: &Self::AcvmType) -> bool {
        matches!(a, Rep3AcvmType::Shared(_))
    }

    fn get_shared(a: &Self::AcvmType) -> Option<Self::ArithmeticShare> {
        match a {
            Rep3AcvmType::Shared(shared) => Some(*shared),
            _ => None,
        }
    }
    fn get_public(a: &Self::AcvmType) -> Option<F> {
        match a {
            Rep3AcvmType::Public(public) => Some(*public),
            _ => None,
        }
    }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> std::io::Result<Vec<F>> {
        let bs = a.iter().map(|x| x.b).collect_vec();
        self.io_context0.network.send_next(bs)?;
        let mut cs = self.io_context0.network.recv_prev::<Vec<F>>()?;

        izip!(a, cs.iter_mut()).for_each(|(x, c)| *c += x.a + x.b);

        Ok(cs)
    }

    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare {
        let id = self.io_context0.id;
        arithmetic::promote_to_trivial_share(id, public_value)
    }

    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare> {
        let id = self.io_context0.id;
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    fn decompose_arithmetic(
        &mut self,
        input: Self::ArithmeticShare,
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        yao::decompose_arithmetic(
            input,
            &mut self.io_context0,
            total_bit_size_per_field,
            decompose_bit_size,
        )
    }

    fn decompose_arithmetic_many(
        &mut self,
        input: &[Self::ArithmeticShare],
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>> {
        // Defines an upper bound on the size of the input vector to keep the GC at a reasonable size (for RAM)
        const BATCH_SIZE: usize = 512; // TODO adapt this if it requires too much RAM

        let num_decomps_per_field = total_bit_size_per_field.div_ceil(decompose_bit_size);
        let mut results = Vec::with_capacity(input.len());

        for inp_chunk in input.chunks(BATCH_SIZE) {
            let result = yao::decompose_arithmetic_many(
                inp_chunk,
                &mut self.io_context0,
                total_bit_size_per_field,
                decompose_bit_size,
            )?;
            for chunk in result.chunks(num_decomps_per_field) {
                results.push(chunk.to_vec());
            }
        }
        Ok(results)
    }

    fn sort(
        &mut self,
        inputs: &[Self::ArithmeticShare],
        bitsize: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        radix_sort_fields(
            inputs,
            &mut self.io_context0,
            &mut self.io_context1,
            bitsize,
        )
    }

    fn slice(
        &mut self,
        input: Self::ArithmeticShare,
        msb: u8,
        lsb: u8,
        bitsize: usize,
    ) -> std::io::Result<[Self::ArithmeticShare; 3]> {
        let res = yao::slice_arithmetic(
            input,
            &mut self.io_context0,
            msb as usize,
            lsb as usize,
            bitsize,
        )?;
        debug_assert_eq!(res.len(), 3);
        Ok([res[0], res[1], res[2]])
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
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                let lhs: BigUint = lhs.into();
                let rhs: BigUint = rhs.into();
                let res = (lhs & rhs) & mask;
                let res = F::from(res);
                Ok(Rep3AcvmType::Public(res))
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                let shared = conversion::a2b_selector(shared, &mut self.io_context0)?;
                let public: BigUint = public.into();
                let public = public & mask;
                let binary = binary::and_with_public(&shared, &public); // Already includes masking
                let result = conversion::b2a_selector(&binary, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let (lhs, rhs) = join!(
                    conversion::a2b_selector(lhs, &mut self.io_context0),
                    conversion::a2b_selector(rhs, &mut self.io_context1)
                );
                let binary = binary::and(&lhs?, &rhs?, &mut self.io_context0)? & mask;
                let result = conversion::b2a_selector(&binary, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
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
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                let lhs: BigUint = lhs.into();
                let rhs: BigUint = rhs.into();
                let res = (lhs ^ rhs) & mask;
                let res = F::from(res);
                Ok(Rep3AcvmType::Public(res))
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                let shared = conversion::a2b_selector(shared, &mut self.io_context0)?;
                let public: BigUint = public.into();
                let binary = binary::xor_public(&shared, &public, self.io_context0.id) & mask;
                let result = conversion::b2a_selector(&binary, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let (lhs, rhs) = join!(
                    conversion::a2b_selector(lhs, &mut self.io_context0),
                    conversion::a2b_selector(rhs, &mut self.io_context1)
                );
                let binary = binary::xor(&lhs?, &rhs?) & mask;
                let result = conversion::b2a_selector(&binary, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
        }
    }
}
