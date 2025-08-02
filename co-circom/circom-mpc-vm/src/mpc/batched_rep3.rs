use ark_ff::One;
use mpc_net::Network;

use ark_ff::PrimeField;
use itertools::Itertools;
use mpc_core::{
    MpcState as _,
    protocols::rep3::{
        Rep3PrimeFieldShare, Rep3State, arithmetic,
        conversion::{self, A2BType},
        id::PartyID,
        network::Rep3NetworkExt,
    },
};
use num_bigint::BigUint;

use super::{VmCircomWitnessExtension, batched_plain::BatchedCircomPlainVmWitnessExtension};

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;

/// A batched version of the [`CircomRep3VmWitnessExtension`]. It operates on multiple
/// elements at once to reduce mul-depth if run on multiple inputs of the same circuit.
///
/// This is a pure MPC improvement and does not use any advanced ZK techniques like folding.
pub struct BatchedCircomRep3VmWitnessExtension<'a, F: PrimeField, N: Network> {
    _id: PartyID,
    net0: &'a N,
    _net1: &'a N,
    state0: Rep3State,
    _state1: Rep3State,
    plain: BatchedCircomPlainVmWitnessExtension<F>,
    batch_size: usize,
}

impl<'a, F: PrimeField, N: Network> BatchedCircomRep3VmWitnessExtension<'a, F, N> {
    pub fn new(
        net0: &'a N,
        net1: &'a N,
        a2b_type: A2BType,
        batch_size: usize,
    ) -> eyre::Result<Self> {
        let mut state = Rep3State::new(net0, a2b_type)?;
        let state1 = state.fork(0)?;
        Ok(Self {
            _id: state.id(),
            net0,
            _net1: net1,
            state0: state,
            _state1: state1,
            plain: BatchedCircomPlainVmWitnessExtension::new(batch_size),
            batch_size,
        })
    }
}

/// This type represents a public, arithmetic share, or binary share type used in the batched co-cricom MPC-VM.
#[derive(Clone)]
pub enum BatchedRep3VmType<F: PrimeField> {
    /// The public variant
    Public(Vec<F>),
    /// The arithmetic share variant
    Arithmetic(Vec<ArithmeticShare<F>>),
}

impl<F: PrimeField> std::fmt::Debug for BatchedRep3VmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Arithmetic(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

impl<F: PrimeField> From<Vec<F>> for BatchedRep3VmType<F> {
    fn from(value: Vec<F>) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<Vec<ArithmeticShare<F>>> for BatchedRep3VmType<F> {
    fn from(value: Vec<ArithmeticShare<F>>) -> Self {
        Self::Arithmetic(value)
    }
}

#[expect(unused_variables)]
impl<F: PrimeField, N: Network> VmCircomWitnessExtension<F>
    for BatchedCircomRep3VmWitnessExtension<'_, F, N>
{
    type Public = Vec<F>;

    type ArithmeticShare = Vec<ArithmeticShare<F>>;

    type VmType = BatchedRep3VmType<F>;

    fn add(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (BatchedRep3VmType::Public(a), BatchedRep3VmType::Public(b)) => {
                Ok(self.plain.add(a, b)?.into())
            }
            (BatchedRep3VmType::Public(b), BatchedRep3VmType::Arithmetic(a))
            | (BatchedRep3VmType::Arithmetic(a), BatchedRep3VmType::Public(b)) => Ok(a
                .into_iter()
                .zip(b)
                .map(|(a, b)| arithmetic::add_public(a, b, self.state0.id))
                .collect_vec()
                .into()),
            (BatchedRep3VmType::Arithmetic(a), BatchedRep3VmType::Arithmetic(b)) => Ok(a
                .iter()
                .zip(b)
                .map(|(a, b)| arithmetic::add(*a, b))
                .collect_vec()
                .into()),
        }
    }

    fn sub(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (BatchedRep3VmType::Public(a), BatchedRep3VmType::Public(b)) => {
                Ok(self.plain.sub(a, b)?.into())
            }
            (BatchedRep3VmType::Arithmetic(a), BatchedRep3VmType::Public(b)) => Ok(a
                .into_iter()
                .zip(b)
                .map(|(a, b)| arithmetic::sub_shared_by_public(a, b, self.state0.id))
                .collect_vec()
                .into()),
            (BatchedRep3VmType::Public(a), BatchedRep3VmType::Arithmetic(b)) => Ok(a
                .into_iter()
                .zip(b)
                .map(|(a, b)| arithmetic::sub_public_by_shared(a, b, self.state0.id))
                .collect_vec()
                .into()),

            (BatchedRep3VmType::Arithmetic(a), BatchedRep3VmType::Arithmetic(b)) => Ok(a
                .into_iter()
                .zip(b)
                .map(|(a, b)| arithmetic::sub(a, b))
                .collect_vec()
                .into()),
        }
    }

    fn mul(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (BatchedRep3VmType::Public(a), BatchedRep3VmType::Public(b)) => {
                Ok(self.plain.mul(a, b)?.into())
            }
            (BatchedRep3VmType::Public(b), BatchedRep3VmType::Arithmetic(a))
            | (BatchedRep3VmType::Arithmetic(a), BatchedRep3VmType::Public(b)) => Ok(a
                .iter()
                .zip(b)
                .map(|(a, b)| arithmetic::mul_public(*a, b))
                .collect_vec()
                .into()),
            (BatchedRep3VmType::Arithmetic(a), BatchedRep3VmType::Arithmetic(b)) => {
                Ok(arithmetic::mul_many(&a, &b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn int_div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn pow(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn modulo(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (BatchedRep3VmType::Public(a), BatchedRep3VmType::Public(b)) => {
                Ok(self.plain.modulo(a, b)?.into())
            }
            (_, _) => todo!("Shared mod not implemented"),
        }
    }

    fn sqrt(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn neg(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn lt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (BatchedRep3VmType::Public(a), BatchedRep3VmType::Public(b)) => {
                Ok(self.plain.lt(a, b)?.into())
            }
            (BatchedRep3VmType::Public(a), BatchedRep3VmType::Arithmetic(b)) => {
                panic!("1");
            }
            (BatchedRep3VmType::Arithmetic(a), BatchedRep3VmType::Public(b)) => {
                panic!("2");
            }
            (BatchedRep3VmType::Arithmetic(a), BatchedRep3VmType::Arithmetic(b)) => {
                panic!("3");
            }
        }
    }

    fn le(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn gt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn ge(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn eq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn neq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bool_not(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        todo!()
    }

    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> eyre::Result<bool> {
        if !allow_secret_inputs && self.is_shared(&a)? {
            eyre::bail!("allow_secret_inputs is false and input is shared");
        }
        match a {
            BatchedRep3VmType::Public(a) => Ok(self.plain.is_zero(a, allow_secret_inputs)?),
            BatchedRep3VmType::Arithmetic(a) => todo!(),
        }
    }

    fn is_shared(&mut self, a: &Self::VmType) -> eyre::Result<bool> {
        match a {
            BatchedRep3VmType::Public(_) => Ok(false),
            BatchedRep3VmType::Arithmetic(_) => Ok(true),
        }
    }

    fn to_index(&mut self, a: Self::VmType) -> eyre::Result<usize> {
        if let BatchedRep3VmType::Public(a) = a {
            self.plain.to_index(a)
        } else {
            eyre::bail!("ToIndex called on shared value!")
        }
    }

    fn open(&mut self, a: Self::VmType) -> eyre::Result<Self::Public> {
        match a {
            BatchedRep3VmType::Public(public) => Ok(public),
            BatchedRep3VmType::Arithmetic(shares) => Ok(arithmetic::open_vec(&shares, self.net0)?),
        }
    }

    fn to_share(&mut self, a: Self::VmType) -> eyre::Result<Self::ArithmeticShare> {
        match a {
            BatchedRep3VmType::Public(a) => Ok(a
                .iter()
                .map(|a| arithmetic::promote_to_trivial_share(self.state0.id, *a))
                .collect_vec()),
            BatchedRep3VmType::Arithmetic(a) => Ok(a),
        }
    }

    fn public_one(&self) -> Self::VmType {
        Self::VmType::Public(vec![F::one(); self.batch_size])
    }

    fn public_zero(&self) -> Self::VmType {
        Self::VmType::Public(vec![F::zero(); self.batch_size])
    }

    fn compare_vm_config(&mut self, config: &crate::mpc_vm::VMConfig) -> eyre::Result<()> {
        let ser = bincode::serialize(&config)?;
        self.net0.send_next(ser)?;
        let recv: Vec<u8> = self.net0.recv_prev()?;
        let deser = bincode::deserialize(&recv)?;
        if config != &deser {
            eyre::bail!("VM Config does not match: {:?} != {:?}", config, deser);
        }
        Ok(())
    }

    fn num2bits(&mut self, a: Self::VmType, bits: usize) -> eyre::Result<Vec<Self::VmType>> {
        todo!()
    }

    fn addbits(
        &mut self,
        a: Vec<Self::VmType>,
        b: Vec<Self::VmType>,
    ) -> eyre::Result<(Vec<Self::VmType>, Self::VmType)> {
        assert!(a.len() == b.len());
        assert!(!a.is_empty(), "Empty Batch in addbits");
        let bitlen = a.len();
        assert!(bitlen < F::MODULUS_BIT_SIZE as usize - 1);

        let a = a.into_iter().map(|x| match x {
            BatchedRep3VmType::Public(x) => x
                .into_iter()
                .map(|x| arithmetic::promote_to_trivial_share(self.state0.id, x))
                .collect_vec(),
            BatchedRep3VmType::Arithmetic(x) => x,
        });

        let b = b.into_iter().map(|x| match x {
            BatchedRep3VmType::Public(x) => x
                .into_iter()
                .map(|x| arithmetic::promote_to_trivial_share(self.state0.id, x))
                .collect_vec(),
            BatchedRep3VmType::Arithmetic(x) => x,
        });

        let a_sum = a.fold(
            vec![Rep3PrimeFieldShare::zero_share(); self.batch_size],
            |acc, x| acc.iter().zip(x).map(|(acc, x)| acc + acc + x).collect(),
        );
        let b_sum = b.fold(
            vec![Rep3PrimeFieldShare::zero_share(); self.batch_size],
            |acc, x| acc.iter().zip(x).map(|(acc, x)| acc + acc + x).collect(),
        );

        let sum = a_sum
            .into_iter()
            .zip(b_sum)
            .map(|(a, b)| arithmetic::add(a, b))
            .collect_vec();
        let sum_bits = conversion::a2b_many(&sum, self.net0, &mut self.state0)?;

        let individual_bits = (0..bitlen + 1)
            .flat_map(|i| sum_bits.iter().map(move |bit| (bit >> i) & BigUint::one()))
            .collect_vec();

        let result = conversion::bit_inject_many(&individual_bits, self.net0, &mut self.state0)?;
        assert!(result.len() % (bitlen + 1) == 0);
        assert!(result.len() / (bitlen + 1) == self.batch_size);
        let mut res = Vec::with_capacity(bitlen);
        for (idx, bit) in result.chunks_exact(self.batch_size).enumerate() {
            res.push(BatchedRep3VmType::Arithmetic(bit.to_vec()));
        }
        let carry = res.pop().unwrap();
        res.reverse();
        Ok((res, carry))
    }

    fn log(&mut self, a: Self::VmType, allow_leaky_logs: bool) -> eyre::Result<String> {
        match a {
            BatchedRep3VmType::Public(public) => self.plain.log(public, allow_leaky_logs),
            BatchedRep3VmType::Arithmetic(shares) => {
                if allow_leaky_logs {
                    let fields = arithmetic::open_vec(&shares, self.net0)?;
                    self.plain.log(fields, allow_leaky_logs)
                } else {
                    Ok("secret".to_string())
                }
            }
        }
    }
}
