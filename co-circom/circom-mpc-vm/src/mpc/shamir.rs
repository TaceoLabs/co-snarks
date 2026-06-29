use super::{VmCircomWitnessExtension, plain::CircomPlainVmWitnessExtension};
use crate::{mpc::plain::to_usize, mpc_vm::VMConfig};
use ark_ff::PrimeField;
use co_circom_types::ShamirInputType;
use mpc_core::{
    MpcState,
    protocols::shamir::{ShamirPreprocessing, ShamirPrimeFieldShare, ShamirState, arithmetic},
};
use mpc_net::Network;
use num_bigint::BigUint;

type ArithmeticShare<F> = ShamirPrimeFieldShare<F>;

/// This type represents a public, arithmetic share, or binary share type used in the co-cricom MPC-VM
#[derive(Clone)]
pub enum ShamirVmType<F: PrimeField> {
    /// The public variant
    Public(F),
    /// The arithmetic share variant
    Arithmetic(ArithmeticShare<F>),
}

impl<F: PrimeField> From<F> for ShamirVmType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<ArithmeticShare<F>> for ShamirVmType<F> {
    fn from(value: ArithmeticShare<F>) -> Self {
        Self::Arithmetic(value)
    }
}

impl<F: PrimeField> Default for ShamirVmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

impl<F: PrimeField> From<ShamirInputType<F>> for ShamirVmType<F> {
    fn from(value: ShamirInputType<F>) -> Self {
        match value {
            ShamirInputType::Public(public) => Self::Public(public),
            ShamirInputType::Shared(shared) => Self::Arithmetic(shared),
        }
    }
}

pub struct CircomShamirVmWitnessExtension<'a, F: PrimeField, N: Network> {
    net0: &'a N,
    _net1: &'a N,
    state0: ShamirState<F>,
    _state1: ShamirState<F>,
    plain: CircomPlainVmWitnessExtension<F>,
}

impl<'a, F: PrimeField, N: Network> CircomShamirVmWitnessExtension<'a, F, N> {
    pub fn new(
        net0: &'a N,
        net1: &'a N,
        num_parties: usize,
        threshold: usize,
        amount: usize,
    ) -> eyre::Result<Self> {
        let shamir_preprocessed = ShamirPreprocessing::new(num_parties, threshold, amount, net0)?;
        let mut state0 = ShamirState::from(shamir_preprocessed);
        let state1 = state0.fork(0)?;
        Ok(Self {
            net0,
            _net1: net1,
            state0,
            _state1: state1,
            plain: CircomPlainVmWitnessExtension::default(),
        })
    }
}

impl<F: PrimeField, N: Network> VmCircomWitnessExtension<F>
    for CircomShamirVmWitnessExtension<'_, F, N>
{
    type Public = F;

    type ArithmeticShare = ArithmeticShare<F>;

    type VmType = ShamirVmType<F>;

    fn add(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.add(a, b)?.into()),
            (ShamirVmType::Public(b), ShamirVmType::Arithmetic(a))
            | (ShamirVmType::Arithmetic(a), ShamirVmType::Public(b)) => {
                Ok(arithmetic::add_public(a, b).into())
            }
            (ShamirVmType::Arithmetic(a), ShamirVmType::Arithmetic(b)) => {
                Ok(arithmetic::add(a, b).into())
            }
        }
    }

    fn sub(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.sub(a, b)?.into()),
            (ShamirVmType::Arithmetic(a), ShamirVmType::Public(b)) => {
                Ok(arithmetic::add_public(a, -b).into())
            }
            (ShamirVmType::Public(a), ShamirVmType::Arithmetic(b)) => {
                Ok(arithmetic::add_public(arithmetic::neg(b), a).into())
            }
            (ShamirVmType::Arithmetic(a), ShamirVmType::Arithmetic(b)) => {
                Ok(arithmetic::sub(a, b).into())
            }
        }
    }

    fn mul(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.mul(a, b)?.into()),
            (ShamirVmType::Public(b), ShamirVmType::Arithmetic(a))
            | (ShamirVmType::Arithmetic(a), ShamirVmType::Public(b)) => {
                Ok(arithmetic::mul_public(a, b).into())
            }
            (ShamirVmType::Arithmetic(a), ShamirVmType::Arithmetic(b)) => {
                Ok(arithmetic::mul(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.div(a, b)?.into()),
            (ShamirVmType::Public(a), ShamirVmType::Arithmetic(b)) => {
                Ok(arithmetic::div_public_by_shared(a, b, self.net0, &mut self.state0)?.into())
            }
            (ShamirVmType::Arithmetic(a), ShamirVmType::Public(b)) => {
                Ok(arithmetic::div_shared_by_public(a, b)?.into())
            }
            (ShamirVmType::Arithmetic(a), ShamirVmType::Arithmetic(b)) => {
                Ok(arithmetic::div(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn int_div(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.int_div(a, b)?.into())
            }
            _ => unimplemented!("int_div with shared values not implemented for Shamir"),
        }
    }

    fn pow(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.pow(a, b)?.into()),
            _ => unimplemented!("pow with shared values not implemented for Shamir"),
        }
    }

    fn modulo(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.modulo(a, b)?.into())
            }
            _ => unimplemented!("modulo with shared values not implemented for Shamir"),
        }
    }

    fn sqrt(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            ShamirVmType::Public(a) => Ok(self.plain.sqrt(a)?.into()),
            ShamirVmType::Arithmetic(_) => {
                unimplemented!("sqrt on shared value not implemented for Shamir")
            }
        }
    }

    fn neg(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            ShamirVmType::Public(a) => Ok(self.plain.neg(a)?.into()),
            ShamirVmType::Arithmetic(a) => Ok(arithmetic::neg(a).into()),
        }
    }

    fn lt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.lt(a, b)?.into()),
            _ => unimplemented!("lt with shared values not implemented for Shamir"),
        }
    }

    fn le(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.le(a, b)?.into()),
            _ => unimplemented!("le with shared values not implemented for Shamir"),
        }
    }

    fn gt(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.gt(a, b)?.into()),
            _ => unimplemented!("gt with shared values not implemented for Shamir"),
        }
    }

    fn ge(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.ge(a, b)?.into()),
            _ => unimplemented!("ge with shared values not implemented for Shamir"),
        }
    }

    fn eq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.eq(a, b)?.into()),
            _ => unimplemented!("eq with shared values not implemented for Shamir"),
        }
    }

    fn neq(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => Ok(self.plain.neq(a, b)?.into()),
            _ => unimplemented!("neq with shared values not implemented for Shamir"),
        }
    }

    fn shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.shift_r(a, b)?.into())
            }
            _ => unimplemented!("shift_r with shared values not implemented for Shamir"),
        }
    }

    fn shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.shift_l(a, b)?.into())
            }
            _ => unimplemented!("shift_l with shared values not implemented for Shamir"),
        }
    }

    fn bool_not(&mut self, a: Self::VmType) -> eyre::Result<Self::VmType> {
        match a {
            ShamirVmType::Public(a) => Ok(self.plain.bool_not(a)?.into()),
            ShamirVmType::Arithmetic(a) => {
                let neg_a = arithmetic::neg(a);
                let not_a = arithmetic::add_public(neg_a, F::one());
                Ok(not_a.into())
            }
        }
    }

    fn bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.bool_and(a, b)?.into())
            }
            (a, b) => self.mul(a, b),
        }
    }

    fn bool_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.bool_or(a, b)?.into())
            }
            (ShamirVmType::Public(b), ShamirVmType::Arithmetic(a))
            | (ShamirVmType::Arithmetic(a), ShamirVmType::Public(b)) => {
                let mul = arithmetic::mul_public(a, b);
                let add = arithmetic::add_public(a, b);
                let sub = arithmetic::sub(add, mul);
                Ok(sub.into())
            }
            (ShamirVmType::Arithmetic(a), ShamirVmType::Arithmetic(b)) => {
                let mul = arithmetic::mul(a, b, self.net0, &mut self.state0)?;
                let add = arithmetic::add(a, b);
                let sub = arithmetic::sub(add, mul);
                Ok(sub.into())
            }
        }
    }

    fn cmux(
        &mut self,
        cond: Self::VmType,
        truthy: Self::VmType,
        falsy: Self::VmType,
    ) -> eyre::Result<Self::VmType> {
        match (cond, truthy, falsy) {
            (ShamirVmType::Public(cond), truthy, falsy) => {
                assert!(cond.is_one() || cond.is_zero());
                if cond.is_one() { Ok(truthy) } else { Ok(falsy) }
            }
            (ShamirVmType::Arithmetic(cond), truthy, falsy) => {
                let b_min_a = self.sub(truthy, falsy.clone())?;
                let d = self.mul(cond.into(), b_min_a)?;
                self.add(falsy, d)
            }
        }
    }

    fn bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.bit_xor(a, b)?.into())
            }
            _ => unimplemented!("bit_xor with shared values not implemented for Shamir"),
        }
    }

    fn bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.bit_or(a, b)?.into())
            }
            _ => unimplemented!("bit_or with shared values not implemented for Shamir"),
        }
    }

    fn bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> eyre::Result<Self::VmType> {
        match (a, b) {
            (ShamirVmType::Public(a), ShamirVmType::Public(b)) => {
                Ok(self.plain.bit_and(a, b)?.into())
            }
            _ => unimplemented!("bit_and with shared values not implemented for Shamir"),
        }
    }

    fn is_zero(&mut self, a: Self::VmType, allow_secret_inputs: bool) -> eyre::Result<bool> {
        if !allow_secret_inputs && self.is_shared(&a)? {
            unimplemented!("allow_secret_inputs is false and input is shared");
        }
        match a {
            ShamirVmType::Public(a) => Ok(self.plain.is_zero(a, allow_secret_inputs)?),
            ShamirVmType::Arithmetic(_) => {
                unimplemented!("is_zero on shared value not implemented for Shamir")
            }
        }
    }

    fn is_shared(&mut self, a: &Self::VmType) -> eyre::Result<bool> {
        match a {
            ShamirVmType::Public(_) => Ok(false),
            ShamirVmType::Arithmetic(_) => Ok(true),
        }
    }

    fn to_index(&mut self, a: Self::VmType) -> eyre::Result<usize> {
        if let ShamirVmType::Public(a) = a {
            Ok(to_usize!(a))
        } else {
            unimplemented!("ToIndex called on shared value!")
        }
    }

    fn open(&mut self, a: Self::VmType) -> eyre::Result<Self::Public> {
        match a {
            ShamirVmType::Public(a) => Ok(a),
            ShamirVmType::Arithmetic(a) => arithmetic::open(a, self.net0, &mut self.state0),
        }
    }

    fn to_share(&mut self, a: Self::VmType) -> eyre::Result<Self::ArithmeticShare> {
        match a {
            ShamirVmType::Public(a) => Ok(arithmetic::promote_to_trivial_share(a)),
            ShamirVmType::Arithmetic(a) => Ok(a),
        }
    }

    fn public_one(&self) -> Self::VmType {
        F::one().into()
    }

    fn public_zero(&self) -> Self::VmType {
        F::zero().into()
    }

    fn compare_vm_config(&mut self, config: &VMConfig) -> eyre::Result<()> {
        let ser = bincode::serialize(&config)?;
        let n = self.state0.num_parties;
        let id = self.state0.id();
        let next = (id + 1) % n;
        let prev = (id + n - 1) % n;
        self.net0.send(next, &ser)?;
        let recv = self.net0.recv(prev)?;
        let deser: VMConfig = bincode::deserialize(&recv)?;
        if config != &deser {
            eyre::bail!("VM Config does not match: {:?} != {:?}", config, deser);
        }
        Ok(())
    }

    fn num2bits(&mut self, a: Self::VmType, bits: usize) -> eyre::Result<Vec<Self::VmType>> {
        match a {
            ShamirVmType::Public(a) => Ok(self
                .plain
                .num2bits(a, bits)?
                .into_iter()
                .map(ShamirVmType::Public)
                .collect()),
            ShamirVmType::Arithmetic(_) => {
                unimplemented!("num2bits on shared value not implemented for Shamir")
            }
        }
    }

    fn addbits(
        &mut self,
        a: Vec<Self::VmType>,
        b: Vec<Self::VmType>,
    ) -> eyre::Result<(Vec<Self::VmType>, Self::VmType)> {
        let a_pub: Option<Vec<F>> = a
            .iter()
            .map(|x| {
                if let ShamirVmType::Public(v) = x {
                    Some(*v)
                } else {
                    None
                }
            })
            .collect();
        let b_pub: Option<Vec<F>> = b
            .iter()
            .map(|x| {
                if let ShamirVmType::Public(v) = x {
                    Some(*v)
                } else {
                    None
                }
            })
            .collect();
        match (a_pub, b_pub) {
            (Some(a), Some(b)) => {
                let (bits, carry) = self.plain.addbits(a, b)?;
                Ok((
                    bits.into_iter().map(ShamirVmType::Public).collect(),
                    carry.into(),
                ))
            }
            _ => unimplemented!("addbits with shared values not implemented for Shamir"),
        }
    }

    fn log(&mut self, a: Self::VmType, allow_leaky_logs: bool) -> eyre::Result<String> {
        match a {
            ShamirVmType::Public(public) => self.plain.log(public, allow_leaky_logs),
            ShamirVmType::Arithmetic(share) => {
                if allow_leaky_logs {
                    let field = arithmetic::open(share, self.net0, &mut self.state0)?;
                    Ok(field.to_string())
                } else {
                    Ok("secret".to_string())
                }
            }
        }
    }

    fn poseidon2_accelerator<const T: usize>(
        &mut self,
        _inputs: Vec<Self::VmType>,
    ) -> eyre::Result<(Vec<Self::VmType>, Vec<Self::VmType>)> {
        unimplemented!("Not implemented for Shamir")
    }
}

impl<F: PrimeField> std::fmt::Debug for ShamirVmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Arithmetic(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for ShamirVmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.write_str(&format!("Public ({field})")),
            Self::Arithmetic(arithmetic) => {
                f.write_str(&format!("Arithmetic ({})", arithmetic.inner()))
            }
        }
    }
}
