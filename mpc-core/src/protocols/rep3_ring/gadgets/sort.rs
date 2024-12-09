use crate::protocols::rep3_ring::ring::int_ring::IntRing2k;
use crate::protocols::rep3_ring::ring::ring_impl::RingElement;
use crate::protocols::rep3_ring::{arithmetic, conversion};
use crate::protocols::{
    rep3::{
        self,
        arithmetic::FieldShare,
        network::{IoContext, Rep3Network},
        IoResult,
    },
    rep3_ring::Rep3RingShare,
};
use ark_ff::{One, PrimeField};
use num_bigint::BigUint;
use sha3::digest::typenum::bit;

type PermRing = u32;

/// Sorts the inputs using an oblivious radix sort algorithm. Thereby, only the lowest `bitsize` bits are considered. The final results also only have bitsize bits each.
pub fn radix_sort_fields<F: PrimeField, N: Rep3Network>(
    inputs: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
    bitsize: usize,
) -> IoResult<Vec<FieldShare<F>>> {
    let m = inputs.len();
    if m.ilog2() + !m.is_power_of_two() as u32 > PermRing::MAX as u32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Permutation size is too small",
        ));
    }
    if bitsize > 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Bit size is larger than 64",
        ));
    }

    let perm = gen_perm(inputs, io_context, bitsize)?;

    todo!()
}

fn gen_perm<F: PrimeField, N: Rep3Network>(
    inputs: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
    bitsize: usize,
) -> IoResult<Vec<Rep3RingShare<PermRing>>> {
    let mask = (BigUint::one() << bitsize) - BigUint::one();

    // Decompose
    // TODO: This step could be optimized
    let mut bits = Vec::with_capacity(bitsize);
    for inp in inputs.iter().cloned() {
        let mut binary = rep3::conversion::a2b_selector(inp, io_context)?;
        binary &= &mask;
        bits.push(Rep3RingShare::<u64>::new(
            u64::cast_from_biguint(&binary.a),
            u64::cast_from_biguint(&binary.b),
        ));
    }

    let bit_0 = inject_bit(&bits, io_context, 0)?;
    let perm = gen_bit_perm(bit_0, io_context)?;

    for i in 1..bitsize {
        todo!("apply inverse perm");
        let bit_i = inject_bit(&bits, io_context, i)?;
        let perm_i = gen_bit_perm(bit_i, io_context)?;
        todo!("compose perms")
    }

    todo!()
}

fn inject_bit<N: Rep3Network>(
    inputs: &[Rep3RingShare<u64>],
    io_context: &mut IoContext<N>,
    bit: usize,
) -> IoResult<Vec<Rep3RingShare<PermRing>>> {
    let len = inputs.len();
    let mut bits = Vec::with_capacity(len);
    for inp in inputs {
        let a = inp.a.get_bit(bit).0 as PermRing;
        let b = inp.b.get_bit(bit).0 as PermRing;
        bits.push(Rep3RingShare::new_ring(a.into(), b.into()));
    }
    conversion::bit_inject_many(&bits, io_context)
}

fn gen_bit_perm<N: Rep3Network>(
    bits: Vec<Rep3RingShare<PermRing>>,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<PermRing>>> {
    let len = bits.len();
    let mut f0 = Vec::with_capacity(len);
    let mut f1 = Vec::with_capacity(len);
    for inp in bits {
        f0.push(arithmetic::add_public(
            -inp,
            RingElement::one(),
            io_context.id,
        ));
        f1.push(inp);
    }

    let mut s = Rep3RingShare::zero_share();
    let mut s0 = Vec::with_capacity(len);
    let mut s1 = Vec::with_capacity(len);
    for f in f0.iter() {
        s = arithmetic::add(s, *f);
        s0.push(s);
    }
    for f in f1.iter() {
        s = arithmetic::add(s, *f);
        s1.push(s);
    }
    let mul1 = arithmetic::mul_vec(&f0, &s0, io_context)?;
    let mul2 = arithmetic::mul_vec(&f1, &s1, io_context)?;
    let perm = mul1
        .into_iter()
        .zip(mul2)
        .map(|(a, b)| arithmetic::add(a, b))
        .collect();

    Ok(perm)
}

fn compose<N: Rep3Network>(
    sigma: Vec<Rep3RingShare<PermRing>>,
    pi: Vec<Rep3RingShare<PermRing>>,
    io_context: &mut IoContext<N>,
) -> Vec<Rep3RingShare<PermRing>> {
    let len = sigma.len();
    debug_assert_eq!(len, pi.len());

    let unshuffled = (0..len as PermRing).collect::<Vec<_>>();
    todo!()
}

fn shuffle<T: IntRing2k, N: Rep3Network>(
    pi: Vec<Rep3RingShare<PermRing>>,
    input: Vec<Rep3RingShare<T>>,
    io_context: &mut IoContext<N>,
) {
    todo!()
}
