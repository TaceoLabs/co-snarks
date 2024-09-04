use ark_ff::PrimeField;
use num_bigint::BigUint;

use crate::{
    protocols::rep3::{id::PartyID, network::Rep3Network},
    traits::SecretShared,
};

use super::network::IoContext;

mod ops;
pub(super) mod types;

type BinaryShare<F> = types::Rep3BigUintShare<F>;
type IoResult<T> = std::io::Result<T>;

pub fn xor<F: PrimeField>(a: &BinaryShare<F>, b: &BinaryShare<F>) -> BinaryShare<F> {
    a ^ b
}

pub fn xor_public<F: PrimeField>(
    shared: &BinaryShare<F>,
    public: &BigUint,
    id: PartyID,
) -> BinaryShare<F> {
    let mut res = shared.to_owned();
    match id {
        PartyID::ID0 => res.a ^= public,
        PartyID::ID1 => res.b ^= public,
        PartyID::ID2 => {}
    }
    res
}

pub async fn and<F: PrimeField, N: Rep3Network>(
    a: &BinaryShare<F>,
    b: &BinaryShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<BinaryShare<F>> {
    debug_assert!(a.a.bits() <= u64::try_from(bitlen).expect("usize fits into u64"));
    debug_assert!(b.a.bits() <= u64::try_from(bitlen).expect("usize fits into u64"));
    let (mut mask, mask_b) = io_context.rngs.rand.random_biguint(bitlen);
    mask ^= mask_b;
    let local_a = (a & b) ^ mask;
    io_context.network.send_next(local_a.to_owned())?;
    let local_b = io_context.network.recv_prev()?;
    Ok(BinaryShare::new(local_a, local_b))
}

pub fn and_with_public<F: PrimeField>(shared: &BinaryShare<F>, public: &BigUint) -> BinaryShare<F> {
    shared & public
}

//pub async fn and_vec(
//    a: &FieldShareVec<F>,
//    b: &FieldShareVec<F>,
//    io_context: &mut IoContext<N>,
//) -> IoResult<FieldShareVec<F>> {
//    //debug_assert_eq!(a.len(), b.len());
//    let local_a = izip!(a.a.iter(), a.b.iter(), b.a.iter(), b.b.iter())
//        .map(|(aa, ab, ba, bb)| {
//            *aa * ba + *aa * bb + *ab * ba + io_context.rngs.rand.masking_field_element::<F>()
//        })
//        .collect_vec();
//    io_context.network.send_next_many(&local_a)?;
//    let local_b = io_context.network.recv_prev_many()?;
//    if local_b.len() != local_a.len() {
//        return Err(std::io::Error::new(
//            std::io::ErrorKind::InvalidData,
//            "During execution of mul_vec in MPC: Invalid number of elements received",
//        ));
//    }
//    Ok(FieldShareVec::new(local_a, local_b))
//}

pub async fn open<F: PrimeField, N: Rep3Network>(
    a: &BinaryShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BigUint> {
    io_context.network.send_next(a.b.clone())?;
    let c = io_context.network.recv_prev::<BigUint>()?;
    Ok(&a.a ^ &a.b ^ c)
}

/// Transforms a public value into a shared value: \[a\] = a.
pub fn promote_to_trivial_share<F: PrimeField>(
    id: PartyID,
    public_value: BigUint,
) -> BinaryShare<F> {
    match id {
        PartyID::ID0 => BinaryShare::new(public_value, BigUint::ZERO),
        PartyID::ID1 => BinaryShare::new(BigUint::ZERO, public_value),
        PartyID::ID2 => BinaryShare::zero_share(),
    }
}

pub async fn cmux<F: PrimeField, N: Rep3Network>(
    c: &BinaryShare<F>,
    x_t: &BinaryShare<F>,
    x_f: &BinaryShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<BinaryShare<F>> {
    let xor = x_f ^ x_t;
    let mut and = and(c, &xor, io_context, bitlen).await?;
    and ^= x_f;
    Ok(and)
}
