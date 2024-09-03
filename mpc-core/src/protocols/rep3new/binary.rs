use num_bigint::BigUint;

use crate::protocols::rep3::{id::PartyID, network::Rep3Network};

use super::arithmetic::IoContext;

mod ops;
pub(super) mod types;

type BinaryShare = types::Rep3BigUintShare;
type IoResult<T> = std::io::Result<T>;

pub fn xor(a: &BinaryShare, b: &BinaryShare) -> BinaryShare {
    a ^ b
}

pub fn xor_public(shared: &BinaryShare, public: &BigUint, id: PartyID) -> BinaryShare {
    if let PartyID::ID0 = id {
        shared ^ public
    } else {
        shared.to_owned()
    }
}

pub async fn and<N: Rep3Network>(
    a: &BinaryShare,
    b: &BinaryShare,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<BinaryShare> {
    debug_assert!(a.a.bits() <= u64::try_from(bitlen).expect("usize fits into u64"));
    debug_assert!(b.a.bits() <= u64::try_from(bitlen).expect("usize fits into u64"));
    let (mut mask, mask_b) = io_context.rngs.rand.random_biguint(bitlen);
    mask ^= mask_b;
    let local_a = (a & b) ^ mask;
    io_context.network.send_next(local_a.to_owned())?;
    let local_b = io_context.network.recv_prev()?;
    Ok(BinaryShare::new(local_a, local_b))
}

pub fn and_with_public(shared: &BinaryShare, public: &BigUint) -> BinaryShare {
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

pub async fn open<N: Rep3Network>(
    a: &BinaryShare,
    io_context: &mut IoContext<N>,
) -> IoResult<BigUint> {
    io_context.network.send_next(a.b.clone())?;
    let c = io_context.network.recv_prev::<BigUint>()?;
    Ok(&a.a ^ &a.b ^ c)
}

/// Transforms a public value into a shared value: \[a\] = a.
pub fn promote_to_trivial_share(id: PartyID, public_value: BigUint) -> BinaryShare {
    match id {
        PartyID::ID0 => BinaryShare::new(public_value, BigUint::ZERO),
        PartyID::ID1 => BinaryShare::new(BigUint::ZERO, public_value),
        PartyID::ID2 => BinaryShare::zero_share(),
    }
}

pub async fn cmux<N: Rep3Network>(
    c: &BinaryShare,
    x_t: &BinaryShare,
    x_f: &BinaryShare,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<BinaryShare> {
    let xor = x_f ^ x_t;
    let mut and = and(c, &xor, io_context, bitlen).await?;
    and ^= x_f;
    Ok(and)
}
