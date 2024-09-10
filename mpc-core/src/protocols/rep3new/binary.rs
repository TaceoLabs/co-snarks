use ark_ff::{One, PrimeField};
use itertools::izip;
use num_bigint::BigUint;
use types::Rep3BigUintShare;

use crate::protocols::rep3new::{id::PartyID, network::Rep3Network};

use super::{network::IoContext, Rep3PrimeFieldShare};

mod ops;
pub(super) mod types;

type FieldShare<F> = Rep3PrimeFieldShare<F>;
type BinaryShare<F> = Rep3BigUintShare<F>;
type IoResult<T> = std::io::Result<T>;

/// Performs a bitwise XOR operation on two shared values.
pub fn xor<F: PrimeField>(a: &BinaryShare<F>, b: &BinaryShare<F>) -> BinaryShare<F> {
    a ^ b
}

/// Performs a bitwise XOR operation on a shared value and a public value.
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

/// Performs a bitwise OR operation on two shared values.
pub async fn or<F: PrimeField, N: Rep3Network>(
    a: &BinaryShare<F>,
    b: &BinaryShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    let xor = a ^ b;
    let and = and(a, b, io_context).await?;
    Ok(xor ^ and)
}

/// Performs a bitwise OR operation on a shared value and a public value.
pub fn or_public<F: PrimeField>(
    shared: &BinaryShare<F>,
    public: &BigUint,
    id: PartyID,
) -> BinaryShare<F> {
    let tmp = shared & public;
    let xor = xor_public(shared, public, id);
    xor ^ tmp
}

/// Performs a bitwise AND operation on two shared values.
pub async fn and<F: PrimeField, N: Rep3Network>(
    a: &BinaryShare<F>,
    b: &BinaryShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    debug_assert!(a.a.bits() <= u64::from(F::MODULUS_BIT_SIZE));
    debug_assert!(b.a.bits() <= u64::from(F::MODULUS_BIT_SIZE));
    let (mut mask, mask_b) = io_context
        .rngs
        .rand
        .random_biguint(usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize"));
    mask ^= mask_b;
    let local_a = (a & b) ^ mask;
    let local_b = io_context.network.reshare(local_a.clone()).await?;
    Ok(BinaryShare::new(local_a, local_b))
}

/// Performs a bitwise AND operation on a shared value and a public value.
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

/// Performs the opening of a shared value and returns the equivalent public value.
pub async fn open<F: PrimeField, N: Rep3Network>(
    a: &BinaryShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BigUint> {
    let c = io_context.network.reshare(a.b.clone()).await?;
    Ok(&a.a ^ &a.b ^ c)
}

/// Transforms a public value into a shared value: \[a\] = a.
pub fn promote_to_trivial_share<F: PrimeField>(
    id: PartyID,
    public_value: &BigUint,
) -> BinaryShare<F> {
    match id {
        PartyID::ID0 => BinaryShare::new(public_value, BigUint::ZERO),
        PartyID::ID1 => BinaryShare::new(BigUint::ZERO, public_value),
        PartyID::ID2 => BinaryShare::zero_share(),
    }
}

/// Computes a CMUX: If `c` is `1`, returns `x_t`, otherwise returns `x_f`.
pub async fn cmux<F: PrimeField, N: Rep3Network>(
    c: &BinaryShare<F>,
    x_t: &BinaryShare<F>,
    x_f: &BinaryShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    let xor = x_f ^ x_t;
    let mut and = and(c, &xor, io_context).await?;
    and ^= x_f;
    Ok(and)
}

//TODO most likely the inputs here are only one bit therefore we
//do not have to perform an or over the whole length of prime field
//but only one bit.
//Do we want that to be configurable? Semms like a waste?
pub async fn or_tree<F: PrimeField, N: Rep3Network>(
    mut inputs: Vec<BinaryShare<F>>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    let mut num = inputs.len();

    tracing::debug!("starting or tree over {} elements", inputs.len());
    while num > 1 {
        tracing::trace!("binary tree still has {} elements", num);
        let mod_ = num & 1;
        num >>= 1;

        let (a_vec, tmp) = inputs.split_at(num);
        let (b_vec, leftover) = tmp.split_at(num);

        let mut res = Vec::with_capacity(num);
        // TODO WE WANT THIS BATCHED!!!
        // THIS IS SUPER BAD
        for (a, b) in izip!(a_vec.iter(), b_vec.iter()) {
            res.push(or(&a, &b, io_context).await?);
        }

        res.extend_from_slice(leftover);
        inputs = res;

        num += mod_;
    }
    let result = inputs[0].clone();
    tracing::debug!("we did it!");
    Ok(result)
}

/// Computes a binary circuit to check whether the replicated binary-shared input x is zero or not. The output is a binary sharing of one bit.
pub async fn is_zero<F: PrimeField, N: Rep3Network>(
    x: &BinaryShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    let bit_len = F::MODULUS_BIT_SIZE as usize;
    let mask = (BigUint::from(1u64) << bit_len) - BigUint::one();

    // negate
    let mut x = x ^ &mask;

    // do ands in a tree
    // TODO: Make and tree more communication efficient, ATM we send the full element for each level, even though they halve in size
    let mut len = bit_len;
    while len > 1 {
        if len % 2 == 1 {
            len += 1;
            // pad with a 1 (= 1 xor 1 xor 1) in MSB position
            // since this is publicly known we just set the bit in each party's share and its replication
            x.a.set_bit(len as u64 - 1, true);
            x.b.set_bit(len as u64 - 1, true);
        }
        len /= 2;
        let mask = (BigUint::from(1u64) << len) - BigUint::one();
        let y = &x >> len;
        x = and(&(&x & &mask), &(&y & &mask), io_context).await?;
    }
    // extract LSB
    Ok(x & BigUint::one())
}
