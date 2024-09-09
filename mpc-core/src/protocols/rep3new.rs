mod a2b;
pub mod arithmetic;
pub mod binary;
pub mod id;
pub mod lut;
pub mod network;
pub mod pointshare;
pub mod rngs;

pub use arithmetic::types::Rep3PrimeFieldShare;
use ark_ec::CurveGroup;
pub use binary::types::Rep3BigUintShare;
use num_bigint::BigUint;
pub use pointshare::Rep3PointShare;

use ark_ff::{One, PrimeField};
use rand::{CryptoRng, Rng};

pub(crate) type IoResult<T> = std::io::Result<T>;

/// Secret shares a field element using replicated secret sharing and the provided random number generator. The field element is split into three additive shares, where each party holds two. The outputs are of type [Rep3PrimeFieldShare].
pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
    val: F,
    rng: &mut R,
) -> [Rep3PrimeFieldShare<F>; 3] {
    let a = F::rand(rng);
    let b = F::rand(rng);
    let c = val - a - b;
    let share1 = Rep3PrimeFieldShare::new(a, c);
    let share2 = Rep3PrimeFieldShare::new(b, a);
    let share3 = Rep3PrimeFieldShare::new(c, b);
    [share1, share2, share3]
}

/// Secret shares a vector of field element using replicated secret sharing and the provided random number generator. The field elements are split into three additive shares each, where each party holds two. The outputs are of type [Rep3PrimeFieldShareVec].
pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
    vals: &[F],
    rng: &mut R,
) -> [Vec<Rep3PrimeFieldShare<F>>; 3] {
    let mut shares1 = Vec::with_capacity(vals.len());
    let mut shares2 = Vec::with_capacity(vals.len());
    let mut shares3 = Vec::with_capacity(vals.len());
    for val in vals {
        let [share1, share2, share3] = share_field_element(*val, rng);
        shares1.push(share1);
        shares2.push(share2);
        shares3.push(share3);
    }
    [shares1, shares2, shares3]
}

/// Secret shares a field element using replicated secret sharing and the provided random number generator. The field element is split into three binary shares, where each party holds two. The outputs are of type [Rep3BigUintShare].
pub fn share_biguint<F: PrimeField, R: Rng + CryptoRng>(
    val: F,
    rng: &mut R,
) -> [Rep3BigUintShare<F>; 3] {
    let val: BigUint = val.into();
    let limbsize = F::MODULUS_BIT_SIZE.div_ceil(8);
    let mask = (BigUint::from(1u32) << F::MODULUS_BIT_SIZE) - BigUint::one();
    let a = BigUint::new((0..limbsize).map(|_| rng.gen()).collect()) & &mask;
    let b = BigUint::new((0..limbsize).map(|_| rng.gen()).collect()) & mask;

    let c = val ^ &a ^ &b;
    let share1 = Rep3BigUintShare::new(a.to_owned(), c.to_owned());
    let share2 = Rep3BigUintShare::new(b.to_owned(), a);
    let share3 = Rep3BigUintShare::new(c, b);
    [share1, share2, share3]
}

/// Secret shares a curve point using replicated secret sharing and the provided random number generator. The point is split into three additive shares, where each party holds two. The outputs are of type [Rep3PointShare].
pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
    val: C,
    rng: &mut R,
) -> [Rep3PointShare<C>; 3] {
    let a = C::rand(rng);
    let b = C::rand(rng);
    let c = val - a - b;
    let share1 = Rep3PointShare::new(a, c);
    let share2 = Rep3PointShare::new(b, a);
    let share3 = Rep3PointShare::new(c, b);
    [share1, share2, share3]
}

//TODO RENAME ME TO COMBINE_ARITHMETIC_SHARE
/// Reconstructs a field element from its arithmetic replicated shares.
pub fn combine_field_element<F: PrimeField>(
    share1: Rep3PrimeFieldShare<F>,
    share2: Rep3PrimeFieldShare<F>,
    share3: Rep3PrimeFieldShare<F>,
) -> F {
    share1.a + share2.a + share3.a
}

/// Reconstructs a vector of field elements from its arithmetic replicated shares.
/// # Panics
/// Panics if the provided `Vec` sizes do not match.
pub fn combine_field_elements<F: PrimeField>(
    share1: Vec<Rep3PrimeFieldShare<F>>,
    share2: Vec<Rep3PrimeFieldShare<F>>,
    share3: Vec<Rep3PrimeFieldShare<F>>,
) -> Vec<F> {
    assert_eq!(share1.len(), share2.len());
    assert_eq!(share2.len(), share3.len());

    itertools::multizip((share1.into_iter(), share2.into_iter(), share3.into_iter()))
        .map(|(x1, x2, x3)| x1.a + x2.a + x3.a)
        .collect::<Vec<_>>()
}

/// Reconstructs a value (represented as [BigUint]) from its binary replicated shares. Since binary operations can lead to results >= p, the result is not guaranteed to be a valid field element.
pub fn combine_binary_element<F: PrimeField>(
    share1: Rep3BigUintShare<F>,
    share2: Rep3BigUintShare<F>,
    share3: Rep3BigUintShare<F>,
) -> BigUint {
    share1.a ^ share2.a ^ share3.a
}

/// Reconstructs a curve point from its arithmetic replicated shares.
pub fn combine_curve_point<C: CurveGroup>(
    share1: Rep3PointShare<C>,
    share2: Rep3PointShare<C>,
    share3: Rep3PointShare<C>,
) -> C {
    share1.a + share2.a + share3.a
}

pub mod conversion {
    use ark_ff::PrimeField;
    use num_bigint::BigUint;

    use crate::protocols::rep3new::{id::PartyID, network::Rep3Network};

    use super::{a2b, network::IoContext, IoResult, Rep3BigUintShare, Rep3PrimeFieldShare};

    //re-export a2b
    pub use super::a2b::a2b;

    /// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementation currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p.

    // Keep in mind: Only works if the input is actually a binary sharing of a valid field element
    // If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
    pub async fn b2a<F: PrimeField, N: Rep3Network>(
        x: Rep3BigUintShare<F>,
        io_context: &mut IoContext<N>,
    ) -> IoResult<Rep3PrimeFieldShare<F>> {
        let mut y = Rep3BigUintShare::zero_share();
        let mut res = Rep3PrimeFieldShare::zero_share();

        let bitlen = usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize");
        let (mut r, r2) = io_context.rngs.rand.random_biguint(bitlen);
        r ^= r2;

        match io_context.id {
            PartyID::ID0 => {
                let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();

                res.b = (k3.0 + k3.1 + k3.2).neg();
                y.a = r;
            }
            PartyID::ID1 => {
                let k2 = io_context.rngs.bitcomp1.random_fes_3keys::<F>();

                res.a = (k2.0 + k2.1 + k2.2).neg();
                y.a = r;
            }
            PartyID::ID2 => {
                let k2 = io_context.rngs.bitcomp1.random_fes_3keys::<F>();
                let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();

                let k2_comp = k2.0 + k2.1 + k2.2;
                let k3_comp = k3.0 + k3.1 + k3.2;
                let val: BigUint = (k2_comp + k3_comp).into();
                y.a = val ^ r;
                res.a = k3_comp.neg();
                res.b = k2_comp.neg();
            }
        }

        // Reshare y
        io_context.network.send_next(y.a.to_owned()).await?;
        let local_b = io_context.network.recv_prev().await?;
        y.b = local_b;

        let z = a2b::low_depth_binary_add_mod_p::<F, N>(x, y, io_context, bitlen).await?;

        match io_context.id {
            PartyID::ID0 => {
                io_context.network.send_next(z.b.to_owned()).await?;
                let rcv: BigUint = io_context.network.recv_prev().await?;
                res.a = (z.a ^ z.b ^ rcv).into();
            }
            PartyID::ID1 => {
                let rcv: BigUint = io_context.network.recv_prev().await?;
                res.b = (z.a ^ z.b ^ rcv).into();
            }
            PartyID::ID2 => {
                io_context.network.send_next(z.b).await?;
            }
        }
        Ok(res)
    }
}