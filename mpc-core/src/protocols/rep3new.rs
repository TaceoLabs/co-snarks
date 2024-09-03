mod a2b;
pub mod arithmetic;
pub mod binary;

pub use arithmetic::types::Rep3PrimeFieldShare;
pub use arithmetic::types::Rep3PrimeFieldShareVec;

pub use binary::types::Rep3BigUintShare;

pub mod conversion {
    use ark_ff::PrimeField;
    use num_bigint::BigUint;

    use crate::protocols::rep3::{id::PartyID, network::Rep3Network};

    type IoResult<T> = std::io::Result<T>;
    use super::{a2b, arithmetic::IoContext, Rep3BigUintShare, Rep3PrimeFieldShare};

    //re-export a2b
    pub use super::a2b::a2b;

    /// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementation currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p.

    // Keep in mind: Only works if the input is actually a binary sharing of a valid field element
    // If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
    pub async fn b2a<F: PrimeField, N: Rep3Network>(
        x: Rep3BigUintShare,
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
        io_context.network.send_next(y.a.to_owned())?;
        let local_b = io_context.network.recv_prev()?;
        y.b = local_b;

        let z = a2b::low_depth_binary_add_mod_p::<F, N>(x, y, io_context, bitlen).await?;

        match io_context.id {
            PartyID::ID0 => {
                io_context.network.send_next(z.b.to_owned())?;
                let rcv: BigUint = io_context.network.recv_prev()?;
                res.a = (z.a ^ z.b ^ rcv).into();
            }
            PartyID::ID1 => {
                let rcv: BigUint = io_context.network.recv_prev()?;
                res.b = (z.a ^ z.b ^ rcv).into();
            }
            PartyID::ID2 => {
                io_context.network.send_next(z.b)?;
            }
        }
        Ok(res)
    }
}
