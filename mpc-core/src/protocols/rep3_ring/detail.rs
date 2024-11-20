use super::{
    arithmetic::types::Rep3RingShare,
    binary,
    ring::{int_ring::IntRing2k, ring_impl::RingElement},
};
use crate::protocols::rep3::{
    network::{IoContext, Rep3Network},
    IoResult,
};
use rand::{distributions::Standard, prelude::Distribution};

pub(super) fn low_depth_binary_add<T: IntRing2k, N: Rep3Network>(
    x1: &Rep3RingShare<T>,
    x2: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    // Add x1 + x2 via a packed Kogge-Stone adder
    let p = x1 ^ x2;
    let g = binary::and(x1, x2, io_context)?;
    kogge_stone_inner(&p, &g, io_context)
}

fn kogge_stone_inner<T: IntRing2k, N: Rep3Network>(
    p: &Rep3RingShare<T>,
    g: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let bitlen = T::K;
    let d: u32 = bitlen.ilog2(); // T is a ring with 2^k elements
    debug_assert!(bitlen.is_power_of_two());

    let s_ = p.to_owned();
    let mut p = p.to_owned();
    let mut g = g.to_owned();
    for i in 0..d {
        let shift = 1 << i;
        let p_ = p << shift;
        let g_ = g << shift;
        // TODO: Make and more communication efficient, ATM we send the full element for each level, even though they reduce in size
        // maybe just input the mask into AND?
        let (r1, r2) = and_twice(&p, &g_, &p_, io_context)?;
        p = r2;
        g ^= r1;
    }
    g <<= 1;
    g ^= &s_;
    Ok(g)
}

fn and_twice<T: IntRing2k, N: Rep3Network>(
    a: &Rep3RingShare<T>,
    b1: &Rep3RingShare<T>,
    b2: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<(Rep3RingShare<T>, Rep3RingShare<T>)>
where
    Standard: Distribution<T>,
{
    let (mut mask1, mask_b) = io_context.rngs.rand.random_elements::<RingElement<T>>();
    mask1 ^= mask_b;

    let (mut mask2, mask_b) = io_context.rngs.rand.random_elements::<RingElement<T>>();
    mask2 ^= mask_b;

    let local_a1 = (b1 & a) ^ mask1;
    let local_a2 = (a & b2) ^ mask2;
    io_context
        .network
        .send_next([local_a1.to_owned(), local_a2.to_owned()])?;
    let [local_b1, local_b2] = io_context.network.recv_prev()?;

    let r1 = Rep3RingShare {
        a: local_a1,
        b: local_b1,
    };
    let r2 = Rep3RingShare {
        a: local_a2,
        b: local_b2,
    };

    Ok((r1, r2))
}
