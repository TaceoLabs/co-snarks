use crate::protocols::rep3::id::PartyID;
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
use ark_ff::{One, PrimeField, Zero};
use num_bigint::BigUint;
use rand::distributions::Standard;
use rand::prelude::Distribution;

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
) -> IoResult<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let len = pi.len();
    debug_assert_eq!(len, input.len());
    let result = match io_context.id {
        rep3::id::PartyID::ID0 => {
            // has p1, p3
            let mut alpha_1 = Vec::with_capacity(len);
            let mut alpha_3 = Vec::with_capacity(len);
            let mut beta_1 = Vec::with_capacity(len);
            for _ in 0..len {
                let (alpha_1_, alpha_3_) = io_context.random_elements::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                alpha_3.push(alpha_3_);
                beta_1.push(alpha_1_ + alpha_3_);
            }
            // first shuffle
            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1.iter()) {
                let pi_1 = pi.a.0 as usize;
                shuffled_1.push(beta_1[pi_1] - alpha);
            }
            // second shuffle
            let mut shuffled_3 = alpha_1;
            for (des, (pi, alpha)) in shuffled_3.iter_mut().zip(pi.iter().zip(alpha_3)) {
                let pi_3 = pi.b.0 as usize;
                *des = shuffled_1[pi_3] - alpha;
            }
            io_context.network.send_next_many(&shuffled_3)?;

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            for _ in 0..len {
                let (a, b) = io_context.random_elements::<RingElement<T>>();
                result.push(Rep3RingShare::new_ring(a, b));
            }
            result
        }
        rep3::id::PartyID::ID1 => {
            // has p2, p1
            let mut alpha_2 = Vec::with_capacity(len);
            let mut alpha_1 = Vec::with_capacity(len);
            for _ in 0..len {
                let (alpha_2_, alpha_1_) = io_context.random_elements::<RingElement<T>>();
                alpha_2.push(alpha_2_);
                alpha_1.push(alpha_1_);
            }
            // first shuffle
            let beta_2 = alpha_2;
            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                let pi_1 = pi.b.0 as usize;
                shuffled_1.push(beta_2[pi_1] + alpha);
            }
            io_context.network.send_next_many(&shuffled_1)?;
            let delta = io_context.network.recv_prev_many()?;
            // second shuffle
            let mut beta_2_prime = beta_2;
            for (des, pi) in beta_2_prime.iter_mut().zip(pi) {
                let pi_2 = pi.a.0 as usize;
                *des = delta[pi_2];
            }

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            let mut rand = Vec::with_capacity(len);
            for beta in beta_2_prime {
                let b = io_context.rngs.rand.random_element_rng2::<RingElement<T>>();
                rand.push(beta - b);
                result.push(Rep3RingShare::new_ring(RingElement::zero(), b));
            }
            io_context.network.send_next_many(&rand)?;
            let rcv: Vec<RingElement<T>> = io_context.network.recv_many(PartyID::ID2)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.a = r1 + r2;
            }
            result
        }
        rep3::id::PartyID::ID2 => {
            // has p3, p2
            let mut alpha_3 = Vec::with_capacity(len);
            for _ in 0..len {
                let (alpha_3_, _) = io_context.random_elements::<RingElement<T>>();
                alpha_3.push(alpha_3_);
            }
            let gamma: Vec<RingElement<T>> = io_context.network.recv_prev_many()?;
            // first shuffle
            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_3.iter()) {
                let pi_3 = pi.a.0 as usize;
                shuffled_1.push(gamma[pi_3] + alpha);
            }
            // second shuffle
            let mut beta_3_prime = alpha_3;
            for (des, pi) in beta_3_prime.iter_mut().zip(pi) {
                let pi_2 = pi.b.0 as usize;
                *des = shuffled_1[pi_2];
            }

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            let mut rand = Vec::with_capacity(len);
            for beta in beta_3_prime {
                let a = io_context.rngs.rand.random_element_rng1::<RingElement<T>>();
                rand.push(beta - a);
                result.push(Rep3RingShare::new_ring(a, RingElement::zero()));
            }
            io_context.network.send_many(PartyID::ID1, &rand)?;
            let rcv: Vec<RingElement<T>> = io_context.network.recv_prev_many()?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.b = r1 + r2;
            }
            result
        }
    };
    Ok(result)
}

fn unshuffle<T: IntRing2k, N: Rep3Network>(
    pi: Vec<Rep3RingShare<PermRing>>,
    input: Vec<Rep3RingShare<T>>,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let len = pi.len();
    debug_assert_eq!(len, input.len());
    let result = match io_context.id {
        rep3::id::PartyID::ID0 => {
            // has p1, p3
            let mut alpha_3 = Vec::with_capacity(len);
            for _ in 0..len {
                let (_, alpha_3_) = io_context.random_elements::<RingElement<T>>();
                alpha_3.push(alpha_3_);
            }
            let gamma: Vec<RingElement<T>> = io_context.network.recv_many(PartyID::ID1)?;
            // first shuffle
            let mut shuffled_3 = vec![RingElement::zero(); len];
            for (pi, (alpha, gamma)) in pi.iter().zip(alpha_3.iter().zip(gamma)) {
                let pi_3 = pi.b.0 as usize;
                shuffled_3[pi_3] = gamma + alpha;
            }
            // second shuffle
            let mut beta_1_prime = alpha_3;
            for (src, pi) in shuffled_3.into_iter().zip(pi) {
                let pi_1 = pi.a.0 as usize;
                beta_1_prime[pi_1] = src;
            }

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            let mut rand = Vec::with_capacity(len);
            for beta in beta_1_prime {
                let b = io_context.rngs.rand.random_element_rng2::<RingElement<T>>();
                rand.push(beta - b);
                result.push(Rep3RingShare::new_ring(RingElement::zero(), b));
            }
            io_context.network.send_next_many(&rand)?;
            let rcv: Vec<RingElement<T>> = io_context.network.recv_many(PartyID::ID1)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.a = r1 + r2;
            }
            result
        }
        rep3::id::PartyID::ID1 => {
            // has p2, p1
            let mut alpha_2 = Vec::with_capacity(len);
            let mut alpha_1 = Vec::with_capacity(len);
            for _ in 0..len {
                let (alpha_2_, alpha_1_) = io_context.random_elements::<RingElement<T>>();
                alpha_2.push(alpha_2_);
                alpha_1.push(alpha_1_);
            }
            // first shuffle
            let beta_2 = alpha_1;
            let mut shuffled_3 = vec![RingElement::zero(); len];
            for (pi, (alpha, beta_2)) in pi.iter().zip(alpha_2.into_iter().zip(beta_2.iter())) {
                let pi_2 = pi.a.0 as usize;
                shuffled_3[pi_2] = alpha + beta_2;
            }
            io_context.network.send_many(PartyID::ID0, &shuffled_3)?;
            let delta = io_context.network.recv_many(PartyID::ID2)?;
            // second shuffle
            let mut beta_2_prime = beta_2;
            for (src, pi) in delta.into_iter().zip(pi) {
                let pi_1 = pi.b.0 as usize;
                beta_2_prime[pi_1] = src;
            }

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            let mut rand = Vec::with_capacity(len);
            for beta in beta_2_prime {
                let a = io_context.rngs.rand.random_element_rng1::<RingElement<T>>();
                rand.push(beta - a);
                result.push(Rep3RingShare::new_ring(a, RingElement::zero()));
            }
            io_context.network.send_many(PartyID::ID0, &rand)?;
            let rcv: Vec<RingElement<T>> = io_context.network.recv_prev_many()?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.b = r1 + r2;
            }
            result
        }
        rep3::id::PartyID::ID2 => {
            // has p3, p2
            let mut alpha_3 = Vec::with_capacity(len);
            let mut alpha_2 = Vec::with_capacity(len);
            let mut beta_3 = Vec::with_capacity(len);
            for _ in 0..len {
                let (alpha_3_, alpha_2_) = io_context.random_elements::<RingElement<T>>();
                alpha_3.push(alpha_3_);
                alpha_2.push(alpha_2_);
                beta_3.push(alpha_3_ + alpha_2_);
            }
            // first shuffle
            let mut shuffled_3 = vec![RingElement::zero(); len];
            for (pi, (alpha, beta_3)) in pi.iter().zip(alpha_2.iter().zip(beta_3)) {
                let pi_2 = pi.b.0 as usize;
                shuffled_3[pi_2] = beta_3 - alpha;
            }
            // second shuffle
            let mut shuffled_2 = alpha_2;
            for (src, (pi, alpha)) in shuffled_3.into_iter().zip(pi.iter().zip(alpha_3)) {
                let pi_3 = pi.a.0 as usize;
                shuffled_2[pi_3] = src - alpha;
            }
            io_context.network.send_many(PartyID::ID1, &shuffled_2)?;

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            for _ in 0..len {
                let (a, b) = io_context.random_elements::<RingElement<T>>();
                result.push(Rep3RingShare::new_ring(a, b));
            }
            result
        }
    };
    Ok(result)
}
