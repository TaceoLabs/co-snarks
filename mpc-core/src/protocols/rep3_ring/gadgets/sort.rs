//! Sort
//!
//! This module contains some oblivious sorting algorithms for the Rep3 protocol.

use crate::protocols::rep3::id::PartyID;
use crate::protocols::rep3::{Rep3BigUintShare, Rep3PrimeFieldShare};
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

// u32 allows to sort 4*10^9 elements. Inputs of this size require 32*4*10^9*2 bytes, i.e., 256 GB of RAM
type PermRing = u32;

macro_rules! join {
    ($t1: expr, $t2: expr) => {{
        std::thread::scope(|s| {
            let t1 = s.spawn(|| $t1);
            let t2 = $t2;
            (t1.join().expect("can join"), t2)
        })
    }};
}

/// Sorts the inputs using an oblivious radix sort algorithm. Thereby, only the lowest `bitsize` bits are considered. The final results have the size of the inputs, i.e, are not shortened to bitsize.
/// We use the algorithm described in [https://eprint.iacr.org/2019/695.pdf](https://eprint.iacr.org/2019/695.pdf).
pub fn radix_sort_fields<F: PrimeField, N: Rep3Network>(
    inputs: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
    bitsize: usize,
) -> IoResult<Vec<FieldShare<F>>> {
    let len = inputs.len();
    if len
        > PermRing::MAX
            .try_into()
            .expect("transformation of PermRing::MAX into usize failed")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Too many inputs for radix sort. Use a larger PermRing.",
        ));
    }
    let mut forked_io_context = io_context.fork()?; // TODO maybe at some future point we have a second one as input to the function

    let perm = gen_perm(inputs, bitsize, io_context, &mut forked_io_context)?;
    apply_inv_field(&perm, inputs, io_context, &mut forked_io_context)
}

fn gen_perm<F: PrimeField, N: Rep3Network>(
    inputs: &[FieldShare<F>],
    bitsize: usize,
    io_context0: &mut IoContext<N>,
    io_context1: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<PermRing>>> {
    let mask = (BigUint::one() << bitsize) - BigUint::one();

    // Decompose
    let mut bits = vec![Rep3BigUintShare::zero_share(); inputs.len()];
    let (split1, split2) = bits.split_at_mut(inputs.len() / 2);
    let mut result1 = None;
    let mut result2 = None;

    // TODO: This step could be optimized (I: Pack the a2b's, II: only reconstruct bitsize bits)
    join!(
        for (i, inp) in inputs.iter().take(inputs.len() / 2).enumerate() {
            let binary = rep3::conversion::a2b_selector(inp.to_owned(), io_context0);
            if let Err(err) = binary {
                result1 = Some(err);
                break;
            }
            let mut binary = binary.unwrap();
            binary &= &mask;
            split1[i] = binary;
        },
        (
            for (i, inp) in inputs.iter().skip(inputs.len() / 2).enumerate() {
                let binary = rep3::conversion::a2b_selector(inp.to_owned(), io_context1);
                if let Err(err) = binary {
                    result2 = Some(err);
                    break;
                }
                let mut binary = binary.unwrap();
                binary &= &mask;
                split2[i] = binary;
            },
        )
    );
    if let Some(err) = result1 {
        return Err(err);
    }
    if let Some(err) = result2 {
        return Err(err);
    }

    let bit_0 = inject_bit(&bits, io_context0, 0)?;
    let mut perm = gen_bit_perm(bit_0, io_context0)?;

    for i in 1..bitsize {
        let bit_i = inject_bit(&bits, io_context0, i)?;
        let bit_i = apply_inv(&perm, &bit_i, io_context0, io_context1)?;
        let perm_i = gen_bit_perm(bit_i, io_context0)?;
        perm = compose(perm, perm_i, io_context0)?;
    }

    Ok(perm)
}

fn inject_bit<F: PrimeField, N: Rep3Network>(
    inputs: &[Rep3BigUintShare<F>],
    io_context: &mut IoContext<N>,
    bit: usize,
) -> IoResult<Vec<Rep3RingShare<PermRing>>> {
    let len = inputs.len();
    let mut bits = Vec::with_capacity(len);
    for inp in inputs {
        let a = inp.a.bit(bit as u64) as PermRing;
        let b = inp.b.bit(bit as u64) as PermRing;
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

    let mul1 = arithmetic::local_mul_vec(&f0, &s0, &mut io_context.rngs);
    let mul2 = arithmetic::local_mul_vec(&f1, &s1, &mut io_context.rngs);
    let perm_a = mul1.into_iter().zip(mul2).map(|(a, b)| a + b).collect();
    let perm = arithmetic::io_mul_vec(perm_a, io_context)?;

    Ok(perm)
}

fn apply_inv<T: IntRing2k, N: Rep3Network>(
    rho: &[Rep3RingShare<PermRing>],
    bits: &[Rep3RingShare<T>],
    io_context0: &mut IoContext<N>,
    io_context1: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let len = rho.len();
    debug_assert_eq!(len, rho.len());

    let unshuffled = (0..len as PermRing).collect::<Vec<_>>();
    let (perm_a, perm_b) = io_context0.rngs.rand.random_perm(unshuffled);
    let perm: Vec<_> = perm_a
        .into_iter()
        .zip(perm_b)
        .map(|(a, b)| Rep3RingShare::new(a, b))
        .collect();

    let (opened, bits_shuffled) = join!(
        shuffle_reveal::<PermRing, _>(&perm, rho, io_context0),
        shuffle(&perm, bits, io_context1)
    );
    let mut result = vec![Rep3RingShare::zero_share(); len];
    for (p, b) in opened?.into_iter().zip(bits_shuffled?) {
        result[p.0 as usize - 1] = b;
    }
    Ok(result)
}

fn apply_inv_field<F: PrimeField, N: Rep3Network>(
    rho: &[Rep3RingShare<PermRing>],
    bits: &[Rep3PrimeFieldShare<F>],
    io_context0: &mut IoContext<N>,
    io_context1: &mut IoContext<N>,
) -> IoResult<Vec<Rep3PrimeFieldShare<F>>> {
    let len = rho.len();
    debug_assert_eq!(len, rho.len());

    let unshuffled = (0..len as PermRing).collect::<Vec<_>>();
    let (perm_a, perm_b) = io_context0.rngs.rand.random_perm(unshuffled);
    let perm: Vec<_> = perm_a
        .into_iter()
        .zip(perm_b)
        .map(|(a, b)| Rep3RingShare::new(a, b))
        .collect();

    let (opened, bits_shuffled) = join!(
        shuffle_reveal(&perm, rho, io_context0),
        shuffle_field(&perm, bits, io_context1)
    );
    let mut result = vec![Rep3PrimeFieldShare::zero_share(); len];
    for (p, b) in opened?.into_iter().zip(bits_shuffled?) {
        result[p.0 as usize - 1] = b;
    }
    Ok(result)
}

fn compose<N: Rep3Network>(
    sigma: Vec<Rep3RingShare<PermRing>>,
    phi: Vec<Rep3RingShare<PermRing>>,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<PermRing>>> {
    let len = sigma.len();
    debug_assert_eq!(len, phi.len());

    let unshuffled = (0..len as PermRing).collect::<Vec<_>>();
    let (perm_a, perm_b) = io_context.rngs.rand.random_perm(unshuffled);
    let perm: Vec<_> = perm_a
        .into_iter()
        .zip(perm_b)
        .map(|(a, b)| Rep3RingShare::new(a, b))
        .collect();

    let opened = shuffle_reveal(&perm, &sigma, io_context)?;
    let mut shuffled = Vec::with_capacity(len);
    for p in opened {
        shuffled.push(phi[p.0 as usize - 1]);
    }
    unshuffle(&perm, &shuffled, io_context)
}

fn shuffle<T: IntRing2k, N: Rep3Network>(
    pi: &[Rep3RingShare<PermRing>],
    input: &[Rep3RingShare<T>],
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
            for a in input {
                let (alpha_1_, alpha_3_) = io_context.random_elements::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                alpha_3.push(alpha_3_);
                beta_1.push(a.a + a.b);
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
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for a in input {
                let alpha_1_ = io_context.rngs.rand.random_element_rng2::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                beta_2.push(a.a);
            }
            // first shuffle
            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                let pi_1 = pi.b.0 as usize;
                shuffled_1.push(beta_2[pi_1] + alpha);
            }
            let delta = io_context.network.reshare_many(&shuffled_1)?;
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
                let alpha_3_ = io_context.rngs.rand.random_element_rng1::<RingElement<T>>();
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

fn shuffle_field<F: PrimeField, N: Rep3Network>(
    pi: &[Rep3RingShare<PermRing>],
    input: &[Rep3PrimeFieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3PrimeFieldShare<F>>> {
    let len = pi.len();
    debug_assert_eq!(len, input.len());
    let result = match io_context.id {
        rep3::id::PartyID::ID0 => {
            // has p1, p3
            let mut alpha_1 = Vec::with_capacity(len);
            let mut alpha_3 = Vec::with_capacity(len);
            let mut beta_1 = Vec::with_capacity(len);
            for a in input {
                let (alpha_1_, alpha_3_) = io_context.random_fes::<F>();
                alpha_1.push(alpha_1_);
                alpha_3.push(alpha_3_);
                beta_1.push(a.a + a.b);
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
                let (a, b) = io_context.random_fes::<F>();
                result.push(Rep3PrimeFieldShare::new(a, b));
            }
            result
        }
        rep3::id::PartyID::ID1 => {
            // has p2, p1
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for a in input {
                let alpha_1_ = io_context.rngs.rand.random_field_element_rng2::<F>();
                alpha_1.push(alpha_1_);
                beta_2.push(a.a);
            }
            // first shuffle
            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                let pi_1 = pi.b.0 as usize;
                shuffled_1.push(beta_2[pi_1] + alpha);
            }
            let delta = io_context.network.reshare_many(&shuffled_1)?;
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
                let b = io_context.rngs.rand.random_field_element_rng2::<F>();
                rand.push(beta - b);
                result.push(Rep3PrimeFieldShare::new(F::zero(), b));
            }
            io_context.network.send_next_many(&rand)?;
            let rcv: Vec<F> = io_context.network.recv_many(PartyID::ID2)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.a = r1 + r2;
            }
            result
        }
        rep3::id::PartyID::ID2 => {
            // has p3, p2
            let mut alpha_3 = Vec::with_capacity(len);
            for _ in 0..len {
                let alpha_3_ = io_context.rngs.rand.random_field_element_rng1::<F>();
                alpha_3.push(alpha_3_);
            }
            let gamma: Vec<F> = io_context.network.recv_prev_many()?;
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
                let a = io_context.rngs.rand.random_field_element_rng1::<F>();
                rand.push(beta - a);
                result.push(Rep3PrimeFieldShare::new(a, F::zero()));
            }
            io_context.network.send_many(PartyID::ID1, &rand)?;
            let rcv: Vec<F> = io_context.network.recv_prev_many()?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.b = r1 + r2;
            }
            result
        }
    };
    Ok(result)
}

fn shuffle_reveal<T: IntRing2k, N: Rep3Network>(
    pi: &[Rep3RingShare<PermRing>],
    input: &[Rep3RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<RingElement<T>>>
where
    Standard: Distribution<T>,
{
    let len = pi.len();
    debug_assert_eq!(len, input.len());
    let result = match io_context.id {
        PartyID::ID0 => {
            // has p1, p3
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_1 = Vec::with_capacity(len);
            for a in input {
                let alpha_1_ = io_context.rngs.rand.random_element_rng1::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                beta_1.push(a.a + a.b);
            }
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1.iter()) {
                let pi_1 = pi.a.0 as usize;
                shuffled.push(beta_1[pi_1] - alpha);
            }
            io_context.network.send_many(PartyID::ID2, &shuffled)?;
            io_context.network.recv_many(PartyID::ID2)?
        }
        PartyID::ID1 => {
            // has p2, p1
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for a in input {
                let alpha_1_ = io_context.rngs.rand.random_element_rng2::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                beta_2.push(a.a);
            }
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                let pi_1 = pi.b.0 as usize;
                shuffled.push(beta_2[pi_1] + alpha);
            }
            io_context.network.send_next_many(&shuffled)?;
            io_context.network.recv_many(PartyID::ID2)?
        }
        PartyID::ID2 => {
            let delta: Vec<RingElement<T>> = io_context.network.recv_many(PartyID::ID0)?;
            let gamma: Vec<RingElement<T>> = io_context.network.recv_prev_many()?;
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for p in pi {
                let pi_2 = p.b.0 as usize;
                let index = pi[pi_2].a.0 as usize;
                shuffled.push(gamma[index] + delta[index]);
            }
            io_context.network.send_many(PartyID::ID0, &shuffled)?;
            io_context.network.send_many(PartyID::ID1, &shuffled)?;
            shuffled
        }
    };
    Ok(result)
}

fn unshuffle<T: IntRing2k, N: Rep3Network>(
    pi: &[Rep3RingShare<PermRing>],

    input: &[Rep3RingShare<T>],
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
                let alpha_3_ = io_context.rngs.rand.random_element_rng2::<RingElement<T>>();
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
            let mut beta_2 = Vec::with_capacity(len);
            for a in input {
                let alpha_2_ = io_context.rngs.rand.random_element_rng1::<RingElement<T>>();
                alpha_2.push(alpha_2_);
                beta_2.push(a.b);
            }
            // first shuffle
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
            for a in input {
                let (alpha_3_, alpha_2_) = io_context.random_elements::<RingElement<T>>();
                alpha_3.push(alpha_3_);
                alpha_2.push(alpha_2_);
                beta_3.push(a.a + a.b);
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
