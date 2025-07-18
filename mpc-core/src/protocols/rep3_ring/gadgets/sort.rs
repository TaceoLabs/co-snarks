//! Sort
//!
//! This module contains some oblivious sorting algorithms for the Rep3 protocol.

use crate::protocols::rep3::id::PartyID;
use crate::protocols::rep3::{
    Rep3BigUintShare, Rep3PrimeFieldShare, Rep3State, network::Rep3NetworkExt,
};
use crate::protocols::rep3_ring::ring::int_ring::IntRing2k;
use crate::protocols::rep3_ring::ring::ring_impl::RingElement;
use crate::protocols::rep3_ring::{arithmetic, conversion};
use crate::protocols::{
    rep3::{self, arithmetic::FieldShare},
    rep3_ring::Rep3RingShare,
};
use ark_ff::{One, PrimeField, Zero};
use mpc_net::Network;
use num_bigint::BigUint;
use rand::distributions::Standard;
use rand::prelude::Distribution;

// u32 allows to sort 4*10^9 elements. Inputs of this size require 32*4*10^9*2 bytes, i.e., 256 GB of RAM
type PermRing = u32;

/// Sorts the inputs (both public and shared, where shared is inputted *before* public) using an oblivious radix sort algorithm. Thereby, only the lowest `bitsize` bits are considered. The final results have the size of the inputs, i.e, are not shortened to bitsize.
/// We use the algorithm described in [https://eprint.iacr.org/2019/695.pdf](https://eprint.iacr.org/2019/695.pdf).
pub fn radix_sort_fields<F: PrimeField, N: Network>(
    mut priv_inputs: Vec<FieldShare<F>>,
    pub_inputs: Vec<F>,
    bitsize: usize,
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<Vec<FieldShare<F>>> {
    let len = priv_inputs.len() + pub_inputs.len();

    if len
        > PermRing::MAX
            .try_into()
            .expect("transformation of PermRing::MAX into usize failed")
    {
        eyre::bail!("Too many inputs for radix sort. Use a larger PermRing.");
    }

    let perm = gen_perm(
        &priv_inputs,
        &pub_inputs,
        bitsize,
        net0,
        net1,
        state0,
        state1,
    )?;
    priv_inputs.reserve(pub_inputs.len());

    // Does not matter whether inputs are shares or not
    for value in pub_inputs {
        priv_inputs.push(rep3::arithmetic::promote_to_trivial_share(state0.id, value));
    }
    apply_inv_field(&perm, &priv_inputs, net0, net1, state0, state1)
}

/// Sorts the inputs (both public and shared) using an oblivious radix sort algorithm according to the permutation which comes from sorting the input `key` (but it is not applied to `key`). The values public/shared values need to be organized to match the order given in `order` (false means a public value, true means a private value). Thereby, only the lowest `bitsize` bits are considered. The final results have the size of the inputs, i.e, are not shortened to bitsize. The resulting permutation is then used to sort the vectors in `inputs`.
/// We use the algorithm described in [https://eprint.iacr.org/2019/695.pdf](https://eprint.iacr.org/2019/695.pdf).
#[expect(clippy::too_many_arguments)]
pub fn radix_sort_fields_vec_by<F: PrimeField, N: Network>(
    priv_key: &[FieldShare<F>],
    pub_key: &[F],
    order: &[bool],
    inputs: Vec<&[FieldShare<F>]>,
    bitsize: usize,
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<Vec<Vec<FieldShare<F>>>> {
    let len = priv_key.len() + pub_key.len();
    if len
        > PermRing::MAX
            .try_into()
            .expect("transformation of PermRing::MAX into usize failed")
    {
        eyre::bail!("Too many inputs for radix sort. Use a larger PermRing.");
    }
    let mut results = Vec::with_capacity(inputs.len());
    let perm = gen_perm_ordered(
        priv_key, pub_key, order, bitsize, net0, net1, state0, state1,
    )?;
    for inp in inputs {
        results.push(apply_inv_field(&perm, inp, net0, net1, state0, state1)?)
    }
    Ok(results)
}

fn decompose<F: PrimeField, N: Network>(
    priv_inputs: &[FieldShare<F>],
    bitsize: usize,
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<Vec<Rep3BigUintShare<F>>> {
    let mask = (BigUint::one() << bitsize) - BigUint::one();
    let mut priv_bits = vec![Rep3BigUintShare::zero_share(); priv_inputs.len()];
    let (split1, split2) = priv_bits.split_at_mut(priv_inputs.len() / 2);
    let mut result1 = None;
    let mut result2 = None;

    // TODO: This step could be optimized (I: Pack the a2b's, II: only reconstruct bitsize bits)
    mpc_net::join(
        || {
            for (i, inp) in priv_inputs.iter().take(priv_inputs.len() / 2).enumerate() {
                let binary = rep3::conversion::a2b_selector(inp.to_owned(), net0, state0);
                if let Err(err) = binary {
                    result1 = Some(err);
                    break;
                }
                let mut binary = binary.unwrap();
                binary &= &mask;
                split1[i] = binary;
            }
        },
        || {
            for (i, inp) in priv_inputs.iter().skip(priv_inputs.len() / 2).enumerate() {
                let binary = rep3::conversion::a2b_selector(inp.to_owned(), net1, state1);
                if let Err(err) = binary {
                    result2 = Some(err);
                    break;
                }
                let mut binary = binary.unwrap();
                binary &= &mask;
                split2[i] = binary;
            }
        },
    );

    if let Some(err) = result1 {
        return Err(err);
    }
    if let Some(err) = result2 {
        return Err(err);
    }

    Ok(priv_bits)
}

fn gen_perm<F: PrimeField, N: Network>(
    priv_inputs: &[FieldShare<F>],
    pub_inputs: &[F],
    bitsize: usize,
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<PermRing>>> {
    // Decompose all private inputs
    let priv_bits = decompose(priv_inputs, bitsize, net0, net1, state0, state1)?;

    let priv_bit_0 = inject_bit(&priv_bits, 0, net0, state0)?;
    let pub_bit_0 = inject_public_bit(pub_inputs, 0);
    let mut perm = gen_bit_perm(priv_bit_0, pub_bit_0, net0, state0)?;

    for i in 1..bitsize {
        let priv_bit_i = inject_bit(&priv_bits, i, net0, state0)?;
        let pub_bit_i = inject_public_bit(pub_inputs, i);
        let bit_i = apply_inv(&perm, &priv_bit_i, &pub_bit_i, net0, net1, state0, state1)?;
        let perm_i = gen_bit_perm(bit_i, vec![], net0, state0)?;
        perm = compose(perm, perm_i, net0, state0)?;
    }

    Ok(perm)
}

fn order_and_promote_inputs(
    priv_inputs: Vec<Rep3RingShare<PermRing>>,
    pub_inputs: Vec<RingElement<PermRing>>,
    order: &[bool],
    id: PartyID,
) -> Vec<Rep3RingShare<PermRing>> {
    assert_eq!(priv_inputs.len(), order.iter().filter(|x| **x).count());
    assert_eq!(pub_inputs.len(), order.iter().filter(|x| !**x).count());
    let mut perm = Vec::with_capacity(order.len());
    let mut priv_iter = priv_inputs.into_iter();
    let mut pub_iter = pub_inputs.into_iter();
    for order in order {
        if *order {
            perm.push(priv_iter.next().expect("Checked lengths"));
        } else {
            let val =
                arithmetic::promote_to_trivial_share(id, pub_iter.next().expect("Checked lengths"));
            perm.push(val);
        }
    }
    perm
}

#[expect(clippy::too_many_arguments)]
fn gen_perm_ordered<F: PrimeField, N: Network>(
    priv_inputs: &[FieldShare<F>],
    pub_inputs: &[F],
    order: &[bool],
    bitsize: usize,
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<PermRing>>> {
    // Decompose all private inputs
    let priv_bits = decompose(priv_inputs, bitsize, net0, net1, state0, state1)?;

    let priv_bit_0 = inject_bit(&priv_bits, 0, net0, state0)?;
    let pub_bit_0 = inject_public_bit(pub_inputs, 0);
    let perm = order_and_promote_inputs(priv_bit_0, pub_bit_0, order, state0.id);
    let mut perm = gen_bit_perm(perm, vec![], net0, state0)?; // This first permutation could be optimized by not promoting the public bits

    for i in 1..bitsize {
        let priv_bit_i = inject_bit(&priv_bits, i, net0, state0)?;
        let pub_bit_i = inject_public_bit(pub_inputs, i);
        let bit_i = order_and_promote_inputs(priv_bit_i, pub_bit_i, order, state0.id);
        let bit_i = apply_inv(&perm, &bit_i, &[], net0, net1, state0, state1)?;
        let perm_i = gen_bit_perm(bit_i, vec![], net0, state0)?;
        perm = compose(perm, perm_i, net0, state0)?;
    }

    Ok(perm)
}

fn inject_public_bit<F: PrimeField>(inputs: &[F], bit: usize) -> Vec<RingElement<PermRing>> {
    let len = inputs.len();
    let mut bits = Vec::with_capacity(len);
    for inp in inputs.iter().cloned() {
        let inp: BigUint = inp.into();
        bits.push(RingElement(inp.bit(bit as u64) as PermRing));
    }
    bits
}

fn inject_bit<F: PrimeField, N: Network>(
    inputs: &[Rep3BigUintShare<F>],
    bit: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<PermRing>>> {
    let len = inputs.len();
    let mut bits = Vec::with_capacity(len);
    for inp in inputs {
        let a = inp.a.bit(bit as u64) as PermRing;
        let b = inp.b.bit(bit as u64) as PermRing;
        bits.push(Rep3RingShare::new_ring(a.into(), b.into()));
    }
    conversion::bit_inject_many(&bits, net, state)
}

fn gen_bit_perm<N: Network>(
    priv_bits: Vec<Rep3RingShare<PermRing>>,
    pub_bits: Vec<RingElement<PermRing>>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<PermRing>>> {
    let priv_len = priv_bits.len();
    let pub_len = pub_bits.len();
    let len = priv_len + pub_len;
    let id = state.id;

    // Private inputs
    let mut priv_f0 = Vec::with_capacity(priv_len);
    let mut priv_f1 = Vec::with_capacity(priv_len);
    for inp in priv_bits {
        priv_f0.push(arithmetic::add_public(-inp, RingElement::one(), id));
        priv_f1.push(inp);
    }

    // Public inputs
    let mut pub_f0 = Vec::with_capacity(pub_len);
    let mut pub_f1 = Vec::with_capacity(pub_len);
    for inp in pub_bits {
        pub_f0.push(RingElement::one() - inp);
        pub_f1.push(inp);
    }

    let mut s = Rep3RingShare::zero_share();
    let mut s0 = Vec::with_capacity(len);
    let mut s1 = Vec::with_capacity(len);
    // Add both private and public inputs to s0/s1
    for f in priv_f0.iter() {
        s = arithmetic::add(s, *f);
        s0.push(s);
    }
    for f in pub_f0.iter() {
        s = arithmetic::add_public(s, *f, id);
        s0.push(s);
    }
    for f in priv_f1.iter() {
        s = arithmetic::add(s, *f);
        s1.push(s);
    }
    for f in pub_f1.iter() {
        s = arithmetic::add_public(s, *f, id);
        s1.push(s);
    }

    // Private inputs
    let mul1 = arithmetic::local_mul_vec(&priv_f0, &s0[..priv_len], state);
    let mul2 = arithmetic::local_mul_vec(&priv_f1, &s1[..priv_len], state);
    let perm_a = mul1.into_iter().zip(mul2).map(|(a, b)| a + b).collect();
    let mut perm = arithmetic::reshare_vec(perm_a, net)?;

    // Public inputs
    for (s, f) in s0[priv_len..].iter_mut().zip(pub_f0) {
        arithmetic::mul_assign_public(s, f);
    }
    for (s, f) in s1[priv_len..].iter_mut().zip(pub_f1) {
        arithmetic::mul_assign_public(s, f);
    }
    for (s0, s1) in s0[priv_len..].iter_mut().zip(s1[priv_len..].iter()) {
        arithmetic::add_assign(s0, *s1);
    }
    perm.extend_from_slice(&s0[priv_len..]);

    Ok(perm)
}

fn apply_inv<T: IntRing2k, N: Network>(
    rho: &[Rep3RingShare<PermRing>],
    priv_bits: &[Rep3RingShare<T>],
    pub_bits: &[RingElement<T>],
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let len = rho.len();
    debug_assert_eq!(len, priv_bits.len() + pub_bits.len());

    let unshuffled = (0..len as PermRing).collect::<Vec<_>>();
    let (perm_a, perm_b) = state0.rngs.rand.random_perm(unshuffled);
    let perm: Vec<_> = perm_a
        .into_iter()
        .zip(perm_b)
        .map(|(a, b)| Rep3RingShare::new(a, b))
        .collect();

    let (opened, bits_shuffled) = mpc_net::join(
        || shuffle_reveal::<PermRing, _>(&perm, rho, net0, state0),
        || shuffle(&perm, priv_bits, pub_bits, net1, state1),
    );
    let mut result = vec![Rep3RingShare::zero_share(); len];
    for (p, b) in opened?.into_iter().zip(bits_shuffled?) {
        result[p.0 as usize - 1] = b;
    }
    Ok(result)
}

fn apply_inv_field<F: PrimeField, N: Network>(
    rho: &[Rep3RingShare<PermRing>],
    bits: &[Rep3PrimeFieldShare<F>],
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let len = rho.len();
    debug_assert_eq!(len, bits.len());

    let unshuffled = (0..len as PermRing).collect::<Vec<_>>();
    let (perm_a, perm_b) = state0.rngs.rand.random_perm(unshuffled);
    let perm: Vec<_> = perm_a
        .into_iter()
        .zip(perm_b)
        .map(|(a, b)| Rep3RingShare::new(a, b))
        .collect();

    let (opened, bits_shuffled) = mpc_net::join(
        || shuffle_reveal(&perm, rho, net0, state0),
        || shuffle_field(&perm, bits, net1, state1),
    );
    let mut result = vec![Rep3PrimeFieldShare::zero_share(); len];
    for (p, b) in opened?.into_iter().zip(bits_shuffled?) {
        result[p.0 as usize - 1] = b;
    }
    Ok(result)
}

fn compose<N: Network>(
    sigma: Vec<Rep3RingShare<PermRing>>,
    phi: Vec<Rep3RingShare<PermRing>>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<PermRing>>> {
    let len = sigma.len();
    debug_assert_eq!(len, phi.len());

    let unshuffled = (0..len as PermRing).collect::<Vec<_>>();
    let (perm_a, perm_b) = state.rngs.rand.random_perm(unshuffled);
    let perm: Vec<_> = perm_a
        .into_iter()
        .zip(perm_b)
        .map(|(a, b)| Rep3RingShare::new(a, b))
        .collect();

    let opened = shuffle_reveal(&perm, &sigma, net, state)?;
    let mut shuffled = Vec::with_capacity(len);
    for p in opened {
        shuffled.push(phi[p.0 as usize - 1]);
    }
    unshuffle(&perm, &shuffled, net, state)
}

fn shuffle<T: IntRing2k, N: Network>(
    pi: &[Rep3RingShare<PermRing>],
    priv_input: &[Rep3RingShare<T>],
    pub_input: &[RingElement<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let len = pi.len();
    debug_assert_eq!(len, priv_input.len() + pub_input.len());
    let result = match state.id {
        PartyID::ID0 => {
            // has p1, p3
            let mut alpha_1 = Vec::with_capacity(len);
            let mut alpha_3 = Vec::with_capacity(len);
            let mut beta_1 = Vec::with_capacity(len);
            for a in priv_input {
                let (alpha_1_, alpha_3_) = state.rngs.rand.random_elements::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                alpha_3.push(alpha_3_);
                beta_1.push(a.a + a.b);
            }
            for a in pub_input {
                let (alpha_1_, alpha_3_) = state.rngs.rand.random_elements::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                alpha_3.push(alpha_3_);
                beta_1.push(*a); // a.a is public share
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
            net.send_next_many(&shuffled_3)?;

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            for _ in 0..len {
                let (a, b) = state.rngs.rand.random_elements::<RingElement<T>>();
                result.push(Rep3RingShare::new_ring(a, b));
            }
            result
        }
        PartyID::ID1 => {
            // has p2, p1
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for a in priv_input {
                let alpha_1_ = state.rngs.rand.random_element_rng2::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                beta_2.push(a.a);
            }
            for _ in pub_input {
                let alpha_1_ = state.rngs.rand.random_element_rng2::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                beta_2.push(RingElement::zero()); // a.a is 0
            }

            // first shuffle
            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                let pi_1 = pi.b.0 as usize;
                shuffled_1.push(beta_2[pi_1] + alpha);
            }
            let delta = net.reshare_many(&shuffled_1)?;
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
                let b = state.rngs.rand.random_element_rng2::<RingElement<T>>();
                rand.push(beta - b);
                result.push(Rep3RingShare::new_ring(RingElement::zero(), b));
            }
            let rcv: Vec<RingElement<T>> =
                net.send_and_recv_many(PartyID::ID2, &rand, PartyID::ID2)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.a = r1 + r2;
            }
            result
        }
        PartyID::ID2 => {
            // has p3, p2
            let mut alpha_3 = Vec::with_capacity(len);
            for _ in 0..len {
                let alpha_3_ = state.rngs.rand.random_element_rng1::<RingElement<T>>();
                alpha_3.push(alpha_3_);
            }
            let gamma: Vec<RingElement<T>> = net.recv_prev_many()?;
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
                let a = state.rngs.rand.random_element_rng1::<RingElement<T>>();
                rand.push(beta - a);
                result.push(Rep3RingShare::new_ring(a, RingElement::zero()));
            }
            let rcv: Vec<RingElement<T>> =
                net.send_and_recv_many(PartyID::ID1, &rand, PartyID::ID1)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.b = r1 + r2;
            }
            result
        }
    };
    Ok(result)
}

fn shuffle_field<F: PrimeField, N: Network>(
    pi: &[Rep3RingShare<PermRing>],
    input: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let len = pi.len();
    debug_assert_eq!(len, input.len());
    let result = match state.id {
        PartyID::ID0 => {
            // has p1, p3
            let mut alpha_1 = Vec::with_capacity(len);
            let mut alpha_3 = Vec::with_capacity(len);
            let mut beta_1 = Vec::with_capacity(len);
            for a in input {
                let (alpha_1_, alpha_3_) = state.rngs.rand.random_fes::<F>();
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
            net.send_next_many(&shuffled_3)?;

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            for _ in 0..len {
                let (a, b) = state.rngs.rand.random_fes::<F>();
                result.push(Rep3PrimeFieldShare::new(a, b));
            }
            result
        }
        PartyID::ID1 => {
            // has p2, p1
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for a in input {
                let alpha_1_ = state.rngs.rand.random_field_element_rng2::<F>();
                alpha_1.push(alpha_1_);
                beta_2.push(a.a);
            }

            // first shuffle
            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                let pi_1 = pi.b.0 as usize;
                shuffled_1.push(beta_2[pi_1] + alpha);
            }
            let delta = net.reshare_many(&shuffled_1)?;
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
                let b = state.rngs.rand.random_field_element_rng2::<F>();
                rand.push(beta - b);
                result.push(Rep3PrimeFieldShare::new(F::zero(), b));
            }
            let rcv: Vec<F> = net.send_and_recv_many(PartyID::ID2, &rand, PartyID::ID2)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.a = r1 + r2;
            }
            result
        }
        PartyID::ID2 => {
            // has p3, p2
            let mut alpha_3 = Vec::with_capacity(len);
            for _ in 0..len {
                let alpha_3_ = state.rngs.rand.random_field_element_rng1::<F>();
                alpha_3.push(alpha_3_);
            }
            let gamma: Vec<F> = net.recv_prev_many()?;
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
                let a = state.rngs.rand.random_field_element_rng1::<F>();
                rand.push(beta - a);
                result.push(Rep3PrimeFieldShare::new(a, F::zero()));
            }
            let rcv: Vec<F> = net.send_and_recv_many(PartyID::ID1, &rand, PartyID::ID1)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.b = r1 + r2;
            }
            result
        }
    };
    Ok(result)
}

fn shuffle_reveal<T: IntRing2k, N: Network>(
    pi: &[Rep3RingShare<PermRing>],
    input: &[Rep3RingShare<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<RingElement<T>>>
where
    Standard: Distribution<T>,
{
    let len = pi.len();
    debug_assert_eq!(len, input.len());
    let result = match state.id {
        PartyID::ID0 => {
            // has p1, p3
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_1 = Vec::with_capacity(len);
            for a in input {
                let alpha_1_ = state.rngs.rand.random_element_rng1::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                beta_1.push(a.a + a.b);
            }
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1.iter()) {
                let pi_1 = pi.a.0 as usize;
                shuffled.push(beta_1[pi_1] - alpha);
            }
            net.send_and_recv_many(PartyID::ID2, &shuffled, PartyID::ID2)?
        }
        PartyID::ID1 => {
            // has p2, p1
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for a in input {
                let alpha_1_ = state.rngs.rand.random_element_rng2::<RingElement<T>>();
                alpha_1.push(alpha_1_);
                beta_2.push(a.a);
            }
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                let pi_1 = pi.b.0 as usize;
                shuffled.push(beta_2[pi_1] + alpha);
            }
            net.send_and_recv_many(PartyID::ID2, &shuffled, PartyID::ID2)?
        }
        PartyID::ID2 => {
            let delta = net.recv_many::<RingElement<T>>(PartyID::ID0)?;
            let gamma = net.recv_many::<RingElement<T>>(PartyID::ID1)?;
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for p in pi {
                let pi_2 = p.b.0 as usize;
                let index = pi[pi_2].a.0 as usize;
                shuffled.push(gamma[index] + delta[index]);
            }
            let (send0, send1) = mpc_net::join(
                || net.send_many(PartyID::ID0, &shuffled),
                || net.send_many(PartyID::ID1, &shuffled),
            );
            send0?;
            send1?;
            shuffled
        }
    };
    Ok(result)
}

fn unshuffle<T: IntRing2k, N: Network>(
    pi: &[Rep3RingShare<PermRing>],
    input: &[Rep3RingShare<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let len = pi.len();
    debug_assert_eq!(len, input.len());
    let result = match state.id {
        PartyID::ID0 => {
            // has p1, p3
            let mut alpha_3 = Vec::with_capacity(len);
            for _ in 0..len {
                let alpha_3_ = state.rngs.rand.random_element_rng2::<RingElement<T>>();
                alpha_3.push(alpha_3_);
            }
            let gamma: Vec<RingElement<T>> = net.recv_many(PartyID::ID1)?;
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
                let b = state.rngs.rand.random_element_rng2::<RingElement<T>>();
                rand.push(beta - b);
                result.push(Rep3RingShare::new_ring(RingElement::zero(), b));
            }
            let rcv: Vec<RingElement<T>> =
                net.send_and_recv_many(PartyID::ID1, &rand, PartyID::ID1)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.a = r1 + r2;
            }
            result
        }
        PartyID::ID1 => {
            // has p2, p1
            let mut alpha_2 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for a in input {
                let alpha_2_ = state.rngs.rand.random_element_rng1::<RingElement<T>>();
                alpha_2.push(alpha_2_);
                beta_2.push(a.b);
            }
            // first shuffle
            let mut shuffled_3 = vec![RingElement::zero(); len];
            for (pi, (alpha, beta_2)) in pi.iter().zip(alpha_2.into_iter().zip(beta_2.iter())) {
                let pi_2 = pi.a.0 as usize;
                shuffled_3[pi_2] = alpha + beta_2;
            }
            let delta = net.send_and_recv_many(PartyID::ID0, &shuffled_3, PartyID::ID2)?;
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
                let a = state.rngs.rand.random_element_rng1::<RingElement<T>>();
                rand.push(beta - a);
                result.push(Rep3RingShare::new_ring(a, RingElement::zero()));
            }
            let rcv: Vec<RingElement<T>> =
                net.send_and_recv_many(PartyID::ID0, &rand, PartyID::ID0)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.b = r1 + r2;
            }
            result
        }
        PartyID::ID2 => {
            // has p3, p2
            let mut alpha_3 = Vec::with_capacity(len);
            let mut alpha_2 = Vec::with_capacity(len);
            let mut beta_3 = Vec::with_capacity(len);
            for a in input {
                let (alpha_3_, alpha_2_) = state.rngs.rand.random_elements::<RingElement<T>>();
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
            net.send_many(PartyID::ID1, &shuffled_2)?;

            // Opt Reshare
            let mut result = Vec::with_capacity(len);
            for _ in 0..len {
                let (a, b) = state.rngs.rand.random_elements::<RingElement<T>>();
                result.push(Rep3RingShare::new_ring(a, b));
            }
            result
        }
    };
    Ok(result)
}
