//! Circuits
//!
//! This module contains some garbled circuit implementations.

use crate::protocols::rep3::yao::GCUtils;
use ark_ff::PrimeField;
use fancy_garbling::{BinaryBundle, FancyBinary};
use itertools::izip;
use num_bigint::BigUint;
use std::ops::Not;

/// This trait allows to lazily initialize the constants 0 and 1 for the garbled circuit, such that these constants are only send at most once each.
pub trait FancyBinaryConstant: FancyBinary {
    /// Takes an already initialized constant 0 or adds it to the garbled circuit if not yet present
    fn const_zero(&mut self) -> Result<Self::Item, Self::Error>;

    /// Takes an already initialized constant 1 or adds it to the garbled circuit if not yet present
    fn const_one(&mut self) -> Result<Self::Item, Self::Error>;
}

/// This struct contains some predefined garbled circuits.
pub struct GarbledCircuits {}

impl GarbledCircuits {
    fn constant_bundle_from_u32<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        c: u32,
        size: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut result = Vec::with_capacity(size);

        for i in 0..size {
            result.push((c >> i) & 1 != 0);
        }

        Ok(result
            .into_iter()
            .map(|bit| if bit { g.const_one() } else { g.const_zero() })
            .collect::<Result<Vec<G::Item>, G::Error>>()?[..size]
            .to_vec())
    }
    fn shift_left<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        a: &[G::Item],
        shift: usize,
        size: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut result = a.to_owned();
        result.resize(size * 2, g.const_zero()?);
        result.rotate_right(shift);
        Ok(result[..size].to_vec())
    }
    fn shift_right<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        a: &[G::Item],
        shift: usize,
        size: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut result = a.to_owned();
        result.resize(size * 2, g.const_zero()?);
        result.rotate_left(shift);
        Ok(result[..size].to_vec())
    }

    fn full_adder_const<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: bool,
        c: &G::Item,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let (s, c) = if b {
            let z1 = g.negate(a)?;
            let s = g.xor(&z1, c)?;
            let z3 = g.xor(a, c)?;
            let z4 = g.and(&z1, &z3)?;
            let c = g.xor(&z4, a)?;
            (s, c)
        } else {
            let z1 = a;
            let s = g.xor(z1, c)?;
            let z3 = &s;
            let z4 = g.and(z1, z3)?;
            let c = g.xor(&z4, a)?;
            (s, c)
        };

        Ok((s, c))
    }

    fn half_adder<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let s = g.xor(a, b)?;
        let c = g.and(a, b)?;
        Ok((s, c))
    }

    /// Full adder, just outputs carry
    fn full_adder_carry<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
        c: &G::Item,
    ) -> Result<G::Item, G::Error> {
        let z1 = g.xor(a, b)?;
        let z3 = g.xor(a, c)?;
        let z4 = g.and(&z1, &z3)?;
        let c = g.xor(&z4, a)?;
        Ok(c)
    }

    fn full_adder<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
        c: &G::Item,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let z1 = g.xor(a, b)?;
        let s = g.xor(&z1, c)?;
        let z3 = g.xor(a, c)?;
        let z4 = g.and(&z1, &z3)?;
        let c = g.xor(&z4, a)?;
        Ok((s, c))
    }

    /// Full adder with carry in set
    fn full_adder_cin_set<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let z1 = g.xor(a, b)?;
        let s = g.negate(&z1)?;
        let z3 = g.negate(a)?;
        let z4 = g.and(&z1, &z3)?;
        let c = g.xor(&z4, a)?;
        Ok((s, c))
    }
    /// Full adder with carry in set
    fn full_adder_const_cin_set<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        a: &G::Item,
        b: bool,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let (s, c) = if b {
            (a.clone(), g.const_one()?)
        } else {
            (g.negate(a)?, a.clone())
        };
        Ok((s, c))
    }

    /// Full adder with carry in set, just outputs carry
    fn full_adder_carry_cin_set<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
    ) -> Result<G::Item, G::Error> {
        let z1 = g.xor(a, b)?;
        let z3 = g.negate(a)?;
        let z4 = g.and(&z1, &z3)?;
        let c = g.xor(&z4, a)?;
        Ok(c)
    }

    /// Binary addition. Returns the result and the carry.
    #[expect(clippy::type_complexity)]
    fn bin_addition<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        let mut result = Vec::with_capacity(xs.len());

        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        result.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            result.push(s);
        }

        Ok((result, c))
    }

    /// Binary addition. Returns just the result.
    fn bin_addition_no_carry<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        if xs.len() == 1 {
            return Ok(vec![g.xor(&xs[0], &ys[0])?]);
        }

        let mut result = Vec::with_capacity(xs.len());

        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        result.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).take(xs.len() - 1).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            result.push(s);
        }

        // Finally, just the xor of the full_adder
        let z1 = g.xor(xs.last().unwrap(), ys.last().unwrap())?;
        let s = g.xor(&z1, &c)?;
        result.push(s);

        Ok(result)
    }

    /// Binary subtraction. Returns the result and whether it underflowed.
    /// I.e., calculates 2^k + x1 - x2
    #[expect(clippy::type_complexity)]
    fn bin_subtraction<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        let mut result = Vec::with_capacity(xs.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required

        let y0 = g.negate(&ys[0])?;
        let (mut s, mut c) = Self::full_adder_cin_set(g, &xs[0], &y0)?;
        result.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let y = g.negate(y)?;
            let res = Self::full_adder(g, x, &y, &c)?;
            s = res.0;
            c = res.1;
            result.push(s);
        }

        Ok((result, c))
    }

    /// Needed for subtraction in binary division (for shared/shared) where xs is (conceptually) a constant 0 bundle with only some values set
    #[expect(clippy::type_complexity)]
    fn bin_subtraction_partial<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        let mut result = Vec::with_capacity(xs.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required
        let length = xs.len();
        let y0 = g.negate(&ys[0])?;
        let (mut s, mut c) = Self::full_adder_cin_set(g, &xs[0], &y0)?;
        result.push(s);
        if xs.len() > 1 {
            for (x, y) in xs.iter().zip(ys.iter().take(xs.len())).skip(1) {
                let y = g.negate(y)?;
                let res = Self::full_adder(g, x, &y, &c)?;
                s = res.0;
                c = res.1;
                result.push(s);
            }
        }
        for y in ys[length..].iter() {
            let y = g.negate(y)?;
            // FULL ADDER with a=0 (x=0)
            s = g.xor(&y, &c)?;
            c = g.and(&y, &c)?;
            result.push(s);
        }
        Ok((result, c))
    }

    /// Needed for subtraction in binary division (for shared/public) where xs is (conceptually) a constant 0 bundle with only some values set and the subtrahend is a constant/public
    #[expect(clippy::type_complexity)]
    fn bin_subtraction_partial_by_constant<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[bool],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        let mut result = Vec::with_capacity(xs.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required
        let length = xs.len();
        let y0 = &ys[0].not();
        let (mut s, mut c) = Self::full_adder_const_cin_set(g, &xs[0], *y0)?;
        result.push(s);
        if xs.len() > 1 {
            for (x, y) in xs.iter().zip(ys.iter().take(xs.len())).skip(1) {
                let y = y.not();
                let res = Self::full_adder_const(g, x, y, &c)?;
                s = res.0;
                c = res.1;
                result.push(s);
            }
        }
        for y in ys[length..].iter() {
            // FULL ADDER with a=0 (x=0)
            (s, c) = if *y {
                (c, g.const_zero()?)
            } else {
                (g.negate(&c)?, c)
            };
            result.push(s);
        }
        Ok((result, c))
    }

    /// Needed for subtraction in binary division (public/shared) where xs is (conceptually) a constant 0 bundle with only some constant/public values set
    #[expect(clippy::type_complexity)]
    fn bin_subtraction_partial_from_constant<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        xs: &[bool],
        ys: &[G::Item],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        let mut result = Vec::with_capacity(xs.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required
        let length = xs.len();
        let y0 = g.negate(&ys[0])?;
        let (mut s, mut c) = Self::full_adder_const_cin_set(g, &y0, xs[0])?;
        result.push(s);
        if xs.len() > 1 {
            for (x, y) in xs.iter().zip(ys.iter().take(xs.len())).skip(1) {
                let y = g.negate(y)?;
                let res = Self::full_adder_const(g, &y, *x, &c)?;
                s = res.0;
                c = res.1;
                result.push(s);
            }
        }
        if length < ys.len() {
            for y in ys[length..].iter() {
                let y = g.negate(y)?;
                // FULL ADDER with a=0 (x=0)
                s = g.xor(&y, &c)?;
                c = g.and(&y, &c)?;
                result.push(s);
            }
        }
        Ok((result, c))
    }

    /// Binary subtraction. Returns whether it underflowed.
    /// I.e., calculates the msb of 2^k + x1 - x2
    fn bin_subtraction_get_carry_only<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required

        let y0 = g.negate(&ys[0])?;
        let mut c = Self::full_adder_carry_cin_set(g, &xs[0], &y0)?;

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let y = g.negate(y)?;
            c = Self::full_adder_carry(g, x, &y, &c)?;
        }

        Ok(c)
    }

    // From swanky:
    /// Binary division
    fn bin_div<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        dividend: &[G::Item],
        divisor: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut acc: Vec<G::Item> = Vec::with_capacity(dividend.len());
        let mut qs: Vec<G::Item> = vec![];
        for x in dividend.iter().rev() {
            if acc.len() == dividend.len() {
                acc.pop();
            }
            acc.insert(0, x.clone());

            let (res, cout) = Self::bin_subtraction_partial(g, &acc, divisor)?;

            acc = Self::bin_multiplex(g, &cout, &acc, &res)?;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }

    // From swanky:
    /// Binary division by a public value
    fn bin_div_by_public<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        dividend: &[G::Item],
        divisor: &[bool],
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut acc: Vec<G::Item> = Vec::with_capacity(dividend.len());
        let mut qs: Vec<G::Item> = vec![];
        for x in dividend.iter().rev() {
            if acc.len() == dividend.len() {
                acc.pop();
            }
            acc.insert(0, x.clone());

            let (res, cout) = Self::bin_subtraction_partial_by_constant(g, &acc, divisor)?;

            acc = Self::bin_multiplex(g, &cout, &acc, &res)?;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }

    // From swanky:
    /// Binary division of a public by a shared value
    fn bin_div_by_shared<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        dividend: &[bool],
        divisor: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut acc: Vec<bool> = vec![false; divisor.len() - 1];
        let mut acc_g;
        let mut qs: Vec<G::Item> = vec![];
        acc.insert(0, *dividend.last().unwrap());

        let (res, cout) = Self::bin_subtraction_partial_from_constant(g, &acc, divisor)?;

        acc_g = Self::bin_multiplex_const(g, &cout, &acc, &res)?;
        qs.push(cout);
        for x in dividend.iter().rev().skip(1) {
            if acc_g.len() == divisor.len() {
                acc_g.pop();
            }
            acc_g.insert(0, if *x { g.const_one()? } else { g.const_zero()? });
            let (res, cout) = Self::bin_subtraction(g, &acc_g, divisor)?;
            let mut acc_g_tmp = Vec::with_capacity(res.len());
            // this is the first part of the multiplex as the "first" entry is a public bool
            acc_g_tmp.insert(0, {
                if *x {
                    let cout_not = g.negate(&cout)?;
                    g.or(&cout_not, &res[0])?
                } else {
                    g.and(&cout, &res[0])?
                }
            });
            acc_g_tmp.extend(Self::bin_multiplex(g, &cout, &acc_g[1..], &res[1..])?);
            acc_g = acc_g_tmp;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }

    /// Multiplex gadget for binary bundles
    fn bin_multiplex<G: FancyBinary>(
        g: &mut G,
        b: &G::Item,
        x: &[G::Item],
        y: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        x.iter()
            .zip(y.iter())
            .map(|(xwire, ywire)| g.mux(b, xwire, ywire))
            .collect::<Result<Vec<G::Item>, G::Error>>()
    }

    /// Multiplex gadget for public/shared
    fn bin_multiplex_const<G: FancyBinary>(
        g: &mut G,
        b: &G::Item,
        x: &[bool],
        y: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        x.iter()
            .zip(y.iter())
            .map(|(xwire, ywire)| {
                if *xwire {
                    let b_not = g.negate(b)?;
                    g.or(&b_not, ywire)
                } else {
                    g.and(b, ywire)
                }
            })
            .collect::<Result<Vec<G::Item>, G::Error>>()
    }

    /// Subtracts p from wires (with carry) and returns the result and the overflow bit.
    #[expect(clippy::type_complexity)]
    fn sub_p<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires: &[G::Item],
        carry: G::Item,
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        let bitlen = wires.len();
        debug_assert_eq!(bitlen, F::MODULUS_BIT_SIZE as usize);

        // Prepare p for subtraction
        let new_bitlen = bitlen + 1;
        let p_ = (BigUint::from(1u64) << new_bitlen) - F::MODULUS.into();
        let p_bits = GCUtils::biguint_to_bits(&p_, new_bitlen);

        // manual_rca:
        let mut subtracted = Vec::with_capacity(bitlen);
        // half_adder:
        debug_assert!(p_bits[0]);
        let s = g.negate(&wires[0])?;
        subtracted.push(s);
        let mut c = wires[0].to_owned();
        // full_adders:
        for (a, b) in wires.iter().zip(p_bits.iter()).skip(1) {
            let (s, c_) = Self::full_adder_const(g, a, *b, &c)?;
            c = c_;
            subtracted.push(s);
        }
        // final_full_adder to get ov bit
        let z = if p_bits[bitlen] {
            g.negate(&carry)?
        } else {
            carry
        };
        let ov = g.xor(&z, &c)?;

        Ok((subtracted, ov))
    }

    fn sub_p_and_mux_with_output_size<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires: &[G::Item],
        carry: G::Item,
        outlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let (subtracted, ov) = Self::sub_p::<_, F>(g, wires, carry)?;

        // multiplex for result
        let mut result = Vec::with_capacity(outlen);
        for (s, a) in subtracted.iter().zip(wires.iter()).take(outlen) {
            // CMUX
            let r = g.mux(&ov, s, a)?;
            result.push(r);
        }

        Ok(result)
    }

    /// Adds two shared field elements mod p. The field elements are encoded as Yao shared wires. The output is only of size outlen.
    fn adder_mod_p_with_output_size<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        outlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let bitlen = wires_a.len();
        debug_assert_eq!(bitlen, wires_b.len());
        debug_assert_eq!(bitlen, F::MODULUS_BIT_SIZE as usize);

        // First addition
        let (added, carry_add) = Self::bin_addition(g, wires_a, wires_b)?;

        let result = Self::sub_p_and_mux_with_output_size::<_, F>(g, &added, carry_add, outlen)?;
        Ok(result)
    }

    /// Adds two shared field elements mod p. The field elements are encoded as Yao shared wires.
    pub fn adder_mod_p<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let bitlen = wires_a.size();
        debug_assert_eq!(bitlen, wires_b.size());
        let res = Self::adder_mod_p_with_output_size::<_, F>(
            g,
            wires_a.wires(),
            wires_b.wires(),
            bitlen,
        )?;
        Ok(BinaryBundle::new(res))
    }

    /// Adds two shared ring elements mod 2^k. The ring elements are encoded as Yao shared wires.
    pub fn adder_mod_2k<G: FancyBinary>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let res = Self::bin_addition_no_carry(g, wires_a.wires(), wires_b.wires())?;
        Ok(BinaryBundle::new(res))
    }

    /// XORs two bundles of wires. Does not require any network interaction.
    pub(crate) fn xor_many<G: FancyBinary>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let bitlen = wires_a.size();
        debug_assert_eq!(bitlen, wires_b.size());

        let mut result = Vec::with_capacity(wires_a.size());
        for (a, b) in wires_a.wires().iter().zip(wires_b.wires().iter()) {
            let r = g.xor(a, b)?;
            result.push(r);
        }
        Ok(BinaryBundle::new(result))
    }

    /// XORs two bundles of wires. Does not require any network interaction.
    pub(crate) fn xor_many_as_wires<G: FancyBinary>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let bitlen = wires_a.len();
        debug_assert_eq!(bitlen, wires_b.len());

        let mut result = Vec::with_capacity(wires_a.len());
        for (a, b) in wires_a.iter().zip(wires_b.iter()) {
            let r = g.xor(a, b)?;
            result.push(r);
        }
        Ok(result)
    }

    fn compose_field_element<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        field_wires: &[G::Item],
        rand_wires: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = field_wires.len();
        debug_assert!(input_bitlen <= F::MODULUS_BIT_SIZE as usize);
        debug_assert_eq!(rand_wires.len(), F::MODULUS_BIT_SIZE as usize);
        // compose chunk_bits again
        // For the bin addition, our input is not of size F::ModulusBitSize, thus we can optimize a little bit

        if field_wires.is_empty() {
            return Ok(rand_wires.to_owned());
        }

        let mut added = Vec::with_capacity(input_bitlen);

        let xs = field_wires;
        let ys = rand_wires;

        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        added.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().skip(xs.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }

        Self::sub_p_and_mux_with_output_size::<_, F>(g, &added, c, F::MODULUS_BIT_SIZE as usize)
    }

    /// Decomposes a field element (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition ring elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    fn decompose_field_element_to_rings<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        num_decomps_per_field: usize,
        decompose_bitlen: usize,
        output_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let total_output_bitlen = decompose_bitlen * num_decomps_per_field;
        debug_assert_eq!(wires_a.len(), wires_b.len());
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, F::MODULUS_BIT_SIZE as usize);
        debug_assert!(decompose_bitlen <= total_output_bitlen);
        debug_assert_eq!(wires_c.len(), output_bitlen * num_decomps_per_field);
        debug_assert!(output_bitlen >= decompose_bitlen);

        let input_bits =
            Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, total_output_bitlen)?;

        let mut results = Vec::with_capacity(wires_c.len());

        for (xs, ys) in izip!(
            input_bits.chunks(decompose_bitlen),
            wires_c.chunks(output_bitlen),
        ) {
            // compose chunk_bits again
            // For the bin addition, our input is not guaranteed to be of size output_bitlen, thus we can optimize a little bit in some cases

            let mut added = Vec::with_capacity(output_bitlen);

            let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
            added.push(s);

            if ys.len() == 1 {
                results.extend(added);
                continue;
            }

            for (x, y) in xs.iter().zip(ys.iter()).take(ys.len() - 1).skip(1) {
                let res = Self::full_adder(g, x, y, &c)?;
                s = res.0;
                c = res.1;
                added.push(s);
            }
            for y in ys.iter().take(ys.len() - 1).skip(xs.len()) {
                let res = Self::full_adder_const(g, y, false, &c)?;
                s = res.0;
                c = res.1;
                added.push(s);
            }

            // Finally, just the xor of the full_adder
            if xs.len() == ys.len() {
                let z1 = g.xor(xs.last().unwrap(), ys.last().unwrap())?;
                let s = g.xor(&z1, &c)?;
                added.push(s);
            } else {
                added.push(g.xor(ys.last().unwrap(), &c)?);
            }
            results.extend(added);
        }

        Ok(results)
    }

    /// Decomposes a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition ring elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    pub(crate) fn decompose_field_element_to_rings_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        num_decomps_per_field: usize,
        decompose_bitlen: usize,
        output_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        let total_output_bitlen_per_field = decompose_bitlen * num_decomps_per_field;
        let total_output_elements = num_decomps_per_field * num_inputs;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(decompose_bitlen <= total_output_bitlen_per_field);
        debug_assert!(output_bitlen >= decompose_bitlen);
        debug_assert_eq!(wires_c.size(), output_bitlen * total_output_elements);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(output_bitlen * num_decomps_per_field)
        ) {
            let decomposed = Self::decompose_field_element_to_rings::<_, F>(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                num_decomps_per_field,
                decompose_bitlen,
                output_bitlen,
            )?;
            results.extend(decomposed);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Decomposes a field element (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition field elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    fn decompose_field_element<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        decompose_bitlen: usize,
        total_output_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let num_decomps_per_field = total_output_bitlen.div_ceil(decompose_bitlen);
        debug_assert_eq!(wires_a.len(), wires_b.len());
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, F::MODULUS_BIT_SIZE as usize);
        debug_assert!(input_bitlen >= total_output_bitlen);
        debug_assert!(decompose_bitlen <= total_output_bitlen);
        debug_assert_eq!(wires_c.len(), input_bitlen * num_decomps_per_field);

        let input_bits =
            Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, total_output_bitlen)?;

        let mut results = Vec::with_capacity(wires_c.len());

        for (xs, ys) in izip!(
            input_bits.chunks(decompose_bitlen),
            wires_c.chunks(input_bitlen),
        ) {
            let result = Self::compose_field_element::<_, F>(g, xs, ys)?;
            results.extend(result);
        }

        Ok(results)
    }

    /// Decomposes a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition field elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    pub(crate) fn decompose_field_element_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        decompose_bitlen: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(decompose_bitlen);
        let total_output_elements = num_decomps_per_field * num_inputs;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(input_bitlen >= total_output_bitlen_per_field);
        debug_assert!(decompose_bitlen <= total_output_bitlen_per_field);
        debug_assert_eq!(wires_c.size(), input_bitlen * total_output_elements);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen * num_decomps_per_field)
        ) {
            let decomposed = Self::decompose_field_element::<_, F>(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                decompose_bitlen,
                total_output_bitlen_per_field,
            )?;
            results.extend(decomposed);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Slices a field element (represented as two bitdecompositions wires_a, wires_b which need to be added first) at given indices (msb, lsb), both included in the slice. For the bitcomposition, wires_c are used.
    fn slice_field_element<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        msb: usize,
        lsb: usize,
        bitsize: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.len(), wires_b.len());
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, F::MODULUS_BIT_SIZE as usize);
        debug_assert!(input_bitlen >= bitsize);
        debug_assert!(msb >= lsb);
        debug_assert!(msb < bitsize);
        debug_assert_eq!(wires_c.len(), input_bitlen * 3);

        let input_bits = Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, bitsize)?;
        let mut rands = wires_c.chunks(input_bitlen);

        let lo = Self::compose_field_element::<_, F>(g, &input_bits[..lsb], rands.next().unwrap())?;
        let slice =
            Self::compose_field_element::<_, F>(g, &input_bits[lsb..=msb], rands.next().unwrap())?;

        let hi = if msb == bitsize {
            Self::compose_field_element::<_, F>(g, &[], rands.next().unwrap())?
        } else {
            Self::compose_field_element::<_, F>(
                g,
                &input_bits[msb + 1..bitsize],
                rands.next().unwrap(),
            )?
        };

        let mut results = lo;
        results.extend(slice);
        results.extend(hi);

        Ok(results)
    }

    /// Slices a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first) at given indices (msb, lsb), both included in the slice. For the bitcomposition, wires_c are used.
    pub(crate) fn slice_field_element_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        msb: usize,
        lsb: usize,
        bitsize: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        let total_output_elements = 3 * num_inputs;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(input_bitlen >= bitsize);
        debug_assert!(msb >= lsb);
        debug_assert!(msb < bitsize);
        debug_assert_eq!(wires_c.size(), input_bitlen * total_output_elements);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen * 3)
        ) {
            let sliced =
                Self::slice_field_element::<_, F>(g, chunk_a, chunk_b, chunk_c, msb, lsb, bitsize)?;
            results.extend(sliced);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Slices a field element (represented as two bitdecompositions wires_a, wires_b which need to be added first) at given indices (msb, lsb), both included in the slice. For the bitcomposition, wires_c are used.
    fn slice_field_element_once<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        msb: usize,
        lsb: usize,
        bitsize: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.len(), wires_b.len());
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, F::MODULUS_BIT_SIZE as usize);
        debug_assert!(input_bitlen >= bitsize);
        debug_assert!(msb >= lsb);
        debug_assert!(msb < bitsize);
        debug_assert_eq!(wires_c.len(), input_bitlen);

        let input_bits = Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, bitsize)?;
        let mut rands = wires_c.chunks(input_bitlen);

        Self::compose_field_element::<_, F>(g, &input_bits[lsb..=msb], rands.next().unwrap())
    }

    /// Slices a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first) at given indices (msb, lsb), both included in the slice. For the bitcomposition, wires_c are used.
    pub(crate) fn slice_field_element_once_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        msb: usize,
        lsb: usize,
        bitsize: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        let total_output_elements = num_inputs;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(input_bitlen >= bitsize);
        debug_assert!(msb >= lsb);
        debug_assert!(msb < bitsize);
        debug_assert_eq!(wires_c.size(), input_bitlen * total_output_elements);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen * 3)
        ) {
            let sliced = Self::slice_field_element_once::<_, F>(
                g, chunk_a, chunk_b, chunk_c, msb, lsb, bitsize,
            )?;
            results.extend(sliced);
        }

        Ok(BinaryBundle::new(results))
    }

    fn unsigned_ge<G: FancyBinary>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        debug_assert_eq!(a.len(), b.len());
        Self::bin_subtraction_get_carry_only(g, a, b)
    }

    fn unsigned_lt<G: FancyBinary>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        let ge = Self::unsigned_ge(g, a, b)?;
        g.negate(&ge)
    }

    #[expect(dead_code)]
    fn unsigned_le<G: FancyBinary>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        Self::unsigned_ge(g, b, a)
    }

    fn unsigned_gt<G: FancyBinary>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        Self::unsigned_lt(g, b, a)
    }

    fn batcher_odd_even_merge_sort_inner<G: FancyBinary>(
        g: &mut G,
        inputs: &mut [Vec<G::Item>],
    ) -> Result<(), G::Error>
    where
        G::Item: Default,
    {
        debug_assert!(!inputs.is_empty());
        let len = inputs.len();
        let inner_len = inputs[0].len();
        let mut lhs_result = vec![G::Item::default(); inner_len];
        let mut rhs_result = vec![G::Item::default(); inner_len];

        let mut p = 1;
        while p < len {
            let mut k = p;
            while k >= 1 {
                for j in (k % p..len - k).step_by(2 * k) {
                    for i in 0..std::cmp::min(k, len - j - k) {
                        if (i + j) / (2 * p) == (i + j + k) / (2 * p) {
                            {
                                let lhs = &inputs[i + j];
                                let rhs = &inputs[i + j + k];
                                debug_assert_eq!(lhs.len(), rhs.len());
                                debug_assert_eq!(lhs.len(), inner_len);

                                let cmp = Self::unsigned_gt(g, lhs, rhs)?;

                                for (l, r, l_res, r_res) in izip!(
                                    lhs.iter(),
                                    rhs.iter(),
                                    lhs_result.iter_mut(),
                                    rhs_result.iter_mut()
                                ) {
                                    // This is a cmux, setting lres to l if cmp is 0, else r
                                    let xor = g.xor(l, r)?;
                                    let and = g.and(&cmp, &xor)?;
                                    *l_res = g.xor(&and, l)?;
                                    // sets r_res to the opposite of l_res
                                    *r_res = g.xor(&xor, l_res)?;
                                }
                            }
                            inputs[i + j].clone_from_slice(&lhs_result);
                            inputs[i + j + k].clone_from_slice(&rhs_result);
                        }
                    }
                }
                k >>= 1;
            }
            p <<= 1;
        }

        Ok(())
    }

    /// Sorts a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first). Thereby, only bitsize bits are used in sorting. Finally, the sorted vector is composed to shared field elements using wires_c.
    pub(crate) fn batcher_odd_even_merge_sort<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        debug_assert_eq!(wires_a.size(), wires_c.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(input_bitlen >= bitlen);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let mut inputs = Vec::with_capacity(num_inputs);
        for (chunk_a, chunk_b) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
        ) {
            let input_bits =
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_a, chunk_b, bitlen)?;
            inputs.push(input_bits);
        }

        // Perform the actual sorting
        Self::batcher_odd_even_merge_sort_inner(g, &mut inputs)?;

        // Add each field element to wires_c for the composition
        let mut results = Vec::with_capacity(input_size);
        for (xs, ys) in izip!(inputs, wires_c.wires().chunks(input_bitlen),) {
            let result = Self::compose_field_element::<_, F>(g, &xs, ys)?;
            results.extend(result);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Transforms a field_sharing (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing of a ring. The ring share is composed using wires_c.
    fn field_to_ring<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let output_bitlen = wires_c.len();
        debug_assert_eq!(input_bitlen, wires_a.len());
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert!(output_bitlen <= input_bitlen);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let input_bits =
            Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, output_bitlen)?;
        Self::bin_addition_no_carry(g, &input_bits, wires_c)
    }

    /// Transforms a vector of field_sharings (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing vector of rings. The ring shares are composed using wires_c.
    pub(crate) fn field_to_ring_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        output_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let num_inputs = input_size / input_bitlen;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), num_inputs * output_bitlen);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(output_bitlen),
        ) {
            results.extend(Self::field_to_ring::<_, F>(g, chunk_a, chunk_b, chunk_c)?);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Transforms a ring_sharing (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing of a field. The field share is composed using wires_c.
    fn ring_to_field<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = wires_a.len();
        let output_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert_eq!(wires_c.len(), output_bitlen);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let input_bits = Self::bin_addition_no_carry(g, wires_a, wires_b)?;
        Self::compose_field_element::<_, F>(g, &input_bits, wires_c)
    }

    /// Transforms a vector of ring_sharings (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing vector of fields. The field shares are composed using wires_c.
    pub(crate) fn ring_to_field_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let num_inputs = input_size / input_bitlen;

        debug_assert_eq!(input_size % input_bitlen, 0);
        let output_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_c.size(), num_inputs * output_bitlen);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(output_bitlen),
        ) {
            results.extend(Self::ring_to_field::<_, F>(g, chunk_a, chunk_b, chunk_c)?);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Transforms a ring_sharing (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing of another ring. The output ring share is composed using wires_c.
    fn ring_to_ring_upcast<G: FancyBinary>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = wires_a.len();
        let output_bitlen = wires_c.len();
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert!(output_bitlen > input_bitlen);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let input_bits = Self::bin_addition_no_carry(g, wires_a, wires_b)?;

        // compose chunk_bits again
        // For the bin addition, our input is not of size output_bitlen, thus we can optimize a little bit

        let mut added = Vec::with_capacity(input_bitlen);

        let xs = input_bits;
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        added.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(xs.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }

        // Finally, just the xor of the full_adder, where x is 0...
        let s = g.xor(ys.last().unwrap(), &c)?;
        added.push(s);
        Ok(added)
    }

    /// Transforms a vector of ring_sharings (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing vector of another ring. The output ring shares are composed using wires_c.
    pub(crate) fn ring_to_ring_upcast_many<G: FancyBinary>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        output_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let num_inputs = input_size / input_bitlen;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), num_inputs * output_bitlen);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(output_bitlen),
        ) {
            results.extend(Self::ring_to_ring_upcast(g, chunk_a, chunk_b, chunk_c)?);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Divides a ring element by a power of 2. The ring element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b.
    fn ring_div_power_2<G: FancyBinary>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        divisor_bit: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert_eq!(input_bitlen, wires_c.len());
        debug_assert!(divisor_bit < input_bitlen);
        debug_assert!(divisor_bit > 0);

        // Add wires_a and wires_b to get the input bits as Yao wires
        // TODO we do some XORs too much since we do not need the s-values for the first divisor_bit bits. However, this does not effect communication
        let input_bits = Self::bin_addition_no_carry(g, wires_a, wires_b)?;

        // compose chunk_bits again
        // For the bin addition, our input is not of size input_bitlen, thus we can optimize a little bit

        let mut added = Vec::with_capacity(input_bitlen);

        let xs = &input_bits[divisor_bit..];
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        added.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(xs.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }

        // Finally, just the xor of the full_adder, where x is 0...
        let s = g.xor(ys.last().unwrap(), &c)?;
        added.push(s);
        Ok(added)
    }

    /// Divides a field element by a power of 2. The field element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b.
    fn field_int_div_power_2<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        divisor_bit: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = wires_a.len();
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        assert_eq!(input_bitlen, n_bits);
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert_eq!(input_bitlen, wires_c.len());
        debug_assert!(divisor_bit < input_bitlen);
        debug_assert!(divisor_bit > 0);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let (added, carry_add) = Self::bin_addition(g, wires_a, wires_b)?;
        let (subtracted, ov) = Self::sub_p::<_, F>(g, &added, carry_add)?;

        // multiplex for result
        let mut input_bits = Vec::with_capacity(input_bitlen - divisor_bit);
        for (s, a) in subtracted.iter().zip(added.iter()).skip(divisor_bit) {
            // CMUX
            let r = g.mux(&ov, s, a)?;
            input_bits.push(r);
        }

        // compose chunk_bits again
        let result = Self::compose_field_element::<G, F>(g, &input_bits, wires_c)?;

        Ok(result)
    }

    /// Divides a ring element by another. The ring elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn ring_div<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let dividend = Self::bin_addition_no_carry(g, x1s, x2s)?;
        let divisor = Self::bin_addition_no_carry(g, y1s, y2s)?;

        debug_assert_eq!(dividend.len(), input_bitlen);
        debug_assert_eq!(dividend.len(), divisor.len());
        let quotient = Self::bin_div(g, &dividend, &divisor)?;

        let mut added = Vec::with_capacity(input_bitlen);
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &quotient[0], &ys[0])?;
        added.push(s);

        for (x, y) in quotient.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(quotient.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        Ok(added)
    }

    /// Divides a ring element by another public ring element. The ring element is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn ring_div_by_public<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        divisor: &[bool],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let dividend = Self::bin_addition_no_carry(g, x1s, x2s)?;

        debug_assert_eq!(dividend.len(), input_bitlen);
        debug_assert_eq!(dividend.len(), divisor.len());
        let quotient = Self::bin_div_by_public(g, &dividend, divisor)?;

        let mut added = Vec::with_capacity(input_bitlen);
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &quotient[0], &ys[0])?;
        added.push(s);

        for (x, y) in quotient.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(quotient.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        Ok(added)
    }

    /// Divides a public ring element by another shared ring element. The ring element is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn ring_div_by_shared<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        dividend: &[bool],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let divisor = Self::bin_addition_no_carry(g, x1s, x2s)?;

        debug_assert_eq!(dividend.len(), input_bitlen);
        debug_assert_eq!(dividend.len(), dividend.len());
        let quotient = Self::bin_div_by_shared(g, dividend, &divisor)?;

        let mut added = Vec::with_capacity(input_bitlen);
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &quotient[0], &ys[0])?;
        added.push(s);

        for (x, y) in quotient.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(quotient.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        Ok(added)
    }

    /// Divides a field element by another. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn field_int_div<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        assert_eq!(input_bitlen, n_bits);
        debug_assert_eq!(input_bitlen, x1s.len());
        debug_assert_eq!(input_bitlen, wires_c.len());

        // Add x1s and x2s to get the first input bits as Yao wires
        let added1 = Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, x1s.len())?;

        // Add y1s and y2s to get the second input bits as Yao wires
        let added2 = Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, x1s.len())?;

        // compute the division
        let quotient = Self::bin_div(g, &added1, &added2)?;

        // compose chunk_bits again
        let result = Self::compose_field_element::<G, F>(g, &quotient, wires_c)?;

        Ok(result)
    }

    /// Divides a field element by another public field element. The field elements is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn field_int_div_by_public<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        divisor: &[bool],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        assert_eq!(input_bitlen, n_bits);
        debug_assert_eq!(input_bitlen, x1s.len());
        debug_assert_eq!(input_bitlen, wires_c.len());

        // Add x1s and x2s to get the first input bits as Yao wires
        let added1 = Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, x1s.len())?;

        // compute the division
        let quotient = Self::bin_div_by_public(g, &added1, divisor)?;

        // compose chunk_bits again
        let result = Self::compose_field_element::<G, F>(g, &quotient, wires_c)?;

        Ok(result)
    }

    /// Divides a public field element by another shared field element. The field elements is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn field_int_div_by_shared<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        dividend: &[bool],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        assert_eq!(input_bitlen, n_bits);
        debug_assert_eq!(input_bitlen, x1s.len());
        debug_assert_eq!(input_bitlen, wires_c.len());

        // Add x1s and x2s to get the first input bits as Yao wires
        let added1 = Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, x1s.len())?;

        // compute the division
        let quotient = Self::bin_div_by_shared(g, dividend, &added1)?;

        // compose chunk_bits again
        let result = Self::compose_field_element::<G, F>(g, &quotient, wires_c)?;

        Ok(result)
    }

    /// Divides a ring element by a power of 2. The ring element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b.
    pub(crate) fn ring_div_power_2_many<G: FancyBinary>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        divisor_bit: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(divisor_bit < input_bitlen);
        debug_assert!(divisor_bit > 0);
        debug_assert_eq!(wires_c.size(), input_size);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::ring_div_power_2(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                divisor_bit,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides a field element by a power of 2. The field element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b.
    pub(crate) fn field_int_div_power_2_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        divisor_bit: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(divisor_bit < input_bitlen);
        debug_assert!(divisor_bit > 0);
        debug_assert_eq!(wires_c.size(), input_size);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::field_int_div_power_2::<G, F>(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                divisor_bit,
            )?);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Binary division for two vecs of inputs
    pub fn ring_div_many<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length / 2 % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length / 2);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::ring_div(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Binary division for two vecs of inputs. The ring elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub fn ring_div_by_public_many<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        divisor: Vec<bool>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length);
        debug_assert_eq!(divisor.len(), length);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, div, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            divisor.chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::ring_div_by_public(
                g,
                chunk_x1,
                chunk_x2,
                div,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Binary division for two vecs of inputs. The ring elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub fn ring_div_by_shared_many<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        dividend: Vec<bool>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length);
        debug_assert_eq!(dividend.len(), length);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, div, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            dividend.chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::ring_div_by_shared(
                g,
                chunk_x1,
                chunk_x2,
                div,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides a field element by another. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub(crate) fn field_int_div_many<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length / 2 % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length / 2);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::field_int_div::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides a field element by another public. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub(crate) fn field_int_div_by_public_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        divisor: Vec<bool>,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length);
        debug_assert_eq!(divisor.len(), length);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, div, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            divisor.chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::field_int_div_by_public::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                div,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides public field elements by another shared. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub(crate) fn field_int_div_by_shared_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        dividend: Vec<bool>,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length);
        debug_assert_eq!(dividend.len(), length);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, div, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            dividend.chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::field_int_div_by_shared::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                div,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Slices field elements in chunks, then XORs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as two bitdecompositions wires_x1, wires_x2 which need to be split first to get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    pub(crate) fn slice_and_get_xor_rotate_values_from_key_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bit: usize,
        rotation: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
        let num_inputs = (length / 2) / input_bitlen;

        let total_output_elements = 3 * num_decomps_per_field * num_inputs;
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!((length / 2) % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(3 * input_bitlen * num_decomps_per_field),
        ) {
            let value = Self::slice_and_get_xor_rotate_values_from_key::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                base_bit,
                rotation,
                total_output_bitlen_per_field,
            )?;

            results.extend(value);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Slices field elements in chunks, then XORs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as two bitdecompositions wires_x1, wires_x2 which need to be split first to get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    pub(crate) fn slice_and_get_xor_rotate_values_from_key_with_filter_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bits: &[u64],
        rotation: &[usize],
        filter: &[bool],
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = base_bits.len();
        let num_inputs = (length / 2) / input_bitlen;

        let total_output_elements = 3 * num_decomps_per_field * num_inputs;
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!((length / 2) % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(3 * input_bitlen * num_decomps_per_field),
        ) {
            let value = Self::slice_and_get_xor_rotate_values_from_key_with_filter::<G, F>(
                g, chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c, base_bits, rotation, filter,
            )?;

            results.extend(value);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Slices field elements in chunks, then ANDs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as two bitdecompositions wires_x1, wires_x2 which need to be split first to get the two sets of inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    pub(crate) fn slice_and_get_and_rotate_values_from_key_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bit: usize,
        rotation: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
        let num_inputs = (length / 2) / input_bitlen;

        let total_output_elements = 3 * num_decomps_per_field * num_inputs;
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!((length / 2) % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(3 * input_bitlen * num_decomps_per_field),
        ) {
            let value = Self::slice_and_get_and_rotate_values_from_key::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                base_bit,
                rotation,
                total_output_bitlen_per_field,
            )?;
            results.extend(value);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Slice two field elements in chunks, then XORs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two sets of inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_xor_rotate_values_from_key<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bit: usize,
        rotation: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        debug_assert_eq!(wires_c.len(), 3 * input_bitlen * num_decomps_per_field);

        // Combine the inputs
        let input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_output_bitlen_per_field)?;
        let input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_output_bitlen_per_field)?;

        let mut results = Vec::with_capacity(input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);

        // Perform the actual XOR
        let res = input_bits_1
            .iter()
            .zip(input_bits_2.iter())
            .map(|(x, y)| g.xor(x, y))
            .collect::<Result<Vec<_>, _>>()?;

        // Compose the inputs
        for inp in input_bits_1
            .chunks(base_bit)
            .chain(input_bits_2.chunks(base_bit))
        {
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);
        }

        // Compose the results
        for xs in res.chunks(base_bit) {
            if rotation == 0 {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    xs,
                    rands.next().unwrap(),
                )?);
            } else {
                let mut rotated = xs.to_owned();
                rotated.resize(64, g.const_zero()?);
                rotated.rotate_left(rotation);
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    &rotated,
                    rands.next().unwrap(),
                )?);
            }
        }
        Ok(results)
    }

    /// Slice two field elements in chunks, then XORs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two sets of inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_xor_rotate_values_from_key_with_filter<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bits: &[u64],
        rotation: &[usize],
        filter: &[bool],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut base_bits = base_bits.to_vec();
        let base_bits = base_bits.iter_mut().map(|x| x.ilog2()).collect::<Vec<_>>();
        let total_bits: u32 = base_bits.iter().sum();
        let num_decomps_per_field = base_bits.len();
        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        debug_assert_eq!(wires_c.len(), 3 * input_bitlen * num_decomps_per_field);

        // Combine the inputs
        let mut input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_bits as usize)?;
        let mut input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_bits as usize)?;

        // Compose the inputs
        let mut results = Vec::with_capacity(3 * input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);
        let mut offset = 0;
        for &bits in base_bits.iter() {
            let end = offset + bits as usize;

            let inp = &input_bits_1[offset..end];
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);
            offset = end;
        }
        let mut offset = 0;
        for &bits in base_bits.iter() {
            let end = offset + bits as usize;
            let inp = &input_bits_2[offset..end];
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);

            offset = end;
        }

        // TODO optimize for actual chunks we want to do this
        for (i, filt) in filter.iter().enumerate() {
            if *filt {
                let len = base_bits[i];
                let sum: usize = base_bits.iter().take(i).map(|&x| x as usize).sum();
                let one = g.const_one()?;
                input_bits_1[sum] = g.and(&input_bits_1[sum], &one)?;
                input_bits_2[sum] = g.and(&input_bits_2[sum], &one)?;
                input_bits_1[sum + 1] = g.and(&input_bits_1[sum + 1], &one)?;
                input_bits_2[sum + 1] = g.and(&input_bits_2[sum + 1], &one)?;

                for (i1, i2) in input_bits_1
                    .iter_mut()
                    .zip(input_bits_2.iter_mut())
                    .skip(sum)
                    .take(len as usize)
                    .skip(2)
                {
                    *i1 = g.const_zero()?;
                    *i2 = g.const_zero()?;
                }
            }
        }

        // Perform the actual XOR
        let res = input_bits_1
            .iter()
            .zip(input_bits_2.iter())
            .map(|(x, y)| g.xor(x, y))
            .collect::<Result<Vec<_>, _>>()?;

        // Compose the results
        let mut iter = base_bits.iter();
        for (xs, rot) in res
            .chunks(*iter.next().unwrap() as usize)
            .zip(rotation.iter())
        {
            if *rot == 0 {
                let xs = if xs.len() > 32 { &xs[0..32] } else { xs };
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    xs,
                    rands.next().unwrap(),
                )?);
            } else {
                let mut rotated = xs.to_owned();
                rotated.resize(32, g.const_zero()?); // For Blake we need 32 here
                rotated.rotate_left(*rot);
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    &rotated,
                    rands.next().unwrap(),
                )?);
            }
        }
        Ok(results)
    }

    /// Slice two field elements in chunks, then ANDs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_and_rotate_values_from_key<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bit: usize,
        rotation: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        debug_assert_eq!(wires_c.len(), 3 * input_bitlen * num_decomps_per_field);

        // Combine the inputs
        let input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_output_bitlen_per_field)?;
        let input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_output_bitlen_per_field)?;

        let mut results = Vec::with_capacity(input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);

        // Perform the actual AND
        let res = input_bits_1
            .iter()
            .zip(input_bits_2.iter())
            .map(|(x, y)| g.and(x, y))
            .collect::<Result<Vec<_>, _>>()?;

        // Compose the inputs
        for inp in input_bits_1
            .chunks(base_bit)
            .chain(input_bits_2.chunks(base_bit))
        {
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);
        }

        // Compose the results
        for xs in res.chunks(base_bit) {
            if rotation == 0 {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    xs,
                    rands.next().unwrap(),
                )?);
            } else {
                let mut rotated = xs.to_owned();
                rotated.resize(64, g.const_zero()?);
                rotated.rotate_left(rotation);
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    &rotated,
                    rands.next().unwrap(),
                )?);
            }
        }
        Ok(results)
    }

    /// Computes the BLAKE2s hash of 'num_inputs' inputs, each of 'num_bits' bits. The inputs are given as two bitdecompositions wires_a and wires_b, and the output is composed using wires_c. The output is then compose into size 32 Vec of field elements.
    pub(crate) fn blake2s<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        num_inputs: usize,
        num_bits: &[usize],
        // total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut input = Vec::new();
        let mut rands = wires_c.wires().chunks(input_bitlen);
        for (chunk_x1, chunk_x2, bits) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            num_bits
        ) {
            let tmp = Self::adder_mod_p_with_output_size::<_, F>(g, chunk_x1, chunk_x2, *bits)?;
            for chunk in tmp.chunks(8) {
                input.push(chunk.to_owned())
            }
        }
        debug_assert_eq!(input.len(), num_inputs);
        let blocks = num_inputs.div_ceil(64);
        let mut counter: u64 = 0;
        let mut h = Vec::new();
        for inp in Self::IV {
            h.push(Self::constant_bundle_from_u32(g, inp, 32)?);
        }
        let zero = vec![g.const_zero()?; 32];
        let tmp = Self::constant_bundle_from_u32(g, 0x01010020, 32)?;
        let res = Self::xor_many_as_wires(g, &h[0], &tmp)?;
        h[0] = res; // no key provided; = 0x0101kknn where kk is key length and nn is output length
        if num_inputs > 0 {
            for block in 0..blocks - 1 {
                counter += 64;
                let t = [counter as u32, (counter >> 32) as u32];
                let mut tmp: [_; 16] = core::array::from_fn(|_| zero.clone());
                for i in 0..64 {
                    let shift = (i % 4) as u8 * 8;
                    let shifted_left =
                        Self::shift_left(g, &input[64 * block + i], shift as usize, 32)?;
                    tmp[i / 4] = Self::bin_addition_no_carry(g, &tmp[i / 4], &shifted_left)?;
                }
                h = Self::blake2s_compress(g, &tmp, &h, t, [0, 0])?;
            }
        }
        let mut bytes = num_inputs % 64;
        if num_inputs > 0 && bytes == 0 {
            bytes = 64;
        }
        counter += bytes as u64;
        let t = [counter as u32, (counter >> 32) as u32];
        let mut tmp: [_; 16] = core::array::from_fn(|_| zero.clone());
        for i in 0..bytes {
            let shift = (i % 4) as u8 * 8;
            let shifted_left =
                Self::shift_left(g, &input[64 * (blocks - 1) + i], shift as usize, 32)?;
            tmp[i / 4] = Self::bin_addition_no_carry(g, &tmp[i / 4], &shifted_left)?;
        }
        h = Self::blake2s_compress(g, &tmp, &h, t, [0xFFFFFFFF, 0])?;
        let mut result = Vec::new();
        for res in h {
            for chunk in res.chunks(8) {
                result.extend(Self::compose_field_element::<_, F>(
                    g,
                    chunk,
                    rands.next().unwrap(),
                )?)
            }
        }
        Ok(BinaryBundle::new(result))
    }

    pub(crate) fn blake2s_compress<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        input: &[Vec<G::Item>],
        h: &[Vec<G::Item>],
        t: [u32; 2],
        f: [u32; 2],
    ) -> Result<Vec<Vec<G::Item>>, G::Error> {
        let mut state = Vec::new();
        for inp in h {
            state.push(inp.to_vec());
        }
        for inp in Self::IV.iter().take(4) {
            state.push(Self::constant_bundle_from_u32(g, *inp, 32)?);
        }
        let t_0 = Self::constant_bundle_from_u32(g, t[0], 32)?;
        let t_1 = Self::constant_bundle_from_u32(g, t[1], 32)?;
        let f_0 = Self::constant_bundle_from_u32(g, f[0], 32)?;
        let f_1 = Self::constant_bundle_from_u32(g, f[1], 32)?;
        let iv_4 = Self::constant_bundle_from_u32(g, Self::IV[4], 32)?;
        let iv_5 = Self::constant_bundle_from_u32(g, Self::IV[5], 32)?;
        let iv_6 = Self::constant_bundle_from_u32(g, Self::IV[6], 32)?;
        let iv_7 = Self::constant_bundle_from_u32(g, Self::IV[7], 32)?;
        state.push(Self::xor_many_as_wires(g, &iv_4, &t_0)?);
        state.push(Self::xor_many_as_wires(g, &iv_5, &t_1)?);
        state.push(Self::xor_many_as_wires(g, &iv_6, &f_0)?);
        state.push(Self::xor_many_as_wires(g, &iv_7, &f_1)?);

        for r in 0..10 {
            let sr = Self::SIGMA[r];
            let res = Self::blake2s_mix(
                g,
                &state[0],
                &state[4],
                &state[8],
                &state[12],
                &input[sr[0] as usize],
                &input[sr[1] as usize],
            )?; // Column 0
            state[0] = res.0;
            state[4] = res.1;
            state[8] = res.2;
            state[12] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[1],
                &state[5],
                &state[9],
                &state[13],
                &input[sr[2] as usize],
                &input[sr[3] as usize],
            )?; // Column 1
            state[1] = res.0;
            state[5] = res.1;
            state[9] = res.2;
            state[13] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[2],
                &state[6],
                &state[10],
                &state[14],
                &input[sr[4] as usize],
                &input[sr[5] as usize],
            )?; // Column 2
            state[2] = res.0;
            state[6] = res.1;
            state[10] = res.2;
            state[14] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[3],
                &state[7],
                &state[11],
                &state[15],
                &input[sr[6] as usize],
                &input[sr[7] as usize],
            )?; // Column 3
            state[3] = res.0;
            state[7] = res.1;
            state[11] = res.2;
            state[15] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[0],
                &state[5],
                &state[10],
                &state[15],
                &input[sr[8] as usize],
                &input[sr[9] as usize],
            )?; // Diagonal 1 (main diagonal)
            state[0] = res.0;
            state[5] = res.1;
            state[10] = res.2;
            state[15] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[1],
                &state[6],
                &state[11],
                &state[12],
                &input[sr[10] as usize],
                &input[sr[11] as usize],
            )?; // Diagonal 2
            state[1] = res.0;
            state[6] = res.1;
            state[11] = res.2;
            state[12] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[2],
                &state[7],
                &state[8],
                &state[13],
                &input[sr[12] as usize],
                &input[sr[13] as usize],
            )?; // Diagonal 3
            state[2] = res.0;
            state[7] = res.1;
            state[8] = res.2;
            state[13] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[3],
                &state[4],
                &state[9],
                &state[14],
                &input[sr[14] as usize],
                &input[sr[15] as usize],
            )?; // Diagonal 4
            state[3] = res.0;
            state[4] = res.1;
            state[9] = res.2;
            state[14] = res.3;
        }
        let mut result = Vec::new();
        for (i, inp) in h.iter().enumerate() {
            let tmp = Self::xor_many_as_wires(g, &state[i], &state[i + 8])?;
            let tmp = Self::xor_many_as_wires(g, inp, &tmp)?;
            result.push(tmp);
        }
        Ok(result)
    }

    fn blake2s_rotr<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x: &[G::Item],
        n: u8,
    ) -> Result<Vec<G::Item>, G::Error> {
        let right_shift = Self::shift_right(g, x, n as usize, 32)?;
        let left_shift = Self::shift_left(g, x, 32 - n as usize, 32)?;
        Self::bin_addition_no_carry(g, &right_shift, &left_shift)
    }

    #[expect(clippy::type_complexity)]
    fn blake2s_mix<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
        c: &[G::Item],
        d: &[G::Item],
        x: &[G::Item],
        y: &[G::Item],
    ) -> Result<(Vec<G::Item>, Vec<G::Item>, Vec<G::Item>, Vec<G::Item>), G::Error> {
        let mut a = Self::bin_addition_no_carry(g, a, b)?;
        a = Self::bin_addition_no_carry(g, &a, x)?;
        let mut d = Self::xor_many_as_wires(g, d, &a)?;
        d = Self::blake2s_rotr(g, &d, 16)?;
        let mut c = Self::bin_addition_no_carry(g, c, &d)?;
        let mut b = Self::xor_many_as_wires(g, b, &c)?;
        b = Self::blake2s_rotr(g, &b, 12)?;
        a = Self::bin_addition_no_carry(g, &a, &b)?;
        a = Self::bin_addition_no_carry(g, &a, y)?;
        d = Self::xor_many_as_wires(g, &d, &a)?;
        d = Self::blake2s_rotr(g, &d, 8)?;
        c = Self::bin_addition_no_carry(g, &c, &d)?;
        b = Self::xor_many_as_wires(g, &b, &c)?;
        b = Self::blake2s_rotr(g, &b, 7)?;

        Ok((a, b, c, d))
    }
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    const SIGMA: [[u8; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocols::rep3::yao::GCInputs;
    use fancy_garbling::BinaryGadgets;
    use fancy_garbling::{Evaluator, Fancy, Garbler, WireMod2};
    use rand::{thread_rng, CryptoRng, Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use scuttlebutt::{AbstractChannel, Channel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    const TESTRUNS: usize = 5;

    // This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    fn encode_field<F: PrimeField, C: AbstractChannel, R: Rng + CryptoRng>(
        field: F,
        garbler: &mut Garbler<C, R, WireMod2>,
    ) -> GCInputs<WireMod2> {
        let bits = GCUtils::field_to_bits_as_u16(field);
        let mut garbler_wires = Vec::with_capacity(bits.len());
        let mut evaluator_wires = Vec::with_capacity(bits.len());
        for bit in bits {
            let (mine, theirs) = garbler.encode_wire(bit, 2);
            garbler_wires.push(mine);
            evaluator_wires.push(theirs);
        }
        GCInputs {
            garbler_wires: BinaryBundle::new(garbler_wires),
            evaluator_wires: BinaryBundle::new(evaluator_wires),
            delta: garbler.delta(2),
        }
    }

    fn gc_test<F: PrimeField>() {
        let mut rng = thread_rng();

        let a = F::rand(&mut rng);
        let b = F::rand(&mut rng);
        let is_result = a + b;

        let (sender, receiver) = UnixStream::pair().unwrap();

        std::thread::spawn(move || {
            let rng = ChaCha12Rng::from_entropy();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let channel_sender = Channel::new(reader, writer);

            let mut garbler = Garbler::<_, _, WireMod2>::new(channel_sender, rng);

            // This is without OT, just a simulation
            let a = encode_field(a, &mut garbler);
            let b = encode_field(b, &mut garbler);
            for a in a.evaluator_wires.wires().iter() {
                garbler.send_wire(a).unwrap();
            }
            for b in b.evaluator_wires.wires().iter() {
                garbler.send_wire(b).unwrap();
            }

            let garble_result = GarbledCircuits::adder_mod_p::<_, F>(
                &mut garbler,
                &a.garbler_wires,
                &b.garbler_wires,
            )
            .unwrap();

            // Output
            garbler.outputs(garble_result.wires()).unwrap();
        });

        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let channel_rcv = Channel::new(reader, writer);

        let mut evaluator = Evaluator::<_, WireMod2>::new(channel_rcv);

        // This is without OT, just a simulation
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        let mut a = Vec::with_capacity(n_bits);
        let mut b = Vec::with_capacity(n_bits);
        for _ in 0..n_bits {
            let a_ = evaluator.read_wire(2).unwrap();
            a.push(a_);
        }
        for _ in 0..n_bits {
            let b_ = evaluator.read_wire(2).unwrap();
            b.push(b_);
        }
        let a = BinaryBundle::new(a);
        let b = BinaryBundle::new(b);

        let eval_result = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &a, &b).unwrap();

        let result = evaluator.outputs(eval_result.wires()).unwrap().unwrap();
        let result = GCUtils::u16_bits_to_field::<F>(result).unwrap();
        assert_eq!(result, is_result);
    }

    #[test]
    fn gc_test_bn254() {
        for _ in 0..TESTRUNS {
            gc_test::<ark_bn254::Fr>();
        }
    }

    fn gc_test_div_int<F: PrimeField>()
    where
        num_bigint::BigUint: std::convert::From<F>,
    {
        let mut rng = thread_rng();

        let a = F::rand(&mut rng);
        let b = F::rand(&mut rng);
        let is_result = F::from(BigUint::from(a) / BigUint::from(b));
        let (sender, receiver) = UnixStream::pair().unwrap();

        std::thread::spawn(move || {
            let rng = ChaCha12Rng::from_entropy();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let channel_sender = Channel::new(reader, writer);

            let mut garbler = Garbler::<_, _, WireMod2>::new(channel_sender, rng);

            // This is without OT, just a simulation
            let a = encode_field(a, &mut garbler);
            let b = encode_field(b, &mut garbler);
            for a in a.evaluator_wires.wires().iter() {
                garbler.send_wire(a).unwrap();
            }
            for b in b.evaluator_wires.wires().iter() {
                garbler.send_wire(b).unwrap();
            }

            let garble_result =
                BinaryGadgets::bin_div(&mut garbler, &a.garbler_wires, &b.garbler_wires).unwrap();

            // Output
            garbler.outputs(garble_result.wires()).unwrap();
        });

        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let channel_rcv = Channel::new(reader, writer);

        let mut evaluator = Evaluator::<_, WireMod2>::new(channel_rcv);

        // This is without OT, just a simulation
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        let mut a = Vec::with_capacity(n_bits);
        let mut b = Vec::with_capacity(n_bits);
        for _ in 0..n_bits {
            let a_ = evaluator.read_wire(2).unwrap();
            a.push(a_);
        }
        for _ in 0..n_bits {
            let b_ = evaluator.read_wire(2).unwrap();
            b.push(b_);
        }
        let a = BinaryBundle::new(a);
        let b = BinaryBundle::new(b);

        let eval_result = BinaryGadgets::bin_div(&mut evaluator, &a, &b).unwrap();

        let result = evaluator.outputs(eval_result.wires()).unwrap().unwrap();
        let result = GCUtils::u16_bits_to_field::<F>(result).unwrap();
        assert_eq!(result, is_result);
    }

    #[test]
    fn gc_test_bn254_div_int() {
        for _ in 0..TESTRUNS {
            gc_test_div_int::<ark_bn254::Fr>();
        }
    }
}
