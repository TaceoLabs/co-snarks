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

    /// subtracts p from wires (with carry) and returns the result and the overflow bit
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

    /// Adds two shared field elements mod p. The field elements are encoded as Yao shared wires
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

    /// Adds two shared ring elements mod 2^k. The ring elements are encoded as Yao shared wires
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

    /// Divides a ring element by a power of 2. The ring element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b
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

    /// Divides a field element by a power of 2. The field element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b
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

    /// Divides a ring element by another. The ring elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires
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

    /// Divides a ring element by another public ring element. The ring element is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires
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

    /// Divides a public ring element by another shared ring element. The ring element is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires
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

    /// Divides a field element by another. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires
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

    /// Divides a field element by another public field element. The field elements is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires
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

    /// Divides a public field element by another shared field element. The field elements is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires
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

    /// Divides a ring element by a power of 2. The ring element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b
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

    /// Divides a field element by a power of 2. The field element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b
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

    /// Binary division for two vecs of inputs. The ring elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b
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

    /// Binary division for two vecs of inputs. The ring elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b
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

    /// Divides a field element by another. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b
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

    /// Divides a field element by another public. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b
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

    /// Divides a public field element by another shared. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b
    pub(crate) fn field_int_div_by_shared_many<
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
