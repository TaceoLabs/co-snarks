use ark_ff::PrimeField;
use fancy_garbling::{BinaryBundle, FancyBinary};
use num_bigint::BigUint;

fn biguint_to_bits(input: BigUint, n_bits: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(n_bits);
    let mut bits = 0;
    for mut el in input.to_u64_digits() {
        for _ in 0..64 {
            res.push(el & 1 == 1);
            el >>= 1;
            bits += 1;
            if bits == n_bits {
                break;
            }
        }
    }
    res.resize(n_bits, false);
    res
}

fn full_adder_gc_const<G: FancyBinary>(
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
        let z3 = g.xor(a, c)?;
        let z4 = g.and(z1, &z3)?;
        let c = g.xor(&z4, a)?;
        (s, c)
    };

    Ok((s, c))
}

fn half_adder_gc<G: FancyBinary>(
    g: &mut G,
    a: &G::Item,
    b: &G::Item,
) -> Result<(G::Item, G::Item), G::Error> {
    let s = g.xor(a, b)?;
    let c = g.and(a, b)?;
    Ok((s, c))
}

fn full_adder_gc<G: FancyBinary>(
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

/// Binary addition. Returns the result and the carry.
fn bin_addition_gc<G: FancyBinary>(
    g: &mut G,
    xs: &BinaryBundle<G::Item>,
    ys: &BinaryBundle<G::Item>,
) -> Result<(BinaryBundle<G::Item>, G::Item), G::Error> {
    let xwires = xs.wires();
    let ywires = ys.wires();
    debug_assert_eq!(xwires.len(), ywires.len());
    let mut result = Vec::with_capacity(xwires.len());

    let (mut s, mut c) = half_adder_gc(g, &xwires[0], &ywires[0])?;
    result.push(s);

    for (x, y) in xwires.iter().zip(ywires.iter()).skip(1) {
        let res = full_adder_gc(g, x, y, &c)?;
        s = res.0;
        c = res.1;
        result.push(s);
    }

    Ok((BinaryBundle::new(result), c))
}

pub(crate) fn adder_mod_p_gc<G: FancyBinary, F: PrimeField>(
    g: &mut G,
    wires_a: BinaryBundle<G::Item>,
    wires_b: BinaryBundle<G::Item>,
) -> Result<BinaryBundle<G::Item>, G::Error> {
    let bitlen = wires_a.size();
    debug_assert_eq!(bitlen, wires_b.size());

    // First addition
    let (added, carry_add) = bin_addition_gc(g, &wires_a, &wires_b)?;
    let added_wires = added.wires();

    // Prepare p for subtraction
    let new_bitlen = bitlen + 1;
    let p_ = (BigUint::from(1u64) << new_bitlen) - F::MODULUS.into();
    let p_bits = biguint_to_bits(p_, new_bitlen);

    // manual_rca:
    let mut subtracted = Vec::with_capacity(bitlen);
    // half_adder:
    debug_assert!(p_bits[0]);
    let s = g.negate(&added_wires[0])?;
    subtracted.push(s);
    let mut c = added_wires[0].to_owned();
    // full_adders:
    for (a, b) in added_wires.iter().zip(p_bits.iter()).skip(1) {
        let (s, c_) = full_adder_gc_const(g, a, *b, &c)?;
        c = c_;
        subtracted.push(s);
    }
    // final_full_adder to get ov bit
    let z = if p_bits[bitlen] {
        g.negate(&carry_add)?
    } else {
        carry_add
    };
    let ov = g.xor(&z, &c)?;

    // multiplex for result
    let mut result = Vec::with_capacity(bitlen);
    for (s, a) in subtracted.iter().zip(added.iter()) {
        // CMUX
        // let r = g.mux(&ov, s, a)?; // Has two ANDs, only need one though
        let xor = g.xor(s, a)?;
        let and = g.and(&ov, &xor)?;
        let r = g.xor(&and, s)?;
        result.push(r);
    }

    Ok(BinaryBundle::new(result))
}
