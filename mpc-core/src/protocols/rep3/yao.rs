use ark_ff::PrimeField;
use fancy_garbling::{
    BinaryBundle, BinaryGadgets, Bundle, Evaluator, FancyBinary, Garbler, WireMod2,
};
use num_bigint::BigUint;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use scuttlebutt::AbstractChannel;

/// A structure that contains both the garbler and the evaluators
/// wires. This structure simplifies the API of the garbled circuit.
struct GCInputs<F> {
    pub garbler_wires: BinaryBundle<F>,
    pub evaluator_wires: BinaryBundle<F>,
}

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

fn biguint_to_bits_as_u16(input: BigUint, n_bits: usize) -> Vec<u16> {
    let mut res = Vec::with_capacity(n_bits);
    let mut bits = 0;
    for mut el in input.to_u64_digits() {
        for _ in 0..64 {
            res.push((el & 1) as u16);
            el >>= 1;
            bits += 1;
            if bits == n_bits {
                break;
            }
        }
    }
    res.resize(n_bits, 0);
    res
}

fn field_to_bits_as_u16<F: PrimeField>(field: F) -> Vec<u16> {
    let n_bits = F::MODULUS_BIT_SIZE as usize;
    let bigint: BigUint = field.into();

    biguint_to_bits_as_u16(bigint, n_bits)
}

// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
fn encode_field<F: PrimeField, C: AbstractChannel, R: Rng + CryptoRng>(
    field: F,
    garbler: &mut Garbler<C, R, WireMod2>,
) -> GCInputs<WireMod2> {
    let bits = field_to_bits_as_u16(field);
    let mut garbler_wires = Vec::with_capacity(bits.len());
    let mut evaluator_wires = Vec::with_capacity(bits.len());
    for bit in bits {
        let (mine, theirs) = garbler.encode_wire(bit, 2);
        garbler_wires.push(mine);
        evaluator_wires.push(theirs);
    }
    GCInputs {
        garbler_wires: BinaryBundle::from(Bundle::new(garbler_wires)),
        evaluator_wires: BinaryBundle::from(Bundle::new(evaluator_wires)),
    }
}

fn full_adder_gc_const<G>(
    g: &mut G,
    a: &G::Item,
    b: bool,
    c: &G::Item,
) -> Result<(G::Item, G::Item), G::Error>
where
    G: FancyBinary,
{
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

fn adder_mod_p_gc<G, F: PrimeField>(
    g: &mut G,
    wires_a: BinaryBundle<G::Item>,
    wires_b: BinaryBundle<G::Item>,
) -> Result<BinaryBundle<G::Item>, G::Error>
where
    G: BinaryGadgets,
{
    let bitlen = wires_a.size();
    debug_assert_eq!(bitlen, wires_b.size());

    // First addition
    let (added, carry_add) = g.bin_addition(&wires_a, &wires_b)?;
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

    Ok(BinaryBundle::from(Bundle::new(result)))
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::Zero;
    use fancy_garbling::Fancy;
    use rand::thread_rng;
    use scuttlebutt::Channel;
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    const TESTRUNS: usize = 5;

    fn bits_to_field<F: PrimeField>(bits: Vec<u16>) -> F {
        let mut res = BigUint::zero();
        for bit in bits.iter().rev() {
            assert!(*bit < 2);
            res <<= 1;
            res += *bit as u64;
        }
        assert!(res < F::MODULUS.into());
        F::from(res)
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

            let garble_result =
                adder_mod_p_gc::<_, F>(&mut garbler, a.garbler_wires, b.garbler_wires).unwrap();

            // Output
            garbler.outputs(garble_result.wires()).unwrap();
        });

        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let channel_rcv = Channel::new(reader, writer);

        let mut evaluator = Evaluator::<_, WireMod2>::new(channel_rcv);

        // This is wihout OT, just a simulation
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
        let a = BinaryBundle::from(Bundle::new(a));
        let b = BinaryBundle::from(Bundle::new(b));

        let eval_result = adder_mod_p_gc::<_, F>(&mut evaluator, a, b).unwrap();

        let result = evaluator.outputs(eval_result.wires()).unwrap().unwrap();
        let result = bits_to_field::<F>(result);
        assert_eq!(result, is_result);
    }

    #[test]
    fn gc_test_bn254() {
        for _ in 0..TESTRUNS {
            gc_test::<ark_bn254::Fr>();
        }
    }
}
