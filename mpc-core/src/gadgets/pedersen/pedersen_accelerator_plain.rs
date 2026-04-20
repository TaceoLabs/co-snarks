use std::str::FromStr;

use ark_ff::{Field, One, Zero};

use crate::gadgets::pedersen::{PEDERSEN_FULL_TRACE_LENGTH, PEDERSEN_TRACE_INDICES};

use super::{PEDERSEN_COMMIT_BITS_TRACE_VALUE_COUNT, PedersenCommitBitsTrace};

pub(crate) type F = ark_bn254::Fr;

/// A point on the BabyJubJub twisted Edwards curve over the BN254 scalar field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BabyJubJubPoint {
    /// x-coordinate in the BabyJubJub base field.
    pub x: F,
    /// y-coordinate in the BabyJubJub base field.
    pub y: F,
}

#[derive(Debug, Clone, Copy)]
struct MontgomeryPoint {
    pub x: F,
    pub y: F,
}

#[derive(Debug, Clone, Copy)]
struct BabyAddTrace {
    pub lhs: BabyJubJubPoint,
    pub rhs: BabyJubJubPoint,
    pub beta: F,
    pub gamma: F,
    pub delta: F,
    pub tau: F,
    pub out: BabyJubJubPoint,
}

#[derive(Debug, Clone, Copy)]
struct MontgomeryAddTrace {
    pub in2: MontgomeryPoint,
    pub lamda: F,
    pub out: MontgomeryPoint,
}

#[derive(Debug, Clone, Copy)]
struct SegmentTrace {
    pub out: BabyJubJubPoint,
    pub dbl: MontgomeryPoint,
    pub adders: [Option<MontgomeryAddTrace>; 82],
    pub cadd: BabyAddTrace,
    pub mux_a210_x: [Option<F>; 82],
}

impl BabyJubJubPoint {
    #[inline]
    /// Returns the neutral element of the group.
    pub fn identity() -> Self {
        Self {
            x: F::zero(),
            y: F::one(),
        }
    }
}

#[inline]
fn f_from_dec(s: &str) -> F {
    F::from_str(s).expect("valid field element")
}

#[inline]
fn babyjub_generator() -> BabyJubJubPoint {
    BabyJubJubPoint {
        x: f_from_dec(
            "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        ),
        y: f_from_dec(
            "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        ),
    }
}

#[inline]
fn babyjub_h_generator() -> BabyJubJubPoint {
    BabyJubJubPoint {
        x: f_from_dec(
            "18070489056226311699126950111606780081892760427770517382371397914121919205062",
        ),
        y: f_from_dec(
            "15271815330304366999180694217454548993927804584117026509847005260140807626286",
        ),
    }
}

#[inline]
fn montgomery_constants() -> (F, F) {
    let a = F::from(168700u64);
    let d = F::from(168696u64);
    let denominator = (a - d)
        .inverse()
        .expect("BabyJubJub Montgomery denominator must be non-zero");
    let montgomery_a = (F::from(2u64) * (a + d)) * denominator;
    let montgomery_b = F::from(4u64) * denominator;
    (montgomery_a, montgomery_b)
}

#[inline]
fn bit_to_usize(bit: F) -> eyre::Result<usize> {
    if bit.is_zero() {
        Ok(0)
    } else if bit.is_one() {
        Ok(1)
    } else {
        Err(eyre::eyre!("scalar bit is not 0/1"))
    }
}

#[inline]
fn babyjub_add_trace(lhs: BabyJubJubPoint, rhs: BabyJubJubPoint) -> eyre::Result<BabyAddTrace> {
    let a = F::from(168700u64);
    let d = F::from(168696u64);

    let beta = lhs.x * rhs.y;
    let gamma = lhs.y * rhs.x;
    let delta = ((-(a * lhs.x)) + lhs.y) * (rhs.x + rhs.y);
    let tau = beta * gamma;

    let denom_x = F::one() + d * tau;
    let denom_y = F::one() - d * tau;

    let inv_denom_x = denom_x
        .inverse()
        .ok_or_else(|| eyre::eyre!("BabyJubJub add: denom_x is zero"))?;
    let inv_denom_y = denom_y
        .inverse()
        .ok_or_else(|| eyre::eyre!("BabyJubJub add: denom_y is zero"))?;

    let out = BabyJubJubPoint {
        x: (beta + gamma) * inv_denom_x,
        y: (delta + a * beta - gamma) * inv_denom_y,
    };

    Ok(BabyAddTrace {
        lhs,
        rhs,
        beta,
        gamma,
        delta,
        tau,
        out,
    })
}

#[inline]
fn edwards_to_montgomery(point: BabyJubJubPoint) -> eyre::Result<MontgomeryPoint> {
    let one_minus_y = F::one() - point.y;
    let inv_one_minus_y = one_minus_y
        .inverse()
        .ok_or_else(|| eyre::eyre!("Edwards2Montgomery: 1 - y is zero"))?;
    let x = (F::one() + point.y) * inv_one_minus_y;
    let inv_point_x = point
        .x
        .inverse()
        .ok_or_else(|| eyre::eyre!("Edwards2Montgomery: x is zero"))?;
    let y = x * inv_point_x;
    Ok(MontgomeryPoint { x, y })
}

#[inline]
fn montgomery_to_edwards(point: MontgomeryPoint) -> eyre::Result<BabyJubJubPoint> {
    let inv_point_y = point
        .y
        .inverse()
        .ok_or_else(|| eyre::eyre!("Montgomery2Edwards: y is zero"))?;
    let x = point.x * inv_point_y;
    let inv_point_x_plus_one = (point.x + F::one())
        .inverse()
        .ok_or_else(|| eyre::eyre!("Montgomery2Edwards: x + 1 is zero"))?;
    let y = (point.x - F::one()) * inv_point_x_plus_one;
    Ok(BabyJubJubPoint { x, y })
}

#[inline]
fn montgomery_add(lhs: MontgomeryPoint, rhs: MontgomeryPoint) -> eyre::Result<MontgomeryAddTrace> {
    let (montgomery_a, montgomery_b) = montgomery_constants();
    let denominator = rhs.x - lhs.x;
    let inv_denominator = denominator
        .inverse()
        .ok_or_else(|| eyre::eyre!("MontgomeryAdd: x2 - x1 is zero"))?;
    let lamda = (rhs.y - lhs.y) * inv_denominator;
    let out_x = montgomery_b * lamda * lamda - montgomery_a - lhs.x - rhs.x;
    let out = MontgomeryPoint {
        x: out_x,
        y: lamda * (lhs.x - out_x) - lhs.y,
    };
    Ok(MontgomeryAddTrace {
        in2: rhs,
        lamda,
        out,
    })
}

#[inline]
fn montgomery_double(point: MontgomeryPoint) -> eyre::Result<MontgomeryPoint> {
    let (montgomery_a, montgomery_b) = montgomery_constants();
    let x_squared = point.x * point.x;
    let denominator = F::from(2u64) * montgomery_b * point.y;
    let inv_denominator = denominator
        .inverse()
        .ok_or_else(|| eyre::eyre!("MontgomeryDouble: denominator is zero"))?;
    let lamda = (F::from(3u64) * x_squared + F::from(2u64) * montgomery_a * point.x + F::one())
        * inv_denominator;
    let out_x = montgomery_b * lamda * lamda - montgomery_a - point.x - point.x;
    Ok(MontgomeryPoint {
        x: out_x,
        y: lamda * (point.x - out_x) - point.y,
    })
}

fn window_mul_fix(
    bits: [F; 3],
    base: MontgomeryPoint,
) -> eyre::Result<(MontgomeryPoint, MontgomeryPoint, F)> {
    let dbl2 = montgomery_double(base)?;
    let adr3 = montgomery_add(base, dbl2)?.out;
    let adr4 = montgomery_add(base, adr3)?.out;
    let adr5 = montgomery_add(base, adr4)?.out;
    let adr6 = montgomery_add(base, adr5)?.out;
    let adr7 = montgomery_add(base, adr6)?.out;
    let adr8 = montgomery_add(base, adr7)?.out;

    let table = [base, dbl2, adr3, adr4, adr5, adr6, adr7, adr8];
    let selector =
        bit_to_usize(bits[0])? + (bit_to_usize(bits[1])? << 1) + (bit_to_usize(bits[2])? << 2);
    let s10 = bits[1] * bits[0];
    let a210_x =
        (table[7].x - table[6].x - table[5].x + table[4].x - table[3].x + table[2].x + table[1].x
            - table[0].x)
            * s10;

    Ok((table[selector], adr8, a210_x))
}

fn segment_mul_fix_trace(
    base: BabyJubJubPoint,
    bits: &[F],
    n_windows: usize,
) -> eyre::Result<SegmentTrace> {
    let mut padded_bits = bits.to_vec();
    padded_bits.resize(n_windows * 3, F::zero());
    let base_montgomery = edwards_to_montgomery(base)?;

    let mut window_outs = [None; 82];
    let mut window_out8 = [None; 82];
    let mut mux_a210_x = [None; 82];
    for window_index in 0..n_windows {
        let chunk = [
            padded_bits[3 * window_index],
            padded_bits[3 * window_index + 1],
            padded_bits[3 * window_index + 2],
        ];
        let window_base = if window_index == 0 {
            base_montgomery
        } else {
            window_out8[window_index - 1].expect("previous window exists")
        };
        let (out, out8, a210_x) = window_mul_fix(chunk, window_base)?;
        window_outs[window_index] = Some(out);
        window_out8[window_index] = Some(out8);
        if n_windows == 2 {
            if window_index == 0 {
                mux_a210_x[window_index] = Some(a210_x);
            }
        } else {
            mux_a210_x[window_index] = Some(a210_x);
        }
    }

    let last_out8 = window_out8[n_windows - 1].expect("last window exists");
    let dbl_last = montgomery_double(last_out8)?;

    let mut cadders = [None; 82];
    for window_index in 0..n_windows {
        let in1 = if window_index == 0 {
            base_montgomery
        } else {
            cadders[window_index - 1].expect("previous cadder exists")
        };
        let in2 = if window_index + 1 == n_windows {
            dbl_last
        } else {
            window_out8[window_index].expect("window out8 exists")
        };
        cadders[window_index] = Some(montgomery_add(in1, in2)?.out);
    }

    let mut adders: [Option<MontgomeryAddTrace>; 82] = [None; 82];
    for window_index in 0..n_windows {
        let in1 = if window_index == 0 {
            dbl_last
        } else {
            adders[window_index - 1].expect("previous adder exists").out
        };
        let in2 = window_outs[window_index].expect("window out exists");
        adders[window_index] = Some(montgomery_add(in1, in2)?);
    }

    let m2e = montgomery_to_edwards(adders[n_windows - 1].expect("last adder exists").out)?;
    let cm2e = montgomery_to_edwards(cadders[n_windows - 1].expect("last cadder exists"))?;
    let cadd = babyjub_add_trace(
        m2e,
        BabyJubJubPoint {
            x: -cm2e.x,
            y: cm2e.y,
        },
    )?;

    Ok(SegmentTrace {
        out: cadd.out,
        dbl: last_out8,
        adders,
        cadd,
        mux_a210_x,
    })
}

fn append_segment_trace(trace: &mut Vec<F>, segment: &SegmentTrace, n_windows: usize) {
    for window_index in 0..n_windows {
        let adder = segment.adders[window_index].expect("segment adder exists");
        trace.push(adder.out.x);
        trace.push(adder.out.y);
        trace.push(adder.in2.x);
        if !(n_windows == 2 && window_index == 1) {
            trace.push(adder.in2.y);
        }
        trace.push(adder.lamda);
    }

    trace.push(segment.cadd.lhs.x);
    trace.push(segment.cadd.lhs.y);
    trace.push(segment.cadd.tau);

    for window_index in 0..n_windows {
        if let Some(a210_x) = segment.mux_a210_x[window_index] {
            trace.push(a210_x);
        }
    }
}

fn escalar_mul_fix_trace(
    base: BabyJubJubPoint,
    bits: &[F; 251],
) -> eyre::Result<(BabyJubJubPoint, Vec<F>)> {
    let segment0 = segment_mul_fix_trace(base, &bits[..246], 82)?;
    let segment1_base = montgomery_to_edwards(segment0.dbl)?;
    let segment1 = segment_mul_fix_trace(segment1_base, &bits[246..], 2)?;
    let top_adder = babyjub_add_trace(segment0.out, segment1.out)?;

    let mut trace = Vec::with_capacity(516);
    trace.push(top_adder.lhs.x);
    trace.push(top_adder.lhs.y);
    trace.push(top_adder.rhs.x);
    trace.push(top_adder.rhs.y);
    trace.push(top_adder.beta);
    trace.push(top_adder.gamma);
    trace.push(top_adder.delta);
    trace.push(top_adder.tau);

    append_segment_trace(&mut trace, &segment0, 82);
    append_segment_trace(&mut trace, &segment1, 2);

    Ok((top_adder.out, trace))
}

/// Fixed-base scalar multiplication `k·P` where `k` is provided as 251 little-endian bits.
pub fn babyjub_scalar_mul_bits(
    base: BabyJubJubPoint,
    scalar_bits_le_251: &[bool; 251],
) -> eyre::Result<BabyJubJubPoint> {
    let scalar_bits_le_251 = scalar_bits_le_251.map(|bit| if bit { F::one() } else { F::zero() });
    Ok(escalar_mul_fix_trace(base, &scalar_bits_le_251)?.0)
}

/// Fixed-base scalar multiplication `k·P` where `k` is provided as 251 little-endian field bits.
pub fn babyjub_scalar_mul_bits_fr(
    base: BabyJubJubPoint,
    scalar_bits_le_251: &[F; 251],
) -> eyre::Result<BabyJubJubPoint> {
    Ok(escalar_mul_fix_trace(base, scalar_bits_le_251)?.0)
}

/// Computes the full Circom-compatible `pedersen_commit_bits` output and dense accelerator trace.
pub fn pedersen_commit_bits_trace_fr(
    value_bits_le_251: &[F; 251],
    r_bits_le_251: &[F; 251],
) -> eyre::Result<PedersenCommitBitsTrace<F>> {
    let (g_r, mut g_r_trace) = escalar_mul_fix_trace(babyjub_h_generator(), r_bits_le_251)?;
    let (g_value, mut g_value_trace) =
        escalar_mul_fix_trace(babyjub_generator(), value_bits_le_251)?;
    let final_add = babyjub_add_trace(g_value, g_r)?;

    let mut trace = Vec::with_capacity(PEDERSEN_COMMIT_BITS_TRACE_VALUE_COUNT);
    trace.push(final_add.lhs.x);
    trace.push(final_add.lhs.y);
    trace.push(final_add.rhs.x);
    trace.push(final_add.rhs.y);
    trace.push(final_add.beta);
    trace.push(final_add.gamma);
    trace.push(final_add.delta);
    trace.push(final_add.tau);
    trace.append(&mut g_r_trace);
    trace.append(&mut g_value_trace);

    let mut real_trace = vec![F::zero(); PEDERSEN_FULL_TRACE_LENGTH];

    for (val, idx) in trace.into_iter().zip(PEDERSEN_TRACE_INDICES) {
        real_trace[idx as usize] = val;
    }

    Ok(PedersenCommitBitsTrace::new(
        final_add.out.x,
        final_add.out.y,
        real_trace,
    ))
}

/// Rust equivalent of Circom's `pedersen_commit_bits()` using boolean inputs.
pub fn pedersen_commit_bits(
    value_bits_le_251: &[bool; 251],
    r_bits_le_251: &[bool; 251],
) -> eyre::Result<BabyJubJubPoint> {
    let value_bits = value_bits_le_251.map(|bit| if bit { F::one() } else { F::zero() });
    let r_bits = r_bits_le_251.map(|bit| if bit { F::one() } else { F::zero() });
    pedersen_commit_bits_fr(&value_bits, &r_bits)
}

/// Same as [`pedersen_commit_bits`] but takes the bit arrays as `ark_bn254::Fr` values.
pub fn pedersen_commit_bits_fr(
    value_bits_le_251: &[F; 251],
    r_bits_le_251: &[F; 251],
) -> eyre::Result<BabyJubJubPoint> {
    let trace = pedersen_commit_bits_trace_fr(value_bits_le_251, r_bits_le_251)?;
    Ok(BabyJubJubPoint {
        x: trace.out_x,
        y: trace.out_y,
    })
}

#[cfg(test)]
mod tests {
    use crate::gadgets::pedersen::{
        PEDERSEN_COMMIT_BITS_TRACE_MAX_WITNESS_INDEX, PEDERSEN_COMMIT_BITS_TRACE_MIN_WITNESS_INDEX,
    };

    use super::*;
    use ark_babyjubjub::EdwardsAffine;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use std::{fs, path::PathBuf};

    fn pedersen_sym_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../co-circom/co-circom/examples/groth16/test_vectors/pedersen_commit_bits/circuit.sym",
        )
    }

    fn pedersen_trace_sym_names() -> Vec<String> {
        let content = fs::read_to_string(pedersen_sym_path()).expect("circuit.sym should exist");
        let start = usize::from(PEDERSEN_COMMIT_BITS_TRACE_MIN_WITNESS_INDEX);
        let end = usize::from(PEDERSEN_COMMIT_BITS_TRACE_MAX_WITNESS_INDEX);
        let mut names = Vec::new();

        for line in content.lines() {
            let mut parts = line.splitn(4, ',');
            let _first = parts.next();
            let second = parts
                .next()
                .and_then(|x| x.parse::<usize>().ok())
                .unwrap_or(0);
            let _third = parts.next();
            let name = parts.next();

            if (start..=end).contains(&second) {
                names.push(name.unwrap_or_default().to_string());
            }
        }

        names
    }

    fn bits_to_le_bytes(bits: &[bool; 251]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, bit) in bits.iter().enumerate() {
            if *bit {
                out[i / 8] |= 1u8 << (i % 8);
            }
        }
        out
    }

    #[test]
    fn scalar_mul_generator_matches_ark_babyjubjub() {
        let mut rng = StdRng::seed_from_u64(42);

        let g = BabyJubJubPoint {
            x: f_from_dec(
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
            ),
            y: f_from_dec(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            ),
        };

        for _ in 0..16 {
            let mut bits = [false; 251];
            for b in bits.iter_mut() {
                *b = rng.r#gen::<bool>();
            }

            let ours = babyjub_scalar_mul_bits(g, &bits).expect("mul should succeed");

            // Reduce the same 251-bit integer into the curve scalar field and compare against arkworks.
            let k_bytes = bits_to_le_bytes(&bits);
            let k = ark_babyjubjub::Fr::from_le_bytes_mod_order(&k_bytes);
            let ark = (EdwardsAffine::generator() * k).into_affine();

            // Compare by bigint to be robust against any differing concrete base-field type aliases.
            assert_eq!(ours.x.into_bigint(), ark.x.into_bigint());
            assert_eq!(ours.y.into_bigint(), ark.y.into_bigint());
        }
    }

    #[test]
    fn pedersen_commit_is_deterministic() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut value_bits = [false; 251];
        let mut r_bits = [false; 251];
        for i in 0..251 {
            value_bits[i] = rng.r#gen::<bool>();
            r_bits[i] = rng.r#gen::<bool>();
        }

        let c1 = pedersen_commit_bits(&value_bits, &r_bits).unwrap();
        let c2 = pedersen_commit_bits(&value_bits, &r_bits).unwrap();
        assert_eq!(c1, c2);
        assert!(!c1.x.is_zero() || c1.y != F::one());
    }

    #[test]
    fn fr_bits_api_matches_bool_api() {
        let mut rng = StdRng::seed_from_u64(99);
        let mut value_bits = [false; 251];
        let mut r_bits = [false; 251];
        let mut value_bits_fr = [F::zero(); 251];
        let mut r_bits_fr = [F::zero(); 251];

        for i in 0..251 {
            value_bits[i] = rng.r#gen::<bool>();
            r_bits[i] = rng.r#gen::<bool>();
            value_bits_fr[i] = if value_bits[i] { F::one() } else { F::zero() };
            r_bits_fr[i] = if r_bits[i] { F::one() } else { F::zero() };
        }

        let c_bool = pedersen_commit_bits(&value_bits, &r_bits).unwrap();
        let c_fr = pedersen_commit_bits_fr(&value_bits_fr, &r_bits_fr).unwrap();
        assert_eq!(c_bool, c_fr);
    }

    #[test]
    fn pedersen_trace_layout_matches_circuit_sym_contract() {
        let names = pedersen_trace_sym_names();

        assert_eq!(names.len(), PEDERSEN_COMMIT_BITS_TRACE_VALUE_COUNT);

        // Final adder block written first by our trace serializer.
        assert_eq!(names[0], "main.c.add.lhs.x");
        assert_eq!(names[1], "main.c.add.lhs.y");
        assert_eq!(names[2], "main.c.add.rhs.x");
        assert_eq!(names[3], "main.c.add.rhs.y");
        assert!(names[4].starts_with("main.c.add.BabyAdd_"));
        assert!(names[4].ends_with(".beta"));
        assert!(names[5].starts_with("main.c.add.BabyAdd_"));
        assert!(names[5].ends_with(".gamma"));
        assert!(names[6].starts_with("main.c.add.BabyAdd_"));
        assert!(names[6].ends_with(".delta"));
        assert!(names[7].starts_with("main.c.add.BabyAdd_"));
        assert!(names[7].ends_with(".tau"));

        // g_r block occupies exactly one EscalarMulFix trace payload (516 values).
        assert!(names[8].starts_with("main.c.g_r."));
        assert!(names[523].starts_with("main.c.g_r."));
        assert!(names[524].starts_with("main.c.g_value."));

        // g_value block occupies the final EscalarMulFix payload (516 values).
        assert!(names[1039].starts_with("main.c.g_value."));
    }

    #[test]
    fn circom_output_kat() {
        let value_bits = [
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, true, true, true, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false,
        ];
        let r_bits = [
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, true, false, false, false, false, false, false, true, true, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false,
        ];
        let should_x = f_from_dec(
            "19757801306321731221255140900045642466737652558625509354066962242038129252794",
        );
        let should_y = f_from_dec(
            "18146187862815144173113569396796529143208292827289908675458983994242460695898",
        );
        let c = pedersen_commit_bits(&value_bits, &r_bits).unwrap();
        assert_eq!(c.x, should_x);
        assert_eq!(c.y, should_y);
    }

    #[test]
    fn circom_output_kat_trace() {
        let value_bits = [
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, true, true, true, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false,
        ];
        let r_bits = [
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, true, false, false, false, false, false, false, true, true, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false,
        ];
        let should_x = f_from_dec(
            "19757801306321731221255140900045642466737652558625509354066962242038129252794",
        );
        let should_y = f_from_dec(
            "18146187862815144173113569396796529143208292827289908675458983994242460695898",
        );

        let value_bits_fr = value_bits.map(|bit| if bit { F::one() } else { F::zero() });
        let r_bits_fr = r_bits.map(|bit| if bit { F::one() } else { F::zero() });
        let c = pedersen_commit_bits_trace_fr(&value_bits_fr, &r_bits_fr).unwrap();
        assert_eq!(c.out_x, should_x);
        assert_eq!(c.out_y, should_y);
    }
}
