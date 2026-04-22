use std::str::FromStr;

use ark_babyjubjub::EdwardsProjective as BabyJubJubEdwardsProjective;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use eyre::WrapErr;
use mpc_net::Network;
use num_bigint::BigUint;

use super::{
    PEDERSEN_COMMIT_BITS_INPUT_LEN, PEDERSEN_FULL_TRACE_LENGTH, PEDERSEN_TRACE_INDICES,
    PedersenCommitBitsTrace,
};
use crate::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State,
    arithmetic::{self, promote_to_trivial_share},
    conversion,
    pointshare::{self, PointShare},
};

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;
type PublicPoint = ark_babyjubjub::EdwardsAffine;

const PEDERSEN_TOTAL_BITS: usize = PEDERSEN_COMMIT_BITS_INPUT_LEN;
const PEDERSEN_WINDOW_BITS: usize = 3;
const PEDERSEN_FULL_SEGMENT_WINDOWS: usize = 82;
const PEDERSEN_TAIL_SEGMENT_WINDOWS: usize = 2;
const PEDERSEN_HEAD_BITS: usize = PEDERSEN_FULL_SEGMENT_WINDOWS * PEDERSEN_WINDOW_BITS;
const SCALAR_TRACE_VALUES_PER_POINT: usize = 516;

#[derive(Debug, Clone, Copy)]
struct BabyJubJubPointShare<F: PrimeField> {
    x: ArithmeticShare<F>,
    y: ArithmeticShare<F>,
}

#[derive(Debug, Clone, Copy)]
struct MontgomeryPointShare<F: PrimeField> {
    x: ArithmeticShare<F>,
    y: ArithmeticShare<F>,
}

#[derive(Debug, Clone, Copy)]
struct BabyAddTraceShare<F: PrimeField> {
    lhs: BabyJubJubPointShare<F>,
    rhs: BabyJubJubPointShare<F>,
    beta: ArithmeticShare<F>,
    gamma: ArithmeticShare<F>,
    delta: ArithmeticShare<F>,
    tau: ArithmeticShare<F>,
    out: BabyJubJubPointShare<F>,
}

#[derive(Debug, Clone, Copy)]
struct MontgomeryAddTraceShare<F: PrimeField> {
    in2: MontgomeryPointShare<F>,
    lambda: ArithmeticShare<F>,
    out: MontgomeryPointShare<F>,
}

#[derive(Debug, Clone, Copy)]
struct SegmentTraceShare<F: PrimeField> {
    out: Option<BabyJubJubPointShare<F>>,
    adders: [Option<MontgomeryAddTraceShare<F>>; PEDERSEN_FULL_SEGMENT_WINDOWS],
    cadd: Option<BabyAddTraceShare<F>>,
    cadd_lhs: BabyJubJubPointShare<F>,
    cadd_rhs: BabyJubJubPointShare<F>,
    mux_a210_x: [Option<ArithmeticShare<F>>; PEDERSEN_FULL_SEGMENT_WINDOWS],
}

#[inline]
fn montgomery_constants<F: PrimeField>() -> (F, F) {
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
#[expect(clippy::type_complexity)]
fn edwards_to_montgomery_many<F: PrimeField, N: Network>(
    xs: &[ArithmeticShare<F>],
    ys: &[ArithmeticShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<ArithmeticShare<F>>, Vec<ArithmeticShare<F>>)> {
    debug_assert_eq!(xs.len(), ys.len());
    if xs.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let one = promote_to_trivial_share(state.id, F::one());
    let zero = promote_to_trivial_share(state.id, F::zero());

    let x_num: Vec<_> = ys.iter().map(|y| arithmetic::add(one, *y)).collect();
    let one_minus_y: Vec<_> = ys.iter().map(|y| arithmetic::sub(one, *y)).collect();

    let eq_lhs = vec![zero; 2 * xs.len()];
    let mut eq_rhs = Vec::with_capacity(2 * xs.len());
    eq_rhs.extend_from_slice(&one_minus_y);
    eq_rhs.extend_from_slice(xs);
    let is_zero = arithmetic::eq_many(&eq_lhs, &eq_rhs, net, state)?;
    let is_zero_one_minus_y = &is_zero[..xs.len()];
    let is_zero_x = &is_zero[xs.len()..];

    let one_minus_y_tmp: Vec<_> = one_minus_y
        .iter()
        .map(|value| arithmetic::sub_public_by_shared(F::one(), *value, state.id))
        .collect();
    let x_tmp: Vec<_> = xs
        .iter()
        .map(|value| arithmetic::sub_public_by_shared(F::one(), *value, state.id))
        .collect();
    let mut fix_lhs = Vec::with_capacity(2 * xs.len());
    let mut fix_rhs = Vec::with_capacity(2 * xs.len());
    fix_lhs.extend_from_slice(&one_minus_y_tmp);
    fix_lhs.extend_from_slice(&x_tmp);
    fix_rhs.extend_from_slice(is_zero_one_minus_y);
    fix_rhs.extend_from_slice(is_zero_x);
    let fixes = arithmetic::mul_vec(&fix_lhs, &fix_rhs, net, state)?;
    let one_minus_y_fix = &fixes[..xs.len()];
    let x_fix = &fixes[xs.len()..];

    let mut safe_one_minus_y = one_minus_y;
    let mut safe_x = xs.to_vec();
    for i in 0..xs.len() {
        safe_one_minus_y[i] = arithmetic::add(safe_one_minus_y[i], one_minus_y_fix[i]);
        safe_x[i] = arithmetic::add(safe_x[i], x_fix[i]);
    }

    let mut denoms = Vec::with_capacity(2 * xs.len());
    denoms.extend(safe_one_minus_y.iter().copied());
    denoms.extend(safe_x.iter().copied());
    let invs = arithmetic::inv_vec(&denoms, net, state)
        .wrap_err("pedersen rep3 packed: edwards_to_montgomery_many inverse")?;

    let inv_one_minus_y = &invs[..xs.len()];
    let inv_x = &invs[xs.len()..];

    let mut mont_x = arithmetic::mul_vec(&x_num, inv_one_minus_y, net, state)?;
    let mut mont_y = arithmetic::mul_vec(&mont_x, inv_x, net, state)?;

    let nx: Vec<_> = is_zero_one_minus_y
        .iter()
        .map(|value| arithmetic::sub_public_by_shared(F::one(), *value, state.id))
        .collect();
    let ny: Vec<_> = is_zero_x
        .iter()
        .map(|value| arithmetic::sub_public_by_shared(F::one(), *value, state.id))
        .collect();
    let mut mask_lhs = Vec::with_capacity(2 * xs.len());
    let mut mask_rhs = Vec::with_capacity(2 * xs.len());
    mask_lhs.extend_from_slice(&mont_x);
    mask_lhs.extend_from_slice(&mont_y);
    mask_rhs.extend_from_slice(&nx);
    mask_rhs.extend_from_slice(&ny);
    let masked = arithmetic::mul_vec(&mask_lhs, &mask_rhs, net, state)?;
    mont_x = masked[..xs.len()].to_vec();
    mont_y = masked[xs.len()..].to_vec();

    Ok((mont_x, mont_y))
}

#[inline]
fn f_from_dec<F: PrimeField>(value: &str) -> F {
    F::from(BigUint::from_str(value).expect("valid field element"))
}

#[inline]
fn babyjub_generator() -> PublicPoint {
    PublicPoint::new(
        f_from_dec("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
        f_from_dec("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    )
}

#[inline]
fn babyjub_h_generator() -> PublicPoint {
    PublicPoint::new(
        f_from_dec("18070489056226311699126950111606780081892760427770517382371397914121919205062"),
        f_from_dec("15271815330304366999180694217454548993927804584117026509847005260140807626286"),
    )
}

#[inline]
fn promote_public_point_share(
    id: crate::protocols::rep3::id::PartyID,
    point: PublicPoint,
) -> PointShare<BabyJubJubEdwardsProjective> {
    let g = BabyJubJubEdwardsProjective::from(babyjub_generator());
    let h = BabyJubJubEdwardsProjective::from(babyjub_h_generator());
    let p = BabyJubJubEdwardsProjective::from(point);
    let s0 = g;
    let s1 = h;
    let s2 = p - g - h;

    match id {
        crate::protocols::rep3::id::PartyID::ID0 => PointShare::new(s0, s2),
        crate::protocols::rep3::id::PartyID::ID1 => PointShare::new(s1, s0),
        crate::protocols::rep3::id::PartyID::ID2 => PointShare::new(s2, s1),
    }
}

#[inline]
fn cmux_vec_many<F: PrimeField, N: Network>(
    conds: &[ArithmeticShare<F>],
    truthy: &[ArithmeticShare<F>],
    falsy: &[ArithmeticShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<ArithmeticShare<F>>> {
    debug_assert_eq!(conds.len(), truthy.len());
    debug_assert_eq!(conds.len(), falsy.len());
    if conds.is_empty() {
        return Ok(Vec::new());
    }

    let lhs: Vec<_> = truthy
        .iter()
        .zip(falsy.iter())
        .map(|(truthy, falsy)| arithmetic::sub(*truthy, *falsy))
        .collect();
    let products = arithmetic::mul_vec(&lhs, conds, net, state)?;
    Ok(falsy
        .iter()
        .zip(products.iter())
        .map(|(falsy, product)| arithmetic::add(*falsy, *product))
        .collect())
}

#[inline]
fn babyjub_add_trace_many<F: PrimeField, N: Network>(
    lhs: &[BabyJubJubPointShare<F>],
    rhs: &[BabyJubJubPointShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BabyAddTraceShare<F>>> {
    debug_assert_eq!(lhs.len(), rhs.len());
    if lhs.is_empty() {
        return Ok(Vec::new());
    }

    let a = F::from(168700u64);
    let d = F::from(168696u64);

    let lhs_x_scaled: Vec<_> = lhs
        .iter()
        .map(|point| arithmetic::mul_public(point.x, -a))
        .collect();
    let delta_lhs: Vec<_> = lhs_x_scaled
        .iter()
        .zip(lhs.iter())
        .map(|(scaled_x, point)| arithmetic::add(*scaled_x, point.y))
        .collect();
    let delta_rhs: Vec<_> = rhs
        .iter()
        .map(|point| arithmetic::add(point.x, point.y))
        .collect();

    let mut products_lhs = Vec::with_capacity(3 * lhs.len());
    let mut products_rhs = Vec::with_capacity(3 * lhs.len());
    for i in 0..lhs.len() {
        products_lhs.extend([lhs[i].x, lhs[i].y, delta_lhs[i]]);
        products_rhs.extend([rhs[i].y, rhs[i].x, delta_rhs[i]]);
    }
    let products = arithmetic::mul_vec(&products_lhs, &products_rhs, net, state)?;

    let mut beta = Vec::with_capacity(lhs.len());
    let mut gamma = Vec::with_capacity(lhs.len());
    let mut delta = Vec::with_capacity(lhs.len());
    for chunk in products.chunks_exact(3) {
        beta.push(chunk[0]);
        gamma.push(chunk[1]);
        delta.push(chunk[2]);
    }

    let tau = arithmetic::mul_vec(&beta, &gamma, net, state)?;

    let mut denoms = Vec::with_capacity(2 * lhs.len());
    for tau_value in &tau {
        denoms.push(arithmetic::add_public(
            arithmetic::mul_public(*tau_value, d),
            F::one(),
            state.id,
        ));
        denoms.push(arithmetic::add_public(
            arithmetic::mul_public(*tau_value, -d),
            F::one(),
            state.id,
        ));
    }
    let inv_denoms = arithmetic::inv_vec(&denoms, net, state)?;

    let y_num: Vec<_> = beta
        .iter()
        .zip(gamma.iter())
        .zip(delta.iter())
        .map(|((beta_value, gamma_value), delta_value)| {
            arithmetic::sub(
                arithmetic::add(*delta_value, arithmetic::mul_public(*beta_value, a)),
                *gamma_value,
            )
        })
        .collect();

    let mut out_lhs = Vec::with_capacity(2 * lhs.len());
    let mut out_rhs = Vec::with_capacity(2 * lhs.len());
    for i in 0..lhs.len() {
        out_lhs.push(arithmetic::add(beta[i], gamma[i]));
        out_lhs.push(y_num[i]);
        out_rhs.push(inv_denoms[2 * i]);
        out_rhs.push(inv_denoms[2 * i + 1]);
    }
    let out_vals = arithmetic::mul_vec(&out_lhs, &out_rhs, net, state)?;

    let mut traces = Vec::with_capacity(lhs.len());
    for i in 0..lhs.len() {
        traces.push(BabyAddTraceShare {
            lhs: lhs[i],
            rhs: rhs[i],
            beta: beta[i],
            gamma: gamma[i],
            delta: delta[i],
            tau: tau[i],
            out: BabyJubJubPointShare {
                x: out_vals[2 * i],
                y: out_vals[2 * i + 1],
            },
        });
    }

    Ok(traces)
}

#[inline]
fn should_include_a210_trace(window_index: usize, n_windows: usize) -> bool {
    n_windows != PEDERSEN_TAIL_SEGMENT_WINDOWS || window_index == 0
}

#[inline]
fn append_top_add_trace<F: PrimeField>(
    trace: &mut Vec<ArithmeticShare<F>>,
    top: BabyAddTraceShare<F>,
) {
    trace.push(top.lhs.x);
    trace.push(top.lhs.y);
    trace.push(top.rhs.x);
    trace.push(top.rhs.y);
    trace.push(top.beta);
    trace.push(top.gamma);
    trace.push(top.delta);
    trace.push(top.tau);
}

#[inline]
fn append_segment_trace<F: PrimeField>(
    trace: &mut Vec<ArithmeticShare<F>>,
    segment: &SegmentTraceShare<F>,
    n_windows: usize,
) {
    for window_index in 0..n_windows {
        let adder = segment.adders[window_index].expect("segment adder exists");
        trace.push(adder.out.x);
        trace.push(adder.out.y);
        trace.push(adder.in2.x);
        if should_include_a210_trace(window_index, n_windows) {
            trace.push(adder.in2.y);
        }
        trace.push(adder.lambda);
    }

    let cadd = segment.cadd.expect("segment cadd exists");
    trace.push(cadd.lhs.x);
    trace.push(cadd.lhs.y);
    trace.push(cadd.tau);

    for window_index in 0..n_windows {
        if let Some(a210_x) = segment.mux_a210_x[window_index] {
            trace.push(a210_x);
        }
    }
}

fn build_window_tables_from_base(
    base: PointShare<BabyJubJubEdwardsProjective>,
    n_windows: usize,
) -> (
    Vec<[PointShare<BabyJubJubEdwardsProjective>; 8]>,
    Vec<PointShare<BabyJubJubEdwardsProjective>>,
)
where
    BabyJubJubEdwardsProjective: CurveGroup,
{
    let mut window_tables = Vec::with_capacity(n_windows);
    let mut window_out8 = Vec::with_capacity(n_windows);

    for window_index in 0..n_windows {
        let base_point = if window_index == 0 {
            base
        } else {
            window_out8[window_index - 1]
        };
        let dbl2_ed = pointshare::add(&base_point, &base_point);
        let adr3_ed = pointshare::add(&base_point, &dbl2_ed);
        let adr4_ed = pointshare::add(&base_point, &adr3_ed);
        let adr5_ed = pointshare::add(&base_point, &adr4_ed);
        let adr6_ed = pointshare::add(&base_point, &adr5_ed);
        let adr7_ed = pointshare::add(&base_point, &adr6_ed);
        let adr8_ed = pointshare::add(&base_point, &adr7_ed);

        window_tables.push([
            base_point, dbl2_ed, adr3_ed, adr4_ed, adr5_ed, adr6_ed, adr7_ed, adr8_ed,
        ]);
        window_out8.push(adr8_ed);
    }

    (window_tables, window_out8)
}

#[expect(clippy::type_complexity)]
fn segment_mul_fix_trace_two_segments_batched_many<F: PrimeField, N: Network>(
    bases: &[PointShare<BabyJubJubEdwardsProjective>],
    bits_head: &[&[ArithmeticShare<F>]],
    bits_tail: &[&[ArithmeticShare<F>]],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<SegmentTraceShare<F>>, Vec<SegmentTraceShare<F>>)>
where
    BabyJubJubEdwardsProjective: CurveGroup<BaseField = F>,
{
    let num_scalars = bases.len();
    debug_assert_eq!(bits_head.len(), num_scalars);
    debug_assert_eq!(bits_tail.len(), num_scalars);
    if num_scalars == 0 {
        return Ok((Vec::new(), Vec::new()));
    }

    let n0 = PEDERSEN_FULL_SEGMENT_WINDOWS;
    let n1 = PEDERSEN_TAIL_SEGMENT_WINDOWS;
    let zero = promote_to_trivial_share(state.id, F::zero());

    let mut padded_heads = Vec::with_capacity(num_scalars);
    let mut padded_tails = Vec::with_capacity(num_scalars);
    let mut head_out8 = Vec::with_capacity(num_scalars);
    let mut tail_out8 = Vec::with_capacity(num_scalars);
    let mut all_table_points = Vec::with_capacity(num_scalars * 8 * (n0 + n1));

    for scalar_idx in 0..num_scalars {
        let mut padded_head = bits_head[scalar_idx].to_vec();
        padded_head.resize(n0 * PEDERSEN_WINDOW_BITS, zero);

        let (tables0, out80_0) = build_window_tables_from_base(bases[scalar_idx], n0);
        let base1 = out80_0[n0 - 1];

        let mut padded_tail = bits_tail[scalar_idx].to_vec();
        padded_tail.resize(n1 * PEDERSEN_WINDOW_BITS, zero);
        let (tables1, out80_1) = build_window_tables_from_base(base1, n1);

        for table in &tables0 {
            all_table_points.extend_from_slice(table);
        }
        for table in &tables1 {
            all_table_points.extend_from_slice(table);
        }

        padded_heads.push(padded_head);
        padded_tails.push(padded_tail);
        head_out8.push(out80_0);
        tail_out8.push(out80_1);
    }

    let (table_xs, table_ys, _table_is_inf) =
        conversion::point_share_to_fieldshares_many(&all_table_points, net, state)?;
    let (mont_table_xs, _mont_table_ys) =
        edwards_to_montgomery_many(&table_xs, &table_ys, net, state)?;

    let per_scalar_head_points = 8 * n0;
    let per_scalar_tail_points = 8 * n1;
    let per_scalar_total_points = per_scalar_head_points + per_scalar_tail_points;

    let mut stage1_conds = Vec::with_capacity(num_scalars * 8 * (n0 + n1));
    let mut stage1_truthy = Vec::with_capacity(num_scalars * 8 * (n0 + n1));
    let mut stage1_falsy = Vec::with_capacity(num_scalars * 8 * (n0 + n1));

    for scalar_idx in 0..num_scalars {
        let scalar_start = scalar_idx * per_scalar_total_points;
        let table_xs0 = &table_xs[scalar_start..scalar_start + per_scalar_head_points];
        let table_ys0 = &table_ys[scalar_start..scalar_start + per_scalar_head_points];
        let table_xs1 =
            &table_xs[scalar_start + per_scalar_head_points..scalar_start + per_scalar_total_points];
        let table_ys1 =
            &table_ys[scalar_start + per_scalar_head_points..scalar_start + per_scalar_total_points];

        for window_index in 0..n0 {
            let bit0 = padded_heads[scalar_idx][PEDERSEN_WINDOW_BITS * window_index];
            let off = 8 * window_index;
            stage1_truthy.extend_from_slice(&[
                table_xs0[off + 1],
                table_ys0[off + 1],
                table_xs0[off + 3],
                table_ys0[off + 3],
                table_xs0[off + 5],
                table_ys0[off + 5],
                table_xs0[off + 7],
                table_ys0[off + 7],
            ]);
            stage1_falsy.extend_from_slice(&[
                table_xs0[off],
                table_ys0[off],
                table_xs0[off + 2],
                table_ys0[off + 2],
                table_xs0[off + 4],
                table_ys0[off + 4],
                table_xs0[off + 6],
                table_ys0[off + 6],
            ]);
            stage1_conds.extend_from_slice(&[bit0; 8]);
        }

        for window_index in 0..n1 {
            let bit0 = padded_tails[scalar_idx][PEDERSEN_WINDOW_BITS * window_index];
            let off = 8 * window_index;
            stage1_truthy.extend_from_slice(&[
                table_xs1[off + 1],
                table_ys1[off + 1],
                table_xs1[off + 3],
                table_ys1[off + 3],
                table_xs1[off + 5],
                table_ys1[off + 5],
                table_xs1[off + 7],
                table_ys1[off + 7],
            ]);
            stage1_falsy.extend_from_slice(&[
                table_xs1[off],
                table_ys1[off],
                table_xs1[off + 2],
                table_ys1[off + 2],
                table_xs1[off + 4],
                table_ys1[off + 4],
                table_xs1[off + 6],
                table_ys1[off + 6],
            ]);
            stage1_conds.extend_from_slice(&[bit0; 8]);
        }
    }

    let stage1_sel = cmux_vec_many(&stage1_conds, &stage1_truthy, &stage1_falsy, net, state)?;
    let per_scalar_stage1 = 8 * (n0 + n1);
    let per_scalar_stage1_head = 8 * n0;

    let mut stage2_conds = Vec::with_capacity(num_scalars * 4 * (n0 + n1));
    let mut stage2_truthy = Vec::with_capacity(num_scalars * 4 * (n0 + n1));
    let mut stage2_falsy = Vec::with_capacity(num_scalars * 4 * (n0 + n1));

    for scalar_idx in 0..num_scalars {
        let scalar_start = scalar_idx * per_scalar_stage1;
        let stage1_sel0 = &stage1_sel[scalar_start..scalar_start + per_scalar_stage1_head];
        let stage1_sel1 = &stage1_sel[scalar_start + per_scalar_stage1_head..scalar_start + per_scalar_stage1];

        for window_index in 0..n0 {
            let bit1 = padded_heads[scalar_idx][PEDERSEN_WINDOW_BITS * window_index + 1];
            let off = 8 * window_index;
            stage2_truthy.extend_from_slice(&[
                stage1_sel0[off + 2],
                stage1_sel0[off + 3],
                stage1_sel0[off + 6],
                stage1_sel0[off + 7],
            ]);
            stage2_falsy.extend_from_slice(&[
                stage1_sel0[off],
                stage1_sel0[off + 1],
                stage1_sel0[off + 4],
                stage1_sel0[off + 5],
            ]);
            stage2_conds.extend_from_slice(&[bit1; 4]);
        }

        for window_index in 0..n1 {
            let bit1 = padded_tails[scalar_idx][PEDERSEN_WINDOW_BITS * window_index + 1];
            let off = 8 * window_index;
            stage2_truthy.extend_from_slice(&[
                stage1_sel1[off + 2],
                stage1_sel1[off + 3],
                stage1_sel1[off + 6],
                stage1_sel1[off + 7],
            ]);
            stage2_falsy.extend_from_slice(&[
                stage1_sel1[off],
                stage1_sel1[off + 1],
                stage1_sel1[off + 4],
                stage1_sel1[off + 5],
            ]);
            stage2_conds.extend_from_slice(&[bit1; 4]);
        }
    }

    let stage2_sel = cmux_vec_many(&stage2_conds, &stage2_truthy, &stage2_falsy, net, state)?;
    let per_scalar_stage2 = 4 * (n0 + n1);
    let per_scalar_stage2_head = 4 * n0;

    let mut stage3_conds = Vec::with_capacity(num_scalars * 2 * (n0 + n1));
    let mut stage3_truthy = Vec::with_capacity(num_scalars * 2 * (n0 + n1));
    let mut stage3_falsy = Vec::with_capacity(num_scalars * 2 * (n0 + n1));

    for scalar_idx in 0..num_scalars {
        let scalar_start = scalar_idx * per_scalar_stage2;
        let stage2_sel0 = &stage2_sel[scalar_start..scalar_start + per_scalar_stage2_head];
        let stage2_sel1 = &stage2_sel[scalar_start + per_scalar_stage2_head..scalar_start + per_scalar_stage2];

        for window_index in 0..n0 {
            let bit2 = padded_heads[scalar_idx][PEDERSEN_WINDOW_BITS * window_index + 2];
            let off = 4 * window_index;
            stage3_truthy.extend_from_slice(&[stage2_sel0[off + 2], stage2_sel0[off + 3]]);
            stage3_falsy.extend_from_slice(&[stage2_sel0[off], stage2_sel0[off + 1]]);
            stage3_conds.extend_from_slice(&[bit2; 2]);
        }

        for window_index in 0..n1 {
            let bit2 = padded_tails[scalar_idx][PEDERSEN_WINDOW_BITS * window_index + 2];
            let off = 4 * window_index;
            stage3_truthy.extend_from_slice(&[stage2_sel1[off + 2], stage2_sel1[off + 3]]);
            stage3_falsy.extend_from_slice(&[stage2_sel1[off], stage2_sel1[off + 1]]);
            stage3_conds.extend_from_slice(&[bit2; 2]);
        }
    }

    let stage3_sel = cmux_vec_many(&stage3_conds, &stage3_truthy, &stage3_falsy, net, state)?;
    let per_scalar_stage3 = 2 * (n0 + n1);
    let per_scalar_stage3_head = 2 * n0;

    let mut head_window_coords = Vec::with_capacity(num_scalars);
    let mut tail_window_coords = Vec::with_capacity(num_scalars);
    for scalar_idx in 0..num_scalars {
        let scalar_start = scalar_idx * per_scalar_stage3;
        let stage3_sel0 = &stage3_sel[scalar_start..scalar_start + per_scalar_stage3_head];
        let stage3_sel1 = &stage3_sel[scalar_start + per_scalar_stage3_head..scalar_start + per_scalar_stage3];

        let mut head_coords = Vec::with_capacity(n0);
        for window_index in 0..n0 {
            let off = 2 * window_index;
            head_coords.push(BabyJubJubPointShare {
                x: stage3_sel0[off],
                y: stage3_sel0[off + 1],
            });
        }

        let mut tail_coords = Vec::with_capacity(n1);
        for window_index in 0..n1 {
            let off = 2 * window_index;
            tail_coords.push(BabyJubJubPointShare {
                x: stage3_sel1[off],
                y: stage3_sel1[off + 1],
            });
        }

        head_window_coords.push(head_coords);
        tail_window_coords.push(tail_coords);
    }

    let mut all_window_outs_xs = Vec::with_capacity(num_scalars * (n0 + n1));
    let mut all_window_outs_ys = Vec::with_capacity(num_scalars * (n0 + n1));
    for scalar_idx in 0..num_scalars {
        for point in &head_window_coords[scalar_idx] {
            all_window_outs_xs.push(point.x);
            all_window_outs_ys.push(point.y);
        }
        for point in &tail_window_coords[scalar_idx] {
            all_window_outs_xs.push(point.x);
            all_window_outs_ys.push(point.y);
        }
    }

    let all_window_outs_is_inf = vec![zero; num_scalars * (n0 + n1)];
    let all_window_outs_points =
        conversion::fieldshares_to_pointshare_many::<BabyJubJubEdwardsProjective, N>(
            &all_window_outs_xs,
            &all_window_outs_ys,
            &all_window_outs_is_inf,
            net,
            state,
        )?;

    let mut head_window_points = Vec::with_capacity(num_scalars);
    let mut tail_window_points = Vec::with_capacity(num_scalars);
    for scalar_idx in 0..num_scalars {
        let scalar_start = scalar_idx * (n0 + n1);
        head_window_points.push(all_window_outs_points[scalar_start..scalar_start + n0].to_vec());
        tail_window_points.push(
            all_window_outs_points[scalar_start + n0..scalar_start + n0 + n1].to_vec(),
        );
    }

    let mut mux_head = vec![vec![None; n0]; num_scalars];
    let mut mux_tail = vec![vec![None; n1]; num_scalars];
    let mut deferred_a210_lhs = Vec::new();
    let mut deferred_s10_lhs = Vec::new();
    let mut deferred_s10_rhs = Vec::new();
    let mut deferred_targets = Vec::new();

    for scalar_idx in 0..num_scalars {
        let scalar_start = scalar_idx * per_scalar_total_points;
        let mont_table_xs0 = &mont_table_xs[scalar_start..scalar_start + per_scalar_head_points];
        let mont_table_xs1 =
            &mont_table_xs[scalar_start + per_scalar_head_points..scalar_start + per_scalar_total_points];

        for window_index in 0..n0 {
            let off = 8 * window_index;
            let a210_input = arithmetic::sub(
                arithmetic::add(
                    arithmetic::sub(
                        arithmetic::add(
                            arithmetic::sub(mont_table_xs0[off + 7], mont_table_xs0[off + 6]),
                            mont_table_xs0[off + 4],
                        ),
                        mont_table_xs0[off + 5],
                    ),
                    arithmetic::add(mont_table_xs0[off + 2], mont_table_xs0[off + 1]),
                ),
                arithmetic::add(mont_table_xs0[off + 3], mont_table_xs0[off]),
            );
            let bit1 = padded_heads[scalar_idx][PEDERSEN_WINDOW_BITS * window_index + 1];
            let bit0 = padded_heads[scalar_idx][PEDERSEN_WINDOW_BITS * window_index];
            if should_include_a210_trace(window_index, n0) {
                deferred_a210_lhs.push(a210_input);
                deferred_s10_lhs.push(bit1);
                deferred_s10_rhs.push(bit0);
                deferred_targets.push((scalar_idx, 0usize, window_index));
            }
        }

        for window_index in 0..n1 {
            let off = 8 * window_index;
            let a210_input = arithmetic::sub(
                arithmetic::add(
                    arithmetic::sub(
                        arithmetic::add(
                            arithmetic::sub(mont_table_xs1[off + 7], mont_table_xs1[off + 6]),
                            mont_table_xs1[off + 4],
                        ),
                        mont_table_xs1[off + 5],
                    ),
                    arithmetic::add(mont_table_xs1[off + 2], mont_table_xs1[off + 1]),
                ),
                arithmetic::add(mont_table_xs1[off + 3], mont_table_xs1[off]),
            );
            let bit1 = padded_tails[scalar_idx][PEDERSEN_WINDOW_BITS * window_index + 1];
            let bit0 = padded_tails[scalar_idx][PEDERSEN_WINDOW_BITS * window_index];
            if should_include_a210_trace(window_index, n1) {
                deferred_a210_lhs.push(a210_input);
                deferred_s10_lhs.push(bit1);
                deferred_s10_rhs.push(bit0);
                deferred_targets.push((scalar_idx, 1usize, window_index));
            }
        }
    }

    if !deferred_targets.is_empty() {
        let deferred_s10 = arithmetic::mul_vec(&deferred_s10_lhs, &deferred_s10_rhs, net, state)?;
        let deferred_vals = arithmetic::mul_vec(&deferred_a210_lhs, &deferred_s10, net, state)?;
        for ((scalar_idx, segment, window_index), value) in
            deferred_targets.into_iter().zip(deferred_vals)
        {
            if segment == 0 {
                mux_head[scalar_idx][window_index] = Some(value);
            } else {
                mux_tail[scalar_idx][window_index] = Some(value);
            }
        }
    }

    let mut dbl_last_head_points = Vec::with_capacity(num_scalars);
    let mut dbl_last_tail_points = Vec::with_capacity(num_scalars);
    let mut adders_head_points = Vec::with_capacity(num_scalars);
    let mut adders_tail_points = Vec::with_capacity(num_scalars);
    let mut cfinal_head_points = Vec::with_capacity(num_scalars);
    let mut cfinal_tail_points = Vec::with_capacity(num_scalars);

    for scalar_idx in 0..num_scalars {
        let dbl_last_head = pointshare::add(
            &head_out8[scalar_idx][n0 - 1],
            &head_out8[scalar_idx][n0 - 1],
        );
        let dbl_last_tail = pointshare::add(
            &tail_out8[scalar_idx][n1 - 1],
            &tail_out8[scalar_idx][n1 - 1],
        );

        let mut cadders_head = Vec::with_capacity(n0);
        let mut adders_head = Vec::with_capacity(n0);
        for window_index in 0..n0 {
            let cadd_in1 = if window_index == 0 {
                bases[scalar_idx]
            } else {
                cadders_head[window_index - 1]
            };
            let cadd_in2 = if window_index + 1 == n0 {
                dbl_last_head
            } else {
                head_out8[scalar_idx][window_index]
            };
            cadders_head.push(pointshare::add(&cadd_in1, &cadd_in2));

            let add_in1 = if window_index == 0 {
                dbl_last_head
            } else {
                adders_head[window_index - 1]
            };
            adders_head.push(pointshare::add(
                &add_in1,
                &head_window_points[scalar_idx][window_index],
            ));
        }

        let base1 = head_out8[scalar_idx][n0 - 1];
        let mut cadders_tail = Vec::with_capacity(n1);
        let mut adders_tail = Vec::with_capacity(n1);
        for window_index in 0..n1 {
            let cadd_in1 = if window_index == 0 {
                base1
            } else {
                cadders_tail[window_index - 1]
            };
            let cadd_in2 = if window_index + 1 == n1 {
                dbl_last_tail
            } else {
                tail_out8[scalar_idx][window_index]
            };
            cadders_tail.push(pointshare::add(&cadd_in1, &cadd_in2));

            let add_in1 = if window_index == 0 {
                dbl_last_tail
            } else {
                adders_tail[window_index - 1]
            };
            adders_tail.push(pointshare::add(
                &add_in1,
                &tail_window_points[scalar_idx][window_index],
            ));
        }

        dbl_last_head_points.push(dbl_last_head);
        dbl_last_tail_points.push(dbl_last_tail);
        adders_head_points.push(adders_head);
        adders_tail_points.push(adders_tail);
        cfinal_head_points.push(cadders_head[n0 - 1]);
        cfinal_tail_points.push(cadders_tail[n1 - 1]);
    }

    let mut adder_points = Vec::with_capacity(num_scalars * (n0 + n1 + 4));
    for scalar_idx in 0..num_scalars {
        adder_points.push(dbl_last_head_points[scalar_idx]);
        adder_points.extend_from_slice(&adders_head_points[scalar_idx]);
        adder_points.push(dbl_last_tail_points[scalar_idx]);
        adder_points.extend_from_slice(&adders_tail_points[scalar_idx]);
        adder_points.push(cfinal_head_points[scalar_idx]);
        adder_points.push(cfinal_tail_points[scalar_idx]);
    }

    let (adder_xs, adder_ys, _adder_is_inf) =
        conversion::point_share_to_fieldshares_many(&adder_points, net, state)?;

    let per_scalar_adder_points = n0 + n1 + 4;
    let mut dbl_last_head_coords = Vec::with_capacity(num_scalars);
    let mut dbl_last_tail_coords = Vec::with_capacity(num_scalars);
    let mut adders_head_out = Vec::with_capacity(num_scalars);
    let mut adders_tail_out = Vec::with_capacity(num_scalars);
    let mut cadd_rhs_head = Vec::with_capacity(num_scalars);
    let mut cadd_rhs_tail = Vec::with_capacity(num_scalars);

    for scalar_idx in 0..num_scalars {
        let scalar_start = scalar_idx * per_scalar_adder_points;
        dbl_last_head_coords.push(BabyJubJubPointShare {
            x: adder_xs[scalar_start],
            y: adder_ys[scalar_start],
        });

        let mut head_out = Vec::with_capacity(n0);
        for window_index in 0..n0 {
            let off = scalar_start + 1 + window_index;
            head_out.push(BabyJubJubPointShare {
                x: adder_xs[off],
                y: adder_ys[off],
            });
        }

        let tail_start = scalar_start + 1 + n0;
        dbl_last_tail_coords.push(BabyJubJubPointShare {
            x: adder_xs[tail_start],
            y: adder_ys[tail_start],
        });

        let mut tail_out = Vec::with_capacity(n1);
        for window_index in 0..n1 {
            let off = tail_start + 1 + window_index;
            tail_out.push(BabyJubJubPointShare {
                x: adder_xs[off],
                y: adder_ys[off],
            });
        }

        let cadd_head_idx = tail_start + 1 + n1;
        cadd_rhs_head.push(BabyJubJubPointShare {
            x: adder_xs[cadd_head_idx],
            y: adder_ys[cadd_head_idx],
        });
        cadd_rhs_tail.push(BabyJubJubPointShare {
            x: adder_xs[cadd_head_idx + 1],
            y: adder_ys[cadd_head_idx + 1],
        });

        adders_head_out.push(head_out);
        adders_tail_out.push(tail_out);
    }

    let mut in1_xs = Vec::with_capacity(num_scalars * (n0 + n1));
    let mut in1_ys = Vec::with_capacity(num_scalars * (n0 + n1));
    let mut in2_xs = Vec::with_capacity(num_scalars * (n0 + n1));
    let mut in2_ys = Vec::with_capacity(num_scalars * (n0 + n1));
    let mut adder_targets = Vec::with_capacity(num_scalars * (n0 + n1));

    for scalar_idx in 0..num_scalars {
        for window_index in 0..n0 {
            let in1 = if window_index == 0 {
                dbl_last_head_coords[scalar_idx]
            } else {
                adders_head_out[scalar_idx][window_index - 1]
            };
            in1_xs.push(in1.x);
            in1_ys.push(in1.y);
            in2_xs.push(head_window_coords[scalar_idx][window_index].x);
            in2_ys.push(head_window_coords[scalar_idx][window_index].y);
            adder_targets.push((scalar_idx, 0usize, window_index));
        }

        for window_index in 0..n1 {
            let in1 = if window_index == 0 {
                dbl_last_tail_coords[scalar_idx]
            } else {
                adders_tail_out[scalar_idx][window_index - 1]
            };
            in1_xs.push(in1.x);
            in1_ys.push(in1.y);
            in2_xs.push(tail_window_coords[scalar_idx][window_index].x);
            in2_ys.push(tail_window_coords[scalar_idx][window_index].y);
            adder_targets.push((scalar_idx, 1usize, window_index));
        }
    }

    let mut all_in_xs = Vec::with_capacity(2 * in1_xs.len());
    let mut all_in_ys = Vec::with_capacity(2 * in1_ys.len());
    all_in_xs.extend_from_slice(&in1_xs);
    all_in_xs.extend_from_slice(&in2_xs);
    all_in_ys.extend_from_slice(&in1_ys);
    all_in_ys.extend_from_slice(&in2_ys);

    let (all_in_mx, all_in_my) = edwards_to_montgomery_many(&all_in_xs, &all_in_ys, net, state)?;
    let split = adder_targets.len();
    let in1_mx = &all_in_mx[..split];
    let in2_mx = &all_in_mx[split..];
    let in1_my = &all_in_my[..split];
    let in2_my = &all_in_my[split..];

    let mut lambda_den = Vec::with_capacity(split);
    let mut lambda_num = Vec::with_capacity(split);
    for i in 0..split {
        lambda_den.push(arithmetic::sub(in2_mx[i], in1_mx[i]));
        lambda_num.push(arithmetic::sub(in2_my[i], in1_my[i]));
    }

    let zero_den = vec![zero; lambda_den.len()];
    let is_zero_den = arithmetic::eq_many(&zero_den, &lambda_den, net, state)?;
    let den_tmp: Vec<_> = lambda_den
        .iter()
        .map(|denom| arithmetic::sub_public_by_shared(F::one(), *denom, state.id))
        .collect();
    let den_fix = arithmetic::mul_vec(&den_tmp, &is_zero_den, net, state)?;
    let mut safe_den = lambda_den;
    for i in 0..safe_den.len() {
        safe_den[i] = arithmetic::add(safe_den[i], den_fix[i]);
    }
    let lambda_den_inv = arithmetic::inv_vec(&safe_den, net, state)
        .wrap_err("pedersen rep3 packed: montgomery adder inverse")?;
    let mut lambdas = arithmetic::mul_vec(&lambda_num, &lambda_den_inv, net, state)?;
    let keep: Vec<_> = is_zero_den
        .iter()
        .map(|value| arithmetic::sub_public_by_shared(F::one(), *value, state.id))
        .collect();
    lambdas = arithmetic::mul_vec(&lambdas, &keep, net, state)?;

    let (montgomery_a, montgomery_b) = montgomery_constants::<F>();
    let lambda_sq = arithmetic::mul_vec(&lambdas, &lambdas, net, state)?;
    let montgomery_b_share = promote_to_trivial_share(state.id, montgomery_b);
    let b_lambda_sq = arithmetic::mul_vec(
        &lambda_sq,
        &vec![montgomery_b_share; split],
        net,
        state,
    )?;
    let b_lambda_sq_minus_a: Vec<_> = b_lambda_sq
        .iter()
        .map(|value| arithmetic::sub_shared_by_public(*value, montgomery_a, state.id))
        .collect();

    let out_mx: Vec<_> = b_lambda_sq_minus_a
        .iter()
        .enumerate()
        .map(|(i, value)| arithmetic::sub(arithmetic::sub(*value, in1_mx[i]), in2_mx[i]))
        .collect();
    let x1_minus_out: Vec<_> = in1_mx
        .iter()
        .enumerate()
        .map(|(i, value)| arithmetic::sub(*value, out_mx[i]))
        .collect();
    let lambda_times = arithmetic::mul_vec(&lambdas, &x1_minus_out, net, state)?;
    let out_my: Vec<_> = lambda_times
        .iter()
        .enumerate()
        .map(|(i, value)| arithmetic::sub(*value, in1_my[i]))
        .collect();

    let mut adders_head = vec![vec![None; n0]; num_scalars];
    let mut adders_tail = vec![vec![None; n1]; num_scalars];
    for (idx, (scalar_idx, segment, window_index)) in adder_targets.into_iter().enumerate() {
        let adder = MontgomeryAddTraceShare {
            in2: MontgomeryPointShare {
                x: in2_mx[idx],
                y: in2_my[idx],
            },
            lambda: lambdas[idx],
            out: MontgomeryPointShare {
                x: out_mx[idx],
                y: out_my[idx],
            },
        };
        if segment == 0 {
            adders_head[scalar_idx][window_index] = Some(adder);
        } else {
            adders_tail[scalar_idx][window_index] = Some(adder);
        }
    }

    let mut seg0 = Vec::with_capacity(num_scalars);
    let mut seg1 = Vec::with_capacity(num_scalars);
    for scalar_idx in 0..num_scalars {
        let mut adders0 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
        for (dst, src) in adders0.iter_mut().zip(adders_head[scalar_idx].iter().copied()) {
            *dst = src;
        }

        let mut adders1 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
        for (dst, src) in adders1.iter_mut().zip(adders_tail[scalar_idx].iter().copied()) {
            *dst = src;
        }

        let mut mux0 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
        mux0[..n0].copy_from_slice(&mux_head[scalar_idx][..n0]);
        let mut mux1 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
        mux1[..n1].copy_from_slice(&mux_tail[scalar_idx][..n1]);

        seg0.push(SegmentTraceShare {
            out: None,
            adders: adders0,
            cadd: None,
            cadd_lhs: adders_head_out[scalar_idx][n0 - 1],
            cadd_rhs: cadd_rhs_head[scalar_idx],
            mux_a210_x: mux0,
        });
        seg1.push(SegmentTraceShare {
            out: None,
            adders: adders1,
            cadd: None,
            cadd_lhs: adders_tail_out[scalar_idx][n1 - 1],
            cadd_rhs: cadd_rhs_tail[scalar_idx],
            mux_a210_x: mux1,
        });
    }

    Ok((seg0, seg1))
}

#[expect(clippy::type_complexity)]
fn segment_mul_fix_trace_two_stage_many<F: PrimeField, N: Network>(
    bases: &[PublicPoint],
    bits: &[&[ArithmeticShare<F>; PEDERSEN_TOTAL_BITS]],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<SegmentTraceShare<F>>, Vec<SegmentTraceShare<F>>)> 
where
    BabyJubJubEdwardsProjective: CurveGroup<BaseField = F>,
{
    let base_edwards: Vec<_> = bases
        .iter()
        .map(|base| promote_public_point_share(state.id, *base))
        .collect();
    let bits_head: Vec<_> = bits.iter().map(|bits| &bits[..PEDERSEN_HEAD_BITS]).collect();
    let bits_tail: Vec<_> = bits.iter().map(|bits| &bits[PEDERSEN_HEAD_BITS..]).collect();

    let (mut seg0, mut seg1) = segment_mul_fix_trace_two_segments_batched_many(
        &base_edwards,
        &bits_head,
        &bits_tail,
        net,
        state,
    )?;

    let cadd_lhs: Vec<_> = seg0
        .iter()
        .map(|segment| segment.cadd_lhs)
        .chain(seg1.iter().map(|segment| segment.cadd_lhs))
        .collect();
    let cadd_rhs: Vec<_> = seg0
        .iter()
        .map(|segment| BabyJubJubPointShare {
            x: arithmetic::neg(segment.cadd_rhs.x),
            y: segment.cadd_rhs.y,
        })
        .chain(seg1.iter().map(|segment| BabyJubJubPointShare {
            x: arithmetic::neg(segment.cadd_rhs.x),
            y: segment.cadd_rhs.y,
        }))
        .collect();
    let cadds = babyjub_add_trace_many(&cadd_lhs, &cadd_rhs, net, state)?;

    for i in 0..seg0.len() {
        seg0[i].cadd = Some(cadds[i]);
        seg0[i].out = Some(cadds[i].out);
        let tail_idx = i + seg0.len();
        seg1[i].cadd = Some(cadds[tail_idx]);
        seg1[i].out = Some(cadds[tail_idx].out);
    }

    Ok((seg0, seg1))
}

#[expect(clippy::type_complexity)]
fn escalar_mul_fix_trace_many<F: PrimeField, N: Network>(
    bases: &[PublicPoint],
    bits: &[&[ArithmeticShare<F>; PEDERSEN_TOTAL_BITS]],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<BabyJubJubPointShare<F>>, Vec<Vec<ArithmeticShare<F>>>)>
where
    BabyJubJubEdwardsProjective: CurveGroup<BaseField = F>,
{
    let (seg0, seg1) = segment_mul_fix_trace_two_stage_many(bases, bits, net, state)?;
    let top_lhs: Vec<_> = seg0
        .iter()
        .map(|segment| segment.out.expect("segment0 out exists"))
        .collect();
    let top_rhs: Vec<_> = seg1
        .iter()
        .map(|segment| segment.out.expect("segment1 out exists"))
        .collect();
    let top_adders = babyjub_add_trace_many(&top_lhs, &top_rhs, net, state)?;

    let mut outs = Vec::with_capacity(top_adders.len());
    let mut traces = Vec::with_capacity(top_adders.len());
    for ((segment0, segment1), top_adder) in seg0.iter().zip(seg1.iter()).zip(top_adders) {
        let mut trace = Vec::with_capacity(SCALAR_TRACE_VALUES_PER_POINT);
        append_top_add_trace(&mut trace, top_adder);
        append_segment_trace(&mut trace, segment0, PEDERSEN_FULL_SEGMENT_WINDOWS);
        append_segment_trace(&mut trace, segment1, PEDERSEN_TAIL_SEGMENT_WINDOWS);
        outs.push(top_adder.out);
        traces.push(trace);
    }

    Ok((outs, traces))
}

/// Computes the full Circom-compatible `pedersen_commit_bits` outputs and dense accelerator traces
/// for a packed batch of rep3 arithmetic shares, batching MPC networking operations across the
/// full input batch.
pub fn pedersen_commit_bits_trace_rep3_packed<F: PrimeField, N: Network>(
    value_bits_le_251: &[[ArithmeticShare<F>; PEDERSEN_COMMIT_BITS_INPUT_LEN]],
    r_bits_le_251: &[[ArithmeticShare<F>; PEDERSEN_COMMIT_BITS_INPUT_LEN]],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<PedersenCommitBitsTrace<ArithmeticShare<F>>>>
where
    BabyJubJubEdwardsProjective: CurveGroup<BaseField = F>,
{
    eyre::ensure!(
        value_bits_le_251.len() == r_bits_le_251.len(),
        "pedersen packed inputs must have the same batch size"
    );

    if value_bits_le_251.is_empty() {
        return Ok(Vec::new());
    }

    let mut bases = Vec::with_capacity(2 * value_bits_le_251.len());
    let mut bits = Vec::with_capacity(2 * value_bits_le_251.len());
    for (value_bits, r_bits) in value_bits_le_251.iter().zip(r_bits_le_251.iter()) {
        bases.push(babyjub_h_generator());
        bits.push(r_bits);
        bases.push(babyjub_generator());
        bits.push(value_bits);
    }

    let (scalar_outputs, scalar_traces) = escalar_mul_fix_trace_many(&bases, &bits, net, state)?;
    let final_lhs: Vec<_> = scalar_outputs.iter().copied().skip(1).step_by(2).collect();
    let final_rhs: Vec<_> = scalar_outputs.iter().copied().step_by(2).collect();
    let final_adds = babyjub_add_trace_many(&final_lhs, &final_rhs, net, state)?;

    let mut traces = Vec::with_capacity(value_bits_le_251.len());
    let mut scalar_trace_iter = scalar_traces.into_iter();
    for final_add in final_adds {
        let g_r_trace = scalar_trace_iter.next().expect("r trace exists");
        let g_value_trace = scalar_trace_iter.next().expect("value trace exists");
        let ordered_trace_values = [
            final_add.lhs.x,
            final_add.lhs.y,
            final_add.rhs.x,
            final_add.rhs.y,
            final_add.beta,
            final_add.gamma,
            final_add.delta,
            final_add.tau,
        ]
        .into_iter()
        .chain(g_r_trace)
        .chain(g_value_trace);

        let mut real_trace = vec![Rep3PrimeFieldShare::default(); PEDERSEN_FULL_TRACE_LENGTH];
        for (idx, value) in PEDERSEN_TRACE_INDICES.into_iter().zip(ordered_trace_values) {
            real_trace[idx as usize] = value;
        }

        traces.push(PedersenCommitBitsTrace::new(
            final_add.out.x,
            final_add.out.y,
            real_trace,
        ));
    }

    Ok(traces)
}

#[cfg(test)]
mod tests {
    use super::pedersen_commit_bits_trace_rep3_packed;
    use crate::gadgets::pedersen::{
        PedersenCommitBitsTrace, pedersen_accelerator_plain::pedersen_commit_bits_trace_fr,
        pedersen_accelerator_rep3::pedersen_commit_bits_trace_rep3,
    };
    use crate::protocols::rep3;
    use crate::protocols::rep3::conversion::A2BType;
    use crate::protocols::rep3::{Rep3PrimeFieldShare, Rep3State};
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};
    use mpc_net::local::LocalNetwork;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use std::sync::mpsc;

    const PEDERSEN_TOTAL_BITS: usize = 251;

    fn combine_trace(
        party0: &PedersenCommitBitsTrace<Rep3PrimeFieldShare<Fr>>,
        party1: &PedersenCommitBitsTrace<Rep3PrimeFieldShare<Fr>>,
        party2: &PedersenCommitBitsTrace<Rep3PrimeFieldShare<Fr>>,
    ) -> PedersenCommitBitsTrace<Fr> {
        let out_x = rep3::combine_field_element(party0.out_x, party1.out_x, party2.out_x);
        let out_y = rep3::combine_field_element(party0.out_y, party1.out_y, party2.out_y);
        let trace = party0
            .trace
            .iter()
            .zip(party1.trace.iter())
            .zip(party2.trace.iter())
            .map(|((a, b), c)| rep3::combine_field_element(*a, *b, *c))
            .collect();
        PedersenCommitBitsTrace::new(out_x, out_y, trace)
    }

    #[test]
    fn packed_matches_scalar_rep3_and_plain() {
        let mut rng = StdRng::seed_from_u64(12345);
        let batch_size = 50usize;

        let mut plain_values = Vec::with_capacity(batch_size);
        let mut plain_rs = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            let value = std::array::from_fn(|_| {
                if rng.r#gen::<bool>() {
                    Fr::one()
                } else {
                    Fr::zero()
                }
            });
            let r = std::array::from_fn(|_| {
                if rng.r#gen::<bool>() {
                    Fr::one()
                } else {
                    Fr::zero()
                }
            });
            plain_values.push(value);
            plain_rs.push(r);
        }

        let value_bit_shares: Vec<Vec<[Rep3PrimeFieldShare<Fr>; 3]>> = plain_values
            .iter()
            .map(|bits| {
                bits.iter()
                    .map(|bit| rep3::share_field_element(*bit, &mut rng))
                    .collect()
            })
            .collect();
        let r_bit_shares: Vec<Vec<[Rep3PrimeFieldShare<Fr>; 3]>> = plain_rs
            .iter()
            .map(|bits| {
                bits.iter()
                    .map(|bit| rep3::share_field_element(*bit, &mut rng))
                    .collect()
            })
            .collect();

        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (party_index, (net, tx)) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .enumerate()
        {
            let value_batch: Vec<[Rep3PrimeFieldShare<Fr>; PEDERSEN_TOTAL_BITS]> = value_bit_shares
                .iter()
                .map(|bit_shares| std::array::from_fn(|i| bit_shares[i][party_index]))
                .collect();
            let r_batch: Vec<[Rep3PrimeFieldShare<Fr>; PEDERSEN_TOTAL_BITS]> = r_bit_shares
                .iter()
                .map(|bit_shares| std::array::from_fn(|i| bit_shares[i][party_index]))
                .collect();

            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let packed = pedersen_commit_bits_trace_rep3_packed(
                    &value_batch,
                    &r_batch,
                    &net,
                    &mut state,
                )
                .unwrap();

                let scalar = value_batch
                    .iter()
                    .zip(r_batch.iter())
                    .map(|(value_bits, r_bits)| {
                        pedersen_commit_bits_trace_rep3(value_bits, r_bits, &net, &mut state)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();

                tx.send((packed, scalar)).unwrap();
            });
        }

        let (packed_0, scalar_0) = rx1.recv().unwrap();
        let (packed_1, scalar_1) = rx2.recv().unwrap();
        let (packed_2, scalar_2) = rx3.recv().unwrap();

        assert_eq!(packed_0.len(), batch_size);
        assert_eq!(scalar_0.len(), batch_size);

        for i in 0..batch_size {
            let packed_combined = combine_trace(&packed_0[i], &packed_1[i], &packed_2[i]);
            let scalar_combined = combine_trace(&scalar_0[i], &scalar_1[i], &scalar_2[i]);
            let plain = pedersen_commit_bits_trace_fr(&plain_values[i], &plain_rs[i]).unwrap();

            assert_eq!(packed_combined.out_x, scalar_combined.out_x);
            assert_eq!(packed_combined.out_y, scalar_combined.out_y);
            assert_eq!(packed_combined.trace, scalar_combined.trace);

            assert_eq!(packed_combined.out_x, plain.out_x);
            assert_eq!(packed_combined.out_y, plain.out_y);
            assert_eq!(packed_combined.trace, plain.trace);
        }
    }
}


