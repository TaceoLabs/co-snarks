use std::str::FromStr;

use ark_babyjubjub::EdwardsProjective as BabyJubJubEdwardsProjective;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use eyre::WrapErr;
use mpc_net::Network;
use num_bigint::BigUint;

use super::PedersenCommitBitsTrace;
use crate::{
    gadgets::pedersen::{PEDERSEN_FULL_TRACE_LENGTH, PEDERSEN_TRACE_INDICES},
    protocols::rep3::{
        Rep3PrimeFieldShare, Rep3State,
        arithmetic::{self, promote_to_trivial_share},
        conversion,
        pointshare::{self, PointShare},
    },
};

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;
type PublicPoint = ark_babyjubjub::EdwardsAffine;

const PEDERSEN_TOTAL_BITS: usize = 251;
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
        .map(|v| arithmetic::sub_public_by_shared(F::one(), *v, state.id))
        .collect();
    let x_tmp: Vec<_> = xs
        .iter()
        .map(|v| arithmetic::sub_public_by_shared(F::one(), *v, state.id))
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
        .wrap_err("pedersen rep3: edwards_to_montgomery_many inverse")?;

    let inv_one_minus_y = &invs[..xs.len()];
    let inv_x = &invs[xs.len()..];

    let mut mont_x = arithmetic::mul_vec(&x_num, inv_one_minus_y, net, state)?;
    let mut mont_y = arithmetic::mul_vec(&mont_x, inv_x, net, state)?;

    let nx: Vec<_> = is_zero_one_minus_y
        .iter()
        .map(|z| arithmetic::sub_public_by_shared(F::one(), *z, state.id))
        .collect();
    let ny: Vec<_> = is_zero_x
        .iter()
        .map(|z| arithmetic::sub_public_by_shared(F::one(), *z, state.id))
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
fn f_from_dec<F: PrimeField>(s: &str) -> F {
    F::from(BigUint::from_str(s).expect("valid field element"))
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
    // Avoid generator-masking degeneracy for public G in point_share_to_fieldshares.
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

    let lhs: Vec<_> = truthy
        .iter()
        .zip(falsy.iter())
        .map(|(t, f)| arithmetic::sub(*t, *f))
        .collect();
    let products = arithmetic::mul_vec(&lhs, conds, net, state)?;
    Ok(falsy
        .iter()
        .zip(products.iter())
        .map(|(f, p)| arithmetic::add(*f, *p))
        .collect())
}

#[inline]
fn babyjub_add_trace<F: PrimeField, N: Network>(
    lhs: BabyJubJubPointShare<F>,
    rhs: BabyJubJubPointShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BabyAddTraceShare<F>> {
    let a = F::from(168700u64);
    let d = F::from(168696u64);

    let x1_scaled = arithmetic::mul_public(lhs.x, -a);
    let delta_lhs = arithmetic::add(x1_scaled, lhs.y);
    let delta_rhs = arithmetic::add(rhs.x, rhs.y);

    let products = arithmetic::mul_vec(
        &[lhs.x, lhs.y, delta_lhs],
        &[rhs.y, rhs.x, delta_rhs],
        net,
        state,
    )?;
    let beta = products[0];
    let gamma = products[1];
    let delta = products[2];

    let tau = arithmetic::mul(beta, gamma, net, state)?;

    let denom_x = arithmetic::add_public(arithmetic::mul_public(tau, d), F::one(), state.id);
    let denom_y = arithmetic::add_public(arithmetic::mul_public(tau, -d), F::one(), state.id);
    let inv_denoms = arithmetic::inv_vec(&[denom_x, denom_y], net, state)?;

    let y_num = arithmetic::sub(
        arithmetic::add(delta, arithmetic::mul_public(beta, a)),
        gamma,
    );

    // Batch final multiplications for output
    let out_vals = arithmetic::mul_vec(
        &[arithmetic::add(beta, gamma), y_num],
        &[inv_denoms[0], inv_denoms[1]],
        net,
        state,
    )?;
    let out_x = out_vals[0];
    let out_y = out_vals[1];

    Ok(BabyAddTraceShare {
        lhs,
        rhs,
        beta,
        gamma,
        delta,
        tau,
        out: BabyJubJubPointShare { x: out_x, y: out_y },
    })
}

#[inline]
fn babyjub_add_trace_pair<F: PrimeField, N: Network>(
    lhs: [BabyJubJubPointShare<F>; 2],
    rhs: [BabyJubJubPointShare<F>; 2],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[BabyAddTraceShare<F>; 2]> {
    let a = F::from(168700u64);
    let d = F::from(168696u64);

    let lhs_x_scaled = [
        arithmetic::mul_public(lhs[0].x, -a),
        arithmetic::mul_public(lhs[1].x, -a),
    ];
    let delta_lhs = [
        arithmetic::add(lhs_x_scaled[0], lhs[0].y),
        arithmetic::add(lhs_x_scaled[1], lhs[1].y),
    ];
    let delta_rhs = [
        arithmetic::add(rhs[0].x, rhs[0].y),
        arithmetic::add(rhs[1].x, rhs[1].y),
    ];

    let products = arithmetic::mul_vec(
        &[
            lhs[0].x,
            lhs[0].y,
            delta_lhs[0],
            lhs[1].x,
            lhs[1].y,
            delta_lhs[1],
        ],
        &[
            rhs[0].y,
            rhs[0].x,
            delta_rhs[0],
            rhs[1].y,
            rhs[1].x,
            delta_rhs[1],
        ],
        net,
        state,
    )?;
    let beta = [products[0], products[3]];
    let gamma = [products[1], products[4]];
    let delta = [products[2], products[5]];

    let tau = arithmetic::mul_vec(&beta, &gamma, net, state)?;

    let denom_x = [
        arithmetic::add_public(arithmetic::mul_public(tau[0], d), F::one(), state.id),
        arithmetic::add_public(arithmetic::mul_public(tau[1], d), F::one(), state.id),
    ];
    let denom_y = [
        arithmetic::add_public(arithmetic::mul_public(tau[0], -d), F::one(), state.id),
        arithmetic::add_public(arithmetic::mul_public(tau[1], -d), F::one(), state.id),
    ];
    let inv_denoms = arithmetic::inv_vec(
        &[denom_x[0], denom_y[0], denom_x[1], denom_y[1]],
        net,
        state,
    )?;

    let y_num = [
        arithmetic::sub(
            arithmetic::add(delta[0], arithmetic::mul_public(beta[0], a)),
            gamma[0],
        ),
        arithmetic::sub(
            arithmetic::add(delta[1], arithmetic::mul_public(beta[1], a)),
            gamma[1],
        ),
    ];

    let out_vals = arithmetic::mul_vec(
        &[
            arithmetic::add(beta[0], gamma[0]),
            y_num[0],
            arithmetic::add(beta[1], gamma[1]),
            y_num[1],
        ],
        &[inv_denoms[0], inv_denoms[1], inv_denoms[2], inv_denoms[3]],
        net,
        state,
    )?;

    Ok([
        BabyAddTraceShare {
            lhs: lhs[0],
            rhs: rhs[0],
            beta: beta[0],
            gamma: gamma[0],
            delta: delta[0],
            tau: tau[0],
            out: BabyJubJubPointShare {
                x: out_vals[0],
                y: out_vals[1],
            },
        },
        BabyAddTraceShare {
            lhs: lhs[1],
            rhs: rhs[1],
            beta: beta[1],
            gamma: gamma[1],
            delta: delta[1],
            tau: tau[1],
            out: BabyJubJubPointShare {
                x: out_vals[2],
                y: out_vals[3],
            },
        },
    ])
}

#[inline]
fn babyjub_add_trace_quad<F: PrimeField, N: Network>(
    lhs: [BabyJubJubPointShare<F>; 4],
    rhs: [BabyJubJubPointShare<F>; 4],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[BabyAddTraceShare<F>; 4]> {
    let a = F::from(168700u64);
    let d = F::from(168696u64);

    let lhs_x_scaled = [
        arithmetic::mul_public(lhs[0].x, -a),
        arithmetic::mul_public(lhs[1].x, -a),
        arithmetic::mul_public(lhs[2].x, -a),
        arithmetic::mul_public(lhs[3].x, -a),
    ];
    let delta_lhs = [
        arithmetic::add(lhs_x_scaled[0], lhs[0].y),
        arithmetic::add(lhs_x_scaled[1], lhs[1].y),
        arithmetic::add(lhs_x_scaled[2], lhs[2].y),
        arithmetic::add(lhs_x_scaled[3], lhs[3].y),
    ];
    let delta_rhs = [
        arithmetic::add(rhs[0].x, rhs[0].y),
        arithmetic::add(rhs[1].x, rhs[1].y),
        arithmetic::add(rhs[2].x, rhs[2].y),
        arithmetic::add(rhs[3].x, rhs[3].y),
    ];

    let products = arithmetic::mul_vec(
        &[
            lhs[0].x,
            lhs[0].y,
            delta_lhs[0],
            lhs[1].x,
            lhs[1].y,
            delta_lhs[1],
            lhs[2].x,
            lhs[2].y,
            delta_lhs[2],
            lhs[3].x,
            lhs[3].y,
            delta_lhs[3],
        ],
        &[
            rhs[0].y,
            rhs[0].x,
            delta_rhs[0],
            rhs[1].y,
            rhs[1].x,
            delta_rhs[1],
            rhs[2].y,
            rhs[2].x,
            delta_rhs[2],
            rhs[3].y,
            rhs[3].x,
            delta_rhs[3],
        ],
        net,
        state,
    )?;
    let beta = [products[0], products[3], products[6], products[9]];
    let gamma = [products[1], products[4], products[7], products[10]];
    let delta = [products[2], products[5], products[8], products[11]];

    let tau = arithmetic::mul_vec(&beta, &gamma, net, state)?;

    let denom_x = [
        arithmetic::add_public(arithmetic::mul_public(tau[0], d), F::one(), state.id),
        arithmetic::add_public(arithmetic::mul_public(tau[1], d), F::one(), state.id),
        arithmetic::add_public(arithmetic::mul_public(tau[2], d), F::one(), state.id),
        arithmetic::add_public(arithmetic::mul_public(tau[3], d), F::one(), state.id),
    ];
    let denom_y = [
        arithmetic::add_public(arithmetic::mul_public(tau[0], -d), F::one(), state.id),
        arithmetic::add_public(arithmetic::mul_public(tau[1], -d), F::one(), state.id),
        arithmetic::add_public(arithmetic::mul_public(tau[2], -d), F::one(), state.id),
        arithmetic::add_public(arithmetic::mul_public(tau[3], -d), F::one(), state.id),
    ];
    let inv_denoms = arithmetic::inv_vec(
        &[
            denom_x[0],
            denom_y[0],
            denom_x[1],
            denom_y[1],
            denom_x[2],
            denom_y[2],
            denom_x[3],
            denom_y[3],
        ],
        net,
        state,
    )?;

    let y_num = [
        arithmetic::sub(
            arithmetic::add(delta[0], arithmetic::mul_public(beta[0], a)),
            gamma[0],
        ),
        arithmetic::sub(
            arithmetic::add(delta[1], arithmetic::mul_public(beta[1], a)),
            gamma[1],
        ),
        arithmetic::sub(
            arithmetic::add(delta[2], arithmetic::mul_public(beta[2], a)),
            gamma[2],
        ),
        arithmetic::sub(
            arithmetic::add(delta[3], arithmetic::mul_public(beta[3], a)),
            gamma[3],
        ),
    ];

    let out_vals = arithmetic::mul_vec(
        &[
            arithmetic::add(beta[0], gamma[0]),
            y_num[0],
            arithmetic::add(beta[1], gamma[1]),
            y_num[1],
            arithmetic::add(beta[2], gamma[2]),
            y_num[2],
            arithmetic::add(beta[3], gamma[3]),
            y_num[3],
        ],
        &[
            inv_denoms[0],
            inv_denoms[1],
            inv_denoms[2],
            inv_denoms[3],
            inv_denoms[4],
            inv_denoms[5],
            inv_denoms[6],
            inv_denoms[7],
        ],
        net,
        state,
    )?;

    Ok([
        BabyAddTraceShare {
            lhs: lhs[0],
            rhs: rhs[0],
            beta: beta[0],
            gamma: gamma[0],
            delta: delta[0],
            tau: tau[0],
            out: BabyJubJubPointShare {
                x: out_vals[0],
                y: out_vals[1],
            },
        },
        BabyAddTraceShare {
            lhs: lhs[1],
            rhs: rhs[1],
            beta: beta[1],
            gamma: gamma[1],
            delta: delta[1],
            tau: tau[1],
            out: BabyJubJubPointShare {
                x: out_vals[2],
                y: out_vals[3],
            },
        },
        BabyAddTraceShare {
            lhs: lhs[2],
            rhs: rhs[2],
            beta: beta[2],
            gamma: gamma[2],
            delta: delta[2],
            tau: tau[2],
            out: BabyJubJubPointShare {
                x: out_vals[4],
                y: out_vals[5],
            },
        },
        BabyAddTraceShare {
            lhs: lhs[3],
            rhs: rhs[3],
            beta: beta[3],
            gamma: gamma[3],
            delta: delta[3],
            tau: tau[3],
            out: BabyJubJubPointShare {
                x: out_vals[6],
                y: out_vals[7],
            },
        },
    ])
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

#[expect(clippy::type_complexity)]
fn build_window_tables_from_base(
    base_pair: [PointShare<BabyJubJubEdwardsProjective>; 2],
    n_windows: usize,
) -> (
    Vec<[[PointShare<BabyJubJubEdwardsProjective>; 8]; 2]>,
    Vec<PointShare<BabyJubJubEdwardsProjective>>,
    Vec<PointShare<BabyJubJubEdwardsProjective>>,
)
where
    BabyJubJubEdwardsProjective: CurveGroup,
{
    let mut window_tables = Vec::with_capacity(n_windows);
    let mut window_out80 = Vec::with_capacity(n_windows);
    let mut window_out81 = Vec::with_capacity(n_windows);

    for window_index in 0..n_windows {
        let base = [
            if window_index == 0 {
                base_pair[0]
            } else {
                window_out80[window_index - 1]
            },
            if window_index == 0 {
                base_pair[1]
            } else {
                window_out81[window_index - 1]
            },
        ];

        let dbl2_ed = [
            pointshare::add(&base[0], &base[0]),
            pointshare::add(&base[1], &base[1]),
        ];
        let adr3_ed = [
            pointshare::add(&base[0], &dbl2_ed[0]),
            pointshare::add(&base[1], &dbl2_ed[1]),
        ];
        let adr4_ed = [
            pointshare::add(&base[0], &adr3_ed[0]),
            pointshare::add(&base[1], &adr3_ed[1]),
        ];
        let adr5_ed = [
            pointshare::add(&base[0], &adr4_ed[0]),
            pointshare::add(&base[1], &adr4_ed[1]),
        ];
        let adr6_ed = [
            pointshare::add(&base[0], &adr5_ed[0]),
            pointshare::add(&base[1], &adr5_ed[1]),
        ];
        let adr7_ed = [
            pointshare::add(&base[0], &adr6_ed[0]),
            pointshare::add(&base[1], &adr6_ed[1]),
        ];
        let adr8_ed = [
            pointshare::add(&base[0], &adr7_ed[0]),
            pointshare::add(&base[1], &adr7_ed[1]),
        ];

        window_tables.push([
            [
                base[0],
                dbl2_ed[0],
                adr3_ed[0],
                adr4_ed[0],
                adr5_ed[0],
                adr6_ed[0],
                adr7_ed[0],
                adr8_ed[0],
            ],
            [
                base[1],
                dbl2_ed[1],
                adr3_ed[1],
                adr4_ed[1],
                adr5_ed[1],
                adr6_ed[1],
                adr7_ed[1],
                adr8_ed[1],
            ],
        ]);
        window_out80.push(adr8_ed[0]);
        window_out81.push(adr8_ed[1]);
    }

    (window_tables, window_out80, window_out81)
}

#[expect(clippy::type_complexity)]
fn segment_mul_fix_trace_two_segments_batched<F: PrimeField, N: Network>(
    base0: [PointShare<BabyJubJubEdwardsProjective>; 2],
    bits_head: [&[ArithmeticShare<F>]; 2],
    bits_tail: [&[ArithmeticShare<F>]; 2],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(
    SegmentTraceShare<F>,
    SegmentTraceShare<F>,
    SegmentTraceShare<F>,
    SegmentTraceShare<F>,
)>
where
    BabyJubJubEdwardsProjective: CurveGroup<BaseField = F>,
{
    let n0 = PEDERSEN_FULL_SEGMENT_WINDOWS;
    let n1 = PEDERSEN_TAIL_SEGMENT_WINDOWS;
    let zero = promote_to_trivial_share(state.id, F::zero());

    let mut padded0_head_0 = bits_head[0].to_vec();
    let mut padded0_head_1 = bits_head[1].to_vec();
    padded0_head_0.resize(n0 * PEDERSEN_WINDOW_BITS, zero);
    padded0_head_1.resize(n0 * PEDERSEN_WINDOW_BITS, zero);

    let (tables0, out80_0, out81_0) = build_window_tables_from_base(base0, n0);
    let base1 = [out80_0[n0 - 1], out81_0[n0 - 1]];

    let mut padded1_tail_0 = bits_tail[0].to_vec();
    let mut padded1_tail_1 = bits_tail[1].to_vec();
    padded1_tail_0.resize(n1 * PEDERSEN_WINDOW_BITS, zero);
    padded1_tail_1.resize(n1 * PEDERSEN_WINDOW_BITS, zero);

    let (tables1, out80_1, out81_1) = build_window_tables_from_base(base1, n1);

    let mut all_table_points = Vec::with_capacity(16 * (n0 + n1));
    for t in &tables0 {
        all_table_points.extend_from_slice(&t[0]);
        all_table_points.extend_from_slice(&t[1]);
    }
    for t in &tables1 {
        all_table_points.extend_from_slice(&t[0]);
        all_table_points.extend_from_slice(&t[1]);
    }

    let (table_xs, table_ys, _table_is_inf) =
        conversion::point_share_to_fieldshares_many(&all_table_points, net, state)?;
    let (mont_table_xs, _mont_table_ys) =
        edwards_to_montgomery_many(&table_xs, &table_ys, net, state)?;

    let (table_xs0, table_xs1) = table_xs.split_at(16 * n0);
    let (table_ys0, table_ys1) = table_ys.split_at(16 * n0);
    let (mont_table_xs0, mont_table_xs1) = mont_table_xs.split_at(16 * n0);

    let mut stage1_conds = Vec::with_capacity(16 * (n0 + n1));
    let mut stage1_truthy = Vec::with_capacity(16 * (n0 + n1));
    let mut stage1_falsy = Vec::with_capacity(16 * (n0 + n1));

    for window_index in 0..n0 {
        let bit0 = [
            padded0_head_0[PEDERSEN_WINDOW_BITS * window_index],
            padded0_head_1[PEDERSEN_WINDOW_BITS * window_index],
        ];
        let off = 16 * window_index;

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
        stage1_conds.extend_from_slice(&[bit0[0]; 8]);

        stage1_truthy.extend_from_slice(&[
            table_xs0[off + 9],
            table_ys0[off + 9],
            table_xs0[off + 11],
            table_ys0[off + 11],
            table_xs0[off + 13],
            table_ys0[off + 13],
            table_xs0[off + 15],
            table_ys0[off + 15],
        ]);
        stage1_falsy.extend_from_slice(&[
            table_xs0[off + 8],
            table_ys0[off + 8],
            table_xs0[off + 10],
            table_ys0[off + 10],
            table_xs0[off + 12],
            table_ys0[off + 12],
            table_xs0[off + 14],
            table_ys0[off + 14],
        ]);
        stage1_conds.extend_from_slice(&[bit0[1]; 8]);
    }

    for window_index in 0..n1 {
        let bit0 = [
            padded1_tail_0[PEDERSEN_WINDOW_BITS * window_index],
            padded1_tail_1[PEDERSEN_WINDOW_BITS * window_index],
        ];
        let off = 16 * window_index;

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
        stage1_conds.extend_from_slice(&[bit0[0]; 8]);

        stage1_truthy.extend_from_slice(&[
            table_xs1[off + 9],
            table_ys1[off + 9],
            table_xs1[off + 11],
            table_ys1[off + 11],
            table_xs1[off + 13],
            table_ys1[off + 13],
            table_xs1[off + 15],
            table_ys1[off + 15],
        ]);
        stage1_falsy.extend_from_slice(&[
            table_xs1[off + 8],
            table_ys1[off + 8],
            table_xs1[off + 10],
            table_ys1[off + 10],
            table_xs1[off + 12],
            table_ys1[off + 12],
            table_xs1[off + 14],
            table_ys1[off + 14],
        ]);
        stage1_conds.extend_from_slice(&[bit0[1]; 8]);
    }

    let stage1_sel = cmux_vec_many(&stage1_conds, &stage1_truthy, &stage1_falsy, net, state)?;
    let (stage1_sel0, stage1_sel1) = stage1_sel.split_at(16 * n0);

    let mut stage2_conds = Vec::with_capacity(8 * (n0 + n1));
    let mut stage2_truthy = Vec::with_capacity(8 * (n0 + n1));
    let mut stage2_falsy = Vec::with_capacity(8 * (n0 + n1));

    for window_index in 0..n0 {
        let bit1 = [
            padded0_head_0[PEDERSEN_WINDOW_BITS * window_index + 1],
            padded0_head_1[PEDERSEN_WINDOW_BITS * window_index + 1],
        ];
        let off = 16 * window_index;
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
        stage2_conds.extend_from_slice(&[bit1[0]; 4]);

        stage2_truthy.extend_from_slice(&[
            stage1_sel0[off + 10],
            stage1_sel0[off + 11],
            stage1_sel0[off + 14],
            stage1_sel0[off + 15],
        ]);
        stage2_falsy.extend_from_slice(&[
            stage1_sel0[off + 8],
            stage1_sel0[off + 9],
            stage1_sel0[off + 12],
            stage1_sel0[off + 13],
        ]);
        stage2_conds.extend_from_slice(&[bit1[1]; 4]);
    }

    for window_index in 0..n1 {
        let bit1 = [
            padded1_tail_0[PEDERSEN_WINDOW_BITS * window_index + 1],
            padded1_tail_1[PEDERSEN_WINDOW_BITS * window_index + 1],
        ];
        let off = 16 * window_index;
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
        stage2_conds.extend_from_slice(&[bit1[0]; 4]);

        stage2_truthy.extend_from_slice(&[
            stage1_sel1[off + 10],
            stage1_sel1[off + 11],
            stage1_sel1[off + 14],
            stage1_sel1[off + 15],
        ]);
        stage2_falsy.extend_from_slice(&[
            stage1_sel1[off + 8],
            stage1_sel1[off + 9],
            stage1_sel1[off + 12],
            stage1_sel1[off + 13],
        ]);
        stage2_conds.extend_from_slice(&[bit1[1]; 4]);
    }

    let stage2_sel = cmux_vec_many(&stage2_conds, &stage2_truthy, &stage2_falsy, net, state)?;
    let (stage2_sel0, stage2_sel1) = stage2_sel.split_at(8 * n0);

    let mut stage3_conds = Vec::with_capacity(4 * (n0 + n1));
    let mut stage3_truthy = Vec::with_capacity(4 * (n0 + n1));
    let mut stage3_falsy = Vec::with_capacity(4 * (n0 + n1));

    for window_index in 0..n0 {
        let bit2 = [
            padded0_head_0[PEDERSEN_WINDOW_BITS * window_index + 2],
            padded0_head_1[PEDERSEN_WINDOW_BITS * window_index + 2],
        ];
        let off = 8 * window_index;
        stage3_truthy.extend_from_slice(&[stage2_sel0[off + 2], stage2_sel0[off + 3]]);
        stage3_falsy.extend_from_slice(&[stage2_sel0[off], stage2_sel0[off + 1]]);
        stage3_conds.extend_from_slice(&[bit2[0]; 2]);

        stage3_truthy.extend_from_slice(&[stage2_sel0[off + 6], stage2_sel0[off + 7]]);
        stage3_falsy.extend_from_slice(&[stage2_sel0[off + 4], stage2_sel0[off + 5]]);
        stage3_conds.extend_from_slice(&[bit2[1]; 2]);
    }

    for window_index in 0..n1 {
        let bit2 = [
            padded1_tail_0[PEDERSEN_WINDOW_BITS * window_index + 2],
            padded1_tail_1[PEDERSEN_WINDOW_BITS * window_index + 2],
        ];
        let off = 8 * window_index;
        stage3_truthy.extend_from_slice(&[stage2_sel1[off + 2], stage2_sel1[off + 3]]);
        stage3_falsy.extend_from_slice(&[stage2_sel1[off], stage2_sel1[off + 1]]);
        stage3_conds.extend_from_slice(&[bit2[0]; 2]);

        stage3_truthy.extend_from_slice(&[stage2_sel1[off + 6], stage2_sel1[off + 7]]);
        stage3_falsy.extend_from_slice(&[stage2_sel1[off + 4], stage2_sel1[off + 5]]);
        stage3_conds.extend_from_slice(&[bit2[1]; 2]);
    }

    let stage3_sel = cmux_vec_many(&stage3_conds, &stage3_truthy, &stage3_falsy, net, state)?;
    let (stage3_sel0, stage3_sel1) = stage3_sel.split_at(4 * n0);

    let mut window_outs_coords0_0 = Vec::with_capacity(n0);
    let mut window_outs_coords1_0 = Vec::with_capacity(n0);
    for window_index in 0..n0 {
        let off = 4 * window_index;
        window_outs_coords0_0.push(BabyJubJubPointShare {
            x: stage3_sel0[off],
            y: stage3_sel0[off + 1],
        });
        window_outs_coords1_0.push(BabyJubJubPointShare {
            x: stage3_sel0[off + 2],
            y: stage3_sel0[off + 3],
        });
    }

    let mut window_outs_coords0_1 = Vec::with_capacity(n1);
    let mut window_outs_coords1_1 = Vec::with_capacity(n1);
    for window_index in 0..n1 {
        let off = 4 * window_index;
        window_outs_coords0_1.push(BabyJubJubPointShare {
            x: stage3_sel1[off],
            y: stage3_sel1[off + 1],
        });
        window_outs_coords1_1.push(BabyJubJubPointShare {
            x: stage3_sel1[off + 2],
            y: stage3_sel1[off + 3],
        });
    }

    let mut all_window_outs_xs = Vec::with_capacity(2 * (n0 + n1));
    let mut all_window_outs_ys = Vec::with_capacity(2 * (n0 + n1));
    for i in 0..n0 {
        all_window_outs_xs.extend([window_outs_coords0_0[i].x, window_outs_coords1_0[i].x]);
        all_window_outs_ys.extend([window_outs_coords0_0[i].y, window_outs_coords1_0[i].y]);
    }
    for i in 0..n1 {
        all_window_outs_xs.extend([window_outs_coords0_1[i].x, window_outs_coords1_1[i].x]);
        all_window_outs_ys.extend([window_outs_coords0_1[i].y, window_outs_coords1_1[i].y]);
    }

    let all_window_outs_is_inf = vec![zero; 2 * (n0 + n1)];
    let all_window_outs_points =
        conversion::fieldshares_to_pointshare_many::<BabyJubJubEdwardsProjective, N>(
            &all_window_outs_xs,
            &all_window_outs_ys,
            &all_window_outs_is_inf,
            net,
            state,
        )?;

    let (window_outs_points_0, window_outs_points_1) = all_window_outs_points.split_at(2 * n0);
    let mut window_outs_points0_0 = Vec::with_capacity(n0);
    let mut window_outs_points1_0 = Vec::with_capacity(n0);
    for i in 0..n0 {
        window_outs_points0_0.push(window_outs_points_0[2 * i]);
        window_outs_points1_0.push(window_outs_points_0[2 * i + 1]);
    }
    let mut window_outs_points0_1 = Vec::with_capacity(n1);
    let mut window_outs_points1_1 = Vec::with_capacity(n1);
    for i in 0..n1 {
        window_outs_points0_1.push(window_outs_points_1[2 * i]);
        window_outs_points1_1.push(window_outs_points_1[2 * i + 1]);
    }

    let mut mux_a210_x0_0 = vec![None; n0];
    let mut mux_a210_x1_0 = vec![None; n0];
    let mut mux_a210_x0_1 = vec![None; n1];
    let mut mux_a210_x1_1 = vec![None; n1];

    let mut deferred_a210_lhs = Vec::with_capacity(2 * (n0 + n1));
    let mut deferred_s10_lhs = Vec::with_capacity(2 * (n0 + n1));
    let mut deferred_s10_rhs = Vec::with_capacity(2 * (n0 + n1));
    let mut deferred_targets = Vec::with_capacity(2 * (n0 + n1));

    for window_index in 0..n0 {
        let off = 16 * window_index;
        let a210_input = [
            arithmetic::sub(
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
            ),
            arithmetic::sub(
                arithmetic::add(
                    arithmetic::sub(
                        arithmetic::add(
                            arithmetic::sub(
                                mont_table_xs0[off + 15],
                                mont_table_xs0[off + 14],
                            ),
                            mont_table_xs0[off + 12],
                        ),
                        mont_table_xs0[off + 13],
                    ),
                    arithmetic::add(mont_table_xs0[off + 10], mont_table_xs0[off + 9]),
                ),
                arithmetic::add(mont_table_xs0[off + 11], mont_table_xs0[off + 8]),
            ),
        ];
        let bit1 = [
            padded0_head_0[PEDERSEN_WINDOW_BITS * window_index + 1],
            padded0_head_1[PEDERSEN_WINDOW_BITS * window_index + 1],
        ];
        let bit0 = [
            padded0_head_0[PEDERSEN_WINDOW_BITS * window_index],
            padded0_head_1[PEDERSEN_WINDOW_BITS * window_index],
        ];
        if should_include_a210_trace(window_index, n0) {
            for trace in 0..2 {
                deferred_a210_lhs.push(a210_input[trace]);
                deferred_s10_lhs.push(bit1[trace]);
                deferred_s10_rhs.push(bit0[trace]);
                deferred_targets.push((0usize, trace, window_index));
            }
        }
    }

    for window_index in 0..n1 {
        let off = 16 * window_index;
        let a210_input = [
            arithmetic::sub(
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
            ),
            arithmetic::sub(
                arithmetic::add(
                    arithmetic::sub(
                        arithmetic::add(
                            arithmetic::sub(
                                mont_table_xs1[off + 15],
                                mont_table_xs1[off + 14],
                            ),
                            mont_table_xs1[off + 12],
                        ),
                        mont_table_xs1[off + 13],
                    ),
                    arithmetic::add(mont_table_xs1[off + 10], mont_table_xs1[off + 9]),
                ),
                arithmetic::add(mont_table_xs1[off + 11], mont_table_xs1[off + 8]),
            ),
        ];
        let bit1 = [
            padded1_tail_0[PEDERSEN_WINDOW_BITS * window_index + 1],
            padded1_tail_1[PEDERSEN_WINDOW_BITS * window_index + 1],
        ];
        let bit0 = [
            padded1_tail_0[PEDERSEN_WINDOW_BITS * window_index],
            padded1_tail_1[PEDERSEN_WINDOW_BITS * window_index],
        ];
        if should_include_a210_trace(window_index, n1) {
            for trace in 0..2 {
                deferred_a210_lhs.push(a210_input[trace]);
                deferred_s10_lhs.push(bit1[trace]);
                deferred_s10_rhs.push(bit0[trace]);
                deferred_targets.push((1usize, trace, window_index));
            }
        }
    }

    let deferred_s10 = arithmetic::mul_vec(&deferred_s10_lhs, &deferred_s10_rhs, net, state)?;
    let deferred_vals = arithmetic::mul_vec(&deferred_a210_lhs, &deferred_s10, net, state)?;
    for ((seg, trace, window_index), val) in deferred_targets.into_iter().zip(deferred_vals) {
        if seg == 0 {
            if trace == 0 {
                mux_a210_x0_0[window_index] = Some(val);
            } else {
                mux_a210_x1_0[window_index] = Some(val);
            }
        } else if trace == 0 {
            mux_a210_x0_1[window_index] = Some(val);
        } else {
            mux_a210_x1_1[window_index] = Some(val);
        }
    }

    let last_out8_0 = [out80_0[n0 - 1], out81_0[n0 - 1]];
    let last_out8_1 = [out80_1[n1 - 1], out81_1[n1 - 1]];
    let dbl_last_0 = [
        pointshare::add(&last_out8_0[0], &last_out8_0[0]),
        pointshare::add(&last_out8_0[1], &last_out8_0[1]),
    ];
    let dbl_last_1 = [
        pointshare::add(&last_out8_1[0], &last_out8_1[0]),
        pointshare::add(&last_out8_1[1], &last_out8_1[1]),
    ];

    let mut cadders0_0 = Vec::with_capacity(n0);
    let mut cadders1_0 = Vec::with_capacity(n0);
    let mut adders_points0_0 = Vec::with_capacity(n0);
    let mut adders_points1_0 = Vec::with_capacity(n0);
    for window_index in 0..n0 {
        let cadd_in1 = [
            if window_index == 0 {
                base0[0]
            } else {
                cadders0_0[window_index - 1]
            },
            if window_index == 0 {
                base0[1]
            } else {
                cadders1_0[window_index - 1]
            },
        ];
        let cadd_in2 = [
            if window_index + 1 == n0 {
                dbl_last_0[0]
            } else {
                out80_0[window_index]
            },
            if window_index + 1 == n0 {
                dbl_last_0[1]
            } else {
                out81_0[window_index]
            },
        ];
        cadders0_0.push(pointshare::add(&cadd_in1[0], &cadd_in2[0]));
        cadders1_0.push(pointshare::add(&cadd_in1[1], &cadd_in2[1]));

        let add_in1 = [
            if window_index == 0 {
                dbl_last_0[0]
            } else {
                adders_points0_0[window_index - 1]
            },
            if window_index == 0 {
                dbl_last_0[1]
            } else {
                adders_points1_0[window_index - 1]
            },
        ];
        adders_points0_0.push(pointshare::add(&add_in1[0], &window_outs_points0_0[window_index]));
        adders_points1_0.push(pointshare::add(&add_in1[1], &window_outs_points1_0[window_index]));
    }

    let mut cadders0_1 = Vec::with_capacity(n1);
    let mut cadders1_1 = Vec::with_capacity(n1);
    let mut adders_points0_1 = Vec::with_capacity(n1);
    let mut adders_points1_1 = Vec::with_capacity(n1);
    for window_index in 0..n1 {
        let cadd_in1 = [
            if window_index == 0 {
                base1[0]
            } else {
                cadders0_1[window_index - 1]
            },
            if window_index == 0 {
                base1[1]
            } else {
                cadders1_1[window_index - 1]
            },
        ];
        let cadd_in2 = [
            if window_index + 1 == n1 {
                dbl_last_1[0]
            } else {
                out80_1[window_index]
            },
            if window_index + 1 == n1 {
                dbl_last_1[1]
            } else {
                out81_1[window_index]
            },
        ];
        cadders0_1.push(pointshare::add(&cadd_in1[0], &cadd_in2[0]));
        cadders1_1.push(pointshare::add(&cadd_in1[1], &cadd_in2[1]));

        let add_in1 = [
            if window_index == 0 {
                dbl_last_1[0]
            } else {
                adders_points0_1[window_index - 1]
            },
            if window_index == 0 {
                dbl_last_1[1]
            } else {
                adders_points1_1[window_index - 1]
            },
        ];
        adders_points0_1.push(pointshare::add(&add_in1[0], &window_outs_points0_1[window_index]));
        adders_points1_1.push(pointshare::add(&add_in1[1], &window_outs_points1_1[window_index]));
    }

    let cfinals_0 = [cadders0_0[n0 - 1], cadders1_0[n0 - 1]];
    let cfinals_1 = [cadders0_1[n1 - 1], cadders1_1[n1 - 1]];

    let mut adder_points = Vec::with_capacity(2 + 2 * n0 + 2 + 2 * n1 + 4);
    adder_points.extend_from_slice(&dbl_last_0);
    for i in 0..n0 {
        adder_points.push(adders_points0_0[i]);
        adder_points.push(adders_points1_0[i]);
    }
    adder_points.extend_from_slice(&dbl_last_1);
    for i in 0..n1 {
        adder_points.push(adders_points0_1[i]);
        adder_points.push(adders_points1_1[i]);
    }
    adder_points.extend_from_slice(&cfinals_0);
    adder_points.extend_from_slice(&cfinals_1);

    let (adder_xs, adder_ys, _adder_is_inf) =
        conversion::point_share_to_fieldshares_many(&adder_points, net, state)?;

    let dbl_last_coords_0 = [
        BabyJubJubPointShare {
            x: adder_xs[0],
            y: adder_ys[0],
        },
        BabyJubJubPointShare {
            x: adder_xs[1],
            y: adder_ys[1],
        },
    ];
    let mut adders_out0_0 = Vec::with_capacity(n0);
    let mut adders_out1_0 = Vec::with_capacity(n0);
    for i in 0..n0 {
        let off = 2 + 2 * i;
        adders_out0_0.push(BabyJubJubPointShare {
            x: adder_xs[off],
            y: adder_ys[off],
        });
        adders_out1_0.push(BabyJubJubPointShare {
            x: adder_xs[off + 1],
            y: adder_ys[off + 1],
        });
    }

    let seg1_start = 2 + 2 * n0;
    let dbl_last_coords_1 = [
        BabyJubJubPointShare {
            x: adder_xs[seg1_start],
            y: adder_ys[seg1_start],
        },
        BabyJubJubPointShare {
            x: adder_xs[seg1_start + 1],
            y: adder_ys[seg1_start + 1],
        },
    ];
    let mut adders_out0_1 = Vec::with_capacity(n1);
    let mut adders_out1_1 = Vec::with_capacity(n1);
    for i in 0..n1 {
        let off = seg1_start + 2 + 2 * i;
        adders_out0_1.push(BabyJubJubPointShare {
            x: adder_xs[off],
            y: adder_ys[off],
        });
        adders_out1_1.push(BabyJubJubPointShare {
            x: adder_xs[off + 1],
            y: adder_ys[off + 1],
        });
    }

    let cadd_rhs_start = seg1_start + 2 + 2 * n1;
    let cadd_rhs_0 = [
        BabyJubJubPointShare {
            x: adder_xs[cadd_rhs_start],
            y: adder_ys[cadd_rhs_start],
        },
        BabyJubJubPointShare {
            x: adder_xs[cadd_rhs_start + 1],
            y: adder_ys[cadd_rhs_start + 1],
        },
    ];
    let cadd_rhs_1 = [
        BabyJubJubPointShare {
            x: adder_xs[cadd_rhs_start + 2],
            y: adder_ys[cadd_rhs_start + 2],
        },
        BabyJubJubPointShare {
            x: adder_xs[cadd_rhs_start + 3],
            y: adder_ys[cadd_rhs_start + 3],
        },
    ];

    let mut in1_xs = Vec::with_capacity(2 * (n0 + n1));
    let mut in1_ys = Vec::with_capacity(2 * (n0 + n1));
    let mut in2_xs = Vec::with_capacity(2 * (n0 + n1));
    let mut in2_ys = Vec::with_capacity(2 * (n0 + n1));
    let mut adder_targets = Vec::with_capacity(2 * (n0 + n1));

    for window_index in 0..n0 {
        let in1_0 = if window_index == 0 {
            dbl_last_coords_0[0]
        } else {
            adders_out0_0[window_index - 1]
        };
        let in1_1 = if window_index == 0 {
            dbl_last_coords_0[1]
        } else {
            adders_out1_0[window_index - 1]
        };
        in1_xs.extend([in1_0.x, in1_1.x]);
        in1_ys.extend([in1_0.y, in1_1.y]);
        in2_xs.extend([window_outs_coords0_0[window_index].x, window_outs_coords1_0[window_index].x]);
        in2_ys.extend([window_outs_coords0_0[window_index].y, window_outs_coords1_0[window_index].y]);
        adder_targets.push((0usize, 0usize, window_index));
        adder_targets.push((0usize, 1usize, window_index));
    }
    for window_index in 0..n1 {
        let in1_0 = if window_index == 0 {
            dbl_last_coords_1[0]
        } else {
            adders_out0_1[window_index - 1]
        };
        let in1_1 = if window_index == 0 {
            dbl_last_coords_1[1]
        } else {
            adders_out1_1[window_index - 1]
        };
        in1_xs.extend([in1_0.x, in1_1.x]);
        in1_ys.extend([in1_0.y, in1_1.y]);
        in2_xs.extend([window_outs_coords0_1[window_index].x, window_outs_coords1_1[window_index].x]);
        in2_ys.extend([window_outs_coords0_1[window_index].y, window_outs_coords1_1[window_index].y]);
        adder_targets.push((1usize, 0usize, window_index));
        adder_targets.push((1usize, 1usize, window_index));
    }

    let mut all_in_xs = Vec::with_capacity(4 * (n0 + n1));
    let mut all_in_ys = Vec::with_capacity(4 * (n0 + n1));
    all_in_xs.extend_from_slice(&in1_xs);
    all_in_xs.extend_from_slice(&in2_xs);
    all_in_ys.extend_from_slice(&in1_ys);
    all_in_ys.extend_from_slice(&in2_ys);

    let (all_in_mx, all_in_my) = edwards_to_montgomery_many(&all_in_xs, &all_in_ys, net, state)?;
    let split = 2 * (n0 + n1);
    let in1_mx = &all_in_mx[..split];
    let in2_mx = &all_in_mx[split..];
    let in1_my = &all_in_my[..split];
    let in2_my = &all_in_my[split..];

    let mut lambda_den = Vec::with_capacity(2 * (n0 + n1));
    let mut lambda_num = Vec::with_capacity(2 * (n0 + n1));
    for i in 0..(2 * (n0 + n1)) {
        lambda_den.push(arithmetic::sub(in2_mx[i], in1_mx[i]));
        lambda_num.push(arithmetic::sub(in2_my[i], in1_my[i]));
    }

    let zero_den = vec![zero; lambda_den.len()];
    let is_zero_den = arithmetic::eq_many(&zero_den, &lambda_den, net, state)?;
    let den_tmp: Vec<_> = lambda_den
        .iter()
        .map(|d| arithmetic::sub_public_by_shared(F::one(), *d, state.id))
        .collect();
    let den_fix = arithmetic::mul_vec(&den_tmp, &is_zero_den, net, state)?;
    let mut safe_den = lambda_den;
    for i in 0..safe_den.len() {
        safe_den[i] = arithmetic::add(safe_den[i], den_fix[i]);
    }
    let lambda_den_inv = arithmetic::inv_vec(&safe_den, net, state)
        .wrap_err("pedersen rep3: batched montgomery adder inverse")?;
    let mut lambdas = arithmetic::mul_vec(&lambda_num, &lambda_den_inv, net, state)?;
    let keep: Vec<_> = is_zero_den
        .iter()
        .map(|z| arithmetic::sub_public_by_shared(F::one(), *z, state.id))
        .collect();
    lambdas = arithmetic::mul_vec(&lambdas, &keep, net, state)?;

    let (montgomery_a, montgomery_b) = montgomery_constants::<F>();
    let lambda_sq = arithmetic::mul_vec(&lambdas, &lambdas, net, state)?;
    let montgomery_b_share = promote_to_trivial_share(state.id, montgomery_b);
    let b_lambda_sq = arithmetic::mul_vec(
        &lambda_sq,
        &vec![montgomery_b_share; 2 * (n0 + n1)],
        net,
        state,
    )?;
    let b_lambda_sq_minus_a: Vec<_> = b_lambda_sq
        .iter()
        .map(|v| arithmetic::sub_shared_by_public(*v, montgomery_a, state.id))
        .collect();

    let out_mx: Vec<_> = b_lambda_sq_minus_a
        .iter()
        .enumerate()
        .map(|(i, v)| arithmetic::sub(arithmetic::sub(*v, in1_mx[i]), in2_mx[i]))
        .collect();
    let x1_minus_out: Vec<_> = in1_mx
        .iter()
        .enumerate()
        .map(|(i, v)| arithmetic::sub(*v, out_mx[i]))
        .collect();
    let lambda_times = arithmetic::mul_vec(&lambdas, &x1_minus_out, net, state)?;
    let out_my: Vec<_> = lambda_times
        .iter()
        .enumerate()
        .map(|(i, v)| arithmetic::sub(*v, in1_my[i]))
        .collect();

    let mut adders0_0: Vec<Option<MontgomeryAddTraceShare<F>>> = vec![None; n0];
    let mut adders1_0: Vec<Option<MontgomeryAddTraceShare<F>>> = vec![None; n0];
    let mut adders0_1: Vec<Option<MontgomeryAddTraceShare<F>>> = vec![None; n1];
    let mut adders1_1: Vec<Option<MontgomeryAddTraceShare<F>>> = vec![None; n1];

    for (idx, (seg, trace, window_index)) in adder_targets.into_iter().enumerate() {
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
        if seg == 0 {
            if trace == 0 {
                adders0_0[window_index] = Some(adder);
            } else {
                adders1_0[window_index] = Some(adder);
            }
        } else if trace == 0 {
            adders0_1[window_index] = Some(adder);
        } else {
            adders1_1[window_index] = Some(adder);
        }
    }

    let m2e_0 = [adders_out0_0[n0 - 1], adders_out1_0[n0 - 1]];
    let m2e_1 = [adders_out0_1[n1 - 1], adders_out1_1[n1 - 1]];

    let mut out_adders0_0 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
    let mut out_adders1_0 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
    for (dst, src) in out_adders0_0.iter_mut().zip(adders0_0).take(n0) {
        *dst = Some(src.expect("adder0 seg0 exists"));
    }
    for (dst, src) in out_adders1_0.iter_mut().zip(adders1_0).take(n0) {
        *dst = Some(src.expect("adder1 seg0 exists"));
    }
    let mut out_adders0_1 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
    let mut out_adders1_1 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
    for (dst, src) in out_adders0_1.iter_mut().zip(adders0_1).take(n1) {
        *dst = Some(src.expect("adder0 seg1 exists"));
    }
    for (dst, src) in out_adders1_1.iter_mut().zip(adders1_1).take(n1) {
        *dst = Some(src.expect("adder1 seg1 exists"));
    }

    let mut out_mux0_0 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
    let mut out_mux1_0 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
    out_mux0_0[..n0].copy_from_slice(&mux_a210_x0_0[..n0]);
    out_mux1_0[..n0].copy_from_slice(&mux_a210_x1_0[..n0]);
    let mut out_mux0_1 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
    let mut out_mux1_1 = [None; PEDERSEN_FULL_SEGMENT_WINDOWS];
    out_mux0_1[..n1].copy_from_slice(&mux_a210_x0_1[..n1]);
    out_mux1_1[..n1].copy_from_slice(&mux_a210_x1_1[..n1]);

    Ok((
        SegmentTraceShare {
            out: None,
            adders: out_adders0_0,
            cadd: None,
            cadd_lhs: m2e_0[0],
            cadd_rhs: cadd_rhs_0[0],
            mux_a210_x: out_mux0_0,
        },
        SegmentTraceShare {
            out: None,
            adders: out_adders1_0,
            cadd: None,
            cadd_lhs: m2e_0[1],
            cadd_rhs: cadd_rhs_0[1],
            mux_a210_x: out_mux1_0,
        },
        SegmentTraceShare {
            out: None,
            adders: out_adders0_1,
            cadd: None,
            cadd_lhs: m2e_1[0],
            cadd_rhs: cadd_rhs_1[0],
            mux_a210_x: out_mux0_1,
        },
        SegmentTraceShare {
            out: None,
            adders: out_adders1_1,
            cadd: None,
            cadd_lhs: m2e_1[1],
            cadd_rhs: cadd_rhs_1[1],
            mux_a210_x: out_mux1_1,
        },
    ))
}

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

#[expect(clippy::too_many_arguments)]
fn segment_mul_fix_trace_two_stage_pair<F: PrimeField, N: Network>(
    bases: [PublicPoint; 2],
    bits: [&[ArithmeticShare<F>; PEDERSEN_TOTAL_BITS]; 2],
    seg0_a: &mut SegmentTraceShare<F>,
    seg0_b: &mut SegmentTraceShare<F>,
    seg1_a: &mut SegmentTraceShare<F>,
    seg1_b: &mut SegmentTraceShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<()>
where
    BabyJubJubEdwardsProjective: CurveGroup<BaseField = F>,
{
    let base_edwards = [
        promote_public_point_share(state.id, bases[0]),
        promote_public_point_share(state.id, bases[1]),
    ];
    (*seg0_a, *seg0_b, *seg1_a, *seg1_b) = segment_mul_fix_trace_two_segments_batched(
        base_edwards,
        [
            &bits[0][..PEDERSEN_HEAD_BITS],
            &bits[1][..PEDERSEN_HEAD_BITS],
        ],
        [
            &bits[0][PEDERSEN_HEAD_BITS..],
            &bits[1][PEDERSEN_HEAD_BITS..],
        ],
        net,
        state,
    )?;

    let cadds = babyjub_add_trace_quad(
        [seg0_a.cadd_lhs, seg0_b.cadd_lhs, seg1_a.cadd_lhs, seg1_b.cadd_lhs],
        [
            BabyJubJubPointShare {
                x: arithmetic::neg(seg0_a.cadd_rhs.x),
                y: seg0_a.cadd_rhs.y,
            },
            BabyJubJubPointShare {
                x: arithmetic::neg(seg0_b.cadd_rhs.x),
                y: seg0_b.cadd_rhs.y,
            },
            BabyJubJubPointShare {
                x: arithmetic::neg(seg1_a.cadd_rhs.x),
                y: seg1_a.cadd_rhs.y,
            },
            BabyJubJubPointShare {
                x: arithmetic::neg(seg1_b.cadd_rhs.x),
                y: seg1_b.cadd_rhs.y,
            },
        ],
        net,
        state,
    )?;

    seg0_a.cadd = Some(cadds[0]);
    seg0_a.out = Some(cadds[0].out);
    seg0_b.cadd = Some(cadds[1]);
    seg0_b.out = Some(cadds[1].out);

    seg1_a.cadd = Some(cadds[2]);
    seg1_a.out = Some(cadds[2].out);
    seg1_b.cadd = Some(cadds[3]);
    seg1_b.out = Some(cadds[3].out);

    Ok(())
}

#[expect(clippy::type_complexity)]
fn escalar_mul_fix_trace_pair<F: PrimeField, N: Network>(
    bases: [PublicPoint; 2],
    bits: [&[ArithmeticShare<F>; PEDERSEN_TOTAL_BITS]; 2],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<([BabyJubJubPointShare<F>; 2], [Vec<ArithmeticShare<F>>; 2])>
where
    BabyJubJubEdwardsProjective: CurveGroup<BaseField = F>,
{
    let mut seg0_a = SegmentTraceShare {
        out: None,
        adders: [None; PEDERSEN_FULL_SEGMENT_WINDOWS],
        cadd: None,
        cadd_lhs: BabyJubJubPointShare {
            x: Rep3PrimeFieldShare::default(),
            y: Rep3PrimeFieldShare::default(),
        },
        cadd_rhs: BabyJubJubPointShare {
            x: Rep3PrimeFieldShare::default(),
            y: Rep3PrimeFieldShare::default(),
        },
        mux_a210_x: [None; PEDERSEN_FULL_SEGMENT_WINDOWS],
    };
    let mut seg0_b = seg0_a;
    let mut seg1_a = seg0_a;
    let mut seg1_b = seg0_a;
    segment_mul_fix_trace_two_stage_pair(
        bases,
        bits,
        &mut seg0_a,
        &mut seg0_b,
        &mut seg1_a,
        &mut seg1_b,
        net,
        state,
    )?;

    let top_adders = babyjub_add_trace_pair(
        [
            seg0_a.out.expect("segment0 a out exists"),
            seg0_b.out.expect("segment0 b out exists"),
        ],
        [
            seg1_a.out.expect("segment1 a out exists"),
            seg1_b.out.expect("segment1 b out exists"),
        ],
        net,
        state,
    )?;

    let mut trace_a = Vec::with_capacity(SCALAR_TRACE_VALUES_PER_POINT);
    append_top_add_trace(&mut trace_a, top_adders[0]);
    append_segment_trace(&mut trace_a, &seg0_a, PEDERSEN_FULL_SEGMENT_WINDOWS);
    append_segment_trace(&mut trace_a, &seg1_a, PEDERSEN_TAIL_SEGMENT_WINDOWS);

    let mut trace_b = Vec::with_capacity(SCALAR_TRACE_VALUES_PER_POINT);
    append_top_add_trace(&mut trace_b, top_adders[1]);
    append_segment_trace(&mut trace_b, &seg0_b, PEDERSEN_FULL_SEGMENT_WINDOWS);
    append_segment_trace(&mut trace_b, &seg1_b, PEDERSEN_TAIL_SEGMENT_WINDOWS);

    Ok(([top_adders[0].out, top_adders[1].out], [trace_a, trace_b]))
}

/// Computes the full Circom-compatible `pedersen_commit_bits` output and dense accelerator trace for rep3 arithmetic shares.
pub fn pedersen_commit_bits_trace_rep3<F: PrimeField, N: Network>(
    value_bits_le_251: &[ArithmeticShare<F>; PEDERSEN_TOTAL_BITS],
    r_bits_le_251: &[ArithmeticShare<F>; PEDERSEN_TOTAL_BITS],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<PedersenCommitBitsTrace<ArithmeticShare<F>>>
where
    BabyJubJubEdwardsProjective: CurveGroup<BaseField = F>,
{
    let ([g_r, g_value], [g_r_trace, g_value_trace]) = escalar_mul_fix_trace_pair(
        [babyjub_h_generator(), babyjub_generator()],
        [r_bits_le_251, value_bits_le_251],
        net,
        state,
    )?;
    let final_add = babyjub_add_trace(g_value, g_r, net, state)?;

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

    for (idx, val) in PEDERSEN_TRACE_INDICES.into_iter().zip(ordered_trace_values) {
        real_trace[idx as usize] = val;
    }
    Ok(PedersenCommitBitsTrace::new(
        final_add.out.x,
        final_add.out.y,
        real_trace,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::pedersen::pedersen_accelerator_plain::{
        BabyJubJubPoint, babyjub_scalar_mul_bits_fr, pedersen_commit_bits_trace_fr,
    };
    use crate::protocols::rep3;
    use crate::protocols::rep3::conversion::A2BType;
    use ark_ff::{One, Zero};
    use itertools::izip;
    use mpc_net::local::LocalNetwork;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use std::sync::mpsc;

    fn affine_to_plain_point(point: PublicPoint) -> BabyJubJubPoint {
        BabyJubJubPoint {
            x: point.x,
            y: point.y,
        }
    }

    #[test]
    fn rep3_scalar_mul_pair_matches_plain_outputs() {
        type Fr = ark_bn254::Fr;

        let mut rng = StdRng::seed_from_u64(42);
        let mut value_bits = [Fr::zero(); PEDERSEN_TOTAL_BITS];
        let mut r_bits = [Fr::zero(); PEDERSEN_TOTAL_BITS];
        for bit in &mut value_bits {
            *bit = if rng.r#gen::<bool>() {
                Fr::one()
            } else {
                Fr::zero()
            };
        }
        for bit in &mut r_bits {
            *bit = if rng.r#gen::<bool>() {
                Fr::one()
            } else {
                Fr::zero()
            };
        }

        let value_bit_shares: Vec<_> = value_bits
            .into_iter()
            .map(|bit| rep3::share_field_element(bit, &mut rng))
            .collect();
        let r_bit_shares: Vec<_> = r_bits
            .into_iter()
            .map(|bit| rep3::share_field_element(bit, &mut rng))
            .collect();

        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (party_index, net, tx) in izip!(0..3, nets, [tx1, tx2, tx3]) {
            let value_shares = std::array::from_fn(|idx| value_bit_shares[idx][party_index]);
            let r_shares = std::array::from_fn(|idx| r_bit_shares[idx][party_index]);
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let ([g_r, g_value], _) = escalar_mul_fix_trace_pair(
                    [babyjub_h_generator(), babyjub_generator()],
                    [&r_shares, &value_shares],
                    &net,
                    &mut state,
                )
                .unwrap();
                tx.send((g_r, g_value)).unwrap();
            });
        }

        let (g_r_0, g_value_0) = rx1.recv().unwrap();
        let (g_r_1, g_value_1) = rx2.recv().unwrap();
        let (g_r_2, g_value_2) = rx3.recv().unwrap();

        let got_g_r = BabyJubJubPoint {
            x: rep3::combine_field_element(g_r_0.x, g_r_1.x, g_r_2.x),
            y: rep3::combine_field_element(g_r_0.y, g_r_1.y, g_r_2.y),
        };
        let got_g_value = BabyJubJubPoint {
            x: rep3::combine_field_element(g_value_0.x, g_value_1.x, g_value_2.x),
            y: rep3::combine_field_element(g_value_0.y, g_value_1.y, g_value_2.y),
        };

        let expected_g_r =
            babyjub_scalar_mul_bits_fr(affine_to_plain_point(babyjub_h_generator()), &r_bits)
                .unwrap();
        let expected_g_value =
            babyjub_scalar_mul_bits_fr(affine_to_plain_point(babyjub_generator()), &value_bits)
                .unwrap();

        assert_eq!(got_g_r, expected_g_r, "g_r mismatch");
        assert_eq!(got_g_value, expected_g_value, "g_value mismatch");

        let expected_trace = pedersen_commit_bits_trace_fr(&value_bits, &r_bits).unwrap();
        let _ = expected_trace;
    }
}
