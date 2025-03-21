use ark_bn254::Bn254;
use co_builder::{
    prelude::{HonkCurve, PrecomputedEntities},
    TranscriptFieldType,
};
use co_ultrahonk::prelude::{
    AllEntitiesBatchRelations, NoirUltraHonkProver, PlainUltraHonkDriver,
    Poseidon2ExternalRelation, Poseidon2ExternalRelationAccHalfShared, ProverUnivariates,
    SumCheckDataForRelation,
};
use criterion::*;
use itertools::Itertools;
use rand::{thread_rng, Rng};
use rayon::{ThreadPool, ThreadPoolBuilder};
use ultrahonk::prelude::{ShiftedWitnessEntities, WitnessEntities};

type FieldType = ark_bn254::Fr;

macro_rules! fold_accumulator {
    ($acc: expr, $elements: expr) => {
        let evaluations_len = $acc.len();
        let mut acc = [T::ArithmeticShare::default(); 7];
        acc[..evaluations_len].clone_from_slice($acc);
        for (idx, b) in $elements.iter().enumerate() {
            let a = &mut acc[idx % 7];
            T::add_assign(a, *b);
        }
        $acc.clone_from_slice(&acc[..evaluations_len]);
    };
}

fn run_elliptic_bench_old<T, P>(
    driver: &mut T,
    w_l: &[T::ArithmeticShare],
    w_r: &[T::ArithmeticShare],
    w_o: &[T::ArithmeticShare],
    w_4: &[T::ArithmeticShare],
    q_l: &[P::ScalarField],
    q_elliptic: &[P::ScalarField],
    q_m: &[P::ScalarField],
    scaling_factors: &[P::ScalarField],
    r0: &mut [T::ArithmeticShare; 6],
    r1: &mut [T::ArithmeticShare; 6],
) -> eyre::Result<()>
where
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
{
    let party_id = driver.get_party_id();
    let x_1 = w_r;
    let y_1 = w_o;

    let x_2 = w_l;
    let y_2 = w_4;
    let y_3 = w_o;
    let x_3 = w_r;

    let q_sign = q_l;
    let q_elliptic = q_elliptic;
    let q_is_double = q_m;

    // First round of multiplications
    let x_diff = T::sub_many(x_2, x_1);
    let y1_plus_y3 = T::add_many(y_1, y_3);
    let mut y_diff = T::mul_with_public_many(q_sign, y_2);
    T::sub_assign_many(&mut y_diff, y_1);

    let mut x1_mul_3 = T::add_many(x_1, x_1);
    T::add_assign_many(&mut x1_mul_3, x_1);
    let mut lhs = Vec::with_capacity(
        (2 * y_1.len())
            + y_2.len()
            + x_diff.len()
            + y1_plus_y3.len()
            + y_diff.len()
            + x1_mul_3.len(),
    );

    let mut rhs = Vec::with_capacity(lhs.len());
    lhs.extend(y_1);
    lhs.extend(y_2);
    lhs.extend(y_1);
    lhs.extend(x_diff.clone());
    lhs.extend(y1_plus_y3.clone());
    lhs.extend(y_diff.clone());
    lhs.extend(x1_mul_3.clone());

    rhs.extend(y_1);
    rhs.extend(y_2);
    rhs.extend(y_2);
    rhs.extend(x_diff.clone());
    rhs.extend(x_diff);
    rhs.extend(T::sub_many(x_3, x_1));
    rhs.extend(x_1);
    let mul1 = driver.mul_many(&lhs, &rhs)?;
    // we need the different contributions again
    let chunks1 = mul1.chunks_exact(mul1.len() / 7).collect_vec();
    debug_assert_eq!(chunks1.len(), 7);

    // Second round of multiplications
    let curve_b = P::get_curve_b(); // here we need the extra constraint on the Curve
    let y1_sqr = chunks1[0];
    let y1_sqr_mul_4 = T::add_many(y1_sqr, y1_sqr);
    let y1_sqr_mul_4 = T::add_many(&y1_sqr_mul_4, &y1_sqr_mul_4);
    let x1_sqr_mul_3 = chunks1[6];

    let mut lhs = Vec::with_capacity(2 * x_3.len() + y1_sqr.len() + x1_sqr_mul_3.len() + y_1.len());
    lhs.extend(T::add_many(&T::add_many(x_3, x_2), x_1));
    lhs.extend(T::add_scalar(y1_sqr, -curve_b, party_id));
    lhs.extend(T::add_many(&T::add_many(x_3, x_1), x_1));
    lhs.extend(x1_sqr_mul_3);
    lhs.extend(T::add_many(y_1, y_1));

    let mut rhs = Vec::with_capacity(lhs.len());
    rhs.extend(chunks1[3]);
    rhs.extend(x1_mul_3);
    rhs.extend(y1_sqr_mul_4);
    rhs.extend(T::sub_many(x_1, x_3));
    rhs.extend(y1_plus_y3);

    let mul2 = driver.mul_many(&lhs, &rhs)?;
    let chunks2 = mul2.chunks_exact(mul2.len() / 5).collect_vec();
    debug_assert_eq!(chunks2.len(), 5);

    // Contribution (1) point addition, x-coordinate check
    // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
    let y2_sqr = chunks1[1];
    let y1y2 = T::mul_with_public_many(q_sign, chunks1[2]);
    let mut x_add_identity = T::sub_many(chunks2[0], y2_sqr);
    T::sub_assign_many(&mut x_add_identity, y1_sqr);
    T::add_assign_many(&mut x_add_identity, &y1y2);
    T::add_assign_many(&mut x_add_identity, &y1y2);

    let q_elliptic_by_scaling = q_elliptic
        .iter()
        .zip_eq(scaling_factors)
        .map(|(a, b)| *a * *b)
        .collect_vec();
    let q_elliptic_q_double_scaling = q_elliptic_by_scaling
        .iter()
        .zip_eq(q_is_double)
        .map(|(a, b)| *a * *b)
        .collect_vec();
    let q_elliptic_not_double_scaling = q_elliptic_by_scaling
        .iter()
        .zip_eq(q_elliptic_q_double_scaling.iter())
        .map(|(a, b)| *a - *b)
        .collect_vec();

    let mut tmp_1 = T::mul_with_public_many(&q_elliptic_not_double_scaling, &x_add_identity);

    ///////////////////////////////////////////////////////////////////////
    // Contribution (2) point addition, x-coordinate check
    // q_elliptic * (q_sign * y1 + y3)(x2 - x1) + (x3 - x1)(y2 - q_sign * y1) = 0
    let y_add_identity = T::add_many(chunks1[4], chunks1[5]);
    let mut tmp_2 = T::mul_with_public_many(&q_elliptic_not_double_scaling, &y_add_identity);

    ///////////////////////////////////////////////////////////////////////
    // Contribution (3) point doubling, x-coordinate check
    // (x3 + x1 + x1) (4y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
    // N.B. we're using the equivalence x1*x1*x1 === y1*y1 - curve_b to reduce degree by 1
    let x_pow_4_mul_3 = chunks2[1];
    let mut x1_pow_4_mul_9 = T::add_many(x_pow_4_mul_3, x_pow_4_mul_3);
    T::add_assign_many(&mut x1_pow_4_mul_9, x_pow_4_mul_3);
    let x_double_identity = T::sub_many(chunks2[2], &x1_pow_4_mul_9);

    let tmp = T::mul_with_public_many(&q_elliptic_q_double_scaling, &x_double_identity);
    T::add_assign_many(&mut tmp_1, &tmp);

    ///////////////////////////////////////////////////////////////////////
    // Contribution (4) point doubling, y-coordinate check
    // (y1 + y1) (2y1) - (3 * x1 * x1)(x1 - x3) = 0
    let y_double_identity = T::sub_many(chunks2[3], chunks2[4]);
    let tmp = T::mul_with_public_many(&q_elliptic_q_double_scaling, &y_double_identity);
    T::add_assign_many(&mut tmp_2, &tmp);

    fold_accumulator!(r0, tmp_1);
    fold_accumulator!(r1, tmp_2);
    Ok(())
}
fn run_elliptic_bench_new(c: &mut Criterion) {}

fn random_edge<R: Rng>(mut rng: R) -> ProverUnivariates<PlainUltraHonkDriver, Bn254> {
    let mut edge = ProverUnivariates {
        witness: WitnessEntities::default(),
        precomputed: PrecomputedEntities::default(),
        shifted_witness: ShiftedWitnessEntities::default(),
    };
    // random evald
    for w in edge.witness.iter_mut() {
        w.evaluations = rng.gen();
    }

    for p in edge.precomputed.iter_mut() {
        p.evaluations = rng.gen();
    }

    for s in edge.shifted_witness.iter_mut() {
        s.evaluations = rng.gen();
    }
    edge
}

fn run_poseidon_external_relation(
    c: &mut Criterion,
    ele: usize,
    threads_todo_list: &[usize],
    sum_check_data: &SumCheckDataForRelation<PlainUltraHonkDriver, Bn254>,
) {
    let mut group = c.benchmark_group(format!("Poseidon External Relation/#{ele} elements"));
    let mut driver = PlainUltraHonkDriver {};
    let mut acc = Poseidon2ExternalRelationAccHalfShared::default();
    group.bench_function("single threaded", |b| {
        b.iter(|| {
            black_box(Poseidon2ExternalRelation::accumulate_small(
                &mut driver,
                black_box(&mut acc),
                &sum_check_data.all_entites,
                &sum_check_data.scaling_factors,
            ))
            .unwrap();
        })
    });
    for num_threads in threads_todo_list {
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(*num_threads)
            .build()
            .unwrap();
        group.bench_function(format!("#{num_threads} threads"), |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(Poseidon2ExternalRelation::accumulate_multithreaded(
                        &mut driver,
                        black_box(&mut acc),
                        &sum_check_data.all_entites,
                        &sum_check_data.scaling_factors,
                    ))
                    .unwrap();
                })
            })
        });
    }
}

fn run_relations_bench(c: &mut Criterion) {
    let todo_list = [1, 1 << 4, 1 << 8, 1 << 12, 1 << 16, 1 << 20];
    let threads = [8, 16];
    let mut rng = thread_rng();

    let mut all_entites = AllEntitiesBatchRelations::new();
    for num_elements in todo_list {
        for _ in (0..num_elements).step_by(2) {
            all_entites.fold_and_filter(random_edge(&mut rng), rng.gen());
        }
        run_poseidon_external_relation(c, num_elements, &threads, &all_entites.poseidon_ext);
    }
    //collect_poseidon(c, &todo_list, &threads);
}

criterion_group!(benches, run_relations_bench);
criterion_main!(benches);
