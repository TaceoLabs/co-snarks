use criterion::*;

use ark_bn254::Bn254 as B;
use ark_ff::Zero as _;
use co_ultrahonk::prelude::{NoirUltraHonkProver as P, PlainUltraHonkDriver as D};
use itertools::izip;
use rand::{thread_rng, Rng as _, RngCore};
use rayon::prelude::*;

type FieldType = ark_bn254::Fr;
const MAX_PARTIAL_RELATION_LENGTH: usize = 7;

fn run_add_mul_many(c: &mut Criterion) {
    let num_threads = [8, 16];
    let todo_list = vec![1 << 4, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20];
    for num_threads in num_threads {
        add_mul_many(c, num_threads, &todo_list);
    }
}

fn add_mul_many(c: &mut Criterion, num_threads: usize, todo_list: &[usize]) {
    let thread_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    let zero = FieldType::from(0_u64);
    let one = FieldType::from(1_u64);
    let two = FieldType::from(2_u64);

    let mut rng = thread_rng();

    for num_elements in todo_list.iter().copied() {
        let w_l = (0..num_elements)
            .map(|_| rng.gen::<FieldType>())
            .collect::<Vec<_>>();
        let w_4 = (0..num_elements)
            .map(|_| rng.gen::<FieldType>())
            .collect::<Vec<_>>();
        let w_l_shift = (0..num_elements)
            .map(|_| rng.gen::<FieldType>())
            .collect::<Vec<_>>();
        let q_m = (0..num_elements)
            .map(|_| rng.gen::<FieldType>())
            .collect::<Vec<_>>();
        let q_arith = (0..num_elements)
            .map(|_| rng.gen::<FieldType>())
            .collect::<Vec<_>>();
        let scaling_factors = (0..num_elements)
            .map(|_| rng.gen::<FieldType>())
            .collect::<Vec<_>>();

        let q_arith_neg_1 = q_arith.iter().map(|q| *q - one).collect::<Vec<_>>();

        let q_arith_neg_2 = q_arith.iter().map(|q| *q - two).collect::<Vec<_>>();

        let mut group = c.benchmark_group(format!(
            "assign_many_{}_elems_{}_threads",
            num_elements, num_threads
        ));
        group.throughput(Throughput::Elements(num_elements as u64));
        group.bench_function("go", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    let mut tmp = <D as P<B>>::add_many(&w_l, &w_4);
                    <D as P<B>>::sub_assign_many(&mut tmp, &w_l_shift);
                    <D as P<B>>::add_assign_public_many(&mut tmp, &q_m, 0);
                    <D as P<B>>::mul_assign_with_public_many(&mut tmp, &q_arith_neg_2);
                    <D as P<B>>::mul_assign_with_public_many(&mut tmp, &q_arith_neg_1);
                    <D as P<B>>::mul_assign_with_public_many(&mut tmp, &q_arith);
                    <D as P<B>>::mul_assign_with_public_many(&mut tmp, &scaling_factors);
                    let mut acc = [zero; MAX_PARTIAL_RELATION_LENGTH];
                    for (idx, b) in tmp.iter().enumerate() {
                        let a = &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH];
                        <D as P<B>>::add_assign(a, *b);
                    }

                    criterion::black_box(acc);
                });
            })
        });
        group.finish();

        let mut group = c.benchmark_group(format!(
            "loop_{}_elems_{}_threads",
            num_elements, num_threads
        ));
        group.throughput(Throughput::Elements(num_elements as u64));
        group.bench_function("go", |b| {
            b.iter(|| {
                let mut acc = [zero; MAX_PARTIAL_RELATION_LENGTH];

                for i in 0..w_l.len() {
                    let tmp = <D as P<B>>::add(w_l[i], w_4[i]);
                    let tmp = <D as P<B>>::sub(tmp, w_l_shift[i]);
                    let tmp = <D as P<B>>::add_with_public(q_m[i], tmp, 0);
                    let tmp = <D as P<B>>::mul_with_public(q_arith[i] - two, tmp);
                    let tmp = <D as P<B>>::mul_with_public(q_arith[i] - one, tmp);
                    let tmp = <D as P<B>>::mul_with_public(q_arith[i], tmp);
                    let tmp = <D as P<B>>::mul_with_public(scaling_factors[i], tmp);
                    let a = &mut acc[i % MAX_PARTIAL_RELATION_LENGTH];
                    <D as P<B>>::add_assign(a, tmp);
                }
                criterion::black_box(acc);
            })
        });
        group.finish();

        let mut group = c.benchmark_group(format!(
            "loop_rayon_{}_elems_{}_threads",
            num_elements, num_threads
        ));
        group.throughput(Throughput::Elements(num_elements as u64));
        group.bench_function("go", |b| {
            b.iter(|| {
                let acc = (&w_l, &w_4, &w_l_shift, &q_m, &q_arith, &scaling_factors)
                    .into_par_iter()
                    .map(|(w_l, w_4, w_l_shift, q_m, q_arith, scaling_factor)| {
                        let tmp = <D as P<B>>::add(*w_l, *w_4);
                        let tmp = <D as P<B>>::sub(tmp, *w_l_shift);
                        let tmp = <D as P<B>>::add_with_public(*q_m, tmp, 0);
                        let tmp = <D as P<B>>::mul_with_public(*q_arith - one, tmp);
                        let tmp = <D as P<B>>::mul_with_public(*q_arith - two, tmp);
                        let tmp = <D as P<B>>::mul_with_public(*q_arith, tmp);
                        <D as P<B>>::mul_with_public(*scaling_factor, tmp)
                    })
                    .enumerate()
                    .fold(
                        || [ark_bn254::Fr::zero(); MAX_PARTIAL_RELATION_LENGTH],
                        |mut acc, (idx, tmp)| {
                            <D as P<B>>::add_assign(
                                &mut acc[idx % MAX_PARTIAL_RELATION_LENGTH],
                                tmp,
                            );
                            acc
                        },
                    )
                    .reduce(
                        || [ark_bn254::Fr::zero(); MAX_PARTIAL_RELATION_LENGTH],
                        |mut acc, next| {
                            for (acc, next) in izip!(acc.iter_mut(), next) {
                                <D as P<B>>::add_assign(acc, next);
                            }
                            acc
                        },
                    );
                criterion::black_box(acc);
            })
        });
        group.finish();
    }
}

criterion_group!(benches, run_add_mul_many);
criterion_main!(benches);
