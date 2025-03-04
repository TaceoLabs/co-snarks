use criterion::*;

use ark_bn254::Bn254 as B;
use co_ultrahonk::prelude::{NoirUltraHonkProver as P, PlainUltraHonkDriver as D};
use rand::{thread_rng, RngCore};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;

type FieldType = ark_bn254::Fr;
const MAX_PARTIAL_RELATION_LENGTH: usize = 7;

fn add_mul_many(c: &mut Criterion) {
    let num_threads = std::env::var("BENCHES_NUM_THREADS")
        .unwrap()
        .parse::<usize>()
        .unwrap();

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();

    let zero = FieldType::from(0_u64);
    let one = FieldType::from(1_u64);
    let two = FieldType::from(2_u64);

    let mut rng = thread_rng();

    let todo_list = vec![
        8,
        16,
        32,
        64,
        128,
        256,
        512,
        1024,
        1024 * 2,
        1024 * 4,
        1024 * 8,
        1024 * 16,
        1024 * 32,
        1024 * 64,
        1024 * 128,
        1024 * 256,
    ];

    for num_elements in todo_list {
        let w_l = (0..num_elements)
            .map(|_| FieldType::from(rng.next_u64()))
            .collect::<Vec<_>>();
        let w_4 = (0..num_elements)
            .map(|_| FieldType::from(rng.next_u64()))
            .collect::<Vec<_>>();
        let w_l_shift = (0..num_elements)
            .map(|_| FieldType::from(rng.next_u64()))
            .collect::<Vec<_>>();
        let q_m = (0..num_elements)
            .map(|_| FieldType::from(rng.next_u64()))
            .collect::<Vec<_>>();
        let q_arith = (0..num_elements)
            .map(|_| FieldType::from(rng.next_u64()))
            .collect::<Vec<_>>();
        let scaling_factors = (0..num_elements)
            .map(|_| FieldType::from(rng.next_u64()))
            .collect::<Vec<_>>();

        let q_arith_neg_1 = q_arith.iter().map(|q| *q - one).collect::<Vec<_>>();

        let q_arith_neg_2 = q_arith.iter().map(|q| *q - two).collect::<Vec<_>>();

        let mut group = c.benchmark_group(format!(
            "assign_many_{}_elems_{}_threads",
            num_elements, num_threads
        ));
        group.throughput(Throughput::Elements(num_elements));
        group.bench_function("go", |b| {
            b.iter(|| {
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
            })
        });
        group.finish();

        let mut group = c.benchmark_group(format!(
            "loop_{}_elems_{}_threads",
            num_elements, num_threads
        ));
        group.throughput(Throughput::Elements(num_elements));
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
            })
        });
        group.finish();

        let mut group = c.benchmark_group(format!(
            "loop_rayon_{}_elems_{}_threads",
            num_elements, num_threads
        ));
        group.throughput(Throughput::Elements(num_elements));
        group.bench_function("go", |b| {
            b.iter(|| {
                w_l.par_iter()
                    .enumerate()
                    .zip(&w_4)
                    .zip(&w_l_shift)
                    .zip(&q_m)
                    .zip(&q_arith)
                    .zip(&scaling_factors)
                    .for_each(
                        |((((((i, w_l), w_4), w_l_shift), q_m), q_arith), scaling_factors)| {
                            let tmp = <D as P<B>>::add(*w_l, *w_4);
                            let tmp = <D as P<B>>::sub(tmp, *w_l_shift);
                            let tmp = <D as P<B>>::add_with_public(*q_m, tmp, 0);
                            let tmp = <D as P<B>>::mul_with_public(*q_arith - two, tmp);
                            let tmp = <D as P<B>>::mul_with_public(*q_arith - one, tmp);
                            let tmp = <D as P<B>>::mul_with_public(*q_arith, tmp);
                            let tmp = <D as P<B>>::mul_with_public(*scaling_factors, tmp);
                            let mut acc = [zero; MAX_PARTIAL_RELATION_LENGTH]; // this here is somewhat wrong!
                            let a = &mut acc[i % MAX_PARTIAL_RELATION_LENGTH];
                            <D as P<B>>::add_assign(a, tmp);
                        },
                    );
            })
        });
        group.finish();
    }
}

criterion_group!(benches, add_mul_many,);
criterion_main!(benches);
