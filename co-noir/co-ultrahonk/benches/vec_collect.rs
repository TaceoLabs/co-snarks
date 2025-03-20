use ark_bn254::Bn254;
use co_ultrahonk::prelude::{NoirUltraHonkProver, PlainUltraHonkDriver};
use criterion::*;
use mpc_core::protocols::rep3::arithmetic::FieldShare;
use rand::{thread_rng, Rng, RngCore as _};
use rayon::prelude::*;

type FieldShareType = FieldShare<FieldType>;
type FieldType = ark_bn254::Fr;

fn collect_poseidon(c: &mut Criterion, todo_list: &[usize], threads: &[usize]) {
    let mut rng = thread_rng();
    for num_threads in threads.iter().cloned() {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap();
        for num_elements in todo_list.iter().cloned() {
            let w_l = (0..num_elements)
                .map(|_| rng.gen::<FieldType>())
                .collect::<Vec<_>>();
            let w_r = (0..num_elements)
                .map(|_| rng.gen::<FieldType>())
                .collect::<Vec<_>>();
            let w_o = (0..num_elements)
                .map(|_| rng.gen::<FieldType>())
                .collect::<Vec<_>>();
            let w_4 = (0..num_elements)
                .map(|_| rng.gen::<FieldType>())
                .collect::<Vec<_>>();

            let q_l = (0..num_elements)
                .map(|_| rng.gen::<FieldType>())
                .collect::<Vec<_>>();
            let q_r = (0..num_elements)
                .map(|_| rng.gen::<FieldType>())
                .collect::<Vec<_>>();
            let q_o = (0..num_elements)
                .map(|_| rng.gen::<FieldType>())
                .collect::<Vec<_>>();
            let q_4 = (0..num_elements)
                .map(|_| rng.gen::<FieldType>())
                .collect::<Vec<_>>();

            let mut group = c.benchmark_group(format!(
                "collect {} elems {} threads",
                num_elements, num_threads
            ));
            group.throughput(Throughput::Elements(num_elements as u64));

            group.bench_function("current impl no mt", |b| {
                b.iter(|| {
                    thread_pool.install(|| {
                        let s1 = <PlainUltraHonkDriver as NoirUltraHonkProver<Bn254>>::add_with_public_many(
                            &q_l, &w_l, 0,
                        );
                        let s2 = <PlainUltraHonkDriver as NoirUltraHonkProver<Bn254>>::add_with_public_many(
                            &q_r, &w_r, 0,
                        );
                        let s3 = <PlainUltraHonkDriver as NoirUltraHonkProver<Bn254>>::add_with_public_many(
                            &q_o, &w_o, 0,
                        );
                        let s4 = <PlainUltraHonkDriver as NoirUltraHonkProver<Bn254>>::add_with_public_many(
                            &q_4, &w_4, 0,

                        );
                        let mut s = Vec::with_capacity(s1.len() + s2.len() + s3.len() + s4.len());
                        s.extend(s1);
                        s.extend(s2);
                        s.extend(s3);
                        s.extend(s4);
                        black_box(s);
                    })
                })
            });

            group.bench_function("par iter chain in main thread", |b| {
                b.iter(|| {
                    thread_pool.install(|| {
                        let s1 = (&q_l, &w_l).into_par_iter().map(|(q_l, w_l)| q_l + w_l);
                        let s2 = (&q_r, &w_r).into_par_iter().map(|(q_l, w_l)| q_l + w_l);
                        let s3 = (&q_o, &w_o).into_par_iter().map(|(q_l, w_l)| q_l + w_l);
                        let s4 = (&q_4, &w_4).into_par_iter().map(|(q_l, w_l)| q_l + w_l);
                        black_box(s1.chain(s2).chain(s3).chain(s4).collect::<Vec<_>>());
                    })
                })
            });
            group.bench_function("par iter chain with join", |b| {
                b.iter(|| {
                    thread_pool.install(|| {
                        let ((s1, s2), (s3, s4)) = rayon::join(
                            || {
                                rayon::join(
                                    || (&q_l, &w_l).into_par_iter().map(|(q_l, w_l)| q_l + w_l),
                                    || (&q_r, &w_r).into_par_iter().map(|(q_l, w_l)| q_l + w_l),
                                )
                            },
                            || {
                                rayon::join(
                                    || (&q_o, &w_o).into_par_iter().map(|(q_l, w_l)| q_l + w_l),
                                    || (&q_4, &w_4).into_par_iter().map(|(q_l, w_l)| q_l + w_l),
                                )
                            },
                        );
                        black_box(s1.chain(s2).chain(s3).chain(s4).collect::<Vec<_>>());
                    })
                })
            });
            group.finish();
        }
    }
}

fn run_collect(c: &mut Criterion) {
    let todo_list = [1 << 4, 1 << 8, 1 << 12, 1 << 16, 1 << 20];
    let threads = [8, 16];
    collect_poseidon(c, &todo_list, &threads);
}

criterion_group!(benches, run_collect);
criterion_main!(benches);
