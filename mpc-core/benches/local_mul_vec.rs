pub use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use criterion::*;
use mpc_core::protocols::rep3::{arithmetic::FieldShare, rngs::Rep3Rand};
use rayon::prelude::*;

type FieldShareType = FieldShare<ark_bn254::Fr>;
fn run_bench(c: &mut Criterion, num_threads: usize, todo_list: &[usize]) {
    let thread_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();
    let mut rep3_rand = Rep3Rand::new([1; 32], [2; 32]);

    for amount in todo_list.iter().copied() {
        let vec_a: Vec<FieldShareType> = (0..amount)
            .map(|_| {
                let (a, b) = rep3_rand.random_fes();
                FieldShare::new(a, b)
            })
            .collect();
        let vec_b: Vec<FieldShareType> = (0..amount)
            .map(|_| {
                let (a, b) = rep3_rand.random_fes();
                FieldShare::new(a, b)
            })
            .collect();

        let mut group = c.benchmark_group(format!("# threads {}, size {}", num_threads, amount));
        group.throughput(Throughput::Elements(amount as u64));
        group.bench_function("current impl (with_min_len 1024)", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(local_mul_vec_current(&vec_a, &vec_b, &mut rep3_rand));
                })
            })
        });

        group.bench_function("no rayon, just iter", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(local_mul_vec_no_rayon(&vec_a, &vec_b, &mut rep3_rand));
                });
            })
        });

        group.bench_function("no rayon, just iter/squeeze at beginning", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(local_mul_vec_no_rayon_squeeze_at_beginning(
                        &vec_a,
                        &vec_b,
                        &mut rep3_rand,
                    ));
                });
            })
        });

        group.bench_function("ordinary rayon no min_len", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(local_mul_vec_no_min_len(&vec_a, &vec_b, &mut rep3_rand));
                });
            })
        });

        group.bench_function("local_mul_vec with min len(8)", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(local_mul_vec_rayon_min_lem(
                        &vec_a,
                        &vec_b,
                        &mut rep3_rand,
                        8,
                    ));
                });
            })
        });

        group.bench_function("local_mul_vec with min len(256)", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(local_mul_vec_rayon_min_lem(
                        &vec_a,
                        &vec_b,
                        &mut rep3_rand,
                        256,
                    ));
                });
            })
        });

        group.bench_function("local_mul_vec with min len(4096)", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(local_mul_vec_rayon_min_lem(
                        &vec_a,
                        &vec_b,
                        &mut rep3_rand,
                        4096,
                    ));
                });
            })
        });

        group.bench_function("local_mul_vec with min len(vec.len()/threads)", |b| {
            b.iter(|| {
                thread_pool.install(|| {
                    black_box(local_mul_vec_rayon_min_lem(
                        &vec_a,
                        &vec_b,
                        &mut rep3_rand,
                        amount / num_threads,
                    ));
                });
            })
        });

        group.finish();
    }
}

fn local_mul_vec_current<F: PrimeField>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
    rand: &mut Rep3Rand,
) -> Vec<F> {
    //squeeze all random elements at once in beginning for determinismus
    let masking_fes = rand.masking_field_elements_vec::<F>(lhs.len());

    lhs.par_iter()
        .zip_eq(rhs.par_iter())
        .zip_eq(masking_fes.par_iter())
        .with_min_len(1024)
        .map(|((lhs, rhs), masking)| lhs * rhs + masking)
        .collect()
}

fn local_mul_vec_no_min_len<F: PrimeField>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
    rand: &mut Rep3Rand,
) -> Vec<F> {
    //squeeze all random elements at once in beginning for determinismus
    let masking_fes = rand.masking_field_elements_vec::<F>(lhs.len());

    lhs.par_iter()
        .zip_eq(rhs.par_iter())
        .zip_eq(masking_fes.par_iter())
        .map(|((lhs, rhs), masking)| lhs * rhs + masking)
        .collect()
}

fn local_mul_vec_no_rayon_squeeze_at_beginning<F: PrimeField>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
    rand: &mut Rep3Rand,
) -> Vec<F> {
    //squeeze all random elements at once in beginning for determinismus
    let masking_fes = rand.masking_field_elements_vec::<F>(lhs.len());

    lhs.iter()
        .zip(rhs.iter())
        .zip(masking_fes.iter())
        .map(|((lhs, rhs), masking)| lhs * rhs + masking)
        .collect()
}

fn local_mul_vec_no_rayon<F: PrimeField>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
    rand: &mut Rep3Rand,
) -> Vec<F> {
    lhs.iter()
        .zip(rhs.iter())
        .map(|(lhs, rhs)| lhs * rhs + rand.masking_field_element::<F>())
        .collect()
}

fn local_mul_vec_rayon_min_lem<F: PrimeField>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
    rand: &mut Rep3Rand,
    min_len: usize,
) -> Vec<F> {
    //squeeze all random elements at once in beginning for determinismus
    let masking_fes = rand.masking_field_elements_vec::<F>(lhs.len());

    lhs.par_iter()
        .zip_eq(rhs.par_iter())
        .zip_eq(masking_fes.par_iter())
        .with_min_len(min_len)
        .map(|((lhs, rhs), masking)| lhs * rhs + masking)
        .collect()
}

fn local_mul_vec_bench(c: &mut Criterion) {
    let todo_list = [1 << 8, 1 << 12, 1 << 16, 1 << 20];
    let threads = [8, 16];

    for num_threads in threads {
        run_bench(c, num_threads, &todo_list);
    }
}

criterion_group!(benches, local_mul_vec_bench);
criterion_main!(benches);
