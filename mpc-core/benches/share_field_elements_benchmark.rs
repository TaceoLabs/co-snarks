use ark_bn254::Fr;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_core::protocols::shamir::share_field_elements;

fn generate_test_values(n: usize) -> Vec<Fr> {
    let mut rng = thread_rng();
    (0..n).map(|_| Fr::rand(&mut rng)).collect()
}

fn benchmark_share_field_elements(c: &mut Criterion) {
    let values = generate_test_values(1_000_000);
    let degree = 1;
    let num_parties = 3;
    let mut rng = thread_rng();

    c.bench_function("share_field_elements", |b| {
        b.iter(|| {
            let result = share_field_elements(
                black_box(&values),
                black_box(degree),
                black_box(num_parties),
                black_box(&mut rng),
            );
            black_box(result);
        })
    });
}

criterion_group!(benches, benchmark_share_field_elements);
criterion_main!(benches);
