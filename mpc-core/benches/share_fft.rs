use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use criterion::{criterion_group, criterion_main, Criterion};
use mpc_core::protocols::rep3::{fieldshare::Rep3PrimeFieldShareVec, Rep3PrimeFieldShare};

fn criterion_benchmark_fft_size<F: PrimeField>(c: &mut Criterion, num_elements: usize) {
    let domain = Radix2EvaluationDomain::<F>::new(num_elements).unwrap();
    let mut vec = (0..num_elements).map(|_| F::one()).collect::<Vec<F>>();
    let mut share_vec = (0..num_elements)
        .map(|_| Rep3PrimeFieldShare::new(F::one(), F::zero()))
        .collect::<Vec<Rep3PrimeFieldShare<F>>>();
    let mut separate_share_vec = Rep3PrimeFieldShareVec::new(vec.clone(), vec.clone());
    let mut group2 = c.benchmark_group(&format!("FFT, {} El", num_elements));
    group2.throughput(criterion::Throughput::Elements(1));
    group2.bench_function("single vec", |bench| {
        bench.iter(|| domain.fft_in_place(&mut vec));
    });
    group2.bench_function("(A,B,A,B,...) vec", |bench| {
        bench.iter(|| domain.fft_in_place(&mut share_vec));
    });
    group2.bench_function("(A,A,...), (B,B,...) vec", |bench| {
        bench.iter(|| {
            domain.fft_in_place(&mut separate_share_vec.a);
            domain.fft_in_place(&mut separate_share_vec.b);
        });
    });

    group2.finish();
}

fn criterion_benchmark_fft<F: PrimeField>(c: &mut Criterion) {
    for num_elements in &[1 << 10, 1 << 15, 1 << 20] {
        criterion_benchmark_fft_size::<F>(c, *num_elements);
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_fft::<ark_bn254::Fr>
);
criterion_main!(benches);
