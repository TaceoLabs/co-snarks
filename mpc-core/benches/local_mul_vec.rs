pub use ark_ec::pairing::Pairing;
use criterion::*;
use mpc_core::protocols::rep3::{
    arithmetic::{self, FieldShare},
    id::PartyID,
    network::{IoContext, Rep3Network},
    rngs::{Rep3CorrelatedRng, Rep3Rand, Rep3RandBitComp},
};
use rand::SeedableRng;

type FieldShareType =
    FieldShare<<ark_ec::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::ScalarField>;

struct Dummy;
impl Rep3Network for Dummy {
    fn get_id(&self) -> PartyID {
        todo!()
    }

    fn reshare_many<F: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize>(
        &mut self,
        _: &[F],
    ) -> std::io::Result<Vec<F>> {
        todo!()
    }

    fn broadcast_many<
        F: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize,
    >(
        &mut self,
        _: &[F],
    ) -> std::io::Result<(Vec<F>, Vec<F>)> {
        todo!()
    }

    fn send_many<F: ark_serialize::CanonicalSerialize>(
        &mut self,
        _: PartyID,
        _: &[F],
    ) -> std::io::Result<()> {
        todo!()
    }

    fn recv_many<F: ark_serialize::CanonicalDeserialize>(
        &mut self,
        _: PartyID,
    ) -> std::io::Result<Vec<F>> {
        todo!()
    }

    fn fork(&mut self) -> std::io::Result<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}
fn current_main_local_mul_vec(c: &mut Criterion) {
    let mut io_context = IoContext::<Dummy> {
        id: PartyID::ID0,
        a2b_type: Default::default(),
        rngs: Rep3CorrelatedRng::new(
            Rep3Rand::new([0; 32], [0; 32]),
            Rep3RandBitComp::new_2keys([0; 32], [0; 32]),
            Rep3RandBitComp::new_2keys([0; 32], [0; 32]),
        ),
        network: Dummy {},
        rng: rand_chacha::ChaCha12Rng::from_entropy(),
    };
    let size = 1024 * 128 * 128 * 48;
    let vec_a: Vec<FieldShareType> = (0..size)
        .map(|_| FieldShare::rand(&mut io_context))
        .collect();
    let vec_b: Vec<FieldShareType> = (0..size)
        .map(|_| FieldShare::rand(&mut io_context))
        .collect();

    let mut group = c.benchmark_group("throughput 0");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("current main", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("throughput 1");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("no rayon, just iter", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec_no_rayon(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("throughput 2");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("primitive rayon", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec_simple(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("throughput 3");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("local_mul_vec_no_multi", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec_no_multi(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("throughput 4");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("with_min_len 2", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec_2(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("throughput 5");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("with_min_len 4", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec_4(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("throughput 6");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("with_min_len 8", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec_8(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("throughput 7");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("with_min_len 16", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec_16(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("throughput 8");
    group.throughput(Throughput::Elements(vec_a.len() as u64));
    group.bench_function("local_mul_vec_big", |b| {
        b.iter(|| {
            let _ = arithmetic::local_mul_vec_big(&vec_a, &vec_b, &mut io_context.rngs);
        })
    });
    group.finish();
}

criterion_group!(benches, current_main_local_mul_vec,);
criterion_main!(benches);
