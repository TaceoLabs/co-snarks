use ark_bn254::Bn254;
use co_ultrahonk::prelude::{
    Relation as _, RelationParameters, UltraArithmeticRelation,
    UltraArithmeticRelationAccHalfShared,
};

use co_builder::prelude::PrecomputedEntities;
use co_ultrahonk::prelude::{
    AllEntitiesBatchRelations, DeltaRangeConstraintRelation,
    DeltaRangeConstraintRelationAccHalfShared, PlainUltraHonkDriver, Poseidon2ExternalRelation,
    Poseidon2ExternalRelationAccHalfShared, Poseidon2InternalRelation,
    Poseidon2InternalRelationAccHalfShared, ProverUnivariates, UltraPermutationRelation,
    UltraPermutationRelationAccHalfShared,
};
use criterion::*;
use rand::{thread_rng, Rng};
use rayon::ThreadPoolBuilder;
use ultrahonk::prelude::{ShiftedWitnessEntities, WitnessEntities};

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

fn run_delta_range_constraint_relation(
    c: &mut Criterion,
    threads_todo_list: &[usize],
    sum_check_data: &[(
        usize,
        AllEntitiesBatchRelations<PlainUltraHonkDriver, Bn254>,
    )],
) {
    let mut driver = PlainUltraHonkDriver {};
    for (num_elements, data) in sum_check_data {
        let mut group = c.benchmark_group(format!(
            "Delta Range Constraint Relation/#{num_elements} elements"
        ));
        let mut acc = DeltaRangeConstraintRelationAccHalfShared::default();
        group.bench_function("single threaded", |b| {
            b.iter(|| {
                black_box(DeltaRangeConstraintRelation::accumulate_small(
                    &mut driver,
                    black_box(&mut acc),
                    &data.delta_range.all_entites,
                    &data.delta_range.scaling_factors,
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
                        black_box(DeltaRangeConstraintRelation::accumulate_multithreaded(
                            &mut driver,
                            black_box(&mut acc),
                            &data.delta_range.all_entites,
                            &data.delta_range.scaling_factors,
                        ))
                        .unwrap();
                    })
                })
            });
        }
    }
}

fn run_ultra_arith_relation(
    c: &mut Criterion,
    threads_todo_list: &[usize],
    params: &RelationParameters<ark_bn254::Fr>,
    sum_check_data: &[(
        usize,
        AllEntitiesBatchRelations<PlainUltraHonkDriver, Bn254>,
    )],
) {
    let mut driver = PlainUltraHonkDriver {};
    for (num_elements, data) in sum_check_data {
        let mut group = c.benchmark_group(format!(
            "Ultra Arithmetic Relation/#{num_elements} elements"
        ));
        let mut acc = UltraArithmeticRelationAccHalfShared::default();
        for num_threads in threads_todo_list {
            let thread_pool = ThreadPoolBuilder::new()
                .num_threads(*num_threads)
                .build()
                .unwrap();
            group.bench_function(format!("#{num_threads} threads"), |b| {
                b.iter(|| {
                    thread_pool.install(|| {
                        black_box(UltraArithmeticRelation::accumulate(
                            &mut driver,
                            black_box(&mut acc),
                            &data.poseidon_ext.all_entites,
                            params,
                            &data.poseidon_ext.scaling_factors,
                        ))
                        .unwrap();
                    })
                })
            });
        }
    }
}

fn run_ultra_permutation_relation(
    c: &mut Criterion,
    threads_todo_list: &[usize],
    params: &RelationParameters<ark_bn254::Fr>,
    sum_check_data: &[(
        usize,
        AllEntitiesBatchRelations<PlainUltraHonkDriver, Bn254>,
    )],
) {
    let mut driver = PlainUltraHonkDriver {};
    for (num_elements, data) in sum_check_data {
        let mut group = c.benchmark_group(format!(
            "Ultra Permutation Relation/#{num_elements} elements"
        ));
        let mut acc = UltraPermutationRelationAccHalfShared::default();
        for num_threads in threads_todo_list {
            let thread_pool = ThreadPoolBuilder::new()
                .num_threads(*num_threads)
                .build()
                .unwrap();
            group.bench_function(format!("#{num_threads} threads"), |b| {
                b.iter(|| {
                    thread_pool.install(|| {
                        black_box(UltraPermutationRelation::accumulate(
                            &mut driver,
                            black_box(&mut acc),
                            &data.poseidon_ext.all_entites,
                            params,
                            &data.poseidon_ext.scaling_factors,
                        ))
                        .unwrap();
                    })
                })
            });
        }
    }
}

fn run_poseidon_external_relation(
    c: &mut Criterion,
    threads_todo_list: &[usize],
    sum_check_data: &[(
        usize,
        AllEntitiesBatchRelations<PlainUltraHonkDriver, Bn254>,
    )],
) {
    let mut driver = PlainUltraHonkDriver {};
    for (num_elements, data) in sum_check_data {
        let mut group = c.benchmark_group(format!(
            "Poseidon External Relation/#{num_elements} elements"
        ));
        let mut acc = Poseidon2ExternalRelationAccHalfShared::default();
        group.bench_function("single threaded", |b| {
            b.iter(|| {
                black_box(Poseidon2ExternalRelation::accumulate_small(
                    &mut driver,
                    black_box(&mut acc),
                    &data.poseidon_ext.all_entites,
                    &data.poseidon_ext.scaling_factors,
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
                            &data.poseidon_ext.all_entites,
                            &data.poseidon_ext.scaling_factors,
                        ))
                        .unwrap();
                    })
                })
            });
        }
    }
}

fn run_poseidon_internal_relation(
    c: &mut Criterion,
    threads_todo_list: &[usize],
    sum_check_data: &[(
        usize,
        AllEntitiesBatchRelations<PlainUltraHonkDriver, Bn254>,
    )],
) {
    let mut driver = PlainUltraHonkDriver {};
    for (num_elements, data) in sum_check_data {
        let mut group = c.benchmark_group(format!(
            "Poseidon Internal Relation/#{num_elements} elements"
        ));
        let mut acc = Poseidon2InternalRelationAccHalfShared::default();
        group.bench_function("single threaded", |b| {
            b.iter(|| {
                black_box(Poseidon2InternalRelation::accumulate_small(
                    &mut driver,
                    black_box(&mut acc),
                    &data.poseidon_int.all_entites,
                    &data.poseidon_int.scaling_factors,
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
                        black_box(Poseidon2InternalRelation::accumulate_multithreaded(
                            &mut driver,
                            black_box(&mut acc),
                            &data.poseidon_int.all_entites,
                            &data.poseidon_int.scaling_factors,
                        ))
                        .unwrap();
                    })
                })
            });
        }
    }
}

fn run_relations_bench(c: &mut Criterion) {
    let todo_list = [1_usize, 1 << 4, 1 << 8, 1 << 12, 1 << 16, 1 << 20];
    let threads = [8, 16];
    let mut rng = thread_rng();

    let mut test_vecs = vec![];
    for num_elements in todo_list {
        let mut all_entites = AllEntitiesBatchRelations::new();
        for _ in (0..num_elements).step_by(2) {
            all_entites.fold_and_filter(random_edge(&mut rng), rng.gen());
        }
        test_vecs.push((num_elements, all_entites));
    }
    let params = RelationParameters::<ark_bn254::Fr> {
        eta_1: rng.gen(),
        eta_2: rng.gen(),
        eta_3: rng.gen(),
        beta: rng.gen(),
        gamma: rng.gen(),
        public_input_delta: rng.gen(),
        alphas: rng.gen(),
        gate_challenges: vec![],
    };

    run_ultra_arith_relation(c, &threads, &params, &test_vecs);
    run_ultra_permutation_relation(c, &threads, &params, &test_vecs);
    run_delta_range_constraint_relation(c, &threads, &test_vecs);
    run_poseidon_external_relation(c, &threads, &test_vecs);
    run_poseidon_internal_relation(c, &threads, &test_vecs);
}

criterion_group!(benches, run_relations_bench);
criterion_main!(benches);
