use std::{io::Read, sync::Arc, thread, vec};

use ark_bn254::Bn254;
use ark_ec::{bn::Bn, pairing::Pairing};
use ark_ff::AdditiveGroup;
use co_builder::{
    flavours::mega_flavour::{MegaFlavour, MegaPrecomputedEntities, MegaProverWitnessEntities},
    prelude::{ActiveRegionData, PublicComponentKey},
    prover_flavour::ProverFlavour,
};
use co_noir_common::{
    crs::parse::CrsParser,
    honk_proof::TranscriptFieldType,
    mpc::{NoirUltraHonkProver, rep3::Rep3UltraHonkDriver},
    polynomials::{polynomial::Polynomial, shared_polynomial::SharedPolynomial},
    types::ZeroKnowledge,
};
use co_ultrahonk::{
    co_decider::types::{ProverMemory, RelationParameters},
    co_oink::co_oink_prover::CoOink,
    prelude::ProvingKey,
    types::Polynomials,
};
use co_ultrahonk::{co_decider::univariates::SharedUnivariate, types::AllEntities};
use flate2::read::GzDecoder;
use itertools::izip;
use mpc_core::{
    gadgets::field_from_hex_string,
    protocols::rep3::{Rep3State, conversion::A2BType, share_field_elements},
};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;
use serde::de::DeserializeOwned;

use ultrahonk::prelude::{
    GateSeparatorPolynomial, HonkProof, Poseidon2Sponge, Transcript, Univariate,
};

use crate::{
    co_protogalaxy_prover::{BATCHED_EXTENDED_LENGTH, MAX_TOTAL_RELATION_LENGTH, NUM_KEYS},
    co_protogalaxy_prover_internal::{
        compute_and_extend_alphas, compute_extended_relation_parameters,
    },
};
use crate::{
    co_protogalaxy_prover::{CONST_PG_LOG_N, CoProtogalaxyProver, DeciderProverMemory},
    co_protogalaxy_prover_internal::{
        compute_combiner, compute_combiner_quotient, compute_perturbator, compute_row_evaluations,
        construct_perturbator_coefficients,
    },
};

const EXTENDED_LENGTH: usize = (MAX_TOTAL_RELATION_LENGTH - 1) * (NUM_KEYS - 1) + 1;
const CRS_PATH_G1: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../co-noir-common/src/crs/bn254_g1.dat"
);
const CRS_PATH_G2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../co-noir-common/src/crs/bn254_g2.dat"
);
type F = TranscriptFieldType;
type C = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;
type Driver = Rep3UltraHonkDriver;
type SharedEntities =
    AllEntities<Vec<<Driver as NoirUltraHonkProver<C>>::ArithmeticShare>, Vec<F>, MegaFlavour>;

fn decompress_and_read_test_data<T: DeserializeOwned>(filename: &str) -> T {
    let gzip_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/{}.gz",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );
    let mut d = GzDecoder::new(std::fs::File::open(gzip_file).unwrap());
    let mut buffer = String::new();
    d.read_to_string(&mut buffer).unwrap();
    serde_json::from_str::<T>(&buffer).unwrap()
}

// Macro to transfor a String or a vec of Strings or a vec of vecs of Strings or a Vec of slices of Strings into the corresponding field type

macro_rules! to_field {
    ($x:expr) => {
        field_from_hex_string($x.as_str()).unwrap()
    };
    ($x:expr, 1) => {
        $x.into_iter().map(|s| to_field!(s)).collect::<Vec<_>>()
    };
    ($x:expr, 2) => {
        $x.into_iter().map(|s| to_field!(s, 1)).collect::<Vec<_>>()
    };
}

fn structure_parameters<T: PartialEq + Default>(
    [
        eta_1,
        eta_2,
        eta_3,
        beta,
        gamma,
        public_input_delta,
        lookup_grand_product_delta,
    ]: [T; 7],
) -> RelationParameters<T> {
    RelationParameters {
        eta_1,
        eta_2,
        eta_3,
        beta,
        gamma,
        public_input_delta,
        lookup_grand_product_delta,
        ..Default::default()
    }
}
#[test]
fn test_compute_and_extend_alphas() {
    let test_file = "unit/compute_and_extend_alphas";

    let (alphas_0, alphas_1, expected_alphas): (
        Vec<String>,
        Vec<String>,
        Vec<[String; BATCHED_EXTENDED_LENGTH]>,
    ) = decompress_and_read_test_data(test_file);

    let alphas_0 = to_field!(alphas_0, 1);
    let alphas_1 = to_field!(alphas_1, 1);

    let mut memory_0 = ProverMemory::<Driver, C, MegaFlavour> {
        alphas: alphas_0.clone(),
        // Fields not used in this test
        gate_challenges: vec![],
        relation_parameters: RelationParameters::default(),
        polys: Default::default(),
    };

    let mut memory_1 = ProverMemory::<Driver, C, MegaFlavour> {
        alphas: alphas_1.clone(),
        // Fields not used in this test
        gate_challenges: vec![],
        relation_parameters: RelationParameters::default(),
        polys: Default::default(),
    };

    let prover_memory = vec![&mut memory_0, &mut memory_1];

    assert_eq!(
        compute_and_extend_alphas(&prover_memory),
        to_field!(expected_alphas, 2)
            .into_iter()
            .map(|alphas| Univariate {
                evaluations: alphas.try_into().unwrap()
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_compute_extended_relation_parameters() {
    let test_file = "unit/compute_extended_relation_parameters";

    let (parameters_1_values, parameters_2_values, univariates): (
        [String; 7],
        [String; 7],
        Vec<[String; EXTENDED_LENGTH]>,
    ) = decompress_and_read_test_data(test_file);

    let parameters_1 = structure_parameters(to_field!(parameters_1_values, 1).try_into().unwrap());
    let parameters_2 = structure_parameters(to_field!(parameters_2_values, 1).try_into().unwrap());

    let expected_relation_parameters = structure_parameters(
        to_field!(univariates, 2)
            .into_iter()
            .map(|v| Univariate {
                evaluations: v.try_into().unwrap(),
            })
            .collect::<Vec<Univariate<F, { EXTENDED_LENGTH }>>>()
            .try_into()
            .unwrap(),
    );

    let mut memory_1 = ProverMemory::<Driver, C, MegaFlavour> {
        relation_parameters: parameters_1,
        // Fields not used in this test
        polys: Default::default(),
        alphas: vec![],
        gate_challenges: vec![],
    };
    let mut memory_2 = ProverMemory::<Driver, C, MegaFlavour> {
        relation_parameters: parameters_2,
        // Fields not used in this test
        polys: Default::default(),
        alphas: vec![],
        gate_challenges: vec![],
    };

    let prover_memory = vec![&mut memory_1, &mut memory_2];

    let extended_parameters = compute_extended_relation_parameters(&prover_memory);
    for (p1, p2) in extended_parameters
        .get_params()
        .iter()
        .zip(expected_relation_parameters.get_params())
    {
        // Due to skipped indices
        assert_eq!(p1.evaluations[..EXTENDED_LENGTH], p2.evaluations);
    }
}

#[test]
fn test_compute_combiner_quotient() {
    let test_file = "unit/compute_combiner_quotient";

    let (combiner_values, perturbator_evaluation, expected_combiner_quotient): (
        [String; BATCHED_EXTENDED_LENGTH],
        String,
        [String; BATCHED_EXTENDED_LENGTH - NUM_KEYS],
    ) = decompress_and_read_test_data(test_file);

    let combiners = share_field_elements::<F, _>(&to_field!(combiner_values, 1), &mut thread_rng())
        .map(SharedUnivariate::<Driver, C, BATCHED_EXTENDED_LENGTH>::from_vec);

    let perturbator_evaluation: F = to_field!(perturbator_evaluation);

    let expected_evalutations = to_field!(expected_combiner_quotient, 1);

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);

    for (net, combiner) in nets.into_iter().zip(combiners.into_iter()) {
        threads.push(thread::spawn(move || {
            let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

            let combiner_quotient =
                compute_combiner_quotient(&state, &combiner, perturbator_evaluation);

            <Driver as NoirUltraHonkProver<C>>::open_many(
                &combiner_quotient.evaluations,
                &net,
                &mut state,
            )
            .unwrap()
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    for eval in results.into_iter() {
        assert_eq!(eval, expected_evalutations);
    }
}

#[test]
fn test_construct_perturbator_coefficients() {
    let test_file = "unit/construct_perturbator_coefficients";

    let (
        betas_values,
        deltas_values,
        perturbator_coefficients_values,
        full_honk_evaluations_values,
    ): (Vec<String>, Vec<String>, Vec<String>, Vec<String>) =
        decompress_and_read_test_data(test_file);

    let betas = to_field!(betas_values, 1);
    let deltas = to_field!(deltas_values, 1);

    let betas_ref = Arc::new(betas);
    let deltas_ref = Arc::new(deltas);

    let perturbator_coefficients = to_field!(perturbator_coefficients_values, 1);
    let full_honk_evaluations = share_field_elements::<F, _>(
        &to_field!(full_honk_evaluations_values, 1),
        &mut thread_rng(),
    )
    .map(|coefficients| SharedPolynomial::<Driver, C> { coefficients });

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);

    for (net, full_honk_evaluations) in nets.into_iter().zip(full_honk_evaluations.into_iter()) {
        threads.push(thread::spawn({
            let betas_ref = betas_ref.clone();
            let deltas_ref = deltas_ref.clone();

            move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let coefficients = construct_perturbator_coefficients::<Driver, C>(
                    &betas_ref,
                    &deltas_ref,
                    full_honk_evaluations,
                );

                <Driver as NoirUltraHonkProver<C>>::open_many(&coefficients, &net, &mut state)
                    .unwrap()
            }
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    for coeffs in results.into_iter() {
        assert_eq!(coeffs, perturbator_coefficients);
    }
}

#[test]
fn test_compute_row_evaluations() {
    let test_file = "unit/compute_row_evaluations";

    let (alphas, relation_parameters, polys, expected_full_honk_evaluations): (
        Vec<String>,
        Vec<String>,
        Vec<Vec<String>>,
        Vec<String>,
    ) = decompress_and_read_test_data(test_file);

    let alphas = to_field!(alphas, 1);
    let relation_parameters =
        structure_parameters(to_field!(relation_parameters, 1).try_into().unwrap());
    let expected_full_honk_evaluations: Vec<F> = to_field!(expected_full_honk_evaluations, 1);
    let mut public_polys = to_field!(polys, 2);
    let others = public_polys.split_off(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
    let shared_polys = others
        .into_iter()
        //.map(|p| [p.clone(), p.clone(), p.clone()])
        .map(|p| share_field_elements::<F, _>(&p, &mut thread_rng()))
        .fold([vec![], vec![], vec![]], |[mut a, mut b, mut c], f| {
            a.push(f[0].clone());
            b.push(f[1].clone());
            c.push(f[2].clone());
            [a, b, c]
        });

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);

    for (net, shared_polys) in nets.into_iter().zip(shared_polys) {
        threads.push(thread::spawn({
            let polys = SharedEntities::from_elements(shared_polys, public_polys.clone());
            let prover_memory = ProverMemory::<Driver, C, MegaFlavour> {
                relation_parameters: relation_parameters.clone(),
                polys,
                alphas: alphas.clone(),
                gate_challenges: vec![], // Not used in this test
            };

            move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let shared_poly =
                    compute_row_evaluations::<Driver, C, _>(&net, &mut state, &prover_memory)
                        .unwrap();

                <Driver as NoirUltraHonkProver<C>>::open_many(
                    &shared_poly.coefficients,
                    &net,
                    &mut state,
                )
                .unwrap()
            }
        }));
    }
    let results: Vec<Vec<F>> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for res in results.into_iter() {
        assert_eq!(res, expected_full_honk_evaluations);
    }
}

#[test]
fn test_compute_perturbator() {
    let test_file = "unit/compute_row_evaluations";

    let (alphas, relation_parameters, polys, _): (
        Vec<String>,
        Vec<String>,
        Vec<Vec<String>>,
        Vec<String>,
    ) = decompress_and_read_test_data(test_file);

    let test_file = "unit/compute_perturbator";

    let (deltas, gate_challenges, circuit_log_size, perturbator_coefficients): (
        Vec<String>,
        Vec<String>,
        usize,
        Vec<String>,
    ) = decompress_and_read_test_data(test_file);

    let alphas = to_field!(alphas, 1);
    let relation_parameters = to_field!(relation_parameters, 1);
    let gate_challenges = to_field!(gate_challenges, 1);
    let perturbator_coefficients = to_field!(perturbator_coefficients, 1);

    let mut public_polys = to_field!(polys, 2);
    let others = public_polys.split_off(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
    let shared_polys = others
        .into_iter()
        .map(|p| share_field_elements::<F, _>(&p, &mut thread_rng()))
        .fold([vec![], vec![], vec![]], |[mut a, mut b, mut c], f| {
            a.push(f[0].clone());
            b.push(f[1].clone());
            c.push(f[2].clone());
            [a, b, c]
        });

    let relation_parameters = structure_parameters(relation_parameters.try_into().unwrap());

    let deltas = to_field!(deltas, 1);
    let deltas_ref = Arc::new(deltas);

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);

    for (net, shared_polys) in nets.into_iter().zip(shared_polys) {
        threads.push(thread::spawn({
            let polys = SharedEntities::from_elements(shared_polys, public_polys.clone());
            let prover_memory = ProverMemory::<Driver, C, MegaFlavour> {
                relation_parameters: relation_parameters.clone(),
                polys,
                alphas: alphas.clone(),
                gate_challenges: gate_challenges.clone(),
            };
            let mut proving_key = ProvingKey::<Driver, C, MegaFlavour>::new(
                2usize.pow(circuit_log_size as u32),
                // Irrelevant values, as we are only using the circuit size in this test
                0,
                0,
                PublicComponentKey::default(),
            );
            let deltas_ref = deltas_ref.clone();

            move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let shared_poly = compute_perturbator::<Driver, C, _>(
                    &net,
                    &mut state,
                    &mut proving_key,
                    &deltas_ref,
                    &prover_memory,
                )
                .unwrap();

                <Driver as NoirUltraHonkProver<C>>::open_many(
                    &shared_poly.coefficients,
                    &net,
                    &mut state,
                )
                .unwrap()
            }
        }));
    }
    let results: Vec<Vec<F>> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for res in results.into_iter() {
        assert_eq!(res, perturbator_coefficients);
    }
}

#[ignore = "Requires a large test file"]
#[test]
fn test_compute_combiner() {
    type CombinerTestData = (
        Vec<String>,
        Vec<Vec<String>>,
        Vec<Vec<String>>,
        (Vec<Vec<String>>, Vec<Vec<String>>),
        Vec<String>,
    );

    let test_file = "unit/compute_combiner";

    let (beta_products, alphas, relation_parameters, (polys_1, polys_2), combiner): CombinerTestData = decompress_and_read_test_data(test_file);

    let alphas = to_field!(alphas, 2)
        .into_iter()
        .map(|a| Univariate {
            evaluations: a.try_into().unwrap(),
        })
        .collect::<Vec<Univariate<F, BATCHED_EXTENDED_LENGTH>>>();
    let beta_products = to_field!(beta_products, 1);
    let relation_parameters = to_field!(relation_parameters, 2)
        .into_iter()
        .map(|mut p| {
            // Handle skipped indices
            p.push(F::ZERO);
            p
        })
        .collect::<Vec<Vec<F>>>();
    let combiner = to_field!(combiner, 1);
    let mut public_polys_1 = to_field!(polys_1, 2);
    let mut public_polys_2 = to_field!(polys_2, 2);

    let others = public_polys_1.split_off(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
    let shared_polys_1 = others
        .into_iter()
        .map(|p| share_field_elements::<F, _>(&p, &mut thread_rng()))
        .fold([vec![], vec![], vec![]], |[mut a, mut b, mut c], f| {
            a.push(f[0].clone());
            b.push(f[1].clone());
            c.push(f[2].clone());
            [a, b, c]
        });

    let others = public_polys_2.split_off(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
    let shared_polys_2 = others
        .into_iter()
        .map(|p| share_field_elements::<F, _>(&p, &mut thread_rng()))
        .fold([vec![], vec![], vec![]], |[mut a, mut b, mut c], f| {
            a.push(f[0].clone());
            b.push(f[1].clone());
            c.push(f[2].clone());
            [a, b, c]
        });

    let relation_parameters = structure_parameters(
        relation_parameters
            .into_iter()
            .map(|evaluations| Univariate {
                evaluations: evaluations.try_into().unwrap(),
            })
            .collect::<Vec<Univariate<F, BATCHED_EXTENDED_LENGTH>>>()
            .try_into()
            .unwrap(),
    );

    let gate_separator_polynomial = GateSeparatorPolynomial::<F> {
        beta_products: beta_products.clone(),
        // Fields not used in this test
        betas: Default::default(),
        partial_evaluation_result: Default::default(),
        current_element_idx: 0,
        periodicity: 0,
    };

    let relation_parameters_ref = Arc::new(relation_parameters);
    let alphas_ref = Arc::new(alphas);
    let gate_separator_polynomial_ref = Arc::new(gate_separator_polynomial);

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);

    for (net, shared_polys_1, shared_polys_2) in izip!(
        nets.into_iter(),
        shared_polys_1.into_iter(),
        shared_polys_2.into_iter()
    ) {
        threads.push(thread::spawn({
            let polys_1 = SharedEntities::from_elements(shared_polys_1, public_polys_1.clone());
            let polys_2 = SharedEntities::from_elements(shared_polys_2, public_polys_2.clone());

            let mut prover_memory_1 = ProverMemory::<Driver, C, MegaFlavour> {
                polys: polys_1,
                // Fields not used in this test
                alphas: Default::default(),
                gate_challenges: vec![],
                relation_parameters: Default::default(),
            };

            let mut prover_memory_2 = ProverMemory::<Driver, C, MegaFlavour> {
                polys: polys_2,
                // Fields not used in this test
                alphas: Default::default(),
                gate_challenges: vec![],
                relation_parameters: Default::default(),
            };

            let relation_parameters = relation_parameters_ref.clone();
            let alphas = alphas_ref.clone();
            let gate_separator_polynomial = gate_separator_polynomial_ref.clone();

            move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let shared_univariate = compute_combiner(
                    &net,
                    &mut state,
                    &vec![&mut prover_memory_1, &mut prover_memory_2],
                    &gate_separator_polynomial,
                    &relation_parameters,
                    &alphas,
                )
                .unwrap()
                .evaluations
                .to_vec();

                <Driver as NoirUltraHonkProver<C>>::open_many(&shared_univariate, &net, &mut state)
                    .unwrap()
            }
        }));
    }

    let results: Vec<Vec<F>> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for res in results.into_iter() {
        assert_eq!(res, combiner);
    }
}

#[test]
#[ignore]
fn test_protogalaxy_prover() {
    type SavedPK = (
        (
            u32,
            u32,
            u32,
            u32,
            usize,
            Vec<String>,
            Vec<Vec<String>>,
            Vec<u32>,
            Vec<u32>,
            (Vec<(usize, usize)>, Vec<usize>, usize),
        ),
        Vec<String>,
    );

    type FoldingResult = (
        (
            String,
            Vec<String>,
            Vec<String>,
            Vec<String>,
            Vec<Vec<String>>,
        ),
        Vec<String>,
    );

    let test_file_acc = "e2e/accumulator";
    let test_file_folded = "e2e/folded_key";
    let test_file_folding_result = "e2e/folding_result";

    let (
        (
            circuit_size_1,
            num_public_inputs_1,
            pub_inputs_offset_1,
            start_idx_1,
            final_active_wire_idx_1,
            public_inputs_1,
            polys_1,
            memory_read_records_1,
            memory_write_records_1,
            (ranges_1, idxs_1, current_end_1),
        ),
        _,
    ): SavedPK = decompress_and_read_test_data(test_file_acc);

    let (
        (
            circuit_size_2,
            num_public_inputs_2,
            pub_inputs_offset_2,
            start_idx_2,
            final_active_wire_idx_2,
            public_inputs_2,
            polys_2,
            memory_read_records_2,
            memory_write_records_2,
            (ranges_2, idxs_2, current_end_2),
        ),
        _,
    ): SavedPK = decompress_and_read_test_data(test_file_folded);

    let (
        (
            target_sum_result,
            gate_challenges_result,
            alphas_result,
            relation_parameters_result,
            polynomials_folding_result,
        ),
        honk_proof,
    ): FoldingResult = decompress_and_read_test_data(test_file_folding_result);

    let crs = CrsParser::<<Bn<ark_bn254::Config> as Pairing>::G1>::get_crs::<Bn254>(
        CRS_PATH_G1,
        CRS_PATH_G2,
        circuit_size_1 as usize,
        ZeroKnowledge::No,
    )
    .unwrap();

    let (prover_crs, _) = crs.split();

    let honk_proof = to_field!(honk_proof, 1);

    let alphas_result = to_field!(alphas_result, 1);
    let relation_parameters_result = to_field!(relation_parameters_result, 1);
    let gate_challenges_result = to_field!(gate_challenges_result, 1);
    let polynomials_folding_result: Vec<Vec<F>> = to_field!(polynomials_folding_result, 2);

    let target_sum_result: F = to_field!(target_sum_result);

    let public_inputs_1 = to_field!(public_inputs_1, 1);
    let public_inputs_2 = to_field!(public_inputs_2, 1);

    let mut public_polys_1 = to_field!(polys_1, 2);
    let mut public_polys_2 = to_field!(polys_2, 2);

    let others = public_polys_1.split_off(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
    let shared_polys_1 = others
        .into_iter()
        .map(|p| share_field_elements::<F, _>(&p, &mut thread_rng()))
        .fold([vec![], vec![], vec![]], |[mut a, mut b, mut c], f| {
            a.push(f[0].clone());
            b.push(f[1].clone());
            c.push(f[2].clone());
            [a, b, c]
        });

    let others = public_polys_2.split_off(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
    let shared_polys_2 = others
        .into_iter()
        .map(|p| share_field_elements::<F, _>(&p, &mut thread_rng()))
        .fold([vec![], vec![], vec![]], |[mut a, mut b, mut c], f| {
            a.push(f[0].clone());
            b.push(f[1].clone());
            c.push(f[2].clone());
            [a, b, c]
        });

    let structure_prover_polys =
        |shared: Vec<Vec<<Rep3UltraHonkDriver as NoirUltraHonkProver<C>>::ArithmeticShare>>,
         public: Vec<Vec<F>>| {
            let (witness, _) = shared.split_at(MegaFlavour::WITNESS_ENTITIES_SIZE);

            // Remove z_perm and lookup_inverses from witness
            let mut shared = witness[..4].to_vec();
            shared.extend_from_slice(&witness[6..]);

            let shared = shared
                .into_iter()
                .map(|coefficients| Polynomial { coefficients })
                .collect::<Vec<_>>();

            let public = public
                .into_iter()
                .map(|coefficients| Polynomial { coefficients })
                .collect::<Vec<_>>();

            Polynomials::<
                <Rep3UltraHonkDriver as NoirUltraHonkProver<C>>::ArithmeticShare,
                F,
                MegaFlavour,
            > {
                witness: MegaProverWitnessEntities {
                    elements: shared.try_into().unwrap(),
                },
                precomputed: MegaPrecomputedEntities {
                    elements: public.try_into().unwrap(),
                },
            }
        };

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);

    for (net, shared_polys_1, shared_polys_2) in izip!(
        nets.into_iter(),
        shared_polys_1.into_iter(),
        shared_polys_2.into_iter()
    ) {
        threads.push(thread::spawn({
            let polys_1 = structure_prover_polys(shared_polys_1.clone(), public_polys_1.clone());
            let polys_2 = structure_prover_polys(shared_polys_2, public_polys_2.clone());

            let mut accumulator = ProvingKey::<Driver, C, MegaFlavour> {
                circuit_size: circuit_size_1,
                num_public_inputs: num_public_inputs_1,
                pub_inputs_offset: pub_inputs_offset_1,
                public_inputs: public_inputs_1.clone(),
                memory_read_records: memory_read_records_1.clone(),
                memory_write_records: memory_write_records_1.clone(),
                active_region_data: ActiveRegionData {
                    ranges: ranges_1.clone(),
                    idxs: idxs_1.clone(),
                    current_end: current_end_1,
                },
                pairing_inputs_public_input_key: PublicComponentKey {
                    start_idx: start_idx_1,
                },
                final_active_wire_idx: final_active_wire_idx_1,
                polynomials: polys_1,
                phantom: Default::default(),
                memory_records_shared: Default::default(),
            };

            let folded_key = ProvingKey::<Driver, C, MegaFlavour> {
                circuit_size: circuit_size_2,
                num_public_inputs: num_public_inputs_2,
                pub_inputs_offset: pub_inputs_offset_2,
                public_inputs: public_inputs_2.clone(),
                memory_read_records: memory_read_records_2.clone(),
                memory_write_records: memory_write_records_2.clone(),
                active_region_data: ActiveRegionData {
                    ranges: ranges_2.clone(),
                    idxs: idxs_2.clone(),
                    current_end: current_end_2,
                },
                pairing_inputs_public_input_key: PublicComponentKey {
                    start_idx: start_idx_2,
                },
                final_active_wire_idx: final_active_wire_idx_2,
                polynomials: polys_2,
                phantom: Default::default(),
                memory_records_shared: Default::default(),
            };

            let public_polys_1 = public_polys_1.clone();
            let shared_polys_1 = shared_polys_1.clone();
            let prover_crs = prover_crs.clone();

            move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                // Compute the first Oink proof
                let mut transcript = Transcript::<F, Poseidon2Sponge>::new();
                let oink = CoOink::<Driver, C, Poseidon2Sponge, LocalNetwork, MegaFlavour>::new(
                    &net,
                    &mut state,
                    ZeroKnowledge::No,
                );
                let oink_memory_1 = oink
                    .prove(&mut accumulator, &mut transcript, &prover_crs)
                    .unwrap();

                let mut accumulator_prover_memory =
                    DeciderProverMemory::<Driver, C>::from_memory_and_polynomials(
                        oink_memory_1,
                        structure_prover_polys(shared_polys_1, public_polys_1),
                    );

                accumulator_prover_memory.gate_challenges = vec![F::ZERO; CONST_PG_LOG_N];

                let prover = CoProtogalaxyProver::<Driver, C, Poseidon2Sponge, LocalNetwork>::new(
                    &net,
                    &mut state,
                    &prover_crs,
                );
                let (proof, target_sum) = prover
                    .prove(
                        &mut accumulator,
                        &mut accumulator_prover_memory,
                        vec![folded_key],
                    )
                    .unwrap();

                let alphas = accumulator_prover_memory.alphas.clone();
                let relation_parameters = accumulator_prover_memory
                    .relation_parameters
                    .get_params()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>();
                let gate_challenges = accumulator_prover_memory.gate_challenges.clone();
                let polynomials = accumulator_prover_memory.polys;
                let public_polynomials =
                    polynomials.public_iter().cloned().collect::<Vec<Vec<_>>>();
                let shared_polynomials = polynomials
                    .shared_iter()
                    .map(|shared| {
                        <Driver as NoirUltraHonkProver<C>>::open_many(shared, &net, &mut state)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                let polynomials = public_polynomials
                    .into_iter()
                    .chain(shared_polynomials.into_iter())
                    .collect::<Vec<_>>();
                (
                    proof,
                    target_sum,
                    alphas,
                    relation_parameters,
                    gate_challenges,
                    polynomials,
                )
            }
        }));
    }
    type OutData = (HonkProof<F>, F, Vec<F>, Vec<F>, Vec<F>, Vec<Vec<F>>);

    let results: Vec<OutData> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for (proof, target_sum, alphas, relation_parameters, gate_challenges, polynomials) in
        results.into_iter()
    {
        assert_eq!(proof.inner(), honk_proof);
        assert_eq!(target_sum, target_sum_result);
        assert_eq!(alphas, alphas_result);
        assert_eq!(relation_parameters, relation_parameters_result);
        assert_eq!(gate_challenges, gate_challenges_result);
        assert_eq!(polynomials, polynomials_folding_result);
    }
}
