use std::{array, io::Read, sync::Arc, vec};

use ark_bn254::Bn254;
use ark_ec::{bn::Bn, pairing::Pairing};
use ark_ff::AdditiveGroup;
use co_builder::{
    flavours::mega_flavour::{MegaFlavour, MegaPrecomputedEntities, MegaProverWitnessEntities},
    prelude::{ActiveRegionData, Polynomials, PublicComponentKey},
    prover_flavour::ProverFlavour,
};
use co_noir_common::{
    crs::{ProverCrs, parse::CrsParser},
    honk_proof::TranscriptFieldType,
    polynomials::polynomial::Polynomial,
    types::ZeroKnowledge,
};
use flate2::read::GzDecoder;
use mpc_core::gadgets::field_from_hex_string;
use serde::de::DeserializeOwned;
use ultrahonk::prelude::AllEntities;
use ultrahonk::{
    decider::types::{ProverMemory, RelationParameters},
    oink::oink_prover::Oink,
    prelude::{GateSeparatorPolynomial, Poseidon2Sponge, ProvingKey, Transcript, Univariate},
};

use crate::{
    protogalaxy_prover::{BATCHED_EXTENDED_LENGTH, MAX_TOTAL_RELATION_LENGTH, NUM_KEYS},
    protogalaxy_prover_internal::{
        compute_and_extend_alphas, compute_extended_relation_parameters,
    },
};
use crate::{
    protogalaxy_prover::{CONST_PG_LOG_N, DeciderProverMemory, ProtogalaxyProver},
    protogalaxy_prover_internal::{
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

    let mut memory_0 = ProverMemory::<C, MegaFlavour> {
        alphas: alphas_0.clone(),
        // Fields not used in this test
        gate_challenges: vec![],
        relation_parameters: RelationParameters::default(),
        polys: Default::default(),
    };

    let mut memory_1 = ProverMemory::<C, MegaFlavour> {
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

    let mut memory_1 = ProverMemory::<C, MegaFlavour> {
        relation_parameters: parameters_1,
        // Fields not used in this test
        polys: Default::default(),
        alphas: vec![],
        gate_challenges: vec![],
    };
    let mut memory_2 = ProverMemory::<C, MegaFlavour> {
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

    let combiner = Univariate::<F, BATCHED_EXTENDED_LENGTH> {
        evaluations: to_field!(combiner_values, 1).try_into().unwrap(),
    };

    let perturbator_evaluation: F = to_field!(perturbator_evaluation);

    let expected_combiner_quotient = Univariate::<F, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }> {
        evaluations: to_field!(expected_combiner_quotient, 1).try_into().unwrap(),
    };

    assert_eq!(
        compute_combiner_quotient::<C>(&combiner, perturbator_evaluation),
        expected_combiner_quotient
    );
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
    let full_honk_evaluations = to_field!(full_honk_evaluations_values, 1);
    let perturbator_coefficients = to_field!(perturbator_coefficients_values, 1);

    let coefficients = construct_perturbator_coefficients::<C>(
        &betas,
        &deltas,
        Polynomial {
            coefficients: full_honk_evaluations,
        },
    );

    assert_eq!(coefficients, perturbator_coefficients);
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
    let relation_parameters = to_field!(relation_parameters, 1);
    let polys = to_field!(polys, 2);
    let expected_full_honk_evaluations = to_field!(expected_full_honk_evaluations, 1);

    let relation_parameters = structure_parameters(relation_parameters.try_into().unwrap());

    let polys = AllEntities::<Vec<F>, MegaFlavour>::from_elements(polys);

    let prover_memory = ProverMemory::<C, MegaFlavour> {
        relation_parameters,
        polys,
        alphas,
        gate_challenges: vec![], // Not used in this test
    };

    assert_eq!(
        compute_row_evaluations::<C>(&prover_memory).coefficients,
        expected_full_honk_evaluations
    );
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
    let polys = to_field!(polys, 2);
    let deltas = to_field!(deltas, 1);
    let gate_challenges = to_field!(gate_challenges, 1);
    let perturbator_coefficients = to_field!(perturbator_coefficients, 1);

    let relation_parameters = structure_parameters(relation_parameters.try_into().unwrap());

    let polys = AllEntities::<Vec<F>, MegaFlavour>::from_elements(polys);

    let prover_memory = ProverMemory::<C, MegaFlavour> {
        relation_parameters,
        polys,
        alphas,
        gate_challenges,
    };

    let mut proving_key = ProvingKey::<C, MegaFlavour>::new(
        2usize.pow(circuit_log_size as u32),
        // Irrelevant values, as we are only using the circuit size in this test
        0, // Irrelevant,
        Arc::new(ProverCrs::<C> { monomials: vec![] }),
        0,
    );

    assert_eq!(
        compute_perturbator::<C>(&mut proving_key, &deltas, &prover_memory).coefficients,
        perturbator_coefficients
    );
}

#[test]
#[ignore = "Requires a large test file"]
fn test_compute_combiner() {
    let test_file = "unit/compute_combiner";
    type Out = (
        Vec<String>,
        Vec<Vec<String>>,
        Vec<Vec<String>>,
        (Vec<Vec<String>>, Vec<Vec<String>>),
        Vec<String>,
    );

    let (beta_products, alphas, relation_parameters, (polys_1, polys_2), combiner): Out =
        decompress_and_read_test_data(test_file);

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
    let polys_1 = to_field!(polys_1, 2);
    let polys_2 = to_field!(polys_2, 2);
    let combiner = to_field!(combiner, 1);

    let polys_1 = AllEntities::from_elements(polys_1);
    let polys_2 = AllEntities::from_elements(polys_2);

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

    let mut prover_memory_1 = ProverMemory::<C, MegaFlavour> {
        polys: polys_1,
        // Fields not used in this test
        alphas: Default::default(),
        gate_challenges: vec![],
        relation_parameters: Default::default(),
    };

    let mut prover_memory_2 = ProverMemory::<C, MegaFlavour> {
        polys: polys_2,
        // Fields not used in this test
        alphas: Default::default(),
        gate_challenges: vec![],
        relation_parameters: Default::default(),
    };

    let gate_separator_polynomial = GateSeparatorPolynomial::<F> {
        beta_products,
        // Fields not used in this test
        betas: Default::default(),
        partial_evaluation_result: Default::default(),
        current_element_idx: 0,
        periodicity: 0,
    };

    assert_eq!(
        compute_combiner(
            &vec![&mut prover_memory_1, &mut prover_memory_2],
            &gate_separator_polynomial,
            &relation_parameters,
            &alphas
        )
        .evaluations
        .to_vec(),
        combiner
    );
}

#[test]
fn test_protogalaxy_prover() {
    let test_file_acc = "e2e/accumulator";
    let test_file_folded = "e2e/folded_key";
    let test_file_folding_result = "e2e/folding_result";
    type SavedPK = (
        (
            u32,                                      // circuit_size
            u32,                                      // num_public_inputs
            u32,                                      // pub_inputs_offset
            u32,                                      // start_idx
            usize,                                    // final_active_wire_idx
            Vec<String>,                              // public_inputs
            Vec<Vec<String>>,                         // polys
            Vec<u32>,                                 // memory_read_records
            Vec<u32>,                                 // memory_write_records
            (Vec<(usize, usize)>, Vec<usize>, usize), // active_region_data
        ),
        Vec<String>, // honk_proof
    );
    type SavedResult = (
        (
            String,           // target_sum_result
            Vec<String>,      // gate_challenges_result
            Vec<String>,      // alphas_result
            Vec<String>,      // relation_parameters_result
            Vec<Vec<String>>, // polynomials_folding_result
        ),
        Vec<String>, // honk_proof
    );

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
    ): SavedResult = decompress_and_read_test_data(test_file_folding_result);

    let crs = CrsParser::<<Bn<ark_bn254::Config> as Pairing>::G1>::get_crs::<Bn254>(
        CRS_PATH_G1,
        CRS_PATH_G2,
        circuit_size_1 as usize,
        ZeroKnowledge::Yes,
    )
    .unwrap();

    let (prover_crs, _) = crs.split();

    let honk_proof = to_field!(honk_proof, 1);

    let alphas_result = to_field!(alphas_result, 1);
    let relation_parameters_result = to_field!(relation_parameters_result, 1);
    let gate_challenges_result = to_field!(gate_challenges_result, 1);
    let polynomials_folding_result = to_field!(polynomials_folding_result, 2);

    let target_sum_result: F = to_field!(target_sum_result);

    let public_inputs_1 = to_field!(public_inputs_1, 1);
    let public_inputs_2 = to_field!(public_inputs_2, 1);

    let polys_1 = to_field!(polys_1, 2)
        .into_iter()
        .map(|coefficients| Polynomial { coefficients })
        .collect::<Vec<_>>();

    let polys_2 = to_field!(polys_2, 2)
        .into_iter()
        .map(|coefficients| Polynomial { coefficients })
        .collect::<Vec<_>>();

    let structure_prover_polys = |polys: Vec<Polynomial<F>>| {
        let (precomputed, other) = polys.split_at(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
        let (witness, _) = other.split_at(MegaFlavour::WITNESS_ENTITIES_SIZE);
        // Remove z_perm and lookup_inverses from witness
        let mut prover_witness = witness[..4].to_vec();
        prover_witness.extend_from_slice(&witness[6..]);

        Polynomials::<F, MegaFlavour> {
            witness: MegaProverWitnessEntities {
                elements: array::from_fn(|i| prover_witness[i].clone()),
            },
            precomputed: MegaPrecomputedEntities {
                elements: array::from_fn(|i| precomputed[i].clone()),
            },
        }
    };

    let mut accumulator = ProvingKey::<C, MegaFlavour> {
        crs: Arc::new(prover_crs.clone()),
        circuit_size: circuit_size_1,
        num_public_inputs: num_public_inputs_1,
        pub_inputs_offset: pub_inputs_offset_1,
        public_inputs: public_inputs_1,
        memory_read_records: memory_read_records_1,
        memory_write_records: memory_write_records_1,
        active_region_data: ActiveRegionData {
            ranges: ranges_1,
            idxs: idxs_1,
            current_end: current_end_1,
        },
        pairing_inputs_public_input_key: PublicComponentKey {
            start_idx: start_idx_1,
        },
        final_active_wire_idx: final_active_wire_idx_1,
        polynomials: structure_prover_polys(polys_1.clone()),
    };

    let folded_key = ProvingKey::<C, MegaFlavour> {
        crs: Arc::new(prover_crs),
        circuit_size: circuit_size_2,
        num_public_inputs: num_public_inputs_2,
        pub_inputs_offset: pub_inputs_offset_2,
        public_inputs: public_inputs_2,
        memory_read_records: memory_read_records_2,
        memory_write_records: memory_write_records_2,
        active_region_data: ActiveRegionData {
            ranges: ranges_2,
            idxs: idxs_2,
            current_end: current_end_2,
        },
        pairing_inputs_public_input_key: PublicComponentKey {
            start_idx: start_idx_2,
        },
        final_active_wire_idx: final_active_wire_idx_2,
        polynomials: structure_prover_polys(polys_2),
    };

    let prover = ProtogalaxyProver::<C, Poseidon2Sponge>::new();

    // Compute the first Oink proof
    let mut transcript = Transcript::<F, Poseidon2Sponge>::new();
    let oink = Oink::<C, Poseidon2Sponge, MegaFlavour>::new(ZeroKnowledge::No);
    let oink_memory_1 = oink.prove(&mut accumulator, &mut transcript).unwrap();

    let mut accumulator_prover_memory = DeciderProverMemory::<C>::from_memory_and_polynomials(
        oink_memory_1,
        structure_prover_polys(polys_1),
    );

    accumulator_prover_memory.gate_challenges = vec![F::ZERO; CONST_PG_LOG_N];

    let (proof, target_sum) = prover
        .prove(
            &mut accumulator,
            &mut accumulator_prover_memory,
            vec![folded_key],
        )
        .unwrap();

    assert_eq!(proof.inner(), honk_proof);

    assert_eq!(accumulator_prover_memory.alphas, alphas_result);

    assert_eq!(
        accumulator_prover_memory
            .relation_parameters
            .get_params()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>(),
        relation_parameters_result
    );

    assert_eq!(
        accumulator_prover_memory.gate_challenges,
        gate_challenges_result
    );

    assert_eq!(target_sum, target_sum_result);

    itertools::assert_equal(
        accumulator_prover_memory.polys.into_iterator(),
        polynomials_folding_result,
    );
}
