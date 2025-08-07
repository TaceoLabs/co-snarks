use core::panic;
use std::{array, ops::RangeBounds, sync::Arc, vec};

use ark_bn254::Bn254;
use ark_ff::{AdditiveGroup, Field};
use ark_poly::polynomial;
use co_builder::{flavours::mega_flavour::{MegaFlavour, MegaPrecomputedEntities, MegaProverWitnessEntities}, prelude::{ActiveRegionData, CrsParser, Polynomial, Polynomials, ProverCrs, PublicComponentKey}, prover_flavour::ProverFlavour, TranscriptFieldType};
use itertools::concat;
use mpc_core::{gadgets::{field_from_hex_string, poseidon2::Poseidon2}, protocols::rep3::poly};
use tracing::instrument::WithSubscriber;
use ultrahonk::{
    decider::types::{ProverMemory, RelationParameters}, oink::prover::Oink, prelude::{GateSeparatorPolynomial, Poseidon2Sponge, ProvingKey, Transcript, TranscriptHasher, Univariate, ZeroKnowledge}
};
use ultrahonk::prelude::AllEntities;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;

use crate::{protogalaxy_prover::{DeciderProverMemory, ProtogalaxyProver, CONST_PG_LOG_N}, protogalaxy_prover_internal::{
    compute_combiner, compute_combiner_quotient, compute_perturbator, compute_row_evaluations, construct_perturbator_coefficients
}};
use crate::{
    protogalaxy_prover::{
        BATCHED_EXTENDED_LENGTH, EXTENDED_LENGTH, ExtendedRelationParameters, NUM,
    },
    protogalaxy_prover_internal::{
        compute_and_extend_alphas, compute_extended_relation_parameters,
    },
};
const CRS_PATH_G1: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../co-builder/src/crs/bn254_g1.dat"
);
const CRS_PATH_G2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../co-builder/src/crs/bn254_g2.dat"
);
type F = TranscriptFieldType;
type C = Bn254;


fn structure_parameters<T: PartialEq>(
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
    }
}
#[test]
fn test_compute_and_extend_alphas() {
    let test_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/compute_and_extend_alphas",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file).unwrap();
    let (alphas_0, alphas_1, expected_alphas): (
        Vec<&str>,
        Vec<&str>,
        Vec<[&str; BATCHED_EXTENDED_LENGTH]>,
    ) = serde_json::from_str(&content).unwrap();

    let prover_memory = vec![
        ProverMemory::<C, MegaFlavour> {
            alphas: alphas_0
                    .clone()
                    .into_iter()
                    .map(field_from_hex_string)
                    .map(Result::unwrap)
                    .collect(),
            // Fields not used in this test
            gate_challenges: vec![], 
            relation_parameters: RelationParameters::default(),
            polys: Default::default(),
        },
        ProverMemory::<C, MegaFlavour> {
                alphas: alphas_1
                    .clone()
                    .into_iter()
                    .map(field_from_hex_string)
                    .map(Result::unwrap)
                    .collect(),
            // Fields not used in this test
            gate_challenges: vec![], 
            relation_parameters: RelationParameters::default(),
            polys: Default::default(),
        },
    ];

    assert_eq!(
        compute_and_extend_alphas(&prover_memory),
        expected_alphas
            .into_iter()
            .map(|alphas| alphas.map(field_from_hex_string).map(Result::unwrap))
            .map(|alphas| Univariate {
                evaluations: alphas
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_compute_extended_relation_parameters() {
    let test_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/compute_extended_relation_parameters",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file).unwrap();
    let (parameters_1_values, parameters_2_values, univariates): (
        [&str; 7],
        [&str; 7],
        Vec<[&str; EXTENDED_LENGTH]>,
    ) = serde_json::from_str(&content).unwrap();

    let parameters_1 = structure_parameters(
        parameters_1_values
            .map(field_from_hex_string)
            .map(Result::unwrap),
    );
    let parameters_2 = structure_parameters(
        parameters_2_values
            .map(field_from_hex_string)
            .map(Result::unwrap),
    );

    let expected_relation_parameters = structure_parameters(
        univariates
            .into_iter()
            .map(|evaluations| evaluations.map(field_from_hex_string).map(Result::unwrap))
            .map(|evaluations| Univariate { evaluations })
            .collect::<Vec<Univariate<F, EXTENDED_LENGTH>>>()
            .try_into()
            .unwrap(),
    );

    let prover_memory = vec![
        ProverMemory::<C, MegaFlavour> {
            relation_parameters: parameters_1,
            // Fields not used in this test
            polys: Default::default(),
            alphas: vec![], 
            gate_challenges: vec![],
        },
        ProverMemory::<C, MegaFlavour> {
            relation_parameters: parameters_2,
            // Fields not used in this test
            polys: Default::default(),
            alphas: vec![],
            gate_challenges: vec![],
        },
    ];

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
    let test_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/compute_combiner_quotient",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file).unwrap();
    let (combiner_values, perturbator_evaluation, expected_combiner_quotient): (
        [&str; BATCHED_EXTENDED_LENGTH],
        &str,
        [&str; BATCHED_EXTENDED_LENGTH - NUM],
    ) = serde_json::from_str(&content).unwrap();

    let combiner = Univariate::<F, BATCHED_EXTENDED_LENGTH> {
        evaluations: combiner_values
            .map(field_from_hex_string)
            .map(Result::unwrap),
    };
    let perturbator_evaluation: F = field_from_hex_string(perturbator_evaluation).unwrap();

    let expected_combiner_quotient = Univariate::<F, { BATCHED_EXTENDED_LENGTH - NUM }> {
        evaluations: expected_combiner_quotient
            .map(field_from_hex_string)
            .map(Result::unwrap),
    };

    assert_eq!(
        compute_combiner_quotient::<C>(&combiner, perturbator_evaluation),
        expected_combiner_quotient
    );
}

// TODO CESAR: Full Honk evaluation is a huge vector, maybe it makes sense to use a lfs
#[test]
fn test_construct_perturbator_coefficients() {
    let test_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/construct_perturbator_coefficients",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file).unwrap();
    let (
        betas_values,
        deltas_values,
        perturbator_coefficients_values,
        full_honk_evaluations_values,
    ): (Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>) = serde_json::from_str(&content).unwrap();

    let betas = betas_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let deltas = deltas_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let full_honk_evaluations = full_honk_evaluations_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let perturbator_coefficients = perturbator_coefficients_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();

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
// TODO CESAR: AllEntities is a huge struct, rethink this test
fn test_compute_row_evaluations() {
    let test_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/compute_row_evaluations",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file).unwrap();
    let (
        alphas_values,
        relation_parameters_values,
        polys_values,
        full_honk_evaluations_values,
    ): (Vec<&str>, Vec<&str>, Vec<Vec<&str>>, Vec<&str>) = serde_json::from_str(&content).unwrap();

    let alphas = alphas_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let relation_parameters_iter = relation_parameters_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let polys_iter = polys_values.clone()
        .into_iter()
        .map(|p| p.into_iter().map(field_from_hex_string).map(Result::unwrap).collect::<Vec<F>>())
        .collect::<Vec<Vec<F>>>();
    let expected_full_honk_evaluations = full_honk_evaluations_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();

    let (precomputed_entities, other) = polys_iter.split_at(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
    let (witness_entities, shifted_witness_entities) = other.split_at(MegaFlavour::WITNESS_ENTITIES_SIZE);

    let [eta_1, eta_2, eta_3, beta, gamma, public_input_delta, lookup_grand_product_delta] =
        relation_parameters_iter.as_slice().try_into().unwrap();
    let relation_parameters = RelationParameters {
        eta_1,
        eta_2,
        eta_3,
        beta,
        gamma,
        public_input_delta,
        lookup_grand_product_delta,
    };

    let mut polys = AllEntities::<Vec<F>, MegaFlavour>::default();
    polys.witness = <MegaFlavour as ProverFlavour>::WitnessEntities::from_elements(
        &witness_entities.to_vec()
    );
    polys.precomputed = <MegaFlavour as ProverFlavour>::PrecomputedEntities::from_elements(
        &precomputed_entities.to_vec()
    );
    polys.shifted_witness = <MegaFlavour as ProverFlavour>::ShiftedWitnessEntities::from_elements(
        &shifted_witness_entities.to_vec()
    );

    let prover_memory = ProverMemory::<C, MegaFlavour> {
        relation_parameters,
        polys,
        alphas,
        gate_challenges: vec![], // Not used in this test
    };

    assert_eq!(
        compute_row_evaluations::<C, MegaFlavour>(&prover_memory).coefficients,
        expected_full_honk_evaluations
    );
}

#[test]
fn test_compute_perturbator() {
    let test_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/compute_row_evaluations",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file).unwrap();
    let (
        alphas_values,
        relation_parameters_values,
        polys_values,
        _
    ): (Vec<&str>, Vec<&str>, Vec<Vec<&str>>, Vec<&str>) = serde_json::from_str(&content).unwrap();

    let test_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/compute_perturbator",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file).unwrap();
    let (
        deltas,
        gate_challenges_values,
        circuit_log_size,
        perturbator_coefficients_values
    ): (Vec<&str>, Vec<&str>, usize, Vec<&str>) = serde_json::from_str(&content).unwrap();

    let alphas = alphas_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let relation_parameters_iter = relation_parameters_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let polys_iter = polys_values.clone()
        .into_iter()
        .map(|p| p.into_iter().map(field_from_hex_string).map(Result::unwrap).collect::<Vec<F>>())
        .collect::<Vec<Vec<F>>>();
    let deltas = deltas
        .into_iter()
        .map(field_from_hex_string)     
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let gate_challenges = gate_challenges_values
        .into_iter()
        .map(field_from_hex_string) 
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let perturbator_coefficients = perturbator_coefficients_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();   

    let (precomputed_entities, other) = polys_iter.split_at(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
    let (witness_entities, shifted_witness_entities) = other.split_at(MegaFlavour::WITNESS_ENTITIES_SIZE);

    let [eta_1, eta_2, eta_3, beta, gamma, public_input_delta, lookup_grand_product_delta] =
        relation_parameters_iter.as_slice().try_into().unwrap();
    let relation_parameters = RelationParameters {
        eta_1,
        eta_2,
        eta_3,
        beta,
        gamma,
        public_input_delta,
        lookup_grand_product_delta,
    };

    let mut polys = AllEntities::<Vec<F>, MegaFlavour>::default();
    polys.witness = <MegaFlavour as ProverFlavour>::WitnessEntities::from_elements(
        &witness_entities.to_vec()
    );
    polys.precomputed = <MegaFlavour as ProverFlavour>::PrecomputedEntities::from_elements(
        &precomputed_entities.to_vec()
    );
    polys.shifted_witness = <MegaFlavour as ProverFlavour>::ShiftedWitnessEntities::from_elements(
        &shifted_witness_entities.to_vec()
    );

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
        Arc::new(ProverCrs::<C>{
            monomials: vec![]
        }),
        0,
    );

    assert_eq!(
        compute_perturbator::<C, MegaFlavour>(&mut proving_key, &deltas, &prover_memory).coefficients,
        perturbator_coefficients
    );
}

#[test]
fn test_compute_combiner() {
    let test_file = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/compute_combiner",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file).unwrap();
    let (
        beta_products_values,
        alphas_values,
        relation_parameters_values,
        (polys_values_1, polys_values_2),
        combiner_values
    ): (Vec<&str>, Vec<Vec<&str>>, Vec<Vec<&str>>, (Vec<Vec<&str>>, Vec<Vec<&str>>), Vec<&str>) = serde_json::from_str(&content).unwrap();

    let alphas = alphas_values
        .into_iter()
        .map(|a| a.into_iter().map(field_from_hex_string).map(Result::unwrap).collect::<Vec<F>>())
        .map(|a| Univariate {
            evaluations: a.try_into().unwrap()
        })
        .collect::<Vec<Univariate<F, BATCHED_EXTENDED_LENGTH>>>();
    let beta_products = beta_products_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();
    let relation_parameters_iter = relation_parameters_values
        .into_iter()
        .map(|p| {
            let mut new_v = p.into_iter().map(field_from_hex_string).map(Result::unwrap).collect::<Vec<F>>();
            new_v.push(F::ZERO);
            new_v
        })
        .collect::<Vec<Vec<F>>>();
    let polys_iter_1 = polys_values_1
        .into_iter()        
        .map(|p| p.into_iter().map(field_from_hex_string).map(Result::unwrap).collect::<Vec<F>>())
        .collect::<Vec<Vec<F>>>();
    let polys_iter_2 = polys_values_2
        .into_iter()        
        .map(|p| p.into_iter().map(field_from_hex_string).map(Result::unwrap).collect::<Vec<F>>())
        .collect::<Vec<Vec<F>>>();
    let combiner = combiner_values
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();

    let structure_polys = |polys: Vec<Vec<F>>| {
        let (precomputed_entities, other) = polys.split_at(MegaFlavour::PRECOMPUTED_ENTITIES_SIZE);
        let (witness_entities, shifted_witness_entities) = other.split_at(MegaFlavour::WITNESS_ENTITIES_SIZE);

        let mut polys = AllEntities::<Vec<F>, MegaFlavour>::default();
        polys.witness = <MegaFlavour as ProverFlavour>::WitnessEntities::from_elements(
            &witness_entities.to_vec()
        );
        polys.precomputed = <MegaFlavour as ProverFlavour>::PrecomputedEntities::from_elements(
            &precomputed_entities.to_vec()
        );
        polys.shifted_witness = <MegaFlavour as ProverFlavour>::ShiftedWitnessEntities::from_elements(
            &shifted_witness_entities.to_vec()
        );
        polys
    };

    let polys_1 = structure_polys(polys_iter_1);
    let polys_2 = structure_polys(polys_iter_2);


    let relation_parameters = structure_parameters(relation_parameters_iter.into_iter().map(|evaluations| Univariate {
        evaluations: evaluations.try_into().unwrap()
    }).collect::<Vec<Univariate<F, BATCHED_EXTENDED_LENGTH>>>().try_into().unwrap());

    let prover_memory_1 = ProverMemory::<C, MegaFlavour> {
        polys: polys_1,
        // Fields not used in this test
        alphas: Default::default(),
        gate_challenges: vec![],
        relation_parameters: Default::default(),
    };

    let prover_memory_2 = ProverMemory::<C, MegaFlavour> {
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
        compute_combiner(&vec![prover_memory_1, prover_memory_2], &gate_separator_polynomial, &relation_parameters, &alphas).evaluations.to_vec(),
        combiner
    );
}

#[test]
fn test_protogalaxy_prover() {
    let test_file_acc = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/run_oink_prover/accumulator",
        env!("CARGO_MANIFEST_DIR")
    );

    let test_file_folded = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/run_oink_prover/folded_key",
        env!("CARGO_MANIFEST_DIR")
    );

    let test_file_folding_result = format!(
        "{}/../../test_vectors/noir/protogalaxy_prover/run_oink_prover/folding_result",
        env!("CARGO_MANIFEST_DIR")
    );

    let content = std::fs::read_to_string(&test_file_acc).unwrap();
    let ((circuit_size_1, num_public_inputs_1, pub_inputs_offset_1, start_idx_1, final_active_wire_idx_1, public_inputs_1, polynomials_1_str, memory_read_records_1, memory_write_records_1, (ranges_1, idxs_1, current_end_1)), oink_proof_1): 
        ((u32, u32, u32, u32, usize, Vec<&str>, Vec<Vec<&str>>, Vec<u32>, Vec<u32>, (Vec<(usize, usize)>, Vec<usize>, usize)), Vec<&str>)
    = serde_json::from_str(&content).unwrap();

    let content = std::fs::read_to_string(&test_file_folded).unwrap();
    let ((circuit_size_2, num_public_inputs_2, pub_inputs_offset_2, start_idx_2, final_active_wire_idx_2, public_inputs_2, polynomials_2_str, memory_read_records_2, memory_write_records_2, (ranges_2, idxs_2, current_end_2)), oink_proof_2):
        ((u32, u32, u32, u32, usize, Vec<&str>, Vec<Vec<&str>>, Vec<u32>, Vec<u32>, (Vec<(usize, usize)>, Vec<usize>, usize)), Vec<&str>)
     = serde_json::from_str(&content).unwrap();

    let content = std::fs::read_to_string(&test_file_folding_result).unwrap();
    let ((target_sum_result, gate_challenges_result, alphas_result, relation_parameters_result, polynomials_folding_result_str), honk_proof): ((&str, Vec<&str>, Vec<&str>, Vec<&str>, Vec<Vec<&str>>), Vec<&str>) = serde_json::from_str(&content).unwrap();


    println!("circuit_size_1: {}, circuit_size_2: {}", circuit_size_1, circuit_size_2);
    let crs = CrsParser::<C>::get_crs(
        CRS_PATH_G1,
        CRS_PATH_G2,
        circuit_size_1 as usize,
        ZeroKnowledge::Yes,
    ).unwrap();

    let (prover_crs, _) = crs.split();

    let honk_proof = honk_proof
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();

    let alphas_result = alphas_result
        .into_iter()
        .map(field_from_hex_string)
        .map(Result::unwrap)
        .collect::<Vec<F>>();

    let relation_parameters_result = relation_parameters_result
        .into_iter()
        .map(field_from_hex_string)         
        .map(Result::unwrap)
        .collect::<Vec<F>>();

    let target_sum_result: F = field_from_hex_string(target_sum_result).unwrap();

    let polys_1 = polynomials_1_str
        .into_iter()
        .map(|p| p.into_iter().map(field_from_hex_string).map(Result::unwrap).collect::<Vec<F>>())
        .map(|coefficients| Polynomial { coefficients })
        .collect::<Vec<_>>();

    let polys_2 = polynomials_2_str
        .into_iter()
        .map(|p| p.into_iter().map(field_from_hex_string).map(Result::      unwrap).collect::<Vec<F>>())
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
                elements: array::from_fn(|i| prover_witness[i].clone())
            },
            precomputed: MegaPrecomputedEntities {
                elements: array::from_fn(|i| precomputed[i].clone())
            },
        }
    };

    let mut accumulator = ProvingKey::<C, MegaFlavour> {
        crs: Arc::new(prover_crs.clone()),
        circuit_size: circuit_size_1,
        num_public_inputs: num_public_inputs_1,
        pub_inputs_offset: pub_inputs_offset_1,
        public_inputs: public_inputs_1
            .into_iter()
            .map(field_from_hex_string)
            .map(Result::unwrap)
            .collect::<Vec<F>>(),
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
        public_inputs: public_inputs_2
            .into_iter()
            .map(field_from_hex_string)
            .map(Result::unwrap)
            .collect::<Vec<F>>(),
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

    let prover = ProtogalaxyProver::<C, Poseidon2Sponge, MegaFlavour>::with_empty_transcript();

    // Compute the first Oink proof
    let mut transcript = Transcript::<F, Poseidon2Sponge>::new();
    let oink = Oink::<C, Poseidon2Sponge, MegaFlavour>::new(ZeroKnowledge::No);
    let oink_memory_1 = oink
        .prove(&mut accumulator, &mut transcript).unwrap();

    let mut accumulator_prover_memory = DeciderProverMemory::<C, MegaFlavour>::from_memory_and_polynomials(oink_memory_1, 
        structure_prover_polys(polys_1)
    );

    accumulator_prover_memory.gate_challenges = vec![F::ZERO; CONST_PG_LOG_N];

    assert_eq!(
        prover.prove(&mut accumulator, accumulator_prover_memory, folded_key).inner(),
        honk_proof
    );

    // assert_eq!(
    //     accumulator_prover_memory.alphas,
    //     alphas_result
    // );
}