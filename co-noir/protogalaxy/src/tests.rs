use std::vec;

use ark_bn254::Bn254;
use co_builder::{TranscriptFieldType, flavours::mega_flavour::MegaFlavour, prelude::Polynomial};
use mpc_core::gadgets::field_from_hex_string;
use ultrahonk::{
    decider::types::{ProverMemory, RelationParameters},
    prelude::Univariate,
};

use crate::protogalaxy_prover_internal::{
    compute_combiner_quotient, construct_perturbator_coefficients,
};
use crate::{
    protogalaxy_prover::{
        BATCHED_EXTENDED_LENGTH, EXTENDED_LENGTH, ExtendedRelationParameters, NUM,
    },
    protogalaxy_prover_internal::{
        compute_and_extend_alphas, compute_extended_relation_parameters,
    },
};

type F = TranscriptFieldType;
type C = Bn254;

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
            relation_parameters: RelationParameters {
                alphas: alphas_0
                    .clone()
                    .into_iter()
                    .map(field_from_hex_string)
                    .map(Result::unwrap)
                    .collect(),
                ..Default::default()
            },
            polys: Default::default(),
        },
        ProverMemory::<C, MegaFlavour> {
            relation_parameters: RelationParameters {
                alphas: alphas_1
                    .clone()
                    .into_iter()
                    .map(field_from_hex_string)
                    .map(Result::unwrap)
                    .collect(),
                ..Default::default()
            },
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

    let destructure_parameters = |[
        eta_1,
        eta_2,
        eta_3,
        beta,
        gamma,
        public_input_delta,
        lookup_grand_product_delta,
    ]: [F; 7]| {
        RelationParameters::<F, MegaFlavour> {
            eta_1,
            eta_2,
            eta_3,
            beta,
            gamma,
            public_input_delta,
            lookup_grand_product_delta,
            ..Default::default()
        }
    };

    let parameters_1 = destructure_parameters(
        parameters_1_values
            .map(field_from_hex_string)
            .map(Result::unwrap),
    );
    let parameters_2 = destructure_parameters(
        parameters_2_values
            .map(field_from_hex_string)
            .map(Result::unwrap),
    );

    let expected_relation_parameters = ExtendedRelationParameters::from_vec(
        &univariates
            .into_iter()
            .map(|evaluations| evaluations.map(field_from_hex_string).map(Result::unwrap))
            .map(|evaluations| Univariate { evaluations })
            .collect::<Vec<Univariate<F, EXTENDED_LENGTH>>>(),
    );

    let prover_memory = vec![
        ProverMemory::<C, MegaFlavour> {
            relation_parameters: parameters_1,
            polys: Default::default(),
        },
        ProverMemory::<C, MegaFlavour> {
            relation_parameters: parameters_2,
            polys: Default::default(),
        },
    ];

    assert_eq!(
        compute_extended_relation_parameters(&prover_memory),
        expected_relation_parameters
    );
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
