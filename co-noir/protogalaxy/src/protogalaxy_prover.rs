use std::marker::PhantomData;

use ark_ec::AdditiveGroup;

use ark_ff::{PrimeField, fields::Field};

use co_builder::{
    HonkProofResult, TranscriptFieldType,
    prelude::{HonkCurve, Polynomial, ProvingKey},
};

use itertools::Itertools;

use ultrahonk::{
    oink::prover::Oink,
    plain_prover_flavour::{PlainProverFlavour, UnivariateTrait},
    prelude::{
        GateSeparatorPolynomial, HonkProof, Transcript, TranscriptHasher, Univariate, ZeroKnowledge,
    },
};

use crate::protogalaxy_prover_internal::{
    compute_and_extend_alphas, compute_combiner_quotient, compute_perturbator,
};
use crate::protogalaxy_prover_internal::{compute_combiner, compute_extended_relation_parameters};

pub(crate) const CONST_PG_LOG_N: usize = 20;

// TODO CESAR: Move constants to the flavor files
pub(crate) const MAX_TOTAL_RELATION_LENGTH: usize = 11;
pub(crate) const NUM: usize = 2;
pub(crate) const EXTENDED_LENGTH: usize = (MAX_TOTAL_RELATION_LENGTH - 1) * (NUM - 1) + 1;
pub(crate) const BATCHED_EXTENDED_LENGTH: usize =
    (MAX_TOTAL_RELATION_LENGTH - 1 + NUM - 1) * (NUM - 1) + 1;

pub(crate) type OinkProverMemory<C, L> = ultrahonk::oink::types::ProverMemory<C, L>;
pub(crate) type DeciderProverMemory<C, L> = ultrahonk::decider::types::ProverMemory<C, L>;

#[derive(Default, PartialEq, Debug)]
pub struct ExtendedRelationParameters<F: PrimeField> {
    pub eta: Univariate<F, EXTENDED_LENGTH>,
    pub eta_two: Univariate<F, EXTENDED_LENGTH>,
    pub eta_three: Univariate<F, EXTENDED_LENGTH>,
    pub beta: Univariate<F, EXTENDED_LENGTH>,
    pub gamma: Univariate<F, EXTENDED_LENGTH>,
    pub public_input_delta: Univariate<F, EXTENDED_LENGTH>,
    pub lookup_grand_product_delta: Univariate<F, EXTENDED_LENGTH>,
}

impl<F: PrimeField> ExtendedRelationParameters<F> {
    pub fn get_params_as_mut(&mut self) -> Vec<&mut Univariate<F, EXTENDED_LENGTH>> {
        vec![
            &mut self.eta,
            &mut self.eta_two,
            &mut self.eta_three,
            &mut self.beta,
            &mut self.gamma,
            &mut self.public_input_delta,
            &mut self.lookup_grand_product_delta,
        ]
    }

    pub fn from_vec(univariates: &Vec<Univariate<F, EXTENDED_LENGTH>>) -> Self {
        assert_eq!(
            univariates.len(),
            7,
            "Expected 7 univariates for ExtendedRelationParameters, got {}",
            univariates.len()
        );
        ExtendedRelationParameters {
            eta: univariates[0].clone(),
            eta_two: univariates[1].clone(),
            eta_three: univariates[2].clone(),
            beta: univariates[3].clone(),
            gamma: univariates[4].clone(),
            public_input_delta: univariates[5].clone(),
            lookup_grand_product_delta: univariates[6].clone(),
        }
    }

    pub fn get_params(&self) -> Vec<&Univariate<F, EXTENDED_LENGTH>> {
        vec![
            &self.eta,
            &self.eta_two,
            &self.eta_three,
            &self.beta,
            &self.gamma,
            &self.public_input_delta,
            &self.lookup_grand_product_delta,
        ]
    }
}

pub struct DeciderProvingKey<C, L>
where
    C: HonkCurve<TranscriptFieldType>,
    L: PlainProverFlavour,
{
    pub is_accumulator: bool,
    pub target_sum: C::ScalarField,
    pub proving_key: ProvingKey<C, L>,
}

pub struct ProtogalaxyProver<C, H, L>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
{
    transcript: Transcript<TranscriptFieldType, H>,
    phantom_data: PhantomData<(C, L)>,
}

impl<C, H, L> ProtogalaxyProver<C, H, L>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour<Alpha<C::ScalarField> = C::ScalarField>,
{
    fn run_oink_prover_on_one_incomplete_key(
        &mut self,
        proving_key: &mut DeciderProvingKey<C, L>,
    ) -> HonkProofResult<OinkProverMemory<C, L>> {
        // TODO CESAR: ZeroKnowledge?
        let oink_prover = Oink::<C, H, L>::new(ZeroKnowledge::No);
        oink_prover.prove(&mut proving_key.proving_key, &mut self.transcript)
    }

    fn run_oink_prover_on_each_incomplete_key(
        &mut self,
        proving_keys: &mut Vec<DeciderProvingKey<C, L>>,
    ) -> HonkProofResult<Vec<OinkProverMemory<C, L>>> {
        let mut memory = Vec::with_capacity(proving_keys.len());
        let first_key = proving_keys.first_mut().unwrap();
        if !first_key.is_accumulator {
            memory.push(self.run_oink_prover_on_one_incomplete_key(first_key));
            first_key.target_sum = C::ScalarField::ZERO;
            // TODO CESAR: gate_challenges?
        }

        for key in proving_keys.iter_mut().skip(1) {
            memory.push(self.run_oink_prover_on_one_incomplete_key(key));
        }

        // unwrap all the results
        memory.into_iter().collect::<HonkProofResult<Vec<_>>>()
    }

    // TODO CESAR: This is wrong, handle the case where subrelations are linearly independent
    fn process_subrelation_evaluations(
        all_rel_evals: L::AllRelationEvaluations<C::ScalarField>,
        challenges: &Vec<C::ScalarField>,
        linearly_dependent_contribution: &C::ScalarField,
    ) -> C::ScalarField {
        todo!()
    }

    fn perturbator_round(
        &mut self,
        accumulator: &mut DeciderProvingKey<C, L>,
        accumulator_prover_memory: &DeciderProverMemory<C, L>,
    ) -> (Vec<C::ScalarField>, Polynomial<C::ScalarField>) {
        let delta = self.transcript.get_challenge::<C>("delta".to_owned());

        let deltas = std::iter::successors(Some(delta), |&x| Some(x * delta))
            .take(CONST_PG_LOG_N)
            .collect();

        // An honest prover with valid initial key computes that the perturbator is 0 in the first round
        let perturbator = if accumulator.is_accumulator {
            compute_perturbator(accumulator, &deltas, accumulator_prover_memory)
        } else {
            Polynomial::new(vec![C::ScalarField::ZERO; CONST_PG_LOG_N + 1])
        };

        // Prover doesn't send the constant coefficient of F because this is supposed to be equal to the target sum of
        // the accumulator which the folding verifier has from the previous iteration.
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1087): Verifier circuit for first IVC step is
        // different
        (1..=CONST_PG_LOG_N).for_each(|i| {
            self.transcript
                .send_fr_to_verifier::<C>(format!("perturbator_{i}"), perturbator.coefficients[i]);
        });

        (deltas, perturbator)
    }

    fn combiner_quotient_round(
        &mut self,
        prover_memory: &Vec<DeciderProverMemory<C, L>>,
        perturbator: Polynomial<C::ScalarField>,
        gate_challenges: &Vec<C::ScalarField>,
        deltas: Vec<C::ScalarField>,
    ) -> (
        Vec<C::ScalarField>,
        Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
        ExtendedRelationParameters<C::ScalarField>,
        C::ScalarField,
        Univariate<C::ScalarField, { BATCHED_EXTENDED_LENGTH - NUM }>,
    ) {
        let perturbator_challenge = self
            .transcript
            .get_challenge::<C>("perturbator_challenge".to_owned());

        let updated_gate_challenges = gate_challenges
            .iter()
            .zip(deltas.iter())
            .map(|(&g, &d)| g + perturbator_challenge * d)
            .collect_vec();

        let alphas = compute_and_extend_alphas(prover_memory);

        // TODO CESAR: Avoid the clone here
        let gate_separators =
            GateSeparatorPolynomial::new(updated_gate_challenges.clone(), CONST_PG_LOG_N);
        let relation_parameters = compute_extended_relation_parameters(prover_memory);

        let combiner = compute_combiner(
            prover_memory,
            &gate_separators,
            &relation_parameters,
            &alphas,
        );
        let perturbator_evaluation = perturbator.eval_poly(perturbator_challenge);
        let combiner_quotient = compute_combiner_quotient::<C>(&combiner, perturbator_evaluation);

        for (i, eval) in combiner_quotient.evaluations.iter().enumerate() {
            self.transcript
                .send_fr_to_verifier::<C>(format!("combiner_quotient_{i}"), *eval);
        }

        (
            updated_gate_challenges,
            alphas,
            relation_parameters,
            perturbator_evaluation,
            combiner_quotient,
        )
    }

    fn update_target_sum_and_fold(
        mut self,
        prover_memory: &mut Vec<DeciderProverMemory<C, L>>,
        combiner_quotient: Univariate<C::ScalarField, { BATCHED_EXTENDED_LENGTH - NUM }>,
        alphas: Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
        univariate_relation_parameters: ExtendedRelationParameters<C::ScalarField>,
        perturbator_evaluation: C::ScalarField,
    ) -> (HonkProof<TranscriptFieldType>, C::ScalarField) {
        let (accumulator_prover_memory, other_prover_memories) = prover_memory.split_at_mut(1);
        let accumulator_prover_memory = &mut accumulator_prover_memory[0];

        let combiner_challenge = self
            .transcript
            .get_challenge::<C>("combiner_quotient_challenge".to_owned());

        let proof = self.transcript.get_proof();

        // TODO CESAR: Reintroduce the accumulator flag
        // accumulator.is_accumulator = true;

        // TODO CESAR: This works for NUM = 2, but should be generalized
        let (vanishing_polynomial_at_challenge, lagranges) = (
            combiner_challenge * (combiner_challenge - C::ScalarField::ONE),
            vec![C::ScalarField::ONE - combiner_challenge, combiner_challenge],
        );

        let target_sum = perturbator_evaluation * lagranges[0]
            + vanishing_polynomial_at_challenge * combiner_quotient.evaluate(combiner_challenge);

        // TODO CESAR: Overflow stuff
        // TODO CESAR: Is the unshifted stuff correct?
        accumulator_prover_memory
            .polys
            .iter_unshifted_mut()
            .for_each(|poly| {
                poly.iter_mut()
                    .for_each(|coeff| *coeff = coeff.clone() * lagranges[0]);
            });

        for (memory, lagrange) in other_prover_memories.iter_mut().zip(lagranges.iter()) {
            for (key_poly, acc_poly) in memory
                .polys
                .iter_unshifted_mut()
                .zip(accumulator_prover_memory.polys.iter_unshifted_mut())
            {
                acc_poly
                    .iter_mut()
                    .zip(key_poly.iter_mut())
                    .for_each(|(acc_coeff, key_coeff)| *acc_coeff += key_coeff.clone() * lagrange);
            }
        }

        // Evaluate the combined batching  α_i univariate at challenge to obtain next α_i and send it to the
        // verifier, where i ∈ {0,...,NUM_SUBRELATIONS - 1}
        for (folded_alpha, key_alpha) in accumulator_prover_memory
            .relation_parameters
            .alphas
            .iter_mut()
            .zip(alphas.iter())
        {
            *folded_alpha = key_alpha.evaluate(combiner_challenge);
        }

        // Evaluate each relation parameter univariate at challenge to obtain the folded relation parameters.
        for (value, univariate) in accumulator_prover_memory
            .relation_parameters
            .get_params_as_mut()
            .into_iter()
            .zip(univariate_relation_parameters.get_params().iter())
        {
            *value = univariate.evaluate(combiner_challenge);
        }

        (proof, target_sum)
    }

    pub fn prove(
        mut self,
        accumulator: &mut DeciderProvingKey<C, L>,
        mut proving_keys: Vec<DeciderProvingKey<C, L>>,
    ) -> HonkProof<TranscriptFieldType> {
        let max_circuit_size = proving_keys
            .iter()
            .map(|pk| pk.proving_key.circuit_size)
            .max()
            .unwrap_or(0);
        // TODO CESAR: Increase Virtual size shenanigans

        // Run Oink prover
        // TODO CESAR: No unwrap here, handle the error properly
        let oink_memory = self
            .run_oink_prover_on_each_incomplete_key(&mut proving_keys)
            .unwrap();

        let mut prover_memory = oink_memory
            .into_iter()
            .zip(proving_keys.into_iter())
            .map(|(oink_memory, proving_key)| {
                DeciderProverMemory::from_memory_and_polynomials(
                    oink_memory,
                    proving_key.proving_key.polynomials,
                )
            })
            .collect::<Vec<DeciderProverMemory<C, L>>>();

        // Perturbator round
        let accumulator_prover_memory = &prover_memory[0];
        let (deltas, perturbator) = self.perturbator_round(accumulator, accumulator_prover_memory);

        // Combiner quotient round
        let (
            updated_gate_challenges,
            alphas,
            relation_parameters,
            perturbator_evaluation,
            combiner_quotient,
        ) = self.combiner_quotient_round(
            &prover_memory,
            perturbator,
            // TODO CESAR: This line assumes that the first key is the accumulator, check this
            &accumulator_prover_memory
                .relation_parameters
                .gate_challenges,
            deltas,
        );

        prover_memory[0].relation_parameters.gate_challenges = updated_gate_challenges;

        // update target sum and fold
        // TODO CESAR: handle target sum
        let (proof, target_sum) = self.update_target_sum_and_fold(
            &mut prover_memory,
            combiner_quotient,
            alphas,
            relation_parameters,
            perturbator_evaluation,
        );

        proof
    }
}
