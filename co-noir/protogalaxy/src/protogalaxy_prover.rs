use std::{marker::PhantomData, vec};

use ark_ec::AdditiveGroup;

use ark_ff::fields::Field;

use co_builder::{
    HonkProofResult, TranscriptFieldType,
    prelude::{HonkCurve, Polynomial, ProvingKey},
};

use itertools::{Itertools, izip};

use common::HonkProof;
use ultrahonk::decider::types::RelationParameters;
use ultrahonk::{
    oink::oink_prover::Oink,
    plain_prover_flavour::{PlainProverFlavour, UnivariateTrait},
    prelude::{GateSeparatorPolynomial, Transcript, TranscriptHasher, Univariate, ZeroKnowledge},
};

use crate::protogalaxy_prover_internal::{
    compute_and_extend_alphas, compute_combiner_quotient, compute_perturbator,
};
use crate::protogalaxy_prover_internal::{compute_combiner, compute_extended_relation_parameters};

pub(crate) const CONST_PG_LOG_N: usize = 20;
pub(crate) const MAX_TOTAL_RELATION_LENGTH: usize = 11;

// Mega Protogalaxy prover only supports 2 keys
pub(crate) const NUM_KEYS: usize = 2;

pub(crate) const BATCHED_EXTENDED_LENGTH: usize =
    (MAX_TOTAL_RELATION_LENGTH - 1 + NUM_KEYS - 1) * (NUM_KEYS - 1) + 1;

pub(crate) type OinkProverMemory<C, L> = ultrahonk::oink::types::ProverMemory<C, L>;
pub(crate) type DeciderProverMemory<C, L> = ultrahonk::decider::types::ProverMemory<C, L>;

pub type ExtendedRelationParameters<F> = RelationParameters<Univariate<F, BATCHED_EXTENDED_LENGTH>>;

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
    pub fn new() -> Self {
        Self {
            transcript: Transcript::default(),
            phantom_data: PhantomData,
        }
    }
    fn run_oink_prover_on_one_incomplete_key(
        &mut self,
        proving_key: &mut ProvingKey<C, L>,
    ) -> HonkProofResult<OinkProverMemory<C, L>> {
        let oink_prover = Oink::<C, H, L>::new(ZeroKnowledge::No);
        oink_prover.prove(proving_key, &mut self.transcript)
    }

    pub(crate) fn run_oink_prover_on_each_incomplete_key(
        &mut self,
        proving_keys: &mut Vec<ProvingKey<C, L>>,
    ) -> HonkProofResult<Vec<OinkProverMemory<C, L>>> {
        // Asummes accumulator has not been folded
        let mut memory = Vec::with_capacity(proving_keys.len());

        for key in proving_keys.iter_mut() {
            memory.push(self.run_oink_prover_on_one_incomplete_key(key));
        }

        // unwrap all the results
        memory.into_iter().collect::<HonkProofResult<Vec<_>>>()
    }

    fn perturbator_round(
        &mut self,
        accumulator: &mut ProvingKey<C, L>,
        accumulator_prover_memory: &DeciderProverMemory<C, L>,
    ) -> (Vec<C::ScalarField>, Polynomial<C::ScalarField>) {
        let delta = self.transcript.get_challenge::<C>("delta".to_owned());

        let deltas = std::iter::successors(Some(delta), |&x| Some(x.square()))
            .take(CONST_PG_LOG_N)
            .collect();

        // An honest prover with valid initial key computes that the perturbator is 0 in the first round
        // TODO CESAR: Fix
        let perturbator = if true {
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
        prover_memory: &Vec<&mut DeciderProverMemory<C, L>>,
        perturbator: Polynomial<C::ScalarField>,
        deltas: Vec<C::ScalarField>,
    ) -> (
        Vec<C::ScalarField>,
        Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
        ExtendedRelationParameters<C::ScalarField>,
        C::ScalarField,
        Univariate<C::ScalarField, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }>,
    ) {
        let perturbator_challenge = self
            .transcript
            .get_challenge::<C>("perturbator_challenge".to_owned());

        let updated_gate_challenges = prover_memory[0]
            .gate_challenges
            .iter()
            .zip(deltas.iter())
            .map(|(&g, &d)| g + perturbator_challenge * d)
            .collect_vec();

        let alphas = compute_and_extend_alphas(prover_memory);

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

    /**
     * @brief Given the challenge \gamma, compute Z(\gamma) and {L_0(\gamma),L_1(\gamma)}
     */
    fn update_target_sum_and_fold(
        mut self,
        prover_memory: &mut Vec<&mut DeciderProverMemory<C, L>>,
        combiner_quotient: Univariate<C::ScalarField, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }>,
        alphas: Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
        univariate_relation_parameters: ExtendedRelationParameters<C::ScalarField>,
        perturbator_evaluation: C::ScalarField,
    ) -> HonkProofResult<(HonkProof<TranscriptFieldType>, C::ScalarField)> {
        let (accumulator_prover_memory, next_prover_memory) = prover_memory.split_at_mut(1);
        let accumulator_prover_memory = &mut accumulator_prover_memory[0];
        let next_prover_memory = &next_prover_memory[0];

        let combiner_challenge = self
            .transcript
            .get_challenge::<C>("combiner_quotient_challenge".to_owned());

        let proof = self.transcript.get_proof();

        let (vanishing_polynomial_at_challenge, lagranges) = (
            combiner_challenge * (combiner_challenge - C::ScalarField::ONE),
            vec![C::ScalarField::ONE - combiner_challenge, combiner_challenge],
        );

        let target_sum = perturbator_evaluation * lagranges[0]
            + vanishing_polynomial_at_challenge * combiner_quotient.evaluate(combiner_challenge);

        // TODO CESAR: Overflow stuff
        accumulator_prover_memory.polys.iter_mut().for_each(|poly| {
            poly.iter_mut()
                .for_each(|coeff| *coeff = coeff.clone() * lagranges[0]);
        });

        for (key_poly, acc_poly) in next_prover_memory
            .polys
            .iter()
            .zip(accumulator_prover_memory.polys.iter_mut())
        {
            acc_poly
                .iter_mut()
                .zip(key_poly.iter())
                .for_each(|(acc_coeff, key_coeff)| *acc_coeff += key_coeff.clone() * lagranges[1]);
        }

        // Evaluate the combined batching  α_i univariate at challenge to obtain next α_i and send it to the
        // verifier, where i ∈ {0,...,NUM_SUBRELATIONS - 1}
        for (folded_alpha, key_alpha) in accumulator_prover_memory
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

        HonkProofResult::Ok((proof, target_sum))
    }

    pub fn prove(
        mut self,
        accumulator: &mut ProvingKey<C, L>,
        accumulator_prover_memory: &mut DeciderProverMemory<C, L>,
        mut next_proving_keys: Vec<ProvingKey<C, L>>,
    ) -> HonkProofResult<(HonkProof<TranscriptFieldType>, C::ScalarField)> {
        let max_circuit_size = next_proving_keys
            .iter()
            .map(|pk| pk.circuit_size)
            .chain(std::iter::once(accumulator.circuit_size))
            .max()
            .unwrap_or(0);

        next_proving_keys.iter_mut().for_each(|pk| {
            pk.polynomials
                .increase_polynomial_size(max_circuit_size.try_into().unwrap())
        });

        // Run Oink prover
        let oink_memories = self.run_oink_prover_on_each_incomplete_key(&mut next_proving_keys)?;

        let mut next_prover_memories =
            izip!(oink_memories.into_iter(), next_proving_keys.into_iter())
                .map(|(oink_memory, next_proving_key)| {
                    DeciderProverMemory::from_memory_and_polynomials(
                        oink_memory,
                        next_proving_key.polynomials,
                    )
                })
                .collect::<Vec<_>>();

        // Perturbator round
        let (deltas, perturbator) = self.perturbator_round(accumulator, &accumulator_prover_memory);

        let mut prover_memory = std::iter::once(accumulator_prover_memory)
            .chain(next_prover_memories.iter_mut())
            .collect::<Vec<_>>();

        // Combiner quotient round
        let (
            updated_gate_challenges,
            alphas,
            relation_parameters,
            perturbator_evaluation,
            combiner_quotient,
        ) = self.combiner_quotient_round(&prover_memory, perturbator, deltas);

        prover_memory[0].gate_challenges = updated_gate_challenges;

        // update target sum and fold
        self.update_target_sum_and_fold(
            &mut prover_memory,
            combiner_quotient,
            alphas,
            relation_parameters,
            perturbator_evaluation,
        )
    }
}
