use std::vec;

use ark_ff::fields::Field;

use co_builder::{
    HonkProofResult, TranscriptFieldType,
    flavours::mega_flavour::MegaFlavour,
    prelude::{HonkCurve, Polynomial, ProverCrs},
};

use co_ultrahonk::prelude::ProvingKey;
use itertools::{Itertools, izip};

use co_ultrahonk::co_decider::types::RelationParameters;
use co_ultrahonk::co_oink::co_oink_prover::CoOink;
use common::transcript::Transcript;
use common::{
    mpc::NoirUltraHonkProver, shared_polynomial::SharedPolynomial, transcript::TranscriptHasher,
};
use mpc_net::Network;
use ultrahonk::{
    plain_prover_flavour::UnivariateTrait,
    prelude::{GateSeparatorPolynomial, HonkProof, Univariate, ZeroKnowledge},
};

use crate::co_protogalaxy_prover_internal::{
    compute_and_extend_alphas, compute_combiner, compute_combiner_quotient,
    compute_extended_relation_parameters, compute_perturbator,
};
pub(crate) const CONST_PG_LOG_N: usize = 20;
pub(crate) const MAX_TOTAL_RELATION_LENGTH: usize = 11;

// Mega Protogalaxy prover only supports 2 keys
pub(crate) const NUM_KEYS: usize = 2;

pub(crate) const BATCHED_EXTENDED_LENGTH: usize =
    (MAX_TOTAL_RELATION_LENGTH - 1 + NUM_KEYS - 1) * (NUM_KEYS - 1) + 1;

pub(crate) type OinkProverMemory<T, C> = co_ultrahonk::co_oink::types::ProverMemory<T, C>;
pub(crate) type DeciderProverMemory<T, C> =
    co_ultrahonk::co_decider::types::ProverMemory<T, C, MegaFlavour>;
pub(crate) type PerturbatorRoundResult<F> = HonkProofResult<(Vec<F>, Polynomial<F>)>;
pub(crate) type CombinerQuotientRoundResult<F> = HonkProofResult<(
    Vec<F>,
    Vec<Univariate<F, BATCHED_EXTENDED_LENGTH>>,
    ExtendedRelationParameters<F>,
    F,
    Univariate<F, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }>,
)>;

pub type ExtendedRelationParameters<F> = RelationParameters<Univariate<F, BATCHED_EXTENDED_LENGTH>>;

pub struct CoProtogalaxyProver<'a, T, C, H, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    pub(crate) transcript: Transcript<TranscriptFieldType, H>,
    pub(crate) net: &'a N,
    pub(crate) state: &'a mut T::State,
    pub(crate) crs: &'a ProverCrs<C>,
}

impl<'a, T, C, H, N> CoProtogalaxyProver<'a, T, C, H, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    pub fn new(net: &'a N, state: &'a mut T::State, crs: &'a ProverCrs<C>) -> Self {
        Self {
            transcript: Transcript::new(),
            net,
            state,
            crs,
        }
    }
}

impl<'a, T, C, H, N> CoProtogalaxyProver<'a, T, C, H, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    fn run_oink_prover_on_one_incomplete_key(
        &mut self,
        proving_key: &mut ProvingKey<T, C, MegaFlavour>,
    ) -> HonkProofResult<OinkProverMemory<T, C>> {
        let oink_prover =
            CoOink::<T, C, H, N, MegaFlavour>::new(self.net, self.state, ZeroKnowledge::No);
        oink_prover.prove(proving_key, &mut self.transcript, self.crs)
    }

    pub(crate) fn run_oink_prover_on_each_incomplete_key(
        &mut self,
        proving_keys: &mut [ProvingKey<T, C, MegaFlavour>],
    ) -> HonkProofResult<Vec<OinkProverMemory<T, C>>> {
        // Assumes accumulator has not been folded
        let mut memory = Vec::with_capacity(proving_keys.len());

        for key in proving_keys.iter_mut() {
            memory.push(self.run_oink_prover_on_one_incomplete_key(key));
        }

        // unwrap all the results
        memory.into_iter().collect::<HonkProofResult<Vec<_>>>()
    }

    fn perturbator_round(
        &mut self,
        accumulator: &mut ProvingKey<T, C, MegaFlavour>,
        accumulator_prover_memory: &DeciderProverMemory<T, C>,
    ) -> PerturbatorRoundResult<C::ScalarField> {
        let delta = self.transcript.get_challenge::<C>("delta".to_owned());

        let deltas = std::iter::successors(Some(delta), |&x| Some(x.square()))
            .take(CONST_PG_LOG_N)
            .collect::<Vec<_>>();

        // An honest prover with valid initial key computes that the perturbator is 0 in the first round
        // TODO TACEO: Fix once ClientIVC::accumulate is implemented
        let perturbator = if true {
            compute_perturbator(
                self.net,
                self.state,
                accumulator,
                deltas.as_slice(),
                accumulator_prover_memory,
            )?
        } else {
            SharedPolynomial {
                coefficients: vec![T::ArithmeticShare::default(); CONST_PG_LOG_N + 1],
            }
        };

        // Prover doesn't send the constant coefficient of F because this is supposed to be equal to the target sum of
        // the accumulator which the folding verifier has from the previous iteration.
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1087): Verifier circuit for first IVC step is
        // different

        // Open the values of the perturbator
        let perturbator = Polynomial {
            // TACEO TODO: We leak stuff here and therefore should not open these shared values,
            // transcript operations should be performed in MPC.
            coefficients: T::open_many(&perturbator.coefficients, self.net, self.state)?,
        };

        (1..=CONST_PG_LOG_N).for_each(|i| {
            self.transcript
                .send_fr_to_verifier::<C>(format!("perturbator_{i}"), perturbator.coefficients[i]);
        });

        Ok((deltas, perturbator))
    }

    fn combiner_quotient_round(
        &mut self,
        prover_memory: &Vec<&mut DeciderProverMemory<T, C>>,
        perturbator: Polynomial<C::ScalarField>,
        deltas: Vec<C::ScalarField>,
    ) -> CombinerQuotientRoundResult<C::ScalarField> {
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
            self.net,
            self.state,
            prover_memory,
            &gate_separators,
            &relation_parameters,
            &alphas,
        )?;

        let perturbator_evaluation = perturbator.eval_poly(perturbator_challenge);
        let combiner_quotient =
            compute_combiner_quotient(self.state, &combiner, perturbator_evaluation);

        // Open the evaluations of the combiner quotient
        // TACEO TODO: We leak stuff here and therefore should not open these shared values,
        // transcript operations should be performed in MPC.
        let combiner_quotient = Univariate {
            evaluations: T::open_many(&combiner_quotient.evaluations, self.net, self.state)
                .unwrap()
                .try_into()
                .unwrap(),
        };

        for (i, eval) in combiner_quotient.evaluations.iter().enumerate() {
            self.transcript
                .send_fr_to_verifier::<C>(format!("combiner_quotient_{i}"), *eval);
        }

        Ok((
            updated_gate_challenges,
            alphas,
            relation_parameters,
            perturbator_evaluation,
            combiner_quotient,
        ))
    }

    /**
     * @brief Given the challenge \gamma, compute Z(\gamma) and {L_0(\gamma),L_1(\gamma)}
     */
    fn update_target_sum_and_fold(
        mut self,
        prover_memory: &mut Vec<&mut DeciderProverMemory<T, C>>,
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
            + vanishing_polynomial_at_challenge
                * combiner_quotient.evaluate_with_domain_start(combiner_challenge, NUM_KEYS);

        // Accumulate public polynomials
        accumulator_prover_memory
            .polys
            .public_iter_mut()
            .for_each(|poly| {
                poly.iter_mut().for_each(|coeff| *coeff *= lagranges[0]);
            });

        for (key_poly, acc_poly) in next_prover_memory
            .polys
            .public_iter()
            .zip(accumulator_prover_memory.polys.public_iter_mut())
        {
            acc_poly
                .iter_mut()
                .zip(key_poly.iter())
                .for_each(|(acc_coeff, key_coeff)| *acc_coeff += *key_coeff * lagranges[1]);
        }

        // Accumulate shared polynomials
        accumulator_prover_memory
            .polys
            .shared_iter_mut()
            .for_each(|poly| {
                T::scale_many_in_place(poly, lagranges[0]);
            });

        for (key_poly, acc_poly) in next_prover_memory
            .polys
            .shared_iter()
            .zip(accumulator_prover_memory.polys.shared_iter_mut())
        {
            acc_poly
                .iter_mut()
                .zip(
                    key_poly
                        .iter()
                        .map(|key_coeff| T::mul_with_public(lagranges[1], *key_coeff)),
                )
                .for_each(|(acc_coeff, tmp)| T::add_assign(acc_coeff, tmp));
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
        accumulator: &mut ProvingKey<T, C, MegaFlavour>,
        accumulator_prover_memory: &mut DeciderProverMemory<T, C>,
        mut next_proving_keys: Vec<ProvingKey<T, C, MegaFlavour>>,
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
        let (deltas, perturbator) =
            self.perturbator_round(accumulator, accumulator_prover_memory)?;

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
        ) = self.combiner_quotient_round(&prover_memory, perturbator, deltas)?;

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
