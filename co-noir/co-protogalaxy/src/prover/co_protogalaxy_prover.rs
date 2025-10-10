use ark_ec::PrimeGroup;
use ark_ff::fields::Field;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofResult, TranscriptFieldType};
use co_noir_common::polynomials::polynomial::Polynomial;
use co_noir_common::polynomials::shared_polynomial::SharedPolynomial;
use co_noir_common::transcript::Transcript;
use co_noir_common::transcript_mpc::{TranscriptRef, TranscriptRep3};
use co_noir_common::types::ZeroKnowledge;
use co_noir_common::{mpc::NoirUltraHonkProver, transcript::TranscriptHasher};
use co_ultrahonk::co_decider::types::RelationParameters;
use co_ultrahonk::co_oink::co_oink_prover::CoOink;
use co_ultrahonk::prelude::{ProvingKey, SharedUnivariate};
use itertools::{Itertools, izip};
use mpc_net::Network;
use std::vec;
use ultrahonk::prelude::HonkProof;
use ultrahonk::{
    plain_prover_flavour::UnivariateTrait,
    prelude::{GateSeparatorPolynomial, Univariate},
};

use crate::prover::co_protogalaxy_prover_internal::{
    compute_and_extend_alphas, compute_combiner, compute_combiner_quotient,
    compute_extended_relation_parameters, compute_perturbator,
};
pub const CONST_PG_LOG_N: usize = 20;
pub const MAX_TOTAL_RELATION_LENGTH: usize = 11;

// Mega Protogalaxy prover only supports 2 keys
pub const NUM_KEYS: usize = 2;

pub const BATCHED_EXTENDED_LENGTH: usize =
    (MAX_TOTAL_RELATION_LENGTH - 1 + NUM_KEYS - 1) * (NUM_KEYS - 1) + 1;

pub type OinkProverMemory<T, C> = co_ultrahonk::co_oink::types::ProverMemory<T, C>;
pub type DeciderProverMemory<T, C> =
    co_ultrahonk::co_decider::types::ProverMemory<T, C, MegaFlavour>;
pub(crate) type PerturbatorRoundResult<T, C> = HonkProofResult<(
    Vec<<C as PrimeGroup>::ScalarField>,
    Option<Polynomial<<C as PrimeGroup>::ScalarField>>,
    Option<SharedPolynomial<T, C>>,
)>;
pub(crate) type CombinerQuotientRoundResult<T, C> = HonkProofResult<(
    Vec<<C as PrimeGroup>::ScalarField>,
    Vec<Univariate<<C as PrimeGroup>::ScalarField, BATCHED_EXTENDED_LENGTH>>,
    ExtendedRelationParameters<<C as PrimeGroup>::ScalarField>,
    Option<<C as PrimeGroup>::ScalarField>,
    Option<<T as NoirUltraHonkProver<C>>::ArithmeticShare>,
    Option<Univariate<<C as PrimeGroup>::ScalarField, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }>>,
    Option<SharedUnivariate<T, C, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }>>,
)>;

pub type ExtendedRelationParameters<F> = RelationParameters<Univariate<F, BATCHED_EXTENDED_LENGTH>>;

pub struct CoProtogalaxyProver<'a, T, C, H, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, T, C>,
    N: Network,
{
    pub(crate) net: &'a N,
    pub(crate) state: &'a mut T::State,
    pub(crate) crs: &'a ProverCrs<C>,
    phantom: std::marker::PhantomData<H>,
}

impl<'a, T, C, H, N> CoProtogalaxyProver<'a, T, C, H, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, T, C>,
    N: Network,
{
    pub fn new(net: &'a N, state: &'a mut T::State, crs: &'a ProverCrs<C>) -> Self {
        Self {
            net,
            state,
            crs,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, T, C, H, N> CoProtogalaxyProver<'a, T, C, H, N>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, T, C>,
    N: Network,
{
    fn run_oink_prover_on_one_incomplete_key(
        &mut self,
        proving_key: &mut ProvingKey<T, C, MegaFlavour>,
        transcript: &mut TranscriptRef<TranscriptFieldType, T, C, H>,
    ) -> HonkProofResult<OinkProverMemory<T, C>> {
        let oink_prover =
            CoOink::<T, C, H, N, MegaFlavour>::new(self.net, self.state, ZeroKnowledge::No);
        oink_prover.prove_inner(proving_key, transcript, self.crs)
    }

    pub(crate) fn run_oink_prover_on_each_incomplete_key(
        &mut self,
        proving_keys: &mut [ProvingKey<T, C, MegaFlavour>],
        transcript: &mut TranscriptRef<TranscriptFieldType, T, C, H>,
    ) -> HonkProofResult<Vec<OinkProverMemory<T, C>>> {
        // Assumes accumulator has not been folded
        let mut memory = Vec::with_capacity(proving_keys.len());

        for key in proving_keys.iter_mut() {
            memory.push(self.run_oink_prover_on_one_incomplete_key(key, transcript));
        }

        // unwrap all the results
        memory.into_iter().collect::<HonkProofResult<Vec<_>>>()
    }

    fn perturbator_round(
        &mut self,
        accumulator: &mut ProvingKey<T, C, MegaFlavour>,
        accumulator_prover_memory: &DeciderProverMemory<T, C>,
        transcript: &mut TranscriptRef<TranscriptFieldType, T, C, H>,
    ) -> PerturbatorRoundResult<T, C> {
        let delta = match transcript {
            TranscriptRef::Plain(t) => t.get_challenge::<C>("delta".to_owned()),
            TranscriptRef::Rep3(t) => t.get_challenge("delta".to_owned(), self.net, self.state)?,
        };

        let deltas = std::iter::successors(Some(delta), |&x| Some(x.square()))
            .take(CONST_PG_LOG_N)
            .collect::<Vec<_>>();

        // An honest prover with valid initial key computes that the perturbator is 0 in the first round
        // TACEO TODO: Fix once ClientIVC::accumulate is implemented
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
        match transcript {
            TranscriptRef::Plain(t) => {
                // Open the values of the perturbator
                let perturbator = Polynomial {
                    // Note: When using the plain transcript we leak the opened commitments to the verifier/parties which is unintended in ClientIVC (atm)
                    coefficients: T::open_many(&perturbator.coefficients, self.net, self.state)?,
                };
                for i in 1..=CONST_PG_LOG_N {
                    t.send_fr_to_verifier::<C>(format!("perturbator_{i}"), perturbator[i]);
                }
                Ok((deltas, Some(perturbator), None))
            }
            TranscriptRef::Rep3(t) => {
                for i in 1..=CONST_PG_LOG_N {
                    t.send_fr_to_verifier_shared(
                        format!("perturbator_{i}"),
                        perturbator.coefficients[i],
                    );
                }
                Ok((deltas, None, Some(perturbator)))
            }
        }
    }

    fn combiner_quotient_round(
        &mut self,
        prover_memory: &Vec<&mut DeciderProverMemory<T, C>>,
        perturbator_opened: Option<Polynomial<C::ScalarField>>,
        perturbator_shared: Option<SharedPolynomial<T, C>>,
        deltas: Vec<C::ScalarField>,
        transcript: &mut TranscriptRef<TranscriptFieldType, T, C, H>,
    ) -> CombinerQuotientRoundResult<T, C> {
        let perturbator_challenge = match transcript {
            TranscriptRef::Plain(t) => t.get_challenge::<C>("perturbator_challenge".to_owned()),
            TranscriptRef::Rep3(t) => {
                t.get_challenge("perturbator_challenge".to_owned(), self.net, self.state)?
            }
        };

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

        let (eval_open, eval_shared) = match (&perturbator_opened, &perturbator_shared) {
            (Some(p), None) => (Some(p.eval_poly(perturbator_challenge)), None),
            (None, Some(p)) => (
                None,
                Some(T::eval_poly(&p.coefficients, perturbator_challenge)),
            ),
            _ => panic!("Either perturbator_opened or perturbator_shared must be Some"),
        };
        let combiner_quotient =
            compute_combiner_quotient(self.state, &combiner, eval_open, eval_shared);

        match transcript {
            TranscriptRef::Plain(t) => {
                // Open the evaluations of the combiner quotient
                // Note: When using the plain transcript we leak the opened commitments to the verifier/parties which is unintended in ClientIVC (atm)
                let combiner_quotient = Univariate {
                    evaluations: T::open_many(
                        &combiner_quotient.evaluations,
                        self.net,
                        self.state,
                    )?
                    .try_into()
                    .expect("Polynomial has correct length"),
                };
                for (i, eval) in combiner_quotient.evaluations.iter().enumerate() {
                    t.send_fr_to_verifier::<C>(format!("combiner_quotient_{i}"), *eval);
                }
                Ok((
                    updated_gate_challenges,
                    alphas,
                    relation_parameters,
                    eval_open,
                    eval_shared,
                    Some(combiner_quotient),
                    None,
                ))
            }
            TranscriptRef::Rep3(t) => {
                for (i, eval) in combiner_quotient.evaluations.iter().enumerate() {
                    t.send_fr_to_verifier_shared(format!("combiner_quotient_{i}"), *eval);
                }
                Ok((
                    updated_gate_challenges,
                    alphas,
                    relation_parameters,
                    eval_open,
                    eval_shared,
                    None,
                    Some(combiner_quotient),
                ))
            }
        }
    }

    /**
     * @brief Given the challenge \gamma, compute Z(\gamma) and {L_0(\gamma),L_1(\gamma)}
     */
    #[expect(clippy::type_complexity, clippy::too_many_arguments)]
    fn update_target_sum_and_fold(
        self,
        prover_memory: &mut Vec<&mut DeciderProverMemory<T, C>>,
        combiner_quotient_opened: Option<
            Univariate<C::ScalarField, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }>,
        >,
        combiner_quotient_shared: Option<
            SharedUnivariate<T, C, { BATCHED_EXTENDED_LENGTH - NUM_KEYS }>,
        >,
        alphas: Vec<Univariate<C::ScalarField, BATCHED_EXTENDED_LENGTH>>,
        univariate_relation_parameters: ExtendedRelationParameters<C::ScalarField>,
        perturbator_evaluation_opened: Option<C::ScalarField>,
        perturbator_evaluation_shared: Option<T::ArithmeticShare>,
        transcript: TranscriptRef<TranscriptFieldType, T, C, H>,
    ) -> HonkProofResult<(
        Option<HonkProof<TranscriptFieldType>>,
        Option<Vec<T::ArithmeticShare>>,
        Option<C::ScalarField>,
        Option<T::ArithmeticShare>,
    )> {
        let (accumulator_prover_memory, next_prover_memory) = prover_memory.split_at_mut(1);
        let accumulator_prover_memory = &mut accumulator_prover_memory[0];
        let next_prover_memory = &next_prover_memory[0];

        let (combiner_challenge, proof_open, proof_shared) = match transcript {
            TranscriptRef::Plain(transcript) => {
                let challenge =
                    transcript.get_challenge::<C>("combiner_quotient_challenge".to_owned());
                (challenge, Some(transcript.get_proof_ref()), None)
            }
            TranscriptRef::Rep3(transcript_rep3) => {
                let challenge = transcript_rep3.get_challenge(
                    "combiner_quotient_challenge".to_owned(),
                    self.net,
                    self.state,
                )?;
                (challenge, None, Some(transcript_rep3.get_proof()))
            }
        };

        let (vanishing_polynomial_at_challenge, lagranges) = (
            combiner_challenge * (combiner_challenge - C::ScalarField::ONE),
            vec![C::ScalarField::ONE - combiner_challenge, combiner_challenge],
        );

        let (target_sum_open, target_sum_shared) = match (
            &perturbator_evaluation_opened,
            &perturbator_evaluation_shared,
        ) {
            (Some(p), None) => (
                Some(
                    *p * lagranges[0]
                        + vanishing_polynomial_at_challenge
                            * combiner_quotient_opened
                                .expect("combiner_quotient_opened is Some")
                                .evaluate_with_domain_start(combiner_challenge, NUM_KEYS),
                ),
                None,
            ),
            (None, Some(p)) => {
                let tmp = T::mul_with_public(lagranges[0], *p);
                let mut eval = combiner_quotient_shared
                    .expect("combiner_quotient_opened is Some")
                    .evaluate_with_domain_start(combiner_challenge, NUM_KEYS);
                T::mul_assign_with_public(&mut eval, vanishing_polynomial_at_challenge);
                T::add_assign(&mut eval, tmp);
                (None, Some(eval))
            }
            _ => panic!(
                "Either perturbator_evaluation_opened or perturbator_evaluation_shared must be Some"
            ),
        };

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

        HonkProofResult::Ok((proof_open, proof_shared, target_sum_open, target_sum_shared))
    }

    #[expect(clippy::type_complexity)]
    pub fn prove_inner(
        mut self,
        accumulator: &mut ProvingKey<T, C, MegaFlavour>,
        accumulator_prover_memory: &mut DeciderProverMemory<T, C>,
        mut next_proving_keys: Vec<ProvingKey<T, C, MegaFlavour>>,
        mut transcript: TranscriptRef<TranscriptFieldType, T, C, H>,
    ) -> HonkProofResult<(
        Option<HonkProof<TranscriptFieldType>>,
        Option<Vec<T::ArithmeticShare>>,
        Option<C::ScalarField>,
        Option<T::ArithmeticShare>,
    )> {
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
        let oink_memories =
            self.run_oink_prover_on_each_incomplete_key(&mut next_proving_keys, &mut transcript)?;

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
        let (deltas, perturbator_opened, perturbator_shared) =
            self.perturbator_round(accumulator, accumulator_prover_memory, &mut transcript)?;

        let mut prover_memory = std::iter::once(accumulator_prover_memory)
            .chain(next_prover_memories.iter_mut())
            .collect::<Vec<_>>();

        // Combiner quotient round
        let (
            updated_gate_challenges,
            alphas,
            relation_parameters,
            perturbator_evaluation_open,
            perturbator_evaluation_shared,
            combiner_quotient_opened,
            combiner_quotient_shared,
        ) = self.combiner_quotient_round(
            &prover_memory,
            perturbator_opened,
            perturbator_shared,
            deltas,
            &mut transcript,
        )?;

        prover_memory[0].gate_challenges = updated_gate_challenges;

        // update target sum and fold
        self.update_target_sum_and_fold(
            &mut prover_memory,
            combiner_quotient_opened,
            combiner_quotient_shared,
            alphas,
            relation_parameters,
            perturbator_evaluation_open,
            perturbator_evaluation_shared,
            transcript,
        )
    }

    pub fn prove_plain_transcript(
        self,
        accumulator: &mut ProvingKey<T, C, MegaFlavour>,
        accumulator_prover_memory: &mut DeciderProverMemory<T, C>,
        next_proving_keys: Vec<ProvingKey<T, C, MegaFlavour>>,
    ) -> HonkProofResult<(HonkProof<TranscriptFieldType>, C::ScalarField)> {
        let mut transcript = Transcript::new();
        let transcript = TranscriptRef::Plain(&mut transcript);

        let (proof, _, target_sum_open, _) = self.prove_inner(
            accumulator,
            accumulator_prover_memory,
            next_proving_keys,
            transcript,
        )?;

        Ok((
            proof.expect("Proof is Some"),
            target_sum_open.expect("Target sum is Some"),
        ))
    }

    pub fn prove_rep3_transcript(
        self,
        accumulator: &mut ProvingKey<T, C, MegaFlavour>,
        accumulator_prover_memory: &mut DeciderProverMemory<T, C>,
        next_proving_keys: Vec<ProvingKey<T, C, MegaFlavour>>,
    ) -> HonkProofResult<(Vec<T::ArithmeticShare>, T::ArithmeticShare)> {
        let mut transcript = TranscriptRep3::new();
        let transcript = TranscriptRef::Rep3(&mut transcript);

        let (_, proof_shared, _, target_sum_shared) = self.prove_inner(
            accumulator,
            accumulator_prover_memory,
            next_proving_keys,
            transcript,
        )?;

        Ok((
            proof_shared.expect("Proof is Some"),
            target_sum_shared.expect("Target sum is Some"),
        ))
    }
}
