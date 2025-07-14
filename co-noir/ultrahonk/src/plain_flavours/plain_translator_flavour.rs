// #![expect(unused)]
// use crate::decider::types::ClaimedEvaluations;
// use crate::decider::types::{ProverUnivariates, RelationParameters};
// use crate::plain_prover_flavour::PlainProverFlavour;
// use crate::prelude::{Transcript, TranscriptHasher, Univariate};
// use crate::transcript::TranscriptFieldType;
// use co_builder::flavours::translator_flavour::TranslatorFlavour;
// use co_builder::prover_flavour::ProverFlavour;

// impl PlainProverFlavour for TranslatorFlavour {
//     type AllRelationAcc<F: ark_ff::PrimeField> = ();

//     type AllRelationEvaluations<F: ark_ff::PrimeField> = ();

//     type Alphas<F: ark_ff::PrimeField> = ();

//     type SumcheckRoundOutput<F: ark_ff::PrimeField> =
//         Univariate<F, { TranslatorFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

//     type SumcheckRoundOutputZK<F: ark_ff::PrimeField> =
//         Univariate<F, { TranslatorFlavour::BATCHED_RELATION_PARTIAL_LENGTH }>;

//     type ProverUnivariate<F: ark_ff::PrimeField> =
//         Univariate<F, { TranslatorFlavour::MAX_PARTIAL_RELATION_LENGTH }>;

//     const NUM_SUBRELATIONS: usize = 1902; // TODO FLORIN

//     fn scale<F: ark_ff::PrimeField>(
//         acc: &mut Self::AllRelationAcc<F>,
//         first_scalar: F,
//         elements: &Self::Alphas<F>,
//     ) {
//         todo!()
//     }

//     fn extend_and_batch_univariates<F: ark_ff::PrimeField>(
//         acc: &Self::AllRelationAcc<F>,
//         result: &mut Self::SumcheckRoundOutput<F>,
//         extended_random_poly: &Self::SumcheckRoundOutput<F>,
//         partial_evaluation_result: &F,
//     ) {
//         todo!()
//     }

//     fn extend_and_batch_univariates_zk<F: ark_ff::PrimeField>(
//         acc: &Self::AllRelationAcc<F>,
//         result: &mut Self::SumcheckRoundOutputZK<F>,
//         extended_random_poly: &Self::SumcheckRoundOutputZK<F>,
//         partial_evaluation_result: &F,
//     ) {
//         todo!()
//     }

//     fn accumulate_relation_univariates<P: co_builder::prelude::HonkCurve<TranscriptFieldType>>(
//         univariate_accumulators: &mut Self::AllRelationAcc<P::ScalarField>,
//         extended_edges: &ProverUnivariates<P::ScalarField, Self>,
//         relation_parameters: &RelationParameters<P::ScalarField, Self>,
//         scaling_factor: &P::ScalarField,
//     ) {
//         todo!()
//     }

//     fn accumulate_relation_evaluations<P: co_builder::prelude::HonkCurve<TranscriptFieldType>>(
//         univariate_accumulators: &mut Self::AllRelationEvaluations<P::ScalarField>,
//         extended_edges: &ClaimedEvaluations<P::ScalarField, Self>,
//         relation_parameters: &RelationParameters<P::ScalarField, Self>,
//         scaling_factor: &P::ScalarField,
//     ) {
//         todo!()
//     }

//     fn scale_and_batch_elements<F: ark_ff::PrimeField>(
//         all_rel_evals: &Self::AllRelationEvaluations<F>,
//         first_scalar: F,
//         elements: &Self::Alphas<F>,
//     ) -> F {
//         todo!()
//     }

//     fn receive_round_univariate_from_prover<
//         F: ark_ff::PrimeField,
//         H: TranscriptHasher<F>,
//         P: co_builder::prelude::HonkCurve<F>,
//     >(
//         transcript: &mut Transcript<F, H>,
//         label: String,
//     ) -> co_builder::HonkProofResult<Self::SumcheckRoundOutput<P::ScalarField>> {
//         todo!()
//     }

//     fn receive_round_univariate_from_prover_zk<
//         F: ark_ff::PrimeField,
//         H: TranscriptHasher<F>,
//         P: co_builder::prelude::HonkCurve<F>,
//     >(
//         transcript: &mut Transcript<F, H>,
//         label: String,
//     ) -> co_builder::HonkProofResult<Self::SumcheckRoundOutputZK<P::ScalarField>> {
//         todo!()
//     }

//     fn get_alpha_challenges<
//         F: ark_ff::PrimeField,
//         H: TranscriptHasher<F>,
//         P: co_builder::prelude::HonkCurve<F>,
//     >(
//         transcript: &mut Transcript<F, H>,
//         alphas: &mut Self::Alphas<P::ScalarField>,
//     ) {
//         todo!()
//     }
// }
