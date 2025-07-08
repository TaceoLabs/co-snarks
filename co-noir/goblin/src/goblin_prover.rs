// use std::sync::Arc;

// pub struct Goblin {
//     commitment_key: Arc<CommitmentKey<curve::BN254>>,
//     merge_proof: Option<MergeProof>,
//     goblin_proof: GoblinProof,
//     op_queue: OpQueue,
//     translation_batching_challenge_v: Option<Challenge>,
//     evaluation_challenge_x: Option<Challenge>,
//     transcript: Option<Transcript>,
// }

// impl Goblin {
//     pub fn new(commitment_key: Arc<CommitmentKey<curve::BN254>>) -> Self {
//         Self {
//             commitment_key,
//             merge_proof: None,
//             goblin_proof: GoblinProof::default(),
//             op_queue: OpQueue::default(),
//             translation_batching_challenge_v: None,
//             evaluation_challenge_x: None,
//             transcript: None,
//         }
//     }

//     pub fn prove_merge(&mut self) -> MergeProof {
//         profile_this_name("Goblin::merge");
//         let mut merge_prover = MergeProver::new(&self.op_queue, &self.commitment_key);
//         self.merge_proof = Some(merge_prover.construct_proof());
//         self.merge_proof.clone().unwrap()
//     }

//     fn prove_eccvm(&mut self) {
//         let eccvm_builder = ECCVMBuilder::new(&self.op_queue);
//         let mut eccvm_prover = ECCVMProver::new(eccvm_builder);
//         self.goblin_proof.eccvm_proof = eccvm_prover.construct_proof();

//         self.translation_batching_challenge_v = Some(eccvm_prover.batching_challenge_v);
//         self.evaluation_challenge_x = Some(eccvm_prover.evaluation_challenge_x);
//         self.transcript = Some(eccvm_prover.transcript);
//     }

//     fn prove_translator(&mut self) {
//         profile_this_name("Create TranslatorBuilder and TranslatorProver");
//         let translator_builder = TranslatorBuilder::new(
//             self.translation_batching_challenge_v.clone().unwrap(),
//             self.evaluation_challenge_x.clone().unwrap(),
//             &self.op_queue,
//         );
//         let translator_key = Arc::new(TranslatorProvingKey::new(
//             translator_builder,
//             &self.commitment_key,
//         ));
//         let mut translator_prover =
//             TranslatorProver::new(translator_key, self.transcript.clone().unwrap());
//         self.goblin_proof.translator_proof = translator_prover.construct_proof();
//     }

//     pub fn prove(&mut self, merge_proof_in: Option<MergeProof>) -> GoblinProof {
//         profile_this_name("Goblin::prove");

//         info!(
//             "Constructing a Goblin proof with num ultra ops = {}",
//             self.op_queue.get_ultra_ops_table_num_rows()
//         );

//         self.goblin_proof.merge_proof = merge_proof_in.or_else(|| self.merge_proof.take());
//         {
//             profile_this_name("prove_eccvm");
//             vinfo("prove eccvm...");
//             self.prove_eccvm();
//             vinfo("finished eccvm proving.");
//         }
//         {
//             profile_this_name("prove_translator");
//             vinfo("prove translator...");
//             self.prove_translator();
//             vinfo("finished translator proving.");
//         }
//         self.goblin_proof.clone()
//     }

//     pub fn verify(&self, proof: &GoblinProof) -> bool {
//         let merge_verifier = MergeVerifier::new();
//         let merge_verified = merge_verifier.verify_proof(&proof.merge_proof);

//         let eccvm_verifier = ECCVMVerifier::new();
//         let eccvm_verified = eccvm_verifier.verify_proof(&proof.eccvm_proof);

//         let translator_verifier = TranslatorVerifier::new(&eccvm_verifier.transcript);

//         let accumulator_construction_verified = translator_verifier.verify_proof(
//             &proof.translator_proof,
//             &eccvm_verifier.evaluation_challenge_x,
//             &eccvm_verifier.batching_challenge_v,
//         );

//         let translation_verified = translator_verifier.verify_translation(
//             &eccvm_verifier.translation_evaluations,
//             &eccvm_verifier.translation_masking_term_eval,
//         );

//         let op_queue_consistency_verified =
//             translator_verifier.verify_consistency_with_final_merge(&merge_verifier.T_commitments);

//         vinfo!("merge verified?: {}", merge_verified);
//         vinfo!("eccvm verified?: {}", eccvm_verified);
//         vinfo!(
//             "accumulator construction_verified?: {}",
//             accumulator_construction_verified
//         );
//         vinfo!("translation verified?: {}", translation_verified);
//         vinfo!("consistency verified?: {}", op_queue_consistency_verified);

//         merge_verified
//             && eccvm_verified
//             && accumulator_construction_verified
//             && translation_verified
//             && op_queue_consistency_verified
//     }
// }
