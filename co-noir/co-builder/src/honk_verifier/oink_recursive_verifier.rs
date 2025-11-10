use crate::PERMUTATION_ARGUMENT_VALUE_SEPARATOR;
use crate::honk_verifier::recursive_decider_verification_key::RecursiveDeciderVerificationKey;
use crate::honk_verifier::recursive_decider_verification_key::WitnessCommitments;
use crate::honk_verifier::verifier_relations::NUM_SUBRELATIONS;
use crate::{
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::{TranscriptCT, TranscriptHasherCT},
    types::field_ct::FieldCT,
};
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;

use co_noir_common::types::RelationParameters;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use num_bigint::BigUint;

pub(crate) struct OinkRecursiveVerifier;

impl OinkRecursiveVerifier {
    pub fn verify<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        verification_key: &mut RecursiveDeciderVerificationKey<C, T>,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let vk_hash = verification_key
            .vk_and_hash
            .vk
            .hash_through_transcript(transcript, builder, driver)?;

        // Check that the vk hash matches the hash of the verification key
        verification_key
            .vk_and_hash
            .hash
            .assert_equal(&vk_hash, builder, driver);

        transcript.add_element_frs_to_hash_buffer("vk_hash".to_string(), &[vk_hash]);

        let num_public_inputs: BigUint = T::get_public(
            &verification_key
                .vk_and_hash
                .vk
                .num_public_inputs
                .get_value(builder, driver),
        )
        .expect("Number of public inputs should be public")
        .into();
        let num_public_inputs_usize = *num_public_inputs
            .to_u64_digits()
            .first()
            .expect("Should fit into 64 bits") as usize;
        let mut public_inputs = Vec::with_capacity(num_public_inputs_usize);

        for i in 0..num_public_inputs_usize {
            let pi = transcript.receive_fr_from_prover(format!("public_input_{i}"))?;
            public_inputs.push(pi);
        }

        let mut commitments = WitnessCommitments::<C::ScalarField, T>::default();

        // TACEO TODO: batch `is_zero` calls on `receive_point_from_prover`
        // Get commitments to first three wire polynomials
        *commitments.w_l_mut() =
            transcript.receive_point_from_prover("W_L".to_owned(), builder, driver)?;
        *commitments.w_r_mut() =
            transcript.receive_point_from_prover("W_R".to_owned(), builder, driver)?;
        *commitments.w_o_mut() =
            transcript.receive_point_from_prover("W_O".to_owned(), builder, driver)?;

        // Get eta challenges: used in RAM/ROM memory records and log derivative lookup argument
        let [eta_1, eta_2, eta_3] = transcript
            .get_challenges(
                &["eta_1".to_owned(), "eta_2".to_owned(), "eta_3".to_owned()],
                builder,
                driver,
            )?
            .try_into()
            .unwrap();

        // Get commitments to lookup argument polynomials and fourth wire
        *commitments.lookup_read_counts_mut() = transcript.receive_point_from_prover(
            "LOOKUP_READ_COUNTS".to_owned(),
            builder,
            driver,
        )?;
        *commitments.lookup_read_tags_mut() =
            transcript.receive_point_from_prover("LOOKUP_READ_TAGS".to_owned(), builder, driver)?;
        *commitments.w_4_mut() =
            transcript.receive_point_from_prover("W_4".to_owned(), builder, driver)?;

        // Get permutation challenges
        let [beta, gamma] = transcript
            .get_challenges(&["beta".to_owned(), "gamma".to_owned()], builder, driver)?
            .try_into()
            .unwrap();

        *commitments.lookup_inverses_mut() =
            transcript.receive_point_from_prover("LOOKUP_INVERSES".to_owned(), builder, driver)?;

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1283): Suspicious get_value().
        let public_input_delta = Self::compute_public_input_delta(
            &public_inputs,
            &beta,
            &gamma,
            &verification_key.vk_and_hash.vk.pub_inputs_offset,
            builder,
            driver,
        )?;

        // Get commitments to permutation and lookup grand products
        *commitments.z_perm_mut() =
            transcript.receive_point_from_prover("Z_PERM".to_owned(), builder, driver)?;

        let labels = (0..NUM_SUBRELATIONS)
            .map(|i| format!("alpha_{i}"))
            .collect::<Vec<_>>();
        let alphas = transcript.get_challenges(&labels, builder, driver)?;

        verification_key.relation_parameters = RelationParameters {
            beta,
            gamma,
            eta_1,
            eta_2,
            eta_3,
            public_input_delta,
        };
        verification_key.witness_commitments = commitments;
        verification_key.alphas = alphas.try_into().expect("Should fit into NUM_ALPHAS");
        verification_key.public_inputs = public_inputs;
        Ok(())
    }

    /**
     * @brief Compute the correction term for the permutation argument.
     *
     * @tparam Field
     * @param public_inputs x₀, ..., xₘ₋₁ public inputs to the circuit
     * @param beta random linear-combination term to combine both (wʲ, IDʲ) and (wʲ, σʲ)
     * @param gamma Schwartz-Zippel random evaluation to ensure ∏ᵢ (γ + Sᵢ) = ∏ᵢ (γ + Tᵢ)
     * @param domain_size Total number of rows required for the circuit (power of 2)
     * @param offset Extent to which PI are offset from the 0th index in the wire polynomials, for example, due to inclusion
     * of a leading zero row or Goblin style ECC op gates at the top of the execution trace.
     * @return Field Public input Δ
     */
    fn compute_public_input_delta<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        public_inputs: &[FieldCT<C::ScalarField>],
        beta: &FieldCT<C::ScalarField>,
        gamma: &FieldCT<C::ScalarField>,
        // domain_size: &FieldCT<C::ScalarField>,
        offset: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let one = FieldCT::from(C::ScalarField::ONE);

        // Let m be the number of public inputs x₀,…, xₘ₋₁.
        // Recall that we broke the permutation σ⁰ by changing the mapping
        //  (i) -> (n+i)   to   (i) -> (-(i+1))   i.e. σ⁰ᵢ = −(i+1)
        //
        // Therefore, the term in the numerator with ID¹ᵢ = n+i does not cancel out with any term in the denominator.
        // Similarly, the denominator contains an extra σ⁰ᵢ = −(i+1) term that does not appear in the numerator.
        // We expect the values of W⁰ᵢ and W¹ᵢ to be equal to xᵢ.
        // The expected accumulated product would therefore be equal to

        //   ∏ᵢ (γ + W¹ᵢ + β⋅ID¹ᵢ)        ∏ᵢ (γ + xᵢ + β⋅(n+i) )
        //  -----------------------  =  ------------------------
        //   ∏ᵢ (γ + W⁰ᵢ + β⋅σ⁰ᵢ )        ∏ᵢ (γ + xᵢ - β⋅(i+1) )

        // At the start of the loop for each xᵢ where i = 0, 1, …, m-1,
        // we have
        //      numerator_acc   = γ + β⋅(n+i) = γ + β⋅n + β⋅i
        //      denominator_acc = γ - β⋅(1+i) = γ - β   - β⋅i
        // at the end of the loop, add and subtract β to each term respectively to
        // set the expected value for the start of iteration i+1.
        // Note: The public inputs may be offset from the 0th index of the wires, for example due to the inclusion of an
        // initial zero row or Goblin-stlye ECC op gates. Accordingly, the indices i in the above formulas are given by i =
        // [0, m-1] + offset, i.e. i = offset, 1 + offset, …, m - 1 + offset.

        let mut numerator = one.clone();
        let mut denominator = one.clone();
        let separator = FieldCT::from(C::ScalarField::from(PERMUTATION_ARGUMENT_VALUE_SEPARATOR));

        let beta_mul_n_plus_i =
            beta.multiply(&separator.add(offset, builder, driver), builder, driver)?;
        let beta_mul_one_plus_i =
            beta.multiply(&offset.add(&one, builder, driver), builder, driver)?;
        let mut numerator_acc = gamma.add(&beta_mul_n_plus_i, builder, driver);
        let mut denominator_acc = gamma.sub(&beta_mul_one_plus_i, builder, driver);

        // TACEO TODO: Is there a more efficient way to do this?
        for i in 0..public_inputs.len() {
            let input = &public_inputs[i];
            numerator =
                numerator.multiply(&numerator_acc.add(input, builder, driver), builder, driver)?;
            denominator = denominator.multiply(
                &denominator_acc.add(input, builder, driver),
                builder,
                driver,
            )?;

            if i != public_inputs.len() - 1 {
                numerator_acc = numerator_acc.add(beta, builder, driver);
                denominator_acc = denominator_acc.sub(beta, builder, driver);
            }
        }

        Ok(numerator.divide(&denominator, builder, driver)?)
    }
}
