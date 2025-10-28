use ark_ff::{Field, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{
    flavours::mega_flavour::MegaFlavour,
    mega_builder::MegaCircuitBuilder,
    polynomials::polynomial_flavours::WitnessEntitiesFlavour,
    prover_flavour::ProverFlavour,
    transcript::{TranscriptCT, TranscriptHasherCT},
    types::{field_ct::FieldCT, goblin_types::GoblinElement},
};
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use co_ultrahonk::{co_decider::types::RelationParameters, prelude::MPCProverFlavour};

use crate::recursive_verifier::{
    WitnessCommitments, recursive_decider_verification_key::RecursiveDeciderVerificationKey,
};

pub(crate) struct OinkRecursiveVerifier;

impl OinkRecursiveVerifier {
    pub fn verify<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        verification_key: &mut RecursiveDeciderVerificationKey<C, T>,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let circuit_size = verification_key.verification_key.circuit_size.clone();
        let public_input_size = verification_key.verification_key.num_public_inputs.clone();
        let pub_inputs_offset = verification_key.verification_key.pub_inputs_offset.clone();

        transcript.add_element_frs_to_hash_buffer(
            "circuit_size".to_owned(),
            std::slice::from_ref(&circuit_size),
        );
        transcript.add_element_frs_to_hash_buffer(
            "public_input_size".to_owned(),
            std::slice::from_ref(&public_input_size),
        );
        transcript.add_element_frs_to_hash_buffer(
            "pub_inputs_offset".to_owned(),
            std::slice::from_ref(&pub_inputs_offset),
        );

        let public_input_size_bigint = T::get_public(&public_input_size.get_value(builder, driver))
            .expect("public_input_size should be public")
            .into_bigint();

        // Ensure that only the first limb is used
        assert!(
            public_input_size_bigint.0[1..].iter().all(|&x| x == 0),
            "public_input_size should fit within a single limb"
        );
        let public_input_size_int = public_input_size_bigint.0[0] as usize;

        let public_inputs = (0..public_input_size_int)
            .map(|i| transcript.receive_fr_from_prover(format!("public_input_{i}")))
            .collect::<HonkProofResult<Vec<FieldCT<C::ScalarField>>>>()?;

        let mut commitments = WitnessCommitments::<C, T>::from_elements(
            (0..MegaFlavour::WITNESS_ENTITIES_SIZE)
                .map(|_| GoblinElement::point_at_infinity(builder))
                .collect::<Vec<_>>(),
        );

        // TACEO TODO: batch `is_zero` calls on `receive_point_from_prover`
        // Get commitments to first three wire polynomials
        *commitments.w_l_mut() =
            transcript.receive_point_from_prover("W_L".to_owned(), builder, driver)?;
        *commitments.w_r_mut() =
            transcript.receive_point_from_prover("W_R".to_owned(), builder, driver)?;
        *commitments.w_o_mut() =
            transcript.receive_point_from_prover("W_O".to_owned(), builder, driver)?;

        // Since we are in the Mega Flavor case, get commitments to ECC op wire polynomials and DataBus columns
        *commitments.ecc_op_wire_1_mut() =
            transcript.receive_point_from_prover("ECC_OP_WIRE_1".to_owned(), builder, driver)?;
        *commitments.ecc_op_wire_2_mut() =
            transcript.receive_point_from_prover("ECC_OP_WIRE_2".to_owned(), builder, driver)?;
        *commitments.ecc_op_wire_3_mut() =
            transcript.receive_point_from_prover("ECC_OP_WIRE_3".to_owned(), builder, driver)?;
        *commitments.ecc_op_wire_4_mut() =
            transcript.receive_point_from_prover("ECC_OP_WIRE_4".to_owned(), builder, driver)?;

        // Receive DataBus related polynomial commitments
        *commitments.calldata_mut() =
            transcript.receive_point_from_prover("CALLDATA".to_owned(), builder, driver)?;
        *commitments.calldata_read_counts_mut() = transcript.receive_point_from_prover(
            "CALLDATA_READ_COUNTS".to_owned(),
            builder,
            driver,
        )?;
        *commitments.calldata_read_tags_mut() = transcript.receive_point_from_prover(
            "CALLDATA_READ_TAGS".to_owned(),
            builder,
            driver,
        )?;

        *commitments.secondary_calldata_mut() = transcript.receive_point_from_prover(
            "SECONDARY_CALLDATA".to_owned(),
            builder,
            driver,
        )?;
        *commitments.secondary_calldata_read_counts_mut() = transcript.receive_point_from_prover(
            "SECONDARY_CALLDATA_READ_COUNTS".to_owned(),
            builder,
            driver,
        )?;
        *commitments.secondary_calldata_read_tags_mut() = transcript.receive_point_from_prover(
            "SECONDARY_CALLDATA_READ_TAGS".to_owned(),
            builder,
            driver,
        )?;

        *commitments.return_data_mut() =
            transcript.receive_point_from_prover("RETURN_DATA".to_owned(), builder, driver)?;
        *commitments.return_data_read_counts_mut() = transcript.receive_point_from_prover(
            "RETURN_DATA_READ_COUNTS".to_owned(),
            builder,
            driver,
        )?;
        *commitments.return_data_read_tags_mut() = transcript.receive_point_from_prover(
            "RETURN_DATA_READ_TAGS".to_owned(),
            builder,
            driver,
        )?;

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

        // Since we are in the Mega Flavor case, receive commitments to log-deriv inverses polynomials
        *commitments.calldata_inverses_mut() = transcript.receive_point_from_prover(
            "CALLDATA_INVERSES".to_owned(),
            builder,
            driver,
        )?;
        *commitments.secondary_calldata_inverses_mut() = transcript.receive_point_from_prover(
            "SECONDARY_CALLDATA_INVERSES".to_owned(),
            builder,
            driver,
        )?;
        *commitments.return_data_inverses_mut() = transcript.receive_point_from_prover(
            "RETURN_DATA_INVERSES".to_owned(),
            builder,
            driver,
        )?;

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1283): Suspicious get_value().
        let public_input_delta = Self::compute_public_input_delta(
            &public_inputs,
            &beta,
            &gamma,
            &circuit_size,
            &pub_inputs_offset,
            builder,
            driver,
        )?;

        // Get commitments to permutation and lookup grand products
        *commitments.z_perm_mut() =
            transcript.receive_point_from_prover("Z_PERM".to_owned(), builder, driver)?;

        let labels = (0..MegaFlavour::NUM_ALPHAS)
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
            ..Default::default()
        };
        verification_key.witness_commitments = commitments;
        verification_key.public_inputs = public_inputs;
        verification_key.alphas = alphas;
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
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        public_inputs: &[FieldCT<C::ScalarField>],
        beta: &FieldCT<C::ScalarField>,
        gamma: &FieldCT<C::ScalarField>,
        domain_size: &FieldCT<C::ScalarField>,
        offset: &FieldCT<C::ScalarField>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let mut numerator = one.clone();
        let mut denominator = one.clone();

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

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1158): Ensure correct construction of public input
        // delta in the face of increases to virtual size caused by execution trace overflow
        let n_plus_i = domain_size.add(offset, builder, driver);
        let one_plus_i = one.add(offset, builder, driver);

        let beta_mul_n_plus_i = beta.multiply(&n_plus_i, builder, driver)?;
        let beta_mul_one_plus_i = beta.multiply(&one_plus_i, builder, driver)?;

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
