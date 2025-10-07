use crate::{mega_builder::MegaCircuitBuilder, types::field_ct::FieldCT};
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use common::honk_proof::HonkProofResult;
use common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType};

#[derive(Default)]
pub struct RowDisablingPolynomial<
    C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
> {
    pub eval_at_0: FieldCT<C::ScalarField>,
    pub eval_at_1: FieldCT<C::ScalarField>,
}

impl<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>>
    RowDisablingPolynomial<C>
{
    pub fn update_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        round_challenge: C::ScalarField,
        round_idx: usize,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        if round_idx == 1 {
            self.eval_at_0 = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);
        }
        if round_idx >= 2 {
            self.eval_at_1 = self.eval_at_1.multiply(
                &FieldCT::from_witness(round_challenge.into(), builder),
                builder,
                driver,
            )?;
        }
        Ok(())
    }

    pub fn evaluate_at_challenge<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        multivariate_challenge: &[FieldCT<C::ScalarField>],
        log_circuit_size: usize,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let mut evaluation_at_multivariate_challenge = one.clone();

        for val in multivariate_challenge.iter().take(log_circuit_size).skip(2) {
            evaluation_at_multivariate_challenge =
                evaluation_at_multivariate_challenge.multiply(val, builder, driver)?;
        }
        Ok(one.sub(&evaluation_at_multivariate_challenge, builder, driver))
    }
    /**
     * @brief A variant of the above that uses `padding_indicator_array`.
     *
     * @param multivariate_challenge Sumcheck evaluation challenge
     * @param padding_indicator_array An array with first log_n entries equal to 1, and the remaining entries are 0.
     */
    pub fn evaluate_at_challenge_with_padding<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        multivariate_challenge: &[FieldCT<C::ScalarField>],
        padding_indicator_array: &[FieldCT<C::ScalarField>],
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let mut evaluation_at_multivariate_challenge =
            FieldCT::from_witness(C::ScalarField::ONE.into(), builder);

        for (idx, indicator) in padding_indicator_array.iter().enumerate().skip(2) {
            evaluation_at_multivariate_challenge = indicator
                .multiply(&multivariate_challenge[idx], builder, driver)?
                .add(&one, builder, driver)
                .sub(indicator, builder, driver)
                .multiply(&evaluation_at_multivariate_challenge, builder, driver)?;
        }
        Ok(one.sub(&evaluation_at_multivariate_challenge, builder, driver))
    }
}
