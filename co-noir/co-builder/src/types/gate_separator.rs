use ark_ec::CurveGroup;
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use eyre::Ok;

use crate::{prelude::GenericUltraCircuitBuilder, types::field_ct::FieldCT};

pub struct GateSeparatorPolynomial<P: CurveGroup> {
    pub betas: Vec<FieldCT<P::ScalarField>>,
    pub beta_products: Vec<FieldCT<P::ScalarField>>,
    pub partial_evaluation_result: FieldCT<P::ScalarField>,
    pub current_element_idx: usize,
    pub periodicity: usize,
}

impl<P: CurveGroup> GateSeparatorPolynomial<P> {
    pub fn new<T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        betas: Vec<FieldCT<P::ScalarField>>,
        log_num_mononmials: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let pow_size = 1 << log_num_mononmials;
        let current_element_idx = 0;
        let periodicity = 2;
        let one = FieldCT::from(P::ScalarField::ONE);

        // Barretenberg uses multithreading here and a simpler algorithm with worse complexity
        let mut beta_products = vec![one.clone(); pow_size];
        for (i, beta) in betas.iter().take(log_num_mononmials).enumerate() {
            let index = 1 << i;
            beta_products[index] = beta.clone();
            for j in 1..index {
                beta_products[index + j] = beta_products[j].multiply(beta, builder, driver)?;
            }
        }

        Ok(Self {
            betas,
            beta_products,
            partial_evaluation_result: one,
            current_element_idx,
            periodicity,
        })
    }

    pub fn new_without_products(betas: Vec<FieldCT<P::ScalarField>>) -> Self {
        let current_element_idx = 0;
        let periodicity = 2;
        let partial_evaluation_result = FieldCT::from(P::ScalarField::ONE);

        Self {
            betas,
            beta_products: Vec::new(),
            partial_evaluation_result,
            current_element_idx,
            periodicity,
        }
    }

    pub fn current_element(&self) -> &FieldCT<P::ScalarField> {
        &self.betas[self.current_element_idx]
    }

    pub fn partially_evaluate<T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        round_challenge: &FieldCT<P::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let one = FieldCT::from(P::ScalarField::ONE);

        let current_univariate_eval = round_challenge
            .multiply(
                &self.current_element().sub(&one, builder, driver),
                builder,
                driver,
            )?
            .add(&one, builder, driver);

        self.partial_evaluation_result =
            self.partial_evaluation_result
                .multiply(&current_univariate_eval, builder, driver)?;
        self.current_element_idx += 1;
        self.periodicity *= 2;
        Ok(())
    }
}
