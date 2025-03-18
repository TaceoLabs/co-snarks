use std::collections::HashMap;

use ark_ff::PrimeField;
use co_brillig::mpc::BrilligDriver;

use crate::mpc::NoirWitnessExtensionProtocol;

/// TODO better name?
pub struct ValueStore<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    output: Vec<T::AcvmType>,
    inner: HashMap<String, Vec<T::AcvmType>>,
}

impl<T, F> ValueStore<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    pub(super) fn new() -> Self {
        Self {
            output: vec![],
            inner: HashMap::new(),
        }
    }

    pub(super) fn set_output(&mut self, output: Vec<T::AcvmType>) {
        self.output = output;
    }

    pub(super) fn add_from_brillig(
        &mut self,
        driver: &mut T,
        output: HashMap<String, Vec<<T::BrilligDriver as BrilligDriver<F>>::BrilligType>>,
    ) -> eyre::Result<()> {
        #[allow(clippy::iter_over_hash_type)]
        for (key, val) in output {
            let translated = driver.parse_brillig_result(val)?;
            if self.inner.insert(key.clone(), translated).is_some() {
                eyre::bail!(format!("duplicate entry for shared state id: {key}"));
            }
        }
        Ok(())
    }

    pub fn get_output(&self) -> Vec<T::AcvmType> {
        self.output.clone()
    }

    pub fn get_stored(&self) -> HashMap<String, Vec<T::AcvmType>> {
        self.inner.clone()
    }

    #[allow(clippy::type_complexity)]
    pub fn into_inner(self) -> (Vec<T::AcvmType>, HashMap<String, Vec<T::AcvmType>>) {
        (self.output, self.inner)
    }
}
