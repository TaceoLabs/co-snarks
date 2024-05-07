use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, SynthesisError};
use mpc_core::traits::{FFTProvider, PrimeFieldMpcProtocol};

pub struct CollaborativeCircomReduction<F: PrimeField, FFT: FFTProvider<F>> {
    fft_provider: FFT,
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField, FFT: FFTProvider<F>> CollaborativeCircomReduction<F, FFT> {
    pub fn witness_map_from_matrices<D: EvaluationDomain<F>>(
        _matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        _full_assignment: <FFT as PrimeFieldMpcProtocol<F>>::FieldShareSlice,
    ) -> Result<Vec<F>, SynthesisError> {
        let zero = F::zero();
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();
        let mut _a = vec![zero; domain_size];
        let mut _b = vec![zero; domain_size];
        todo!()
    }
}
