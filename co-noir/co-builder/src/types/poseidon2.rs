use crate::{
    types::{
        field_ct::FieldCT,
        types::{Poseidon2ExternalGate, Poseidon2InternalGate},
    },
    ultra_builder::GenericUltraCircuitBuilder,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use mpc_core::gadgets::poseidon2::{Poseidon2, Poseidon2Params};
use num_bigint::BigUint;
use std::{any::TypeId, array};

// This workaround is required due to mutability issues
macro_rules! create_dummy_gate {
    ($builder:expr, $block:expr, $ixd:expr) => {
        GenericUltraCircuitBuilder::<P, WT>::create_dummy_gate($block, $ixd[0].witness_index, $ixd[1].witness_index, $ixd[2].witness_index, $ixd[3].witness_index);
        $builder.check_selector_length_consistency();
        $builder.num_gates += 1; // necessary because create dummy gate cannot increment num_gates itself
    };
}

/// A struct representing the Poseidon2 permutation.
pub(crate) struct Poseidon2CT<F: PrimeField, const T: usize, const D: u64> {
    /// The struct containing the parameters for the Poseidon2 permutation.
    pub poseidon2: Poseidon2<F, T, D>,
}

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2CT<F, T, D> {
    /// Constructs a new Poseidon2 circuit.
    pub fn new(params: &'static Poseidon2Params<F, T, D>) -> Self {
        let poseidon2 = Poseidon2::new(params);
        Self { poseidon2 }
    }

    /// Constraints the external matrix multiplication
    fn matrix_multiplication_external<
        P: CurveGroup<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        state: &mut [FieldCT<F>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        let two = FieldCT::from(F::from(2u64));
        let four = FieldCT::from(F::from(4u64));

        // create the 6 gates for the initial matrix multiplication
        // gate 1: Compute tmp1 = state[0] + state[1] + 2 * state[3]
        let tmp = state[3].multiply(&two, builder, driver)?;
        let tmp1 = state[0].add_two(&state[1], &tmp, builder, driver);

        // gate 2: Compute tmp2 = 2 * state[1] + state[2] + state[3]
        let tmp = state[1].multiply(&two, builder, driver)?;
        let tmp2 = state[2].add_two(&tmp, &state[3], builder, driver);

        // gate 3: Compute v2 = 4 * state[0] + 4 * state[1] + tmp2
        let tmp = state[0].multiply(&four, builder, driver)?;
        let tmp_ = state[1].multiply(&four, builder, driver)?;
        state[1] = tmp2.add_two(&tmp, &tmp_, builder, driver);

        // gate 4: Compute v1 = v2 + tmp1
        state[0] = state[1].add(&tmp1, builder, driver);

        // gate 5: Compute v4 = tmp1 + 4 * state[2] + 4 * state[3]
        let tmp = state[2].multiply(&four, builder, driver)?;
        let tmp_ = state[3].multiply(&four, builder, driver)?;
        state[3] = tmp1.add_two(&tmp, &tmp_, builder, driver);

        // gate 6: Compute v3 = v4 + tmp2
        state[2] = state[3].add(&tmp2, builder, driver);

        // This can only happen if the input contained constant `field_t` elements.
        assert!(
            state[0].is_normalized()
                && state[1].is_normalized()
                && state[2].is_normalized()
                && state[3].is_normalized(),
        );
        Ok(())
    }

    fn create_external_gate<
        P: CurveGroup<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        state: &[FieldCT<F>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        round: usize,
    ) {
        let inp = Poseidon2ExternalGate {
            a: state[0].witness_index,
            b: state[1].witness_index,
            c: state[2].witness_index,
            d: state[3].witness_index,
            round_idx: round,
        };
        builder.create_poseidon2_external_gate(&inp);
    }

    fn create_internal_gate<
        P: CurveGroup<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        state: &[FieldCT<F>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        round: usize,
    ) {
        let inp = Poseidon2InternalGate {
            a: state[0].witness_index,
            b: state[1].witness_index,
            c: state[2].witness_index,
            d: state[3].witness_index,
            round_idx: round,
        };
        builder.create_poseidon2_internal_gate(&inp);
    }

    fn permutation_in_place_plain<
        P: CurveGroup<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        state: &mut [FieldCT<F>; T],
        native_state: &mut [F; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        // Linear layer at beginning
        Poseidon2::<F, T, D>::matmul_external(native_state);
        Self::matrix_multiplication_external(state, builder, driver)?;

        // First set of external rounds
        for r in 0..self.poseidon2.params.rounds_f_beginning {
            Self::create_external_gate(state, builder, r);
            // calculate the new witnesses
            self.poseidon2.external_round(native_state, r);
            for (src, des) in native_state.iter().zip(state.iter_mut()) {
                *des = FieldCT::from_witness(WT::AcvmType::from(*src), builder);
            }
        }

        // Aztec TODO(https://github.com/AztecProtocol/barretenberg/issues/879): dummy gate required since the last external gate
        // from above otherwise expects to read into the first internal gate which is sorted out of sequence
        create_dummy_gate!(builder, &mut builder.blocks.poseidon2_external, state);

        // Internal rounds
        for r in 0..self.poseidon2.params.rounds_p {
            Self::create_internal_gate(state, builder, r);
            // calculate the new witnesses
            self.poseidon2.internal_round(native_state, r);
            for (src, des) in native_state.iter().zip(state.iter_mut()) {
                *des = FieldCT::from_witness(WT::AcvmType::from(*src), builder);
            }
        }

        // Aztec TODO(https://github.com/AztecProtocol/barretenberg/issues/879): dummy gate required since the last internal gate
        // otherwise expects to read into the next external gate which is sorted out of sequence
        create_dummy_gate!(builder, &mut builder.blocks.poseidon2_internal, state);

        // Remaining external rounds
        for r in self.poseidon2.params.rounds_f_beginning
            ..self.poseidon2.params.rounds_f_beginning + self.poseidon2.params.rounds_f_end
        {
            Self::create_external_gate(state, builder, r);
            // calculate the new witnesses
            self.poseidon2.external_round(native_state, r);
            for (src, des) in native_state.iter().zip(state.iter_mut()) {
                *des = FieldCT::from_witness(WT::AcvmType::from(*src), builder);
            }
        }

        // The Poseidon2 permutation is 64 rounds, but needs to be a block of 65 rows, since the result of
        // applying a round of Poseidon2 is stored in the next row (the shifted row). As a result, we need this end row to
        // compare with the result from the 64th round of Poseidon2. Note that it does not activate any selectors since it
        // only serves as a comparison through the shifted wires.
        create_dummy_gate!(builder, &mut builder.blocks.poseidon2_external, state);
        Ok(())
    }

    fn permutation_in_place_shared<
        P: CurveGroup<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        state: &mut [FieldCT<F>; T],
        native_state: &mut [WT::ArithmeticShare; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        let mut precomps = driver.poseidon2_preprocess_permutation(1, &self.poseidon2)?;

        // Linear layer at beginning
        driver.poseidon2_matmul_external_inplace::<T, D>(native_state);
        Self::matrix_multiplication_external(state, builder, driver)?;

        // First set of external rounds
        for r in 0..self.poseidon2.params.rounds_f_beginning {
            Self::create_external_gate(state, builder, r);
            // calculate the new witnesses
            driver.poseidon2_external_round_inplace_with_precomp(
                native_state,
                r,
                &mut precomps,
                &self.poseidon2,
            )?;
            for (src, des) in native_state.iter().zip(state.iter_mut()) {
                *des = FieldCT::from_witness(WT::AcvmType::from(src.to_owned()), builder);
            }
        }

        // Aztec TODO(https://github.com/AztecProtocol/barretenberg/issues/879): dummy gate required since the last external gate
        // from above otherwise expects to read into the first internal gate which is sorted out of sequence
        create_dummy_gate!(builder, &mut builder.blocks.poseidon2_external, state);

        // Internal rounds
        for r in 0..self.poseidon2.params.rounds_p {
            Self::create_internal_gate(state, builder, r);
            // calculate the new witnesses
            driver.poseidon2_internal_round_inplace_with_precomp(
                native_state,
                r,
                &mut precomps,
                &self.poseidon2,
            )?;
            for (src, des) in native_state.iter().zip(state.iter_mut()) {
                *des = FieldCT::from_witness(WT::AcvmType::from(src.to_owned()), builder);
            }
        }

        // Aztec TODO(https://github.com/AztecProtocol/barretenberg/issues/879): dummy gate required since the last internal gate
        // otherwise expects to read into the next external gate which is sorted out of sequence
        create_dummy_gate!(builder, &mut builder.blocks.poseidon2_internal, state);

        // Remaining external rounds
        for r in self.poseidon2.params.rounds_f_beginning
            ..self.poseidon2.params.rounds_f_beginning + self.poseidon2.params.rounds_f_end
        {
            Self::create_external_gate(state, builder, r);
            // calculate the new witnesses
            driver.poseidon2_external_round_inplace_with_precomp(
                native_state,
                r,
                &mut precomps,
                &self.poseidon2,
            )?;
            for (src, des) in native_state.iter().zip(state.iter_mut()) {
                *des = FieldCT::from_witness(WT::AcvmType::from(src.to_owned()), builder);
            }
        }

        // The Poseidon2 permutation is 64 rounds, but needs to be a block of 65 rows, since the result of
        // applying a round of Poseidon2 is stored in the next row (the shifted row). As a result, we need this end row to
        // compare with the result from the 64th round of Poseidon2. Note that it does not activate any selectors since it
        // only serves as a comparison through the shifted wires.
        create_dummy_gate!(builder, &mut builder.blocks.poseidon2_external, state);
        Ok(())
    }

    /// Performs the Poseidon2 Permutation on the given state.
    pub fn permutation_in_place<
        P: CurveGroup<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        state: &mut [FieldCT<F>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        let native_state: [_; T] = array::from_fn(|i| state[i].get_value(builder, driver));

        if native_state.iter().any(|x| WT::is_shared(x)) {
            let mut shared_state = array::from_fn(|i| driver.get_as_shared(&native_state[i]));
            self.permutation_in_place_shared(state, &mut shared_state, builder, driver)?;
        } else {
            let mut plain_state = array::from_fn(|i| {
                WT::get_public(&native_state[i]).expect("All values are public")
            });
            self.permutation_in_place_plain(state, &mut plain_state, builder, driver)?;
        }

        Ok(())
    }

    /// Performs the Poseidon2 Permutation on the given state.
    #[expect(dead_code)]
    pub fn permutation<
        P: CurveGroup<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        input: &[FieldCT<F>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<[FieldCT<F>; T]> {
        let mut state = input.to_owned();
        self.permutation_in_place(&mut state, builder, driver)?;
        Ok(state)
    }
}

impl<F: PrimeField> Default for Poseidon2CT<F, 4, 5> {
    fn default() -> Self {
        if TypeId::of::<F>() == TypeId::of::<ark_bn254::Fr>() {
            let params = &mpc_core::gadgets::poseidon2::POSEIDON2_BN254_T4_PARAMS;
            let poseidon2 = Poseidon2CT::new(params);
            // Safety: We checked that the types match
            unsafe {
                std::mem::transmute::<Poseidon2CT<ark_bn254::Fr, 4, 5>, Poseidon2CT<F, 4, 5>>(
                    poseidon2,
                )
            }
        } else {
            panic!("No Poseidon2CT implementation for this field");
        }
    }
}

pub trait FieldHashCT<P: CurveGroup, const T: usize> {
    #[expect(dead_code)]
    fn permutation<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        input: &[FieldCT<P::ScalarField>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<[FieldCT<P::ScalarField>; T]> {
        let mut state = input.to_owned();
        self.permutation_in_place(&mut state, builder, driver)?;
        Ok(state)
    }
    fn permutation_in_place<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        input: &mut [FieldCT<P::ScalarField>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()>;
}

impl<P: CurveGroup, const T: usize> FieldHashCT<P, T> for Poseidon2CT<P::ScalarField, T, 5> {
    fn permutation_in_place<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        input: &mut [FieldCT<P::ScalarField>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        self.permutation_in_place(input, builder, driver)?;
        Ok(())
    }
}

pub struct FieldSpongeCT<P: CurveGroup, const T: usize, const R: usize, H: FieldHashCT<P, T>> {
    state: [FieldCT<P::ScalarField>; T],
    cache: [FieldCT<P::ScalarField>; R],
    cache_size: usize,
    hasher: H,
}

impl<P: CurveGroup, const T: usize, const R: usize, H: FieldHashCT<P, T>> FieldSpongeCT<P, T, R, H>
where
    H: Default,
{
    pub(crate) fn new<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
        in_len: usize,
    ) -> Self {
        // Add the domain separation to the initial state.
        let iv = BigUint::from(in_len) << 64;
        let mut iv = FieldCT::from(P::ScalarField::from(iv));
        iv.convert_constant_to_fixed_witness(builder, driver);
        let mut state: [FieldCT<P::ScalarField>; T] = array::from_fn(|_| FieldCT::default());
        let cache: [FieldCT<P::ScalarField>; R] = array::from_fn(|_| FieldCT::default());
        state[R] = iv;

        Self {
            state,
            cache,
            cache_size: 0,
            hasher: H::default(),
        }
    }

    fn perform_duplex<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        // add the cache into sponge state
        for i in 0..R {
            self.state[i].add_assign(&self.cache[i], builder, driver);
        }
        self.hasher
            .permutation_in_place(&mut self.state, builder, driver)?;

        // Reset the cache
        self.cache = array::from_fn(|_| FieldCT::default());

        // return `rate` number of field elements from the sponge state.
        Ok(())
    }

    fn absorb<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        input: FieldCT<P::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        if self.cache_size == R {
            // If we're absorbing, and the cache is full, apply the sponge permutation to compress the cache
            self.perform_duplex(builder, driver)?;
            self.cache[0] = input;
            self.cache_size = 1;
        } else {
            // If we're absorbing, and the cache is not full, add the input into the cache
            self.cache[self.cache_size] = input;
            self.cache_size += 1;
        }
        Ok(())
    }

    fn squeeze<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<FieldCT<P::ScalarField>> {
        self.perform_duplex(builder, driver)?;

        Ok(self.state[0].clone())
    }

    /**
     * @brief Use the sponge to hash an input vector.
     *
     * @param input Circuit witnesses (a_0, ..., a_{N-1})
     * @return Hash of the input, a single witness field element.
     */
    // This will be used in the fieldct transcript
    #[expect(unused)]
    pub(crate) fn hash_internal<
        const OUT_LEN: usize,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: &[FieldCT<P::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<FieldCT<P::ScalarField>> {
        let in_len = input.len();

        let mut sponge = Self::new(builder, driver, in_len);
        // Absorb inputs in blocks of size r = 3. Make sure that all inputs are witneesses.
        for input in input.iter() {
            assert!(
                !input.is_constant(),
                "Sponge inputs should not be stdlib constants."
            );
            sponge.absorb(input.clone(), builder, driver)?;
        }

        sponge.squeeze(builder, driver)
    }
}
