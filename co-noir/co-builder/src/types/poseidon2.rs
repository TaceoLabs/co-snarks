use std::{any::TypeId, array};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use mpc_core::gadgets::poseidon2::{Poseidon2, Poseidon2Params};

use crate::{
    builder::GenericUltraCircuitBuilder,
    types::types::{AddQuad, Poseidon2ExternalGate, Poseidon2InternalGate},
};

use super::types::FieldCT;

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
        P: Pairing<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        state: &mut [FieldCT<F>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) {
        let s0 = state[0].get_value(builder, driver);
        let s1 = state[1].get_value(builder, driver);
        let s2 = state[2].get_value(builder, driver);
        let s3 = state[3].get_value(builder, driver);

        // create the 6 gates for the initial matrix multiplication
        // gate 1: Compute tmp1 = state[0] + state[1] + 2 * state[3]
        let mut tmp1 = driver.mul_with_public(F::from(2u64), s3.to_owned());
        driver.add_assign(&mut tmp1, s0.to_owned());
        driver.add_assign(&mut tmp1, s1.to_owned());
        let tmp1 = FieldCT::from_witness(tmp1, builder);

        builder.create_big_add_gate(
            &AddQuad {
                a: state[0].witness_index,
                b: state[1].witness_index,
                c: state[3].witness_index,
                d: tmp1.witness_index,
                a_scaling: F::one(),
                b_scaling: F::one(),
                c_scaling: F::from(2u64),
                d_scaling: -F::one(),
                const_scaling: F::zero(),
            },
            false,
        );
        let tmp1_val = tmp1.get_value(builder, driver);

        // gate 2: Compute tmp2 = 2 * state[1] + state[2] + state[3]
        let mut tmp2 = driver.mul_with_public(F::from(2u64), s1.to_owned());
        driver.add_assign(&mut tmp2, s2.to_owned());
        driver.add_assign(&mut tmp2, s3.to_owned());
        let tmp2 = FieldCT::from_witness(tmp2, builder);

        builder.create_big_add_gate(
            &AddQuad {
                a: state[1].witness_index,
                b: state[2].witness_index,
                c: state[3].witness_index,
                d: tmp2.witness_index,
                a_scaling: F::from(2u64),
                b_scaling: F::one(),
                c_scaling: F::one(),
                d_scaling: -F::one(),
                const_scaling: F::zero(),
            },
            false,
        );
        let tmp2_val = tmp2.get_value(builder, driver);

        // gate 3: Compute v2 = 4 * state[0] + 4 * state[1] + tmp2
        let mut v2 = driver.mul_with_public(F::from(4u64), s0);
        let tmp = driver.mul_with_public(F::from(4u64), s1);
        driver.add_assign(&mut v2, tmp);
        driver.add_assign(&mut v2, tmp2_val.to_owned());
        let v2 = FieldCT::from_witness(v2, builder);
        builder.create_big_add_gate(
            &AddQuad {
                a: state[0].witness_index,
                b: state[1].witness_index,
                c: tmp2.witness_index,
                d: v2.witness_index,
                a_scaling: F::from(4u64),
                b_scaling: F::from(4u64),
                c_scaling: F::one(),
                d_scaling: -F::one(),
                const_scaling: F::zero(),
            },
            false,
        );
        let v2_val = v2.get_value(builder, driver);

        // gate 4: Compute v1 = v2 + tmp1
        let v1 = driver.add(v2_val, tmp1_val.to_owned());
        let v1 = FieldCT::from_witness(v1, builder);
        builder.create_big_add_gate(
            &AddQuad {
                a: v2.witness_index,
                b: tmp1.witness_index,
                c: v1.witness_index,
                d: builder.zero_idx,
                a_scaling: F::one(),
                b_scaling: F::one(),
                c_scaling: -F::one(),
                d_scaling: F::zero(),
                const_scaling: F::zero(),
            },
            false,
        );

        // gate 5: Compute v4 = tmp1 + 4 * state[2] + 4 * state[3]
        let mut v4 = driver.mul_with_public(F::from(4u64), s2);
        let tmp = driver.mul_with_public(F::from(4u64), s3);
        driver.add_assign(&mut v4, tmp);
        driver.add_assign(&mut v4, tmp1_val);
        let v4 = FieldCT::from_witness(v4, builder);
        builder.create_big_add_gate(
            &AddQuad {
                a: tmp1.witness_index,
                b: state[2].witness_index,
                c: state[3].witness_index,
                d: v4.witness_index,
                a_scaling: F::one(),
                b_scaling: F::from(4u64),
                c_scaling: F::from(4u64),
                d_scaling: -F::one(),
                const_scaling: F::zero(),
            },
            false,
        );
        let v4_val = v4.get_value(builder, driver);

        // gate 6: Compute v3 = v4 + tmp2
        let v3 = driver.add(v4_val, tmp2_val);
        let v3 = FieldCT::from_witness(v3, builder);
        builder.create_big_add_gate(
            &AddQuad {
                a: v4.witness_index,
                b: tmp2.witness_index,
                c: v3.witness_index,
                d: builder.zero_idx,
                a_scaling: F::one(),
                b_scaling: F::one(),
                c_scaling: -F::one(),
                d_scaling: F::zero(),
                const_scaling: F::zero(),
            },
            false,
        );

        state[0] = v1;
        state[1] = v2;
        state[2] = v3;
        state[3] = v4;
    }

    fn create_external_gate<
        P: Pairing<ScalarField = F>,
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
        P: Pairing<ScalarField = F>,
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
        P: Pairing<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        state: &mut [FieldCT<F>; T],
        native_state: &mut [F; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) {
        // Linear layer at beginning
        Poseidon2::<F, T, D>::matmul_external(native_state);
        Self::matrix_multiplication_external(state, builder, driver);

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
    }

    fn permutation_in_place_shared<
        P: Pairing<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        state: &mut [FieldCT<F>; T],
        native_state: &mut [WT::ArithmeticShare; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> std::io::Result<()> {
        let mut precomps = driver.poseidon2_preprocess_permutation(1, &self.poseidon2)?;

        // Linear layer at beginning
        driver.poseidon2_matmul_external_inplace::<T, D>(native_state);
        Self::matrix_multiplication_external(state, builder, driver);

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
        P: Pairing<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        state: &mut [FieldCT<F>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> std::io::Result<()> {
        let native_state: [_; T] = array::from_fn(|i| state[i].get_value(builder, driver));

        if native_state.iter().any(|x| WT::is_shared(x)) {
            let mut shared_state = array::from_fn(|i| {
                if WT::is_shared(&native_state[i]) {
                    WT::get_shared(&native_state[i]).expect("Already checked it is shared")
                } else {
                    // We promote since the first linear layer makes every element shared anyway
                    driver.promote_to_trivial_share(
                        WT::get_public(&native_state[i]).expect("Already checked it is public"),
                    )
                }
            });
            self.permutation_in_place_shared(state, &mut shared_state, builder, driver)?;
        } else {
            let mut plain_state = array::from_fn(|i| {
                WT::get_public(&native_state[i]).expect("All values are public")
            });
            self.permutation_in_place_plain(state, &mut plain_state, builder, driver);
        }

        Ok(())
    }

    /// Performs the Poseidon2 Permutation on the given state.
    #[expect(dead_code)]
    pub fn permutation<
        P: Pairing<ScalarField = F>,
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        input: &[FieldCT<F>; T],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> std::io::Result<[FieldCT<F>; T]> {
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
