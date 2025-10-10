use super::{
    plookup::{ColumnIdx, MultiTableId, Plookup},
    types::WitnessOrConstant,
};
use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use co_noir_common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType, utils::Utils};

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;
use std::{array, marker::PhantomData}; // Import FieldCT from the correct module

pub(crate) const AES128_BASE: u32 = 9;
pub const AES128_SBOX: [u8; 256] = [
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

pub struct AES128<F: PrimeField> {
    phantom: PhantomData<F>,
}

impl<F: PrimeField> AES128<F> {
    fn normalize_sparse_form<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        byte: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<F>> {
        Plookup::read_from_1_to_2_table(builder, driver, MultiTableId::AesNormalize, byte)
    }

    fn apply_aes_sbox_map<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        input: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(FieldCT<F>, FieldCT<F>)> {
        Plookup::read_pair_from_table(builder, driver, MultiTableId::AesSbox, input)
    }

    fn convert_into_sparse_bytes<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        block_data: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<[FieldCT<F>; 16]> {
        // `block_data` must be a 128-bit variable
        let mut sparse_bytes: [FieldCT<F>; 16] = array::from_fn(|_| FieldCT::<F>::default());
        let lookup = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::AesInput,
            block_data,
            &FieldCT::<F>::default(),
            false,
        )?;
        for i in 0..16 {
            sparse_bytes[15 - i] = lookup[ColumnIdx::C2][i].clone();
        }

        Ok(sparse_bytes)
    }

    fn convert_from_sparse_bytes<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        sparse_bytes: &[FieldCT<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<F>> {
        debug_assert_eq!(sparse_bytes.len(), 16);
        let sparse_slice: Vec<_> = sparse_bytes[..16]
            .iter()
            .map(|y| y.get_value(builder, driver))
            .collect();
        let all_public = !sparse_slice.iter().any(|v| T::is_shared(v));
        let accumulator = if all_public {
            let mut accumulator = BigUint::zero();
            for byte in sparse_bytes[..16].iter() {
                let mut sparse_byte: BigUint = T::get_public(&byte.get_value(builder, driver))
                    .expect("Already checked it is public")
                    .into();
                sparse_byte &= BigUint::from(u64::MAX);
                let byte = Utils::map_from_sparse_form::<{ AES128_BASE as u64 }>(sparse_byte);
                accumulator <<= 8;
                accumulator += byte as u128;
            }
            F::from(accumulator).into()
        } else {
            T::accumulate_from_sparse_bytes(driver, &sparse_slice, AES128_BASE as u64, 64, 8)?
        };

        let result = FieldCT::<F>::from_witness(accumulator, builder);

        let lookup = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::AesInput,
            &result,
            &FieldCT::<F>::default(),
            false,
        )?;
        for i in 0..16 {
            sparse_bytes[15 - i].assert_equal(&lookup[ColumnIdx::C2][i], builder, driver);
        }
        Ok(result)
    }

    fn expand_key<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        key: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<[FieldCT<F>; 176]> {
        const ROUND_CONSTANTS: [u8; 11] = [
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        ];
        let sparse_round_constants: [FieldCT<F>; 11] = ROUND_CONSTANTS
            .iter()
            .map(|&x| {
                FieldCT::<F>::from(F::from(
                    Utils::map_into_sparse_form::<{ AES128_BASE as u64 }>(x as u64),
                ))
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("Failed to convert Vec to array");

        let mut round_key: [FieldCT<F>; 176] = array::from_fn(|_| FieldCT::<F>::default());
        let sparse_key = Self::convert_into_sparse_bytes(key, builder, driver)?;

        let mut temp: [FieldCT<F>; 4] = array::from_fn(|_| FieldCT::<F>::default());
        let mut temp_add_counts = [0u64; 4];
        let mut add_counts = [1u64; 176];

        round_key[..16].clone_from_slice(&sparse_key[..16]);

        for i in 4..44 {
            let k = (i - 1) * 4;

            temp_add_counts.copy_from_slice(&add_counts[k..k + 4]);
            temp[0] = round_key[k].clone();
            temp[1] = round_key[k + 1].clone();
            temp[2] = round_key[k + 2].clone();
            temp[3] = round_key[k + 3].clone();

            if i % 4 == 0 {
                temp.rotate_left(1);

                for t in &mut temp {
                    *t = Self::apply_aes_sbox_map(t, builder, driver)?.0;
                }

                temp[0].add_assign(&sparse_round_constants[i / 4], builder, driver);
                temp_add_counts[0] += 1;
            }

            let j = i * 4;
            let k = (i - 4) * 4;

            for t in 0..4 {
                round_key[j + t] = round_key[k + t].add(&temp[t], builder, driver);
                add_counts[j + t] = add_counts[k + t] + temp_add_counts[t];

                if add_counts[j + t] > 3 || (add_counts[j + t] > 1 && (j + t) & 12 == 12) {
                    round_key[j + t] =
                        Self::normalize_sparse_form(&round_key[j + t], builder, driver)?;
                    add_counts[j + t] = 1;
                }
            }
        }

        Ok(round_key)
    }

    fn shift_rows(state: &mut [(FieldCT<F>, FieldCT<F>); 16]) {
        // Shift rows in the state
        state.swap(1, 5);
        state.swap(5, 9);
        state.swap(9, 13);

        state.swap(2, 10);
        state.swap(6, 14);

        state.swap(3, 15);
        state.swap(15, 11);
        state.swap(11, 7);
    }

    fn mix_columns_and_add_round_key<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        state_pairs: &mut [(FieldCT<F>, FieldCT<F>); 16],
        round_key: &[FieldCT<F>],
        round: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        for i in (0..16).step_by(4) {
            let column_pairs = &mut state_pairs[i..i + 4];
            let round_pairs = &round_key[i..];
            // This is mix_column_and_add_round_key
            let t0 =
                column_pairs[0]
                    .0
                    .add_two(&column_pairs[3].0, &column_pairs[1].1, builder, driver);
            let t1 =
                column_pairs[1]
                    .0
                    .add_two(&column_pairs[2].0, &column_pairs[3].1, builder, driver);

            let r0 = t0.add_two(&column_pairs[2].0, &column_pairs[0].1, builder, driver);
            let r1 = t0.add_two(&column_pairs[1].0, &column_pairs[2].1, builder, driver);
            let r2 = t1.add_two(&column_pairs[0].0, &column_pairs[2].1, builder, driver);
            let r3 = t1.add_two(&column_pairs[0].1, &column_pairs[3].0, builder, driver);

            column_pairs[0].0 = r0.add(&round_pairs[round * 16], builder, driver);
            column_pairs[1].0 = r1.add(&round_pairs[round * 16 + 1], builder, driver);
            column_pairs[2].0 = r2.add(&round_pairs[round * 16 + 2], builder, driver);
            column_pairs[3].0 = r3.add(&round_pairs[round * 16 + 3], builder, driver);
        }
    }

    fn sub_bytes<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        state_pairs: &mut [(FieldCT<F>, FieldCT<F>); 16],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        for pair in state_pairs.iter_mut() {
            *pair = Self::apply_aes_sbox_map(&pair.0, builder, driver)?;
        }
        Ok(())
    }

    fn add_round_key<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        sparse_state: &mut [(FieldCT<F>, FieldCT<F>); 16],
        sparse_round_key: &[FieldCT<F>],
        round: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        for i in 0..16 {
            sparse_state[i]
                .0
                .add_assign(&sparse_round_key[round * 16 + i], builder, driver);
        }
    }

    fn xor_with_iv<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        state: &mut [(FieldCT<F>, FieldCT<F>); 16],
        iv: &[FieldCT<F>; 16],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        for i in 0..16 {
            state[i].0.add_assign(&iv[i], builder, driver);
        }
    }

    fn aes128_cipher<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        state: &mut [(FieldCT<F>, FieldCT<F>); 16],
        sparse_round_key: &[FieldCT<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        Self::add_round_key(state, sparse_round_key, 0, builder, driver);
        for pair in state.iter_mut() {
            pair.0 = Self::normalize_sparse_form(&pair.0, builder, driver)?;
        }
        for round in 1..10 {
            Self::sub_bytes(state, builder, driver)?;
            Self::shift_rows(state);
            Self::mix_columns_and_add_round_key(state, sparse_round_key, round, builder, driver);

            for pair in state.iter_mut() {
                pair.0 = Self::normalize_sparse_form(&pair.0, builder, driver)?;
            }
        }
        Self::sub_bytes(state, builder, driver)?;
        Self::shift_rows(state);
        Self::add_round_key(state, sparse_round_key, 10, builder, driver);
        Ok(())
    }

    pub(crate) fn encrypt_buffer_cbc<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        input: &[FieldCT<F>],
        iv: &FieldCT<F>,
        key: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Vec<FieldCT<F>>> {
        let round_key = Self::expand_key(key, builder, driver)?;

        let num_blocks = input.len();
        let mut sparse_state = Vec::new();

        for block in input {
            let bytes = Self::convert_into_sparse_bytes(block, builder, driver)?;
            sparse_state.extend(
                bytes
                    .into_iter()
                    .map(|byte| (byte, FieldCT::<F>::default())),
            );
        }

        let mut sparse_iv = Self::convert_into_sparse_bytes(iv, builder, driver)?;

        for i in 0..num_blocks {
            let round_state = &mut sparse_state[i * 16..(i + 1) * 16];
            Self::xor_with_iv(round_state.try_into().unwrap(), &sparse_iv, builder, driver);
            Self::aes128_cipher(round_state.try_into().unwrap(), &round_key, builder, driver)?;

            for j in 0..16 {
                sparse_iv[j] = round_state[j].0.clone();
            }
        }

        let mut sparse_output = Vec::new();
        for element in sparse_state.iter() {
            sparse_output.push(Self::normalize_sparse_form(&element.0, builder, driver)?);
        }

        let mut output = Vec::new();
        for i in 0..num_blocks {
            output.push(Self::convert_from_sparse_bytes(
                &sparse_output[i * 16..(i + 1) * 16],
                builder,
                driver,
            )?);
        }

        Ok(output)
    }
}

// Packs 16 bytes from the inputs (plaintext, iv, key) into a field element
pub(crate) fn pack_input_bytes_into_field<
    P: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
>(
    inputs: &[WitnessOrConstant<P::ScalarField>],
    padding: usize,
    builder: &mut GenericUltraCircuitBuilder<P, T>,
    driver: &mut T,
) -> eyre::Result<FieldCT<P::ScalarField>> {
    let mut converted = FieldCT::default();
    for input in &inputs[..(16 - padding)] {
        converted = converted.multiply(
            &FieldCT::from(P::ScalarField::from(256u64)),
            builder,
            driver,
        )?;
        let byte = input.to_field_ct();
        converted = converted.add(&byte, builder, driver);
    }
    for _ in 0..padding {
        converted = converted.multiply(
            &FieldCT::from(P::ScalarField::from(256u64)),
            builder,
            driver,
        )?;
        let byte = FieldCT::from(P::ScalarField::from(padding as u32));
        converted = converted.add(&byte, builder, driver);
    }
    Ok(converted)
}

// Packs 16 bytes from the outputs (witness indexes) into a field element for comparison
pub(crate) fn pack_output_bytes_into_field<
    P: CurveGroup,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
>(
    outputs: &[u32; 16],
    builder: &mut GenericUltraCircuitBuilder<P, T>,
    driver: &mut T,
) -> eyre::Result<FieldCT<P::ScalarField>> {
    let mut converted = FieldCT::default();
    for &output in outputs {
        converted = converted.multiply(
            &FieldCT::from(P::ScalarField::from(256u64)),
            builder,
            driver,
        )?;
        let byte = FieldCT::from_witness_index(output);
        converted = converted.add(&byte, builder, driver);
    }
    Ok(converted)
}
