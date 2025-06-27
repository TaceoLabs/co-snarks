use self::utils::Utils;
use super::field_ct::FieldCT;
use super::generators;
use crate::TranscriptFieldType;
use crate::prelude::HonkCurve;
use crate::{builder::GenericUltraCircuitBuilder, utils};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{PrimeField, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use itertools::izip;
use mpc_core::protocols::rep3::yao::circuits::SHA256Table;
use num_bigint::BigUint;
use std::array::from_fn;
use std::collections::HashMap;
use std::ops::{Index, IndexMut};

#[expect(dead_code)]
#[repr(usize)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BasicTableId {
    Xor,
    And,
    Pedersen,
    AesSparseMap,
    AesSboxMap,
    AesSparseNormalize,
    Sha256WitnessNormalize,
    Sha256WitnessSlice3,
    Sha256WitnessSlice7Rotate4,
    Sha256WitnessSlice8Rotate7,
    Sha256WitnessSlice14Rotate1,
    Sha256ChNormalize,
    Sha256MajNormalize,
    Sha256Base28,
    Sha256Base28Rotate6,
    Sha256Base28Rotate3,
    Sha256Base16,
    Sha256Base16Rotate2,
    Sha256Base16Rotate6,
    Sha256Base16Rotate7,
    Sha256Base16Rotate8,
    UintXorSlice6Rotate0,
    UintXorSlice2Rotate0,
    UintAndSlice6Rotate0,
    UintAndSlice2Rotate0,
    Bn254XloBasic,
    Bn254XhiBasic,
    Bn254YloBasic,
    Bn254YhiBasic,
    Bn254XyprimeBasic,
    Bn254XloEndoBasic,
    Bn254XhiEndoBasic,
    Bn254XyprimeEndoBasic,
    Secp256k1XloBasic,
    Secp256k1XhiBasic,
    Secp256k1YloBasic,
    Secp256k1YhiBasic,
    Secp256k1XyprimeBasic,
    Secp256k1XloEndoBasic,
    Secp256k1XhiEndoBasic,
    Secp256k1XyprimeEndoBasic,
    BlakeXorRotate0,
    BlakeXorRotate0Slice5Mod4,
    BlakeXorRotate1,
    BlakeXorRotate2,
    BlakeXorRotate4,
    FixedBase0_0,
    FixedBase0_1,
    FixedBase0_2,
    FixedBase0_3,
    FixexBase0_4,
    FixedBase0_5,
    FixedBase0_6,
    FixedBase0_7,
    FixedBase0_8,
    FixedBase0_9,
    FixedBase0_10,
    FixedBase0_11,
    FixedBase0_12,
    FixedBase0_13,
    FixedBase0_14,
    // FixedBase1_0 = BasicTableId::FixedBase0_0 as usize
    // + FixedBaseParams::NUM_TABLES_PER_LO_MULTITABLE,
    FixedBase1_0,
    FixedBase1_1,
    FixedBase1_2,
    FixedBase1_3,
    FixexBase1_4,
    FixedBase1_5,
    FixedBase1_6,
    FixedBase1_7,
    FixedBase1_8,
    FixedBase1_9,
    FixedBase1_10,
    FixedBase1_11,
    FixedBase1_12,
    FixedBase1_13,
    // FixedBase2_0 = BasicTableId::FixedBase1_0 as usize
    //     + FixedBaseParams::NUM_TABLES_PER_HI_MULTITABLE,
    FixedBase2_0,
    FixedBase2_1,
    FixedBase2_2,
    FixedBase2_3,
    FixexBase2_4,
    FixedBase2_5,
    FixedBase2_6,
    FixedBase2_7,
    FixedBase2_8,
    FixedBase2_9,
    FixedBase2_10,
    FixedBase2_11,
    FixedBase2_12,
    FixedBase2_13,
    FixedBase2_14,
    // FixedBase3_0 = BasicTableId::FixedBase2_0 as usize
    //     + FixedBaseParams::NUM_TABLES_PER_LO_MULTITABLE,
    FixedBase3_0,
    FixedBase3_1,
    FixedBase3_2,
    FixedBase3_3,
    FixexBase3_4,
    FixedBase3_5,
    FixedBase3_6,
    FixedBase3_7,
    FixedBase3_8,
    FixedBase3_9,
    FixedBase3_10,
    FixedBase3_11,
    FixedBase3_12,
    FixedBase3_13,
    // HonkDummyBasic1 = BasicTableId::FixedBase3_0 as usize
    //     + FixedBaseParams::NUM_TABLES_PER_HI_MULTITABLE,
    HonkDummyBasic1,
    HonkDummyBasic2,
    KeccakInput,
    KeccakTheta,
    KeccakRho,
    KeccakChi,
    KeccakOutput,
    KeccakRho1,
    KeccakRho2,
    KeccakRho3,
    KeccakRho4,
    KeccakRho5,
    KeccakRho6,
    KeccakRho7,
    KeccakRho8,
    KeccakRho9,
}

impl From<BasicTableId> for usize {
    fn from(id: BasicTableId) -> usize {
        id as usize
    }
}

impl TryFrom<usize> for BasicTableId {
    type Error = std::io::Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > BasicTableId::KeccakRho9 as usize {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid BasicTableId: {value}"),
            ))
        } else {
            // Safety: Safe because BasicTableId is repr(usize) and we checked above it is a valid value
            Ok(unsafe { std::mem::transmute::<usize, BasicTableId>(value) })
        }
    }
}

impl BasicTableId {
    const MAJORITY_NORMALIZATION_TABLE: [u64; 16] = [
        // xor result = 0
        0, // a + b + c = 0 => (a & b) ^ (a & c) ^ (b & c) = 0
        0, // a + b + c = 1 => (a & b) ^ (a & c) ^ (b & c) = 0
        1, // a + b + c = 2 => (a & b) ^ (a & c) ^ (b & c) = 1
        1, // a + b + c = 3 => (a & b) ^ (a & c) ^ (b & c) = 1
        // xor result = 1
        1, 1, 2, 2, // xor result = 2
        0, 0, 1, 1, // xor result = 3
        1, 1, 2, 2,
    ];

    const CHOOSE_NORMALIZATION_TABLE: [u64; 28] = [
        /* xor result = 0 */
        0, // e + 2f + 3g = 0 => e = 0, f = 0, g = 0 => t = 0
        0, // e + 2f + 3g = 1 => e = 1, f = 0, g = 0 => t = 0
        0, // e + 2f + 3g = 2 => e = 0, f = 1, g = 0 => t = 0
        1, // e + 2f + 3g = 3 => e = 0, f = 0, g = 1 OR e = 1, f = 1, g = 0 => t = 1
        0, // e + 2f + 3g = 4 => e = 1, f = 0, g = 1 => t = 0
        1, // e + 2f + 3g = 5 => e = 0, f = 1, g = 1 => t = 1
        1, // e + 2f + 3g = 6 => e = 1, f = 1, g = 1 => t = 1
        /* xor result = 1 */
        1, // e + 2f + 3g = 0 => e = 0, f = 0, g = 0 => t = 0
        1, // e + 2f + 3g = 1 => e = 1, f = 0, g = 0 => t = 0
        1, // e + 2f + 3g = 2 => e = 0, f = 1, g = 0 => t = 0
        2, // e + 2f + 3g = 3 => e = 0, f = 0, g = 1 OR e = 1, f = 1, g = 0 => t = 1
        1, // e + 2f + 3g = 4 => e = 1, f = 0, g = 1 => t = 0
        2, // e + 2f + 3g = 5 => e = 0, f = 1, g = 1 => t = 1
        2, // e + 2f + 3g = 6 => e = 1, f = 1, g = 1 => t = 1
        /* xor result = 2 */
        0, // e + 2f + 3g = 0 => e = 0, f = 0, g = 0 => t = 0
        0, // e + 2f + 3g = 1 => e = 1, f = 0, g = 0 => t = 0
        0, // e + 2f + 3g = 2 => e = 0, f = 1, g = 0 => t = 0
        1, // e + 2f + 3g = 3 => e = 0, f = 0, g = 1 OR e = 1, f = 1, g = 0 => t = 1
        0, // e + 2f + 3g = 4 => e = 1, f = 0, g = 1 => t = 0
        1, // e + 2f + 3g = 5 => e = 0, f = 1, g = 1 => t = 1
        1, // e + 2f + 3g = 6 => e = 1, f = 1, g = 1 => t = 1
        1, // e + 2f + 3g = 0 => e = 0, f = 0, g = 0 => t = 0
        /* xor result = 3 */
        1, // e + 2f + 3g = 1 => e = 1, f = 0, g = 0 => t = 0
        1, // e + 2f + 3g = 2 => e = 0, f = 1, g = 0 => t = 0
        2, // e + 2f + 3g = 3 => e = 0, f = 0, g = 1 OR e = 1, f = 1, g = 0 => t = 1
        1, // e + 2f + 3g = 4 => e = 1, f = 0, g = 1 => t = 0
        2, // e + 2f + 3g = 5 => e = 0, f = 1, g = 1 => t = 1
        2, // e + 2f + 3g = 6 => e = 1, f = 1, g = 1 => t = 1
    ];

    const WITNESS_EXTENSION_NORMALIZATION_TABLE: [u64; 16] = [
        /* xor result = 0 */
        0, 1, 0, 1, /* xor result = 1 */
        1, 2, 1, 2, /* xor result = 2 */
        0, 1, 0, 1, /* xor result = 3 */
        1, 2, 1, 2,
    ];

    pub(crate) fn get_value_from_key<F: PrimeField, const ID: u64>(key: [u64; 2]) -> [F; 2] {
        [F::from(key[0] * 3 + key[1] * 4 + ID * 0x1337), F::zero()]
    }
    pub(crate) fn get_xor_rotate_values_from_key<
        F: PrimeField,
        const NUM_ROTATED_OUTPUT_BITS: u64,
    >(
        key: [u64; 2],
    ) -> [F; 2] {
        [
            F::from((key[0] ^ key[1]).rotate_right(NUM_ROTATED_OUTPUT_BITS as u32)),
            F::zero(),
        ]
    }
    pub(crate) fn get_and_rotate_values_from_key<
        F: PrimeField,
        const NUM_ROTATED_OUTPUT_BITS: u64,
    >(
        key: [u64; 2],
    ) -> [F; 2] {
        [
            F::from((key[0] & key[1]).rotate_right(NUM_ROTATED_OUTPUT_BITS as u32)),
            F::zero(),
        ]
    }

    pub(crate) fn get_basic_fixed_base_table_values<
        C: CurveGroup,
        const MULTITABLE_INDEX: usize,
        const TABLE_INDEX: usize,
    >(
        key: [u64; 2],
    ) -> [C::BaseField; 2] {
        assert!(MULTITABLE_INDEX < FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES);
        assert!(TABLE_INDEX < FixedBaseParams::get_num_bits_of_multi_table(MULTITABLE_INDEX));

        let tables = generators::generate_fixed_base_tables::<C>();
        let basic_table = &tables[MULTITABLE_INDEX][TABLE_INDEX];

        let index = key[0] as usize;
        let point = &basic_table[index];
        let (x, y) = point.xy().unwrap_or_default();
        [x, y]
    }

    pub(crate) fn get_sparse_table_with_rotation_values<
        F: PrimeField,
        const BASE: u64,
        const NUM_ROTATED_BITS: u64,
    >(
        key: [u64; 2],
    ) -> [F; 2] {
        let t0 = Utils::map_into_sparse_form::<BASE>(key[0]);
        let t1 = if NUM_ROTATED_BITS > 0 {
            Utils::map_into_sparse_form::<BASE>(
                (key[0] as u32).rotate_right(NUM_ROTATED_BITS as u32) as u64,
            )
        } else {
            t0.clone()
        };
        [F::from(t0), F::from(t1)]
    }

    pub(crate) fn get_sparse_normalization_values<F: PrimeField, const BASE: u64>(
        key: [u64; 2],
        base_table: &[u64],
    ) -> [F; 2] {
        let mut accumulator = 0u64;
        let mut input = key[0];
        let mut count = 0u64;
        while input > 0 {
            let slice = input % BASE;
            let bit = base_table[slice as usize];
            accumulator += bit << count;
            input -= slice;
            input /= BASE;
            count += 1;
        }
        [F::from(accumulator), F::zero()]
    }

    pub(crate) fn get_sparse_normalization_values_wtns<F: PrimeField, const BASE: u64>(
        key: [u64; 2],
    ) -> [F; 2] {
        Self::get_sparse_normalization_values::<F, BASE>(
            key,
            &Self::WITNESS_EXTENSION_NORMALIZATION_TABLE,
        )
    }

    pub(crate) fn get_sparse_normalization_values_choose<F: PrimeField, const BASE: u64>(
        key: [u64; 2],
    ) -> [F; 2] {
        Self::get_sparse_normalization_values::<F, BASE>(key, &Self::CHOOSE_NORMALIZATION_TABLE)
    }

    pub(crate) fn get_sparse_normalization_values_maj<F: PrimeField, const BASE: u64>(
        key: [u64; 2],
    ) -> [F; 2] {
        Self::get_sparse_normalization_values::<F, BASE>(key, &Self::MAJORITY_NORMALIZATION_TABLE)
    }

    pub(crate) fn get_xor_rotate_values_from_key_with_filter<
        F: PrimeField,
        const NUM_ROTATED_OUTPUT_BITS: u64,
        const FILTER: bool,
    >(
        key: [u64; 2],
    ) -> [F; 2] {
        let filtered_key0 = if FILTER { key[0] & 3 } else { key[0] };
        let filtered_key1 = if FILTER { key[1] & 3 } else { key[1] };
        [
            F::from(
                ((filtered_key0 as u32) ^ (filtered_key1 as u32))
                    .rotate_right(NUM_ROTATED_OUTPUT_BITS as u32),
            ),
            F::zero(),
        ]
    }
}

pub(crate) struct FixedBaseParams {}

#[expect(dead_code)]
impl FixedBaseParams {
    pub(crate) const BITS_PER_TABLE: usize = 9;
    const BITS_ON_CURVE: usize = 254;

    // We split 1 254-bit scalar mul into two scalar muls of size BITS_PER_LO_SCALAR, BITS_PER_HI_SCALAR.
    // This enables us to efficiently decompose our input scalar multiplier into two chunks of a known size.
    // (i.e. we get free BITS_PER_LO_SCALAR, BITS_PER_HI_SCALAR range checks as part of the lookup table subroutine)
    // This in turn allows us to perform a primality test more efficiently.
    // i.e. check that input scalar < prime modulus when evaluated over the integers
    // (the primality check requires us to split the input into high / low bit chunks so getting this for free as part
    // of the lookup algorithm is nice!)
    pub(crate) const BITS_PER_LO_SCALAR: usize = 128;
    pub(crate) const BITS_PER_HI_SCALAR: usize = Self::BITS_ON_CURVE - Self::BITS_PER_LO_SCALAR;
    // max table size because the last lookup table might be smaller (BITS_PER_TABLE does not neatly divide
    // BITS_PER_LO_SCALAR)
    pub(crate) const MAX_TABLE_SIZE: usize = 1 << Self::BITS_PER_TABLE;
    // how many BITS_PER_TABLE lookup tables do we need to traverse BITS_PER_LO_SCALAR-amount of bits?
    // (we implicitly assume BITS_PER_LO_SCALAR > BITS_PER_HI_SCALAR)
    const MAX_NUM_TABLES_IN_MULTITABLE: usize = (Self::BITS_PER_LO_SCALAR / Self::BITS_PER_TABLE)
        + (if Self::BITS_PER_LO_SCALAR % Self::BITS_PER_TABLE == 0 {
            0
        } else {
            1
        });
    const NUM_POINTS: usize = 2;
    // how many multitables are we creating? It's 4 because we want enough lookup tables to cover two field elements,
    // two field elements = 2 scalar muls = 4 scalar mul hi/lo slices = 4 multitables
    pub(crate) const NUM_FIXED_BASE_MULTI_TABLES: usize = Self::NUM_POINTS * 2;
    const NUM_TABLES_PER_LO_MULTITABLE: usize = (Self::BITS_PER_LO_SCALAR / Self::BITS_PER_TABLE)
        + (if Self::BITS_PER_LO_SCALAR % Self::BITS_PER_TABLE == 0 {
            0
        } else {
            1
        });
    const NUM_TABLES_PER_HI_MULTITABLE: usize = (Self::BITS_PER_HI_SCALAR / Self::BITS_PER_TABLE)
        + (if Self::BITS_PER_HI_SCALAR % Self::BITS_PER_TABLE == 0 {
            0
        } else {
            1
        });
    // how many lookups are required to perform a scalar mul of a field element with a base point?
    const NUM_BASIC_TABLES_PER_BASE_POINT: usize =
        (Self::NUM_TABLES_PER_LO_MULTITABLE + Self::NUM_TABLES_PER_HI_MULTITABLE);
    // how many basic lookup tables are we creating in total to support fixed-base-scalar-muls over two precomputed base
    // points.
    const NUM_FIXED_BASE_BASIC_TABLES: usize =
        Self::NUM_BASIC_TABLES_PER_BASE_POINT * Self::NUM_POINTS;

    pub(crate) const fn get_num_tables_per_multi_table<const NUM_BITS: usize>() -> usize {
        (NUM_BITS / Self::BITS_PER_TABLE)
            + if NUM_BITS % Self::BITS_PER_TABLE == 0 {
                0
            } else {
                1
            }
    }

    const fn get_num_bits_of_multi_table(multitable_index: usize) -> usize {
        assert!(multitable_index < Self::NUM_FIXED_BASE_MULTI_TABLES);
        match multitable_index {
            0 => Self::BITS_PER_LO_SCALAR,
            1 => Self::BITS_PER_HI_SCALAR,
            2 => Self::BITS_PER_LO_SCALAR,
            3 => Self::BITS_PER_HI_SCALAR,
            _ => unreachable!(),
        }
    }
}

#[expect(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MultiTableId {
    Sha256ChInput,
    Sha256ChOutput,
    Sha256MajInput,
    Sha256MajOutput,
    Sha256WitnessInput,
    Sha256WitnessOutput,
    AesNormalize,
    AesInput,
    AesSbox,
    FixedBaseLeftLo,
    FixedBaseLeftHi,
    FixedBaseRightLo,
    FixedBaseRightHi,
    Uint32Xor,
    Uint32And,
    Bn254Xlo,
    Bn254Xhi,
    Bn254Ylo,
    Bn254Yhi,
    Bn254Pyrite,
    Bn254XloEndo,
    Bn254XhiEndo,
    Bn254XyprimeEndo,
    Secp256k1Xlo,
    Secp256k1Xhi,
    Secp256k1Ylo,
    Secp256k1Yhi,
    Secp256k1Xyprime,
    Secp256k1XloEndo,
    Secp256k1XhiEndo,
    Secp256k1XyprimeEndo,
    BlakeXor,
    BlakeXorRotate16,
    BlakeXorRotate8,
    BlakeXorRotate7,
    PedersenIv,
    HonkDummyMulti,
    KeccakThetaOutput,
    KeccakChiOutput,
    KeccakFormatInput,
    KeccakFormatOutput,
    KeccakNormalizeAndRotate,
    NumMultiTables = MultiTableId::KeccakNormalizeAndRotate as isize + 25,
}
const BITS_IN_LAST_SLICE: usize = 5;
const SIZE_OF_LAST_SLICE: usize = 1 << BITS_IN_LAST_SLICE;

impl From<MultiTableId> for usize {
    fn from(id: MultiTableId) -> usize {
        id as usize
    }
}

pub(crate) struct Plookup<F: PrimeField> {
    pub(crate) multi_tables: [PlookupMultiTable<F>; MultiTableId::NumMultiTables as usize],
}

impl<F: PrimeField> Plookup<F> {
    pub(crate) fn new<P: HonkCurve<TranscriptFieldType, ScalarField = F>>() -> Self {
        Self {
            multi_tables: Self::init_multi_tables::<P>(),
        }
    }

    fn get_honk_dummy_multitable() -> PlookupMultiTable<F> {
        let id = MultiTableId::HonkDummyMulti;
        let number_of_elements_in_argument = 1 << 1; // Probably has to be a power of 2
        let number_of_elements_in_argument_f = F::from(number_of_elements_in_argument);
        let number_of_lookups = 2;
        let mut table = PlookupMultiTable::new(
            id,
            number_of_elements_in_argument_f,
            number_of_elements_in_argument_f,
            number_of_elements_in_argument_f,
            number_of_lookups,
        );
        table.slice_sizes.push(number_of_elements_in_argument);
        table.basic_table_ids.push(BasicTableId::HonkDummyBasic1);
        table
            .get_table_values
            .push(BasicTableId::get_value_from_key::<F, { BasicTableId::HonkDummyBasic1 as u64 }>);
        table.slice_sizes.push(number_of_elements_in_argument);
        table.basic_table_ids.push(BasicTableId::HonkDummyBasic2);
        table
            .get_table_values
            .push(BasicTableId::get_value_from_key::<F, { BasicTableId::HonkDummyBasic2 as u64 }>);
        table
    }

    fn get_uint32_xor_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::Uint32Xor;
        const TABLE_BIT_SIZE: usize = 6;
        let num_entries = 32 / TABLE_BIT_SIZE;
        let base = 1 << TABLE_BIT_SIZE;
        let mut table =
            PlookupMultiTable::<F>::new(id, base.into(), base.into(), base.into(), num_entries);

        for _ in 0..num_entries {
            table.slice_sizes.push(base);
            table
                .basic_table_ids
                .push(BasicTableId::UintXorSlice6Rotate0);
            table
                .get_table_values
                .push(BasicTableId::get_xor_rotate_values_from_key::<F, 0>);
        }

        // 32 = 5 * 6 + 2
        // all remaining bits
        let last_table_bit_size: usize = 32 - TABLE_BIT_SIZE * num_entries;
        let last_slice_size: usize = 1 << last_table_bit_size;
        table.slice_sizes.push(last_slice_size as u64);
        table
            .basic_table_ids
            .push(BasicTableId::UintXorSlice2Rotate0);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key::<F, 0>);
        table
    }

    fn get_uint32_and_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::Uint32And;
        const TABLE_BIT_SIZE: usize = 6;
        let num_entries = 32 / TABLE_BIT_SIZE;
        let base = 1 << TABLE_BIT_SIZE;
        let mut table =
            PlookupMultiTable::<F>::new(id, base.into(), base.into(), base.into(), num_entries);

        for _ in 0..num_entries {
            table.slice_sizes.push(base);
            table
                .basic_table_ids
                .push(BasicTableId::UintAndSlice6Rotate0);
            table
                .get_table_values
                .push(BasicTableId::get_and_rotate_values_from_key::<F, 0>);
        }

        // 32 = 5 * 6 + 2
        // all remaining bits
        let last_table_bit_size: usize = 32 - TABLE_BIT_SIZE * num_entries;
        let last_slice_size: usize = 1 << last_table_bit_size;
        table.slice_sizes.push(last_slice_size as u64);
        table
            .basic_table_ids
            .push(BasicTableId::UintAndSlice2Rotate0);
        table
            .get_table_values
            .push(BasicTableId::get_and_rotate_values_from_key::<F, 0>);
        table
    }

    fn make_fixed_base_function_pointer_table<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        const MULTITABLE_INDEX: usize,
    >() -> [fn([u64; 2]) -> [F; 2]; FixedBaseParams::MAX_NUM_TABLES_IN_MULTITABLE] {
        [
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 0>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 1>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 2>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 3>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 4>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 5>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 6>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 7>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 8>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 9>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 10>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 11>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 12>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 13>,
            BasicTableId::get_basic_fixed_base_table_values::<P::CycleGroup, MULTITABLE_INDEX, 14>,
        ]
    }

    fn get_fixed_base_table<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        const MULTITABLE_INDEX: usize,
        const NUM_BITS: usize,
    >(
        id: MultiTableId,
    ) -> PlookupMultiTable<F> {
        assert!(
            NUM_BITS == FixedBaseParams::BITS_PER_LO_SCALAR
                || NUM_BITS == FixedBaseParams::BITS_PER_HI_SCALAR
        );
        let num_tables = FixedBaseParams::get_num_tables_per_multi_table::<NUM_BITS>();

        let basic_table_ids = [
            BasicTableId::FixedBase0_0,
            BasicTableId::FixedBase1_0,
            BasicTableId::FixedBase2_0,
            BasicTableId::FixedBase3_0,
        ];

        let get_values_from_key_table =
            Self::make_fixed_base_function_pointer_table::<P, MULTITABLE_INDEX>();

        let mut table = PlookupMultiTable::new(
            id,
            F::from(FixedBaseParams::MAX_TABLE_SIZE as u64),
            F::zero(),
            F::zero(),
            num_tables,
        );
        for (i, func) in get_values_from_key_table
            .into_iter()
            .take(num_tables)
            .enumerate()
        {
            table
                .slice_sizes
                .push(FixedBaseParams::MAX_TABLE_SIZE as u64);
            table.get_table_values.push(func);
            assert!(MULTITABLE_INDEX < FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES);
            let idx = i + usize::from(basic_table_ids[MULTITABLE_INDEX].clone());
            table
                .basic_table_ids
                .push(idx.try_into().expect("Invalid BasicTableId"));
        }

        table
    }

    fn get_majority_input_table() -> PlookupMultiTable<F> {
        //   We want to tackle the SHA256 `maj` sub-algorithm
        //   This requires us to compute ((a >>> 2) ^ (a >>> 13) ^ (a >>> 22)) + ((a & b) ^ (a & c) ^ (b & c))
        //   In sparse form, we can represent this as:
        //        4 * (a >>> 2) + (a >>> 13) + (a >>> 22) +  (a + b + c)
        //   We need to determine the values of the constants (q_1, q_2, q_3) that we will be scaling our lookup values by,
        //   when assembling our accumulated sums.
        //   We need the sparse representation of `a` elsewhere in the algorithm, so the constants in columns 1 and 2 are
        //   fixed.
        let id = MultiTableId::Sha256MajInput;
        let base: u64 = 16;

        // scaling factors applied to a's sparse limbs, excluding the rotated limb
        let rot2_coefficients = [
            F::zero(),
            F::from(base.pow(11 - 2)),
            F::from(base).pow([22 - 2]),
        ];
        let rot13_coefficients = [
            F::from(base).pow([32 - 13]),
            F::zero(),
            F::from(base.pow(22 - 13)),
        ];
        let rot22_coefficients = [
            F::from(base.pow(32 - 22)),
            F::from(base).pow([32 - 22 + 11]),
            F::zero(),
        ];

        // these are the coefficients that we want
        let target_rotation_coefficients = [
            rot2_coefficients[0] + rot13_coefficients[0] + rot22_coefficients[0],
            rot2_coefficients[1] + rot13_coefficients[1] + rot22_coefficients[1],
            rot2_coefficients[2] + rot13_coefficients[2] + rot22_coefficients[2],
        ];

        let column_2_row_3_multiplier = target_rotation_coefficients[1]
            * (-F::from(base).pow([11]))
            + target_rotation_coefficients[2];

        let column_1_coefficients = [F::one(), F::from(1 << 11), F::from(1 << 22)];
        let column_2_coefficients = [F::one(), F::from(base.pow(11)), F::from(base).pow([22])];
        let column_3_coefficients = [F::one(), F::one(), F::one() + column_2_row_3_multiplier];

        let mut table = PlookupMultiTable::<F>::new_from_vec(
            id,
            column_1_coefficients.to_vec(),
            column_2_coefficients.to_vec(),
            column_3_coefficients.to_vec(),
        );
        table.id = MultiTableId::Sha256MajInput;
        table.slice_sizes = vec![(1 << 11), (1 << 11), (1 << 10)];
        table.basic_table_ids = vec![
            BasicTableId::Sha256Base16Rotate2,
            BasicTableId::Sha256Base16Rotate2,
            BasicTableId::Sha256Base16,
        ];
        table.get_table_values = vec![
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 16, 2>(key),
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 16, 2>(key),
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 16, 0>(key),
        ];
        table
    }

    fn get_majority_output_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::Sha256MajOutput;
        let num_entries = 11;
        let base = 16u64.pow(3);
        let mut table =
            PlookupMultiTable::<F>::new(id, base.into(), (1 << 3).into(), F::zero(), num_entries);

        for _ in 0..num_entries {
            table.slice_sizes.push(base);
            table.basic_table_ids.push(BasicTableId::Sha256MajNormalize);
            table.get_table_values.push(|key| {
                BasicTableId::get_sparse_normalization_values::<_, 16>(
                    key,
                    &BasicTableId::MAJORITY_NORMALIZATION_TABLE,
                )
            });
        }
        table
    }

    fn get_choose_input_table() -> PlookupMultiTable<F> {
        let base: u64 = 28;
        let id = MultiTableId::Sha256ChInput;
        // Scaling factors applied to a's sparse limbs, excluding the rotated limb
        let rot6_coefficients = [
            F::zero(),
            F::from(base.pow(11 - 6)),
            F::from(base).pow([22 - 6]),
        ];
        let rot11_coefficients = [
            F::from(base).pow([32 - 11]),
            F::zero(),
            F::from(base.pow(22 - 11)),
        ];
        let rot25_coefficients = [
            F::from(base.pow(32 - 25)),
            F::from(base).pow([32 - 25 + 11]),
            F::zero(),
        ];

        // These are the coefficients that we want
        let target_rotation_coefficients = [
            rot6_coefficients[0] + rot11_coefficients[0] + rot25_coefficients[0],
            rot6_coefficients[1] + rot11_coefficients[1] + rot25_coefficients[1],
            rot6_coefficients[2] + rot11_coefficients[2] + rot25_coefficients[2],
        ];

        let column_2_row_1_multiplier = target_rotation_coefficients[0];

        // This gives us the correct scaling factor for a0's 1st limb
        let current_coefficients = [
            column_2_row_1_multiplier,
            F::from(base.pow(11)) * column_2_row_1_multiplier,
            F::from(base).pow([22]) * column_2_row_1_multiplier,
        ];

        let column_3_row_2_multiplier = -current_coefficients[1] + target_rotation_coefficients[1];

        let column_1_coefficients = [F::one(), F::from(1 << 11), F::from(1 << 22)];
        let column_2_coefficients = [F::one(), F::from(base.pow(11)), F::from(base).pow([22])];
        let column_3_coefficients = [F::one(), column_3_row_2_multiplier + F::one(), F::one()];

        let mut table = PlookupMultiTable::<F>::new_from_vec(
            id,
            column_1_coefficients.to_vec(),
            column_2_coefficients.to_vec(),
            column_3_coefficients.to_vec(),
        );

        table.id = MultiTableId::Sha256ChInput;
        table.slice_sizes = vec![(1 << 11), (1 << 11), (1 << 10)];
        table.basic_table_ids = vec![
            BasicTableId::Sha256Base28Rotate6,
            BasicTableId::Sha256Base28,
            BasicTableId::Sha256Base28Rotate3,
        ];
        table.get_table_values = vec![
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 28, 6>(key),
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 28, 0>(key),
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 28, 3>(key),
        ];

        table
    }

    fn get_choose_output_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::Sha256ChOutput;
        let num_entries = 16;
        let base = 28u64.pow(2);
        let mut table =
            PlookupMultiTable::<F>::new(id, base.into(), (1 << 2).into(), F::zero(), num_entries);

        for _ in 0..num_entries {
            table.slice_sizes.push(base);
            table.basic_table_ids.push(BasicTableId::Sha256ChNormalize);
            table.get_table_values.push(|key| {
                BasicTableId::get_sparse_normalization_values::<_, 28>(
                    key,
                    &BasicTableId::CHOOSE_NORMALIZATION_TABLE,
                )
            });
        }
        table
    }

    fn get_witness_extension_input_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::Sha256WitnessInput;
        let column_1_coefficients = [
            F::one(),
            F::from(1 << 3),
            F::from(1 << 10),
            F::from(1 << 18),
        ];
        let column_2_coefficients = [F::zero(); 4];
        let column_3_coefficients = [F::zero(); 4];
        let mut table = PlookupMultiTable::new_from_vec(
            id,
            column_1_coefficients.to_vec(),
            column_2_coefficients.to_vec(),
            column_3_coefficients.to_vec(),
        );
        table.slice_sizes = vec![(1 << 3), (1 << 7), (1 << 8), (1 << 18)];
        table.basic_table_ids = vec![
            BasicTableId::Sha256WitnessSlice3,
            BasicTableId::Sha256WitnessSlice7Rotate4,
            BasicTableId::Sha256WitnessSlice8Rotate7,
            BasicTableId::Sha256WitnessSlice14Rotate1,
        ];
        table.get_table_values = vec![
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 16, 0>(key),
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 16, 4>(key),
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 16, 7>(key),
            |key| BasicTableId::get_sparse_table_with_rotation_values::<_, 16, 1>(key),
        ];
        table
    }

    fn get_witness_extension_output_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::Sha256WitnessOutput;
        let num_entries = 11;
        let base = 16u64.pow(3);
        let mut table =
            PlookupMultiTable::<F>::new(id, base.into(), (1 << 3).into(), F::zero(), num_entries);

        for _ in 0..num_entries {
            table.slice_sizes.push(base);
            table
                .basic_table_ids
                .push(BasicTableId::Sha256WitnessNormalize);
            table.get_table_values.push(|key| {
                BasicTableId::get_sparse_normalization_values::<_, 16>(
                    key,
                    &BasicTableId::WITNESS_EXTENSION_NORMALIZATION_TABLE,
                )
            });
        }
        table
    }

    fn get_blake2s_xor_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::BlakeXor;
        let num_entries = (32 + 2) / 6 + 1;
        let base = 1 << 6;
        let mut table =
            PlookupMultiTable::<F>::new(id, base.into(), base.into(), base.into(), num_entries);

        for _ in 0..num_entries - 1 {
            table.slice_sizes.push(base);
            table.basic_table_ids.push(BasicTableId::BlakeXorRotate0);
            table
                .get_table_values
                .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        }

        table.slice_sizes.push(SIZE_OF_LAST_SLICE as u64);
        table
            .basic_table_ids
            .push(BasicTableId::BlakeXorRotate0Slice5Mod4);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, true>);

        table
    }

    fn get_blake2s_xor_rotate_16_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::BlakeXorRotate16;
        let base = 1 << 6;
        let coefficient_16 = F::from(1u64) / F::from(1u64 << 16);

        let column_1_coefficients = [
            F::one(),
            F::from(1u64 << 6),
            F::from(1u64 << 12),
            F::from(1u64 << 18),
            F::from(1u64 << 24),
            F::from(1u64 << 30),
        ];

        let column_3_coefficients = [
            F::one(),
            F::from(1u64 << 6),
            coefficient_16,
            coefficient_16 * F::from(1u64 << 2),
            coefficient_16 * F::from(1u64 << 8),
            coefficient_16 * F::from(1u64 << 14),
        ];

        let mut table = PlookupMultiTable::new_from_vec(
            id,
            column_1_coefficients.to_vec(),
            column_1_coefficients.to_vec(),
            column_3_coefficients.to_vec(),
        );

        table.slice_sizes = vec![base, base, base, base, base, SIZE_OF_LAST_SLICE as u64];
        table.basic_table_ids = vec![
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate4,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0Slice5Mod4,
        ];

        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 4, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, true>);

        table
    }

    fn get_blake2s_xor_rotate_8_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::BlakeXorRotate8;
        let base = 1 << 6;
        let coefficient_24 = F::from(1u64) / F::from(1u64 << 24);

        let column_1_coefficients = [
            F::one(),
            F::from(1u64 << 6),
            F::from(1u64 << 12),
            F::from(1u64 << 18),
            F::from(1u64 << 24),
            F::from(1u64 << 30),
        ];

        let column_3_coefficients = [
            F::one(),
            coefficient_24,
            coefficient_24 * F::from(1u64 << 4),
            coefficient_24 * F::from(1u64 << (4 + 6)),
            coefficient_24 * F::from(1u64 << (4 + 12)),
            coefficient_24 * F::from(1u64 << (4 + 18)),
        ];

        let mut table = PlookupMultiTable::new_from_vec(
            id,
            column_1_coefficients.to_vec(),
            column_1_coefficients.to_vec(),
            column_3_coefficients.to_vec(),
        );

        table.slice_sizes = vec![base, base, base, base, base, SIZE_OF_LAST_SLICE as u64];
        table.basic_table_ids = vec![
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate2,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0Slice5Mod4,
        ];

        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 2, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, true>);

        table
    }

    fn get_blake2s_xor_rotate_7_table() -> PlookupMultiTable<F> {
        let id = MultiTableId::BlakeXorRotate7;
        let base = 1 << 6;
        let coefficient_25 = F::from(1u64) / F::from(1u64 << 25);

        let column_1_coefficients = [
            F::one(),
            F::from(1u64 << 6),
            F::from(1u64 << 12),
            F::from(1u64 << 18),
            F::from(1u64 << 24),
            F::from(1u64 << 30),
        ];

        let column_3_coefficients = [
            F::one(),
            coefficient_25,
            coefficient_25 * F::from(1u64 << 5),
            coefficient_25 * F::from(1u64 << (5 + 6)),
            coefficient_25 * F::from(1u64 << (5 + 12)),
            coefficient_25 * F::from(1u64 << (5 + 18)),
        ];

        let mut table = PlookupMultiTable::new_from_vec(
            id,
            column_1_coefficients.to_vec(),
            column_1_coefficients.to_vec(),
            column_3_coefficients.to_vec(),
        );

        table.slice_sizes = vec![base, base, base, base, base, SIZE_OF_LAST_SLICE as u64];
        table.basic_table_ids = vec![
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate1,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0,
            BasicTableId::BlakeXorRotate0Slice5Mod4,
        ];

        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 1, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, false>);
        table
            .get_table_values
            .push(BasicTableId::get_xor_rotate_values_from_key_with_filter::<F, 0, true>);

        table
    }

    fn init_multi_tables<P: HonkCurve<TranscriptFieldType, ScalarField = F>>()
    -> [PlookupMultiTable<F>; MultiTableId::NumMultiTables as usize] {
        // TACEO TODO not all are initialized here! We should probably only initialize those we need here?!
        let mut multi_tables = from_fn(|_| PlookupMultiTable::default());
        multi_tables[usize::from(MultiTableId::HonkDummyMulti)] = Self::get_honk_dummy_multitable();
        multi_tables[usize::from(MultiTableId::Uint32And)] = Self::get_uint32_and_table();
        multi_tables[usize::from(MultiTableId::Uint32Xor)] = Self::get_uint32_xor_table();
        multi_tables[usize::from(MultiTableId::FixedBaseLeftLo)] =
            Self::get_fixed_base_table::<P, 0, 128>(MultiTableId::FixedBaseLeftLo);
        multi_tables[usize::from(MultiTableId::FixedBaseLeftHi)] =
            Self::get_fixed_base_table::<P, 1, 126>(MultiTableId::FixedBaseLeftHi);
        multi_tables[usize::from(MultiTableId::FixedBaseRightLo)] =
            Self::get_fixed_base_table::<P, 2, 128>(MultiTableId::FixedBaseRightLo);
        multi_tables[usize::from(MultiTableId::FixedBaseRightHi)] =
            Self::get_fixed_base_table::<P, 3, 126>(MultiTableId::FixedBaseRightHi);
        multi_tables[usize::from(MultiTableId::Sha256MajInput)] = Self::get_majority_input_table();
        multi_tables[usize::from(MultiTableId::Sha256MajOutput)] =
            Self::get_majority_output_table();
        multi_tables[usize::from(MultiTableId::Sha256ChInput)] = Self::get_choose_input_table();
        multi_tables[usize::from(MultiTableId::Sha256ChOutput)] = Self::get_choose_output_table();
        multi_tables[usize::from(MultiTableId::Sha256WitnessInput)] =
            Self::get_witness_extension_input_table();
        multi_tables[usize::from(MultiTableId::Sha256WitnessOutput)] =
            Self::get_witness_extension_output_table();
        multi_tables[usize::from(MultiTableId::BlakeXor)] = Self::get_blake2s_xor_table();
        multi_tables[usize::from(MultiTableId::BlakeXorRotate16)] =
            Self::get_blake2s_xor_rotate_16_table();
        multi_tables[usize::from(MultiTableId::BlakeXorRotate8)] =
            Self::get_blake2s_xor_rotate_8_table();
        multi_tables[usize::from(MultiTableId::BlakeXorRotate7)] =
            Self::get_blake2s_xor_rotate_7_table();

        multi_tables
    }

    pub(crate) fn get_multitable(&self, id: MultiTableId) -> &PlookupMultiTable<F> {
        assert!(
            matches!(
                id,
                MultiTableId::HonkDummyMulti
                    | MultiTableId::Uint32And
                    | MultiTableId::Uint32Xor
                    | MultiTableId::FixedBaseLeftLo
                    | MultiTableId::FixedBaseLeftHi
                    | MultiTableId::FixedBaseRightLo
                    | MultiTableId::FixedBaseRightHi
                    | MultiTableId::Sha256MajInput
                    | MultiTableId::Sha256MajOutput
                    | MultiTableId::Sha256ChInput
                    | MultiTableId::Sha256ChOutput
                    | MultiTableId::Sha256WitnessInput
                    | MultiTableId::Sha256WitnessOutput
                    | MultiTableId::BlakeXor
                    | MultiTableId::BlakeXorRotate16
                    | MultiTableId::BlakeXorRotate7
                    | MultiTableId::BlakeXorRotate8
            ),
            "Multitable for {id:?} not implemented"
        ); // The only ones implemented so far
        &self.multi_tables[usize::from(id)]
    }

    fn slice_input_using_variable_bases(input: BigUint, bases: &[u64]) -> Vec<u64> {
        let mut target = input;
        let mut slices = Vec::with_capacity(bases.len());
        for i in 0..bases.len() {
            if target >= bases[i].into() && i == bases.len() - 1 {
                panic!("Last key slice greater than {}", bases[i]);
            }
            slices.push((&target % bases[i]).try_into().unwrap());
            target /= bases[i];
        }
        slices
    }

    pub(crate) fn lookup_table_exists_for_point<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
    >(
        point: <P::CycleGroup as CurveGroup>::Affine,
    ) -> bool {
        let generators = generators::default_generators::<P::CycleGroup>();
        point == generators[0] || point == generators[1]
    }

    pub(crate) fn get_lookup_table_ids_for_point<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
    >(
        point: <P::CycleGroup as CurveGroup>::Affine,
    ) -> Option<(MultiTableId, MultiTableId)> {
        let generators = generators::default_generators::<P::CycleGroup>();
        if point == generators[0] {
            Some((MultiTableId::FixedBaseLeftLo, MultiTableId::FixedBaseLeftHi))
        } else if point == generators[1] {
            Some((
                MultiTableId::FixedBaseRightLo,
                MultiTableId::FixedBaseRightHi,
            ))
        } else {
            None
        }
    }

    pub(crate) fn get_generator_offset_for_table_id<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
    >(
        id: MultiTableId,
    ) -> Option<P::CycleGroup> {
        let offsets_generators = generators::fixed_base_table_offset_generators::<P::CycleGroup>();

        match id {
            MultiTableId::FixedBaseLeftLo => Some(offsets_generators[0].to_owned()),
            MultiTableId::FixedBaseLeftHi => Some(offsets_generators[1].to_owned()),
            MultiTableId::FixedBaseRightLo => Some(offsets_generators[2].to_owned()),
            MultiTableId::FixedBaseRightHi => Some(offsets_generators[3].to_owned()),
            _ => None,
        }
    }

    #[expect(clippy::type_complexity)]
    fn slice_and_get_values<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
        id: MultiTableId,
        key_a: T::AcvmType,
        key_b: T::AcvmType,
    ) -> std::io::Result<(
        Vec<(T::AcvmType, T::AcvmType)>,
        Vec<T::AcvmType>,
        Vec<T::AcvmType>,
    )> {
        let multi_table = builder.plookup.get_multitable(id.clone());
        let num_lookups = multi_table.basic_table_ids.len();
        let bases = &multi_table.slice_sizes;
        let mut results = Vec::with_capacity(bases.len());
        let mut key_a_slices = Vec::with_capacity(bases.len());
        let mut key_b_slices = Vec::with_capacity(bases.len());
        if !T::is_shared(&key_a) && !T::is_shared(&key_b) {
            let key_a_slice = Self::slice_input_using_variable_bases(
                T::get_public(&key_a)
                    .expect("Already checked it is public")
                    .into(),
                &multi_table.slice_sizes,
            );
            let key_b_slice = Self::slice_input_using_variable_bases(
                T::get_public(&key_b)
                    .expect("Already checked it is public")
                    .into(),
                &multi_table.slice_sizes,
            );

            for i in 0..num_lookups {
                let values = multi_table.get_table_values[i]([key_a_slice[i], key_b_slice[i]]);
                results.push((values[0].into(), values[1].into()));
            }
            key_a_slices = key_a_slice
                .iter()
                .map(|&x| T::AcvmType::from(F::from(x)))
                .collect();
            key_b_slices = key_b_slice
                .iter()
                .map(|&x| T::AcvmType::from(F::from(x)))
                .collect();

            return Ok((results, key_a_slices, key_b_slices));
        }

        // At least one key is shared, so we have to do something different

        // the case shared/public can probably be optimised (or never happens?)
        let key_a = GenericUltraCircuitBuilder::<P, T>::get_as_shared(&key_a, driver);
        let key_b = GenericUltraCircuitBuilder::<P, T>::get_as_shared(&key_b, driver);

        match multi_table.id {
            MultiTableId::Uint32Xor => {
                let values = T::slice_and_get_xor_rotate_values(
                    driver,
                    key_a,
                    key_b,
                    bases[0].ilog2() as usize,
                    32,
                    0,
                )?;
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }

            MultiTableId::Uint32And => {
                let values = T::slice_and_get_and_rotate_values(
                    driver,
                    key_a,
                    key_b,
                    bases[0].ilog2() as usize,
                    32,
                    0,
                )?;
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }
            MultiTableId::FixedBaseLeftLo => {
                Self::get_fixed_base_table_values::<P, T>(
                    bases,
                    key_a,
                    key_b,
                    0,
                    &mut key_a_slices,
                    &mut key_b_slices,
                    &mut results,
                    driver,
                )?;
            }
            MultiTableId::FixedBaseLeftHi => {
                Self::get_fixed_base_table_values::<P, T>(
                    bases,
                    key_a,
                    key_b,
                    1,
                    &mut key_a_slices,
                    &mut key_b_slices,
                    &mut results,
                    driver,
                )?;
            }
            MultiTableId::FixedBaseRightLo => {
                Self::get_fixed_base_table_values::<P, T>(
                    bases,
                    key_a,
                    key_b,
                    2,
                    &mut key_a_slices,
                    &mut key_b_slices,
                    &mut results,
                    driver,
                )?;
            }
            MultiTableId::FixedBaseRightHi => {
                Self::get_fixed_base_table_values::<P, T>(
                    bases,
                    key_a,
                    key_b,
                    3,
                    &mut key_a_slices,
                    &mut key_b_slices,
                    &mut results,
                    driver,
                )?;
            }

            MultiTableId::Sha256ChInput => {
                let base = bases[0].next_power_of_two().ilog2() as usize;
                let total_bit_size = std::cmp::max(base * bases.len(), 64);
                let rotation = [6, 0, 3];
                let values = T::slice_and_get_sparse_table_with_rotation_values(
                    driver,
                    key_a,
                    key_b,
                    bases,
                    &rotation,
                    total_bit_size,
                    28,
                )?;
                for (a, b) in values.0.into_iter().zip(values.1) {
                    results.push((a, b));
                }

                key_a_slices.extend(values.2);
                key_b_slices.extend(values.3);
            }
            MultiTableId::Sha256ChOutput => {
                let base = bases[0].next_power_of_two().ilog2() as usize;
                let total_bit_size = base * bases.len();
                let values = T::slice_and_get_sparse_normalization_values(
                    driver,
                    key_a,
                    key_b,
                    bases,
                    28,
                    total_bit_size,
                    &SHA256Table::Choose,
                )?;
                results.reserve(values.0.len());
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }
            MultiTableId::Sha256MajInput => {
                let base = bases[0].next_power_of_two().ilog2() as usize;
                let total_bit_size = std::cmp::max(base * bases.len(), 64);
                let rotation = [2, 2, 0];
                let values = T::slice_and_get_sparse_table_with_rotation_values(
                    driver,
                    key_a,
                    key_b,
                    bases,
                    &rotation,
                    total_bit_size,
                    16,
                )?;
                for (a, b) in values.0.into_iter().zip(values.1) {
                    results.push((a, b));
                }

                key_a_slices.extend(values.2);
                key_b_slices.extend(values.3);
            }
            MultiTableId::Sha256MajOutput => {
                let base = bases[0].next_power_of_two().ilog2() as usize;
                let total_bit_size = base * bases.len();
                let values = T::slice_and_get_sparse_normalization_values(
                    driver,
                    key_a,
                    key_b,
                    bases,
                    16,
                    total_bit_size,
                    &SHA256Table::Majority,
                )?;
                results.reserve(values.0.len());
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }
            MultiTableId::Sha256WitnessInput => {
                let base = bases[0].next_power_of_two().ilog2() as usize;
                let total_bit_size = std::cmp::max(base * bases.len(), 64);
                let rotation = [0, 4, 7, 1];
                let values = T::slice_and_get_sparse_table_with_rotation_values(
                    driver,
                    key_a,
                    key_b,
                    bases,
                    &rotation,
                    total_bit_size,
                    16,
                )?;
                for (a, b) in values.0.into_iter().zip(values.1) {
                    results.push((a, b));
                }

                key_a_slices.extend(values.2);
                key_b_slices.extend(values.3);
            }
            MultiTableId::Sha256WitnessOutput => {
                let base = bases[0].next_power_of_two().ilog2() as usize;
                let total_bit_size = base * bases.len();
                let values = T::slice_and_get_sparse_normalization_values(
                    driver,
                    key_a,
                    key_b,
                    bases,
                    16,
                    total_bit_size,
                    &SHA256Table::WitnessExtension,
                )?;
                results.reserve(values.0.len());
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }

            MultiTableId::BlakeXor => {
                let len = multi_table.slice_sizes.len();
                let filter = [false, false, false, false, false, true];
                let values = T::slice_and_get_xor_rotate_values_with_filter(
                    driver,
                    key_a,
                    key_b,
                    bases,
                    &vec![0; len],
                    &filter,
                )?;
                results.reserve(values.0.len());
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }
            MultiTableId::BlakeXorRotate16 => {
                let filter = [false, false, false, false, false, true];
                let rotation = [0, 0, 4, 0, 0, 0];
                let values = T::slice_and_get_xor_rotate_values_with_filter(
                    driver, key_a, key_b, bases, &rotation, &filter,
                )?;
                results.reserve(values.0.len());
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }
            MultiTableId::BlakeXorRotate8 => {
                let filter = [false, false, false, false, false, true];
                let rotation = [0, 2, 0, 0, 0, 0];
                let values = T::slice_and_get_xor_rotate_values_with_filter(
                    driver, key_a, key_b, bases, &rotation, &filter,
                )?;
                results.reserve(values.0.len());
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }
            MultiTableId::BlakeXorRotate7 => {
                let filter = [false, false, false, false, false, true];
                let rotation = [0, 1, 0, 0, 0, 0];
                let values = T::slice_and_get_xor_rotate_values_with_filter(
                    driver, key_a, key_b, bases, &rotation, &filter,
                )?;
                results.reserve(values.0.len());
                for val in values.0 {
                    results.push((val, T::public_zero()))
                }
                key_a_slices.extend(values.1);
                key_b_slices.extend(values.2);
            }

            _ => todo!("{:?} not yet implemented", multi_table.id),
        }

        Ok((results, key_a_slices, key_b_slices))
    }

    #[expect(clippy::too_many_arguments)]
    fn get_fixed_base_table_values<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        bases: &[u64],
        key_a: T::ArithmeticShare,
        _key_b: T::ArithmeticShare,
        multitable_index: usize,
        key_a_slices: &mut Vec<T::AcvmType>,
        key_b_slices: &mut Vec<T::AcvmType>,
        results: &mut Vec<(T::AcvmType, T::AcvmType)>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        assert!(multitable_index < FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES);

        let bitsize = bases[0].ilog2() as usize;
        let total_size = bitsize * bases.len();
        let key_a_slices_ = driver.decompose_arithmetic(key_a, total_size, bitsize)?;
        for slice in key_a_slices_ {
            key_a_slices.push(slice.into());
        }
        key_b_slices.resize(bases.len(), T::public_zero());

        let tables = &generators::generate_fixed_base_tables::<P::CycleGroup>()[multitable_index];

        for (key, table) in key_a_slices.iter().zip(tables.iter()) {
            // Create the tables since the table itself only stores points and not fields
            let mut lut1 = Vec::with_capacity(table.len());
            let mut lut2 = Vec::with_capacity(table.len());
            for point in table.iter() {
                let (x, y) = point.xy().unwrap_or_default();
                lut1.push(x);
                lut2.push(y);
            }

            let output = driver.read_from_public_luts(key.to_owned(), &[lut1, lut2])?;
            debug_assert_eq!(output.len(), 2);
            results.push((output[0].clone(), output[1].clone()));
        }
        Ok(())
    }

    pub(crate) fn get_lookup_accumulators<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
        id: MultiTableId,
        key_a: T::AcvmType,
        key_b: T::AcvmType,
        is_2_to_1_lookup: bool,
    ) -> std::io::Result<ReadData<T::AcvmType>> {
        let mut lookup = ReadData::default();
        let values_sliced = Self::slice_and_get_values(builder, driver, id.clone(), key_a, key_b)?;

        // return multi-table, populating global array of all multi-tables if need be
        let multi_table = builder.plookup.get_multitable(id);
        let num_lookups = multi_table.basic_table_ids.len();

        let key_a_slices = values_sliced.1;
        let key_b_slices = values_sliced.2;
        let values_sliced = values_sliced.0;
        let mut column_1_raw_values = Vec::with_capacity(num_lookups);
        let mut column_2_raw_values = Vec::with_capacity(num_lookups);
        let mut column_3_raw_values = Vec::with_capacity(num_lookups);

        for i in 0..num_lookups {
            // compute the value(s) corresponding to the key(s) using the i-th basic table query function

            column_1_raw_values.push(key_a_slices[i].clone());
            column_2_raw_values.push(if is_2_to_1_lookup {
                key_b_slices[i].clone()
            } else {
                values_sliced[i].0.clone()
            });
            column_3_raw_values.push(if is_2_to_1_lookup {
                values_sliced[i].0.clone()
            } else {
                values_sliced[i].1.clone()
            });

            // Store the lookup entries for use in constructing the sorted table/lookup polynomials later on
            let lookup_entry = LookupEntry::<T::AcvmType> {
                key: [key_a_slices[i].clone(), key_b_slices[i].clone()],
                value: values_sliced[i].clone().into(),
            };
            lookup.lookup_entries.push(lookup_entry);
        }

        lookup[ColumnIdx::C1].resize(num_lookups, Default::default());
        lookup[ColumnIdx::C2].resize(num_lookups, Default::default());
        lookup[ColumnIdx::C3].resize(num_lookups, Default::default());

        // /**
        //  * A multi-table consists of multiple basic tables (say L = 6).
        //  *
        //  *             [      ]                [      ]
        //  *     [      ]|      |[      ][      ]|      |[      ]
        //  * M ≡ |  B1  ||  B2  ||  B3  ||  B4  ||  B5  ||  B6  |
        //  *     [      ]|      |[      ][      ]|      |[      ]
        //  *             [      ]                [      ]
        //  *        |̐       |̐       |̐       |̐       |̐       |̐
        //  *        s1      s2      s3      s4      s5      s6
        //  *
        //  * Note that different basic tables can be of different sizes. Every lookup query generates L output slices (one for
        //  * each basic table, here, s1, s2, ..., s6). In other words, every lookup query adds L lookup gates to the program.
        //  * For example, to look up the XOR of 32-bit inputs, we actually perform 6 individual lookups on the 6-bit XOR basic
        //  * table. Let the input slices/keys be (a1, b1), (a2, b2), ..., (a6, b6). The lookup gate structure is as follows:
        //  *
        //  * +---+-----------------------------------+----------------------------------+-----------------------------------+
        //  * | s | key_a                             | key_b                            | output                            |
        //  * |---+-----------------------------------+----------------------------------+-----------------------------------|
        //  * | 6 | a6 + p.a5 + p^2.a4 + ... + p^5.a1 | b6 + q.b5 + qq.b4 + ... + q^5.b1 | s6 + r.s5 + r^2.s4 + ... + r^5.s1 |
        //  * | 5 | a5 + p.a4 + ...... + p^4.a1       | b5 + q.b4 + ...... + q^4.b1      | s5 + r.s4 + ...... + r^4.s1       |
        //  * | 4 | a4 + p.a3 + ... + p^3.a1          | b4 + q.b3 + ... + q^3.b1         | s4 + r.s3 + ... + r^3.s1          |
        //  * | 3 | a3 + p.a2 + p^2.a1                | b3 + q.b2 + q^2.b1               | s3 + r.s2 + r^2.s1                |
        //  * | 2 | a2 + p.a1                         | b2 + q.b1                        | s2 + r.a1                         |
        //  * | 1 | a1                                | b1                               | s1                                |
        //  * +---+-----------------------------------+----------------------------------+-----------------------------------+
        //  *
        //  * Note that we compute the accumulating sums of the slices so as to avoid using additonal gates for the purpose of
        //  * reconstructing the original inputs/outputs. I.e. the output value at the 0th index in the above table is the
        //  * actual value we were interested in computing in the first place. Importantly, the structure of the remaining rows
        //  * is such that row_i - r*row_{i+1} produces an entry {a_j, b_j, s_j} that exactly corresponds to an entry in a
        //  * BasicTable. This is what gives rise to the wire_i - scalar*wire_i_shift structure in the lookup relation. Here,
        //  * (p, q, r) are referred to as column coefficients/step sizes. In the next few lines, we compute these accumulating
        //  * sums from raw column values (a1, ..., a6), (b1, ..., b6), (s1, ..., s6) and column coefficients (p, q, r).
        //  *
        //  * For more details: see
        //  * https://app.gitbook.com/o/-LgCgJ8TCO7eGlBr34fj/s/-MEwtqp3H6YhHUTQ_pVJ/plookup-gates-for-ultraplonk/lookup-table-structures
        //  *
        //  */
        lookup[ColumnIdx::C1][num_lookups - 1] = column_1_raw_values[num_lookups - 1].clone();
        lookup[ColumnIdx::C2][num_lookups - 1] = column_2_raw_values[num_lookups - 1].clone();
        lookup[ColumnIdx::C3][num_lookups - 1] = column_3_raw_values[num_lookups - 1].clone();

        for i in (1..num_lookups).rev() {
            let tmp_mul = T::mul_with_public(
                driver,
                multi_table.column_1_step_sizes[i],
                lookup[ColumnIdx::C1][i].clone(),
            );
            lookup[ColumnIdx::C1][i - 1] =
                T::add(driver, column_1_raw_values[i - 1].clone(), tmp_mul);

            let tmp_mul = T::mul_with_public(
                driver,
                multi_table.column_2_step_sizes[i],
                lookup[ColumnIdx::C2][i].clone(),
            );
            lookup[ColumnIdx::C2][i - 1] =
                T::add(driver, column_2_raw_values[i - 1].clone(), tmp_mul);

            let tmp_mul = T::mul_with_public(
                driver,
                multi_table.column_3_step_sizes[i],
                lookup[ColumnIdx::C3][i].clone(),
            );
            lookup[ColumnIdx::C3][i - 1] =
                T::add(driver, column_3_raw_values[i - 1].clone(), tmp_mul);
        }

        Ok(lookup)
    }

    pub(crate) fn get_lookup_accumulators_ct<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
        id: MultiTableId,
        key_a: &FieldCT<F>,
        key_b: &FieldCT<F>,
        is_2_to_1_lookup: bool,
    ) -> std::io::Result<ReadData<FieldCT<F>>> {
        let key_a = key_a.normalize(builder, driver);
        let key_b = key_b.normalize(builder, driver);

        let a = key_a.get_value(builder, driver);
        let b = key_b.get_value(builder, driver);

        let mut lookup = ReadData::default();

        let lookup_data = Self::get_lookup_accumulators(
            builder,
            driver,
            id.clone(),
            a.to_owned(),
            b.to_owned(),
            is_2_to_1_lookup,
        )?;

        let is_key_a_constant = key_a.is_constant();
        let length = lookup_data[ColumnIdx::C1].len();
        if is_key_a_constant && (key_b.is_constant() || !is_2_to_1_lookup) {
            for i in 0..length {
                lookup[ColumnIdx::C1].push(FieldCT::from(
                    T::get_public(&lookup_data[ColumnIdx::C1][i])
                        .expect("Constant should be public"),
                ));
                lookup[ColumnIdx::C2].push(FieldCT::from(
                    T::get_public(&lookup_data[ColumnIdx::C2][i])
                        .expect("Constant should be public"),
                ));
                lookup[ColumnIdx::C3].push(FieldCT::from(
                    T::get_public(&lookup_data[ColumnIdx::C3][i])
                        .expect("Constant should be public"),
                ));
            }
        } else {
            let mut lhs_index = key_a.witness_index;
            let mut rhs_index = key_b.witness_index;
            // If only one lookup key is constant, we need to instantiate it as a real witness lookup_data[ColumnIdx::C1][i]
            if is_key_a_constant {
                lhs_index = builder
                    .put_constant_variable(T::get_public(&a).expect("Constant should be public"));
            }
            if key_b.is_constant() && is_2_to_1_lookup {
                rhs_index = builder
                    .put_constant_variable(T::get_public(&b).expect("Constant should be public"));
            }

            let mut key_b_witness = Some(rhs_index);

            if rhs_index == FieldCT::<F>::IS_CONSTANT {
                key_b_witness = None;
            }
            let accumulator_witnesses = builder.create_gates_from_plookup_accumulators(
                id,
                lookup_data,
                lhs_index,
                key_b_witness,
            );

            for i in 0..length {
                lookup[ColumnIdx::C1].push(FieldCT::<F>::from_witness_index(
                    accumulator_witnesses[ColumnIdx::C1][i],
                ));
                lookup[ColumnIdx::C2].push(FieldCT::<F>::from_witness_index(
                    accumulator_witnesses[ColumnIdx::C2][i],
                ));
                lookup[ColumnIdx::C3].push(FieldCT::<F>::from_witness_index(
                    accumulator_witnesses[ColumnIdx::C3][i],
                ));
            }
        }
        Ok(lookup)
    }

    pub fn read_from_2_to_1_table<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
        id: MultiTableId,
        key_a: &FieldCT<F>,
        key_b: &FieldCT<F>,
    ) -> std::io::Result<FieldCT<F>> {
        let lookup = Self::get_lookup_accumulators_ct(builder, driver, id, key_a, key_b, true)?;
        Ok(lookup[ColumnIdx::C3][0].clone())
    }

    pub fn read_from_1_to_2_table<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
        id: MultiTableId,
        key_a: &FieldCT<F>,
    ) -> std::io::Result<FieldCT<F>> {
        let lookup = Plookup::<F>::get_lookup_accumulators_ct(
            builder,
            driver,
            id,
            key_a,
            &FieldCT::default(),
            false,
        )?;
        Ok(lookup[ColumnIdx::C2][0].clone())
    }
}

#[derive(Clone)]
pub(crate) struct LookupEntry<F: Clone> {
    pub(crate) key: [F; 2],
    pub(crate) value: [F; 2],
}

#[expect(dead_code)]
impl<F: PrimeField> LookupEntry<F> {
    pub(crate) fn to_table_components(&self, use_two_key: bool) -> [F; 3] {
        [
            self.key[0],
            if use_two_key {
                self.key[1]
            } else {
                self.value[0]
            },
            if use_two_key {
                self.value[0]
            } else {
                self.value[1]
            },
        ]
    }
}

impl<C: Clone> LookupEntry<C> {
    pub(crate) fn calculate_table_index<
        F: PrimeField,
        T: NoirWitnessExtensionProtocol<F, AcvmType = C>,
    >(
        &self,
        driver: &mut T,
        use_two_key: bool,
        base: F,
    ) -> C {
        let mut index_b = self.key[0].to_owned();
        if use_two_key {
            index_b = driver.mul_with_public(base, index_b);
            driver.add_assign(&mut index_b, self.key[1].to_owned());
        }
        index_b
    }
}

pub(crate) struct PlookupBasicTable<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) id: BasicTableId,
    pub(crate) table_index: usize,
    pub(crate) use_twin_keys: bool,
    pub(crate) column_1_step_size: P::ScalarField,
    pub(crate) column_2_step_size: P::ScalarField,
    pub(crate) column_3_step_size: P::ScalarField,
    pub(crate) column_1: Vec<P::ScalarField>,
    pub(crate) column_2: Vec<P::ScalarField>,
    pub(crate) column_3: Vec<P::ScalarField>,
    pub(crate) lookup_gates: Vec<LookupEntry<T::AcvmType>>,
    pub(crate) index_map: LookupHashMap<P::ScalarField>,
    pub(crate) get_values_from_key: fn([u64; 2]) -> [P::ScalarField; 2],
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> Default
    for PlookupBasicTable<P, T>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> PlookupBasicTable<P, T> {
    fn new() -> Self {
        Self {
            id: BasicTableId::HonkDummyBasic1,
            table_index: 0,
            use_twin_keys: false,
            column_1_step_size: P::ScalarField::zero(),
            column_2_step_size: P::ScalarField::zero(),
            column_3_step_size: P::ScalarField::zero(),
            column_1: Vec::new(),
            column_2: Vec::new(),
            column_3: Vec::new(),
            lookup_gates: Vec::new(),
            index_map: LookupHashMap::default(),
            get_values_from_key: BasicTableId::get_value_from_key::<
                P::ScalarField,
                { BasicTableId::HonkDummyBasic1 as u64 },
            >,
        }
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> PlookupBasicTable<P, T> {
    pub(crate) fn len(&self) -> usize {
        assert_eq!(self.column_1.len(), self.column_2.len());
        assert_eq!(self.column_1.len(), self.column_3.len());
        self.column_1.len()
    }

    fn generate_honk_dummy_table<const ID: u64>(
        id: BasicTableId,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        // We do the assertion, since this function is templated, but the general API for these functions contains the id,
        // too. This helps us ensure that the correct instantion is used for a particular BasicTableId
        assert_eq!(ID, usize::from(id.to_owned()) as u64);
        let base = 1 << 1; // Probably has to be a power of 2
        let mut table = PlookupBasicTable::new();
        table.id = id;
        table.table_index = table_index;
        table.use_twin_keys = true;
        for i in 0..base {
            for j in 0..base {
                table.column_1.push(P::ScalarField::from(i));
                table.column_2.push(P::ScalarField::from(j));
                table
                    .column_3
                    .push(P::ScalarField::from(i * 3 + j * 4 + ID * 0x1337));
            }
        }

        table.get_values_from_key = BasicTableId::get_value_from_key::<P::ScalarField, ID>;
        let base = P::ScalarField::from(base);
        table.column_1_step_size = base;
        table.column_2_step_size = base;
        table.column_3_step_size = base;

        table
    }

    fn generate_and_rotate_table<const BITS_PER_SLICE: u64, const NUM_ROTATED_OUTPUT_BITS: u64>(
        id: BasicTableId,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        let base = 1 << BITS_PER_SLICE;
        let mut table = PlookupBasicTable::new();

        table.id = id;
        table.table_index = table_index;
        table.use_twin_keys = true;

        for i in 0..base {
            for j in 0..base {
                table.column_1.push(P::ScalarField::from(i));
                table.column_2.push(P::ScalarField::from(j));
                table.column_3.push(P::ScalarField::from(
                    ((i & j) as u64).rotate_right(NUM_ROTATED_OUTPUT_BITS as u32),
                ));
            }
        }

        table.get_values_from_key =
            BasicTableId::get_and_rotate_values_from_key::<P::ScalarField, NUM_ROTATED_OUTPUT_BITS>;
        let base = P::ScalarField::from(base);
        table.column_1_step_size = base;
        table.column_2_step_size = base;
        table.column_3_step_size = base;

        table
    }

    fn generate_xor_rotate_table<const BITS_PER_SLICE: u64, const NUM_ROTATED_OUTPUT_BITS: u64>(
        id: BasicTableId,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        let base = 1 << BITS_PER_SLICE;
        let mut table = PlookupBasicTable::new();

        table.id = id;
        table.table_index = table_index;
        table.use_twin_keys = true;

        for i in 0..base {
            for j in 0..base {
                table.column_1.push(P::ScalarField::from(i));
                table.column_2.push(P::ScalarField::from(j));
                table.column_3.push(P::ScalarField::from(
                    ((i ^ j) as u64).rotate_right(NUM_ROTATED_OUTPUT_BITS as u32),
                ));
            }
        }

        table.get_values_from_key =
            BasicTableId::get_xor_rotate_values_from_key::<P::ScalarField, NUM_ROTATED_OUTPUT_BITS>;
        let base = P::ScalarField::from(base);
        table.column_1_step_size = base;
        table.column_2_step_size = base;
        table.column_3_step_size = base;

        table
    }

    fn generate_sparse_table_with_rotation<
        const BASE: u64,
        const BITS_PER_SLICE: u64,
        const NUM_ROTATED_BITS: u64,
    >(
        id: BasicTableId,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        let mut table = PlookupBasicTable::new();
        table.id = id;
        table.table_index = table_index;
        let table_size = 1 << BITS_PER_SLICE;
        table.use_twin_keys = false;

        for i in 0..table_size {
            let source = i as u64;
            let target = Utils::map_into_sparse_form::<BASE>(source);
            table.column_1.push(P::ScalarField::from(source));
            table.column_2.push(P::ScalarField::from(target.clone()));

            if NUM_ROTATED_BITS > 0 {
                let rotated = Utils::map_into_sparse_form::<BASE>(
                    (source as u32).rotate_right(NUM_ROTATED_BITS as u32) as u64,
                );
                table.column_3.push(P::ScalarField::from(rotated));
            } else {
                table.column_3.push(P::ScalarField::from(target));
            }
        }

        table.get_values_from_key = BasicTableId::get_sparse_table_with_rotation_values::<
            P::ScalarField,
            BASE,
            NUM_ROTATED_BITS,
        >;

        let mut sparse_step_size = 1u64;
        for _ in 0..BITS_PER_SLICE {
            sparse_step_size *= BASE;
        }
        table.column_1_step_size = P::ScalarField::from(1 << 11);
        table.column_2_step_size = P::ScalarField::from(sparse_step_size);
        table.column_3_step_size = P::ScalarField::from(sparse_step_size);

        table
    }

    fn generate_sparse_normalization_table<const BASE: u64, const NUM_BITS: usize>(
        id: BasicTableId,
        table_index: usize,
        base_table: &[u64],
        get_values: fn([u64; 2]) -> [P::ScalarField; 2],
    ) -> PlookupBasicTable<P, T> {
        let mut table = PlookupBasicTable::new();
        table.id = id;
        table.table_index = table_index;
        table.use_twin_keys = false;

        let table_size = BASE.pow(NUM_BITS as u32);

        let mut accumulator = 0u64;
        let to_add = 1u64;

        for _ in 0..table_size {
            let mut key = 0u64;
            let mut temp_accumulator = accumulator;

            for j in 0..NUM_BITS {
                let table_idx = (temp_accumulator % BASE) as usize;
                key += base_table[table_idx] << j;
                temp_accumulator /= BASE;
            }

            table.column_1.push(P::ScalarField::from(accumulator));
            table.column_2.push(P::ScalarField::from(key));
            table.column_3.push(P::ScalarField::zero());

            accumulator += to_add;
        }

        table.get_values_from_key = get_values;

        table.column_1_step_size = P::ScalarField::from(table_size);
        table.column_2_step_size = P::ScalarField::from(1u64 << NUM_BITS);
        table.column_3_step_size = P::ScalarField::zero();

        table
    }

    fn generate_xor_rotate_table_blake<
        const BITS_PER_SLICE: u64,
        const NUM_ROTATED_OUTPUT_BITS: u64,
        const FILTER: bool,
    >(
        id: BasicTableId,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        let base = 1 << BITS_PER_SLICE;
        let mut table = PlookupBasicTable::new();

        table.id = id;
        table.table_index = table_index;
        table.use_twin_keys = true;

        for i in 0..base {
            for j in 0..base {
                table.column_1.push(P::ScalarField::from(i));
                table.column_2.push(P::ScalarField::from(j));
                let mut i_copy = i;
                let mut j_copy = j;
                if FILTER {
                    i_copy &= 3;
                    j_copy &= 3;
                }
                table.column_3.push(P::ScalarField::from(
                    ((i_copy as u32) ^ (j_copy as u32))
                        .rotate_right(NUM_ROTATED_OUTPUT_BITS as u32),
                ));
            }
        }

        table.get_values_from_key = BasicTableId::get_xor_rotate_values_from_key_with_filter::<
            P::ScalarField,
            NUM_ROTATED_OUTPUT_BITS,
            FILTER,
        >;
        let base = P::ScalarField::from(base);
        table.column_1_step_size = base;
        table.column_2_step_size = base;
        table.column_3_step_size = base;

        table
    }

    #[expect(dead_code)]
    pub(crate) fn initialize_index_map(&mut self) {
        for (i, (c1, c2, c3)) in izip!(
            self.column_1.iter().cloned(),
            self.column_2.iter().cloned(),
            self.column_3.iter().cloned()
        )
        .enumerate()
        {
            self.index_map.index_map.insert([c1, c2, c3], i);
        }
    }
}

impl<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>>
    PlookupBasicTable<P, T>
{
    fn generate_basic_fixed_base_table<const MULTITABLE_INDEX: usize>(
        id: BasicTableId,
        basic_table_index: usize,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        assert!(MULTITABLE_INDEX < FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES);
        assert!(table_index < FixedBaseParams::get_num_bits_of_multi_table(MULTITABLE_INDEX));

        let multitable_bits = FixedBaseParams::get_num_bits_of_multi_table(MULTITABLE_INDEX);
        let bits_covered_by_previous_tables_in_multitable =
            FixedBaseParams::BITS_PER_TABLE * table_index;
        let is_small_table = (multitable_bits - bits_covered_by_previous_tables_in_multitable)
            < FixedBaseParams::BITS_PER_TABLE;
        let table_bits = if is_small_table {
            multitable_bits - bits_covered_by_previous_tables_in_multitable
        } else {
            FixedBaseParams::BITS_PER_TABLE
        };
        let table_size = 1u64 << table_bits;

        let mut table = PlookupBasicTable::new();
        table.id = id;
        table.table_index = basic_table_index;
        table.use_twin_keys = false;

        let tables = generators::generate_fixed_base_tables::<P::CycleGroup>();
        let basic_table = &tables[MULTITABLE_INDEX][table_index];

        for i in 0..table_size {
            let point = &basic_table[i as usize];
            let (x, y) = point.xy().unwrap_or_default();
            table.column_1.push(P::ScalarField::from(i));
            table.column_2.push(x);
            table.column_3.push(y);
        }

        let get_values_from_key_table =
            Plookup::make_fixed_base_function_pointer_table::<P, MULTITABLE_INDEX>();
        table.get_values_from_key = get_values_from_key_table[table_index];

        table.column_1_step_size = P::ScalarField::from(table_size);
        table.column_2_step_size = P::ScalarField::zero();
        table.column_3_step_size = P::ScalarField::zero();

        table
    }

    pub(crate) fn create_basic_table(id: BasicTableId, index: usize) -> Self {
        // we have >50 basic fixed base tables so we match with some logic instead of a switch statement
        let id_var = usize::from(id.to_owned());
        if id_var >= BasicTableId::FixedBase0_0 as usize
            && id_var < BasicTableId::FixedBase1_0 as usize
        {
            let id_ = id_var - BasicTableId::FixedBase0_0 as usize;
            return Self::generate_basic_fixed_base_table::<0>(id, index, id_);
        }
        if id_var >= BasicTableId::FixedBase1_0 as usize
            && id_var < BasicTableId::FixedBase2_0 as usize
        {
            let id_ = id_var - BasicTableId::FixedBase1_0 as usize;
            return Self::generate_basic_fixed_base_table::<1>(id, index, id_);
        }
        if id_var >= BasicTableId::FixedBase2_0 as usize
            && id_var < BasicTableId::FixedBase3_0 as usize
        {
            let id_ = id_var - BasicTableId::FixedBase2_0 as usize;
            return Self::generate_basic_fixed_base_table::<2>(id, index, id_);
        }
        if id_var >= BasicTableId::FixedBase3_0 as usize
            && id_var < BasicTableId::HonkDummyBasic1 as usize
        {
            let id_ = id_var - BasicTableId::FixedBase3_0 as usize;
            return Self::generate_basic_fixed_base_table::<3>(id, index, id_);
        }

        assert!(
            matches!(
                id,
                BasicTableId::HonkDummyBasic1
                    | BasicTableId::HonkDummyBasic2
                    | BasicTableId::UintAndSlice2Rotate0
                    | BasicTableId::UintXorSlice2Rotate0
                    | BasicTableId::UintAndSlice6Rotate0
                    | BasicTableId::UintXorSlice6Rotate0
                    | BasicTableId::Sha256Base16Rotate2
                    | BasicTableId::Sha256Base28
                    | BasicTableId::Sha256Base28Rotate6
                    | BasicTableId::Sha256Base28Rotate3
                    | BasicTableId::Sha256Base16
                    | BasicTableId::Sha256WitnessSlice3
                    | BasicTableId::Sha256WitnessSlice7Rotate4
                    | BasicTableId::Sha256WitnessSlice8Rotate7
                    | BasicTableId::Sha256WitnessSlice14Rotate1
                    | BasicTableId::Sha256WitnessNormalize
                    | BasicTableId::Sha256ChNormalize
                    | BasicTableId::Sha256MajNormalize
                    | BasicTableId::BlakeXorRotate0
                    | BasicTableId::BlakeXorRotate1
                    | BasicTableId::BlakeXorRotate2
                    | BasicTableId::BlakeXorRotate4
                    | BasicTableId::BlakeXorRotate0Slice5Mod4
            ),
            "Create Basic Table for {id:?} not implemented"
        );

        match id {
            BasicTableId::HonkDummyBasic1 => Self::generate_honk_dummy_table::<
                { BasicTableId::HonkDummyBasic1 as u64 },
            >(id, index),
            BasicTableId::HonkDummyBasic2 => Self::generate_honk_dummy_table::<
                { BasicTableId::HonkDummyBasic2 as u64 },
            >(id, index),

            BasicTableId::UintAndSlice2Rotate0 => {
                Self::generate_and_rotate_table::<2, 0>(id, index)
            }
            BasicTableId::UintXorSlice2Rotate0 => {
                Self::generate_xor_rotate_table::<2, 0>(id, index)
            }
            BasicTableId::UintAndSlice6Rotate0 => {
                Self::generate_and_rotate_table::<6, 0>(id, index)
            }
            BasicTableId::UintXorSlice6Rotate0 => {
                Self::generate_xor_rotate_table::<6, 0>(id, index)
            }

            BasicTableId::Sha256Base16Rotate2 => {
                Self::generate_sparse_table_with_rotation::<16, 11, 2>(id, index)
            }

            BasicTableId::Sha256Base28 => {
                Self::generate_sparse_table_with_rotation::<28, 11, 0>(id, index)
            }

            BasicTableId::Sha256Base28Rotate6 => {
                Self::generate_sparse_table_with_rotation::<28, 11, 6>(id, index)
            }

            BasicTableId::Sha256Base28Rotate3 => {
                Self::generate_sparse_table_with_rotation::<28, 11, 3>(id, index)
            }

            BasicTableId::Sha256Base16 => {
                Self::generate_sparse_table_with_rotation::<16, 11, 0>(id, index)
            }
            BasicTableId::Sha256WitnessSlice3 => {
                Self::generate_sparse_table_with_rotation::<16, 3, 0>(id, index)
            }
            BasicTableId::Sha256WitnessSlice7Rotate4 => {
                Self::generate_sparse_table_with_rotation::<16, 7, 4>(id, index)
            }
            BasicTableId::Sha256WitnessSlice8Rotate7 => {
                Self::generate_sparse_table_with_rotation::<16, 8, 7>(id, index)
            }
            BasicTableId::Sha256WitnessSlice14Rotate1 => {
                Self::generate_sparse_table_with_rotation::<16, 14, 1>(id, index)
            }
            BasicTableId::Sha256WitnessNormalize => {
                Self::generate_sparse_normalization_table::<16, 3>(
                    id,
                    index,
                    &BasicTableId::WITNESS_EXTENSION_NORMALIZATION_TABLE,
                    BasicTableId::get_sparse_normalization_values_wtns::<P::ScalarField, 16>,
                )
            }

            BasicTableId::Sha256ChNormalize => Self::generate_sparse_normalization_table::<28, 2>(
                id,
                index,
                &BasicTableId::CHOOSE_NORMALIZATION_TABLE,
                BasicTableId::get_sparse_normalization_values_choose::<P::ScalarField, 28>,
            ),
            BasicTableId::Sha256MajNormalize => Self::generate_sparse_normalization_table::<16, 3>(
                id,
                index,
                &BasicTableId::MAJORITY_NORMALIZATION_TABLE,
                BasicTableId::get_sparse_normalization_values_maj::<P::ScalarField, 16>,
            ),
            BasicTableId::BlakeXorRotate0 => {
                Self::generate_xor_rotate_table_blake::<6, 0, false>(id, index)
            }
            BasicTableId::BlakeXorRotate1 => {
                Self::generate_xor_rotate_table_blake::<6, 1, false>(id, index)
            }
            BasicTableId::BlakeXorRotate2 => {
                Self::generate_xor_rotate_table_blake::<6, 2, false>(id, index)
            }
            BasicTableId::BlakeXorRotate4 => {
                Self::generate_xor_rotate_table_blake::<6, 4, false>(id, index)
            }
            BasicTableId::BlakeXorRotate0Slice5Mod4 => {
                Self::generate_xor_rotate_table_blake::<5, 0, true>(id, index)
            }
            _ => {
                todo!("Create other tables")
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct LookupHashMap<F: PrimeField> {
    pub(crate) index_map: HashMap<[F; 3], usize>,
}

impl<F: PrimeField> Index<[F; 3]> for LookupHashMap<F> {
    type Output = usize;

    fn index(&self, index: [F; 3]) -> &Self::Output {
        self.index_map.index(&index)
    }
}

pub(crate) struct PlookupMultiTable<F: PrimeField> {
    pub(crate) column_1_coefficients: Vec<F>,
    pub(crate) column_2_coefficients: Vec<F>,
    pub(crate) column_3_coefficients: Vec<F>,
    pub(crate) id: MultiTableId,
    pub(crate) basic_table_ids: Vec<BasicTableId>,
    pub(crate) slice_sizes: Vec<u64>,
    pub(crate) column_1_step_sizes: Vec<F>,
    pub(crate) column_2_step_sizes: Vec<F>,
    pub(crate) column_3_step_sizes: Vec<F>,
    pub(crate) get_table_values: Vec<fn([u64; 2]) -> [F; 2]>,
}

impl<F: PrimeField> Default for PlookupMultiTable<F> {
    fn default() -> Self {
        Self {
            column_1_coefficients: Vec::new(),
            column_2_coefficients: Vec::new(),
            column_3_coefficients: Vec::new(),
            id: MultiTableId::HonkDummyMulti,
            basic_table_ids: Vec::new(),
            slice_sizes: Vec::new(),
            column_1_step_sizes: Vec::new(),
            column_2_step_sizes: Vec::new(),
            column_3_step_sizes: Vec::new(),
            get_table_values: Vec::new(),
        }
    }
}

impl<F: PrimeField> PlookupMultiTable<F> {
    pub(crate) fn new(
        id: MultiTableId,
        col1_repeated_coeff: F,
        col2_repeated_coeff: F,
        col3_repeated_coeff: F,
        num_lookups: usize,
    ) -> Self {
        let mut column_1_coefficients = Vec::with_capacity(num_lookups + 1);
        let mut column_2_coefficients = Vec::with_capacity(num_lookups + 1);
        let mut column_3_coefficients = Vec::with_capacity(num_lookups + 1);

        column_1_coefficients.push(F::one());
        column_2_coefficients.push(F::one());
        column_3_coefficients.push(F::one());

        for _ in 0..num_lookups {
            column_1_coefficients.push(col1_repeated_coeff * column_1_coefficients.last().unwrap());
            column_2_coefficients.push(col2_repeated_coeff * column_2_coefficients.last().unwrap());
            column_3_coefficients.push(col3_repeated_coeff * column_3_coefficients.last().unwrap());
        }

        let mut res = Self {
            id,
            column_1_coefficients,
            column_2_coefficients,
            column_3_coefficients,
            ..Default::default()
        };
        res.init_step_sizes();
        res
    }

    pub(crate) fn new_from_vec(
        id: MultiTableId,
        col_1_coeffs: Vec<F>,
        col_2_coeffs: Vec<F>,
        col_3_coeffs: Vec<F>,
    ) -> Self {
        let mut res = Self {
            id,
            column_1_coefficients: col_1_coeffs,
            column_2_coefficients: col_2_coeffs,
            column_3_coefficients: col_3_coeffs,
            ..Default::default()
        };
        res.init_step_sizes();
        res
    }

    fn init_step_sizes(&mut self) {
        let num_lookups = self.column_1_coefficients.len();
        self.column_1_step_sizes.push(F::one());
        self.column_2_step_sizes.push(F::one());
        self.column_3_step_sizes.push(F::one());

        let mut coefficient_inverses = self.column_1_coefficients.clone();
        coefficient_inverses.extend(&self.column_2_coefficients);
        coefficient_inverses.extend(&self.column_3_coefficients);

        Utils::batch_invert(&mut coefficient_inverses);

        for i in 1..num_lookups {
            self.column_1_step_sizes
                .push(self.column_1_coefficients[i] * coefficient_inverses[i - 1]);
            self.column_2_step_sizes
                .push(self.column_2_coefficients[i] * coefficient_inverses[num_lookups + i - 1]);
            self.column_3_step_sizes.push(
                self.column_3_coefficients[i] * coefficient_inverses[2 * num_lookups + i - 1],
            );
        }
    }
}

#[derive(Default)]
pub(crate) struct ReadData<F: Clone> {
    pub(crate) lookup_entries: Vec<LookupEntry<F>>,
    pub(crate) columns: [Vec<F>; 3],
}

impl<F: Clone> Index<ColumnIdx> for ReadData<F> {
    type Output = Vec<F>;

    fn index(&self, index: ColumnIdx) -> &Self::Output {
        self.columns.index(index as usize)
    }
}

impl<F: Clone> IndexMut<ColumnIdx> for ReadData<F> {
    fn index_mut(&mut self, index: ColumnIdx) -> &mut Self::Output {
        self.columns.index_mut(index as usize)
    }
}

pub(crate) enum ColumnIdx {
    C1,
    C2,
    C3,
}
