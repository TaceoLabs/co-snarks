use self::utils::Utils;
use super::field_ct::FieldCT;
use super::generators;
use crate::prelude::HonkCurve;
use crate::TranscriptFieldType;
use crate::{builder::GenericUltraCircuitBuilder, utils};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{PrimeField, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use itertools::izip;
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
                format!("Invalid BasicTableId: {}", value),
            ))
        } else {
            Ok(unsafe { std::mem::transmute::<usize, BasicTableId>(value) })
        }
    }
}

impl BasicTableId {
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
            F::from(Utils::rotate64(key[0] ^ key[1], NUM_ROTATED_OUTPUT_BITS)),
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
            F::from(Utils::rotate64(key[0] & key[1], NUM_ROTATED_OUTPUT_BITS)),
            F::zero(),
        ]
    }
}

struct FixedBaseParams {}

#[expect(dead_code)]
impl FixedBaseParams {
    const BITS_PER_TABLE: usize = 9;
    const BITS_ON_CURVE: usize = 254;

    // We split 1 254-bit scalar mul into two scalar muls of size BITS_PER_LO_SCALAR, BITS_PER_HI_SCALAR.
    // This enables us to efficiently decompose our input scalar multiplier into two chunks of a known size.
    // (i.e. we get free BITS_PER_LO_SCALAR, BITS_PER_HI_SCALAR range checks as part of the lookup table subroutine)
    // This in turn allows us to perform a primality test more efficiently.
    // i.e. check that input scalar < prime modulus when evaluated over the integers
    // (the primality check requires us to split the input into high / low bit chunks so getting this for free as part
    // of the lookup algorithm is nice!)
    const BITS_PER_LO_SCALAR: usize = 128;
    const BITS_PER_HI_SCALAR: usize = Self::BITS_ON_CURVE - Self::BITS_PER_LO_SCALAR;
    // max table size because the last lookup table might be smaller (BITS_PER_TABLE does not neatly divide
    // BITS_PER_LO_SCALAR)
    const MAX_TABLE_SIZE: usize = 1 << Self::BITS_PER_TABLE;
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
    const NUM_FIXED_BASE_MULTI_TABLES: usize = Self::NUM_POINTS * 2;
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

    fn get_num_tables_per_multi_table<const NUM_BITS: usize>() -> usize {
        (NUM_BITS / Self::BITS_PER_TABLE)
            + if NUM_BITS % Self::BITS_PER_TABLE == 0 {
                0
            } else {
                1
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

impl From<MultiTableId> for usize {
    fn from(id: MultiTableId) -> usize {
        id as usize
    }
}

pub(crate) struct Plookup<F: PrimeField> {
    pub(crate) multi_tables: [PlookupMultiTable<F>; MultiTableId::NumMultiTables as usize],
}

impl<F: PrimeField> Default for Plookup<F> {
    fn default() -> Self {
        Self {
            multi_tables: Self::init_multi_tables(),
        }
    }
}

impl<F: PrimeField> Plookup<F> {
    fn get_honk_dummy_multitable() -> PlookupMultiTable<F> {
        let id = MultiTableId::HonkDummyMulti;
        let number_of_elements_in_argument = 1 << 1; // Probably has to be a power of 2
        let number_of_elements_in_argument_f = F::from(number_of_elements_in_argument);
        let number_of_lookups = 2;
        let mut table = PlookupMultiTable::new(
            number_of_elements_in_argument_f,
            number_of_elements_in_argument_f,
            number_of_elements_in_argument_f,
            number_of_lookups,
        );
        table.id = id;
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
            PlookupMultiTable::<F>::new(base.into(), base.into(), base.into(), num_entries);

        table.id = id;
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
            PlookupMultiTable::<F>::new(base.into(), base.into(), base.into(), num_entries);

        table.id = id;
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

    fn get_fixed_base_table<const INDEX: usize, const NUM_BITS: usize>(
        id: MultiTableId,
    ) -> PlookupMultiTable<F> {
        assert!(
            NUM_BITS == FixedBaseParams::BITS_PER_LO_SCALAR
                || NUM_BITS == FixedBaseParams::BITS_PER_HI_SCALAR
        );
        let num_tables = FixedBaseParams::get_num_tables_per_multi_table::<NUM_BITS>();

        // constexpr std::array<BasicTableId, NUM_FIXED_BASE_MULTI_TABLES>
        let basic_table_ids = [
            BasicTableId::FixedBase0_0,
            BasicTableId::FixedBase1_0,
            BasicTableId::FixedBase2_0,
            BasicTableId::FixedBase3_0,
        ];
        // constexpr function_ptr_table get_values_from_key_table = make_function_pointer_table();

        let mut table = PlookupMultiTable::new(
            F::from(FixedBaseParams::MAX_TABLE_SIZE as u64),
            F::zero(),
            F::zero(),
            num_tables,
        );
        table.id = id;
        for i in 0..num_tables {
            table
                .slice_sizes
                .push(FixedBaseParams::MAX_TABLE_SIZE as u64);
            // table.get_table_values[i] = get_values_from_key_table[multitable_index][i];
            todo!("get_fiexed_base_table");
            assert!(INDEX < FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES);
            let idx = i + usize::from(basic_table_ids[INDEX].clone());
            table
                .basic_table_ids
                .push(idx.try_into().expect("Invalid BasicTableId"));
        }

        table
    }

    fn init_multi_tables() -> [PlookupMultiTable<F>; MultiTableId::NumMultiTables as usize] {
        // TACEO TODO not all are initialized here!
        let mut multi_tables = from_fn(|_| PlookupMultiTable::default());
        multi_tables[usize::from(MultiTableId::HonkDummyMulti)] = Self::get_honk_dummy_multitable();
        multi_tables[usize::from(MultiTableId::Uint32And)] = Self::get_uint32_and_table();
        multi_tables[usize::from(MultiTableId::Uint32Xor)] = Self::get_uint32_xor_table();
        multi_tables[usize::from(MultiTableId::FixedBaseLeftLo)] =
            Self::get_fixed_base_table::<0, 128>(MultiTableId::FixedBaseLeftLo);
        multi_tables[usize::from(MultiTableId::FixedBaseLeftHi)] =
            Self::get_fixed_base_table::<1, 126>(MultiTableId::FixedBaseLeftHi);
        multi_tables[usize::from(MultiTableId::FixedBaseRightLo)] =
            Self::get_fixed_base_table::<2, 128>(MultiTableId::FixedBaseRightLo);
        multi_tables[usize::from(MultiTableId::FixedBaseRightHi)] =
            Self::get_fixed_base_table::<3, 126>(MultiTableId::FixedBaseRightHi);
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
            ),
            "Multitable for {:?} not implemented",
            id
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
        todo!("Implement get_generator_offset_for_table_id");
        match id {
            // MultiTableId::FixedBaseLeftLo => Some(0),
            // MultiTableId::FixedBaseLeftHi => Some(1),
            // MultiTableId::FixedBaseRightLo => Some(2),
            // MultiTableId::FixedBaseRightHi => Some(3),
            _ => None,
        }
    }

    #[expect(clippy::type_complexity)]
    fn slice_and_get_values<P: Pairing<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
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
            // Everything public
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
                results.reserve(values.0.len());
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

    pub(crate) fn get_lookup_accumulators<
        P: Pairing<ScalarField = F>,
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
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
        id: MultiTableId,
        key_a: FieldCT<F>,
        key_b: FieldCT<F>,
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
                lookup[ColumnIdx::C1].push(FieldCT::zero_with_additive(
                    T::get_public(&lookup_data[ColumnIdx::C1][i])
                        .expect("Constant should be public"),
                ));
                lookup[ColumnIdx::C2].push(FieldCT::zero_with_additive(
                    T::get_public(&lookup_data[ColumnIdx::C2][i])
                        .expect("Constant should be public"),
                ));
                lookup[ColumnIdx::C3].push(FieldCT::zero_with_additive(
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
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
        id: MultiTableId,
        key_a: FieldCT<F>,
        key_b: FieldCT<F>,
    ) -> std::io::Result<FieldCT<F>> {
        let lookup = Self::get_lookup_accumulators_ct(builder, driver, id, key_a, key_b, true)?;
        Ok(lookup[ColumnIdx::C3][0].clone())
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
                table.column_3.push(P::ScalarField::from(Utils::rotate64(
                    i & j,
                    NUM_ROTATED_OUTPUT_BITS,
                )));
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
                table.column_3.push(P::ScalarField::from(Utils::rotate64(
                    i ^ j,
                    NUM_ROTATED_OUTPUT_BITS,
                )));
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

    pub(crate) fn create_basic_table(id: BasicTableId, index: usize) -> Self {
        // TACEO TODO this is a dummy implementation
        assert!(
            matches!(
                id,
                BasicTableId::HonkDummyBasic1
                    | BasicTableId::HonkDummyBasic2
                    | BasicTableId::UintAndSlice2Rotate0
                    | BasicTableId::UintXorSlice2Rotate0
                    | BasicTableId::UintAndSlice6Rotate0
                    | BasicTableId::UintXorSlice6Rotate0
            ),
            "Create Basic Table for {:?} not implemented",
            id
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
            _ => {
                todo!("Create other tables")
            }
        }
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
            column_1_coefficients,
            column_2_coefficients,
            column_3_coefficients,
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
