use ark_ff::PrimeField;
use num_bigint::BigUint;
use std::array::from_fn;

use super::types::{ColumnIdx, LookupEntry, PlookupMultiTable, ReadData};

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
    UintXorRotate0,
    UintAndRotate0,
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
    FixedBase1_0 = BasicTableId::FixedBase0_0 as isize
        + FixedBaseParams::NUM_TABLES_PER_LO_MULTITABLE as isize,
    FixedBase2_0 = BasicTableId::FixedBase1_0 as isize
        + FixedBaseParams::NUM_TABLES_PER_HI_MULTITABLE as isize,
    FixedBase3_0 = BasicTableId::FixedBase2_0 as isize
        + FixedBaseParams::NUM_TABLES_PER_LO_MULTITABLE as isize,
    HonkDummyBasic1 = BasicTableId::FixedBase3_0 as isize
        + FixedBaseParams::NUM_TABLES_PER_HI_MULTITABLE as isize,
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

impl BasicTableId {
    pub(crate) fn get_value_from_key<F: PrimeField, const ID: u64>(key: [u64; 2]) -> [F; 2] {
        let value1 = F::from(key[0] * 3 + key[1] * 4 + ID * 0x1337);
        let value2 = F::zero();

        [value1, value2]
    }
}

struct FixedBaseParams {}
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
}

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

    fn init_multi_tables() -> [PlookupMultiTable<F>; MultiTableId::NumMultiTables as usize] {
        // TACEO TODO not all are initialized here!
        let mut multi_tables = from_fn(|_| PlookupMultiTable::default());
        multi_tables[usize::from(MultiTableId::HonkDummyMulti)] = Self::get_honk_dummy_multitable();
        multi_tables
    }

    pub(crate) fn get_multitable(&self, id: MultiTableId) -> &PlookupMultiTable<F> {
        assert_eq!(id, MultiTableId::HonkDummyMulti); // The only one implemented so far
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

    pub(crate) fn get_lookup_accumulators(
        &self,
        id: MultiTableId,
        key_a: F,
        key_b: F,
        is_2_to_1_lookup: bool,
    ) -> ReadData<F> {
        // return multi-table, populating global array of all multi-tables if need be
        let multi_table = self.get_multitable(id);
        let num_lookups = multi_table.basic_table_ids.len();

        let mut lookup = ReadData::<F>::default();
        let key_a_slices =
            Self::slice_input_using_variable_bases(key_a.into(), &multi_table.slice_sizes);
        let key_b_slices =
            Self::slice_input_using_variable_bases(key_b.into(), &multi_table.slice_sizes);

        let mut column_1_raw_values = Vec::with_capacity(num_lookups);
        let mut column_2_raw_values = Vec::with_capacity(num_lookups);
        let mut column_3_raw_values = Vec::with_capacity(num_lookups);

        for i in 0..num_lookups {
            // compute the value(s) corresponding to the key(s) using the i-th basic table query function
            let values = multi_table.get_table_values[i]([key_a_slices[i], key_b_slices[i]]);
            // store all query data in raw columns and key entry
            column_1_raw_values.push(key_a_slices[i]);
            column_2_raw_values.push(if is_2_to_1_lookup {
                F::from(key_b_slices[i])
            } else {
                values[0]
            });
            column_3_raw_values.push(if is_2_to_1_lookup {
                values[0]
            } else {
                values[1]
            });

            // Store the lookup entries for use in constructing the sorted table/lookup polynomials later on
            let lookup_entry = LookupEntry {
                key: [key_a_slices[i].into(), key_b_slices[i].into()],
                value: values,
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
        lookup[ColumnIdx::C1][num_lookups - 1] = F::from(column_1_raw_values[num_lookups - 1]);
        lookup[ColumnIdx::C2][num_lookups - 1] = column_2_raw_values[num_lookups - 1];
        lookup[ColumnIdx::C3][num_lookups - 1] = column_3_raw_values[num_lookups - 1];

        for i in (1..num_lookups).rev() {
            lookup[ColumnIdx::C1][i - 1] = F::from(column_1_raw_values[i - 1])
                + lookup[ColumnIdx::C1][i] * multi_table.column_1_step_sizes[i];
            lookup[ColumnIdx::C2][i - 1] = column_2_raw_values[i - 1]
                + lookup[ColumnIdx::C2][i] * multi_table.column_2_step_sizes[i];
            lookup[ColumnIdx::C3][i - 1] = column_3_raw_values[i - 1]
                + lookup[ColumnIdx::C3][i] * multi_table.column_3_step_sizes[i];
        }
        lookup
    }
}
