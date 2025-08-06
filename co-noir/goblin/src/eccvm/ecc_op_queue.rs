use ark_ff::Zero;
use co_builder::{
    TranscriptFieldType,
    prelude::{HonkCurve, Polynomial},
};
use num_bigint::BigUint;
use std::array;

const NUM_SCALAR_BITS: usize = 128; // The length of scalars handled by the ECCVVM
const NUM_WNAF_DIGIT_BITS: usize = 4; // Scalars are decompose into base 16 in wNAF form
const NUM_WNAF_DIGITS_PER_SCALAR: usize = NUM_SCALAR_BITS / NUM_WNAF_DIGIT_BITS; // 32
const WNAF_DIGITS_PER_ROW: usize = 4;
const ADDITIONS_PER_ROW: usize = 4;
pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub(crate) type EccvmOpsTable<C> = EccOpsTable<ECCVMOperation<C>>;
pub(crate) struct UltraEccOpsTable<C: HonkCurve<TranscriptFieldType>> {
    pub(crate) table: EccOpsTable<UltraOp<C>>,
}

impl<C: HonkCurve<TranscriptFieldType>> UltraEccOpsTable<C> {
    pub fn ultra_table_size(&self) -> usize {
        self.table.size() * NUM_ROWS_PER_OP
    }

    pub fn current_ultra_subtable_size(&self) -> usize {
        self.table.get()[0].len() * NUM_ROWS_PER_OP
    }

    pub fn previous_ultra_table_size(&self) -> usize {
        self.ultra_table_size() - self.current_ultra_subtable_size()
    }

    pub fn create_new_subtable(&mut self, size_hint: usize) {
        self.table.create_new_subtable(size_hint);
    }

    pub fn get_reconstructed(&self) -> Vec<UltraOp<C>>
    where
        UltraOp<C>: Clone,
    {
        self.table.get_reconstructed()
    }

    pub fn construct_table_columns(&self) -> [Polynomial<C::ScalarField>; TABLE_WIDTH] {
        let poly_size = self.ultra_table_size();
        let subtable_start_idx = 0; // include all subtables
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
        )
    }

    pub fn construct_previous_table_columns(&self) -> [Polynomial<C::ScalarField>; TABLE_WIDTH] {
        let poly_size = self.previous_ultra_table_size();
        let subtable_start_idx = 1; // exclude the 0th subtable
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
        )
    }

    pub fn construct_current_ultra_ops_subtable_columns(
        &self,
    ) -> [Polynomial<C::ScalarField>; TABLE_WIDTH] {
        let poly_size = self.current_ultra_subtable_size();
        let subtable_start_idx = 0;
        let subtable_end_idx = 1; // include only the 0th subtable

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
        )
    }

    fn construct_column_polynomials_from_subtables(
        &self,
        poly_size: usize,
        subtable_start_idx: usize,
        subtable_end_idx: usize,
    ) -> [Polynomial<C::ScalarField>; TABLE_WIDTH] {
        let mut column_polynomials: [Polynomial<C::ScalarField>; TABLE_WIDTH] =
            array::from_fn(|_| Polynomial::new(vec![C::ScalarField::zero(); poly_size]));

        let mut i = 0;
        for subtable_idx in subtable_start_idx..subtable_end_idx {
            let subtable = &self.table.get()[subtable_idx];
            for op in subtable {
                column_polynomials[0][i] = C::ScalarField::from(op.op_code.value());
                column_polynomials[1][i] = op.x_lo;
                column_polynomials[2][i] = op.x_hi;
                column_polynomials[3][i] = op.y_lo;
                i += 1;
                column_polynomials[0][i] = C::ScalarField::zero(); // only the first 'op' field is utilized
                column_polynomials[1][i] = op.y_hi;
                column_polynomials[2][i] = op.z_1;
                column_polynomials[3][i] = op.z_2;
                i += 1;
            }
        }
        column_polynomials
    }
}

#[derive(Default)]
pub struct EccOpsTable<OpFormat> {
    pub table: Vec<Vec<OpFormat>>,
}

impl<OpFormat> EccOpsTable<OpFormat> {
    pub fn new() -> Self {
        Self { table: Vec::new() }
    }

    pub fn size(&self) -> usize {
        self.table.iter().map(|subtable| subtable.len()).sum()
    }

    pub fn num_subtables(&self) -> usize {
        self.table.len()
    }

    pub fn get(&self) -> &Vec<Vec<OpFormat>> {
        &self.table
    }

    pub fn create_new_subtable(&mut self, size_hint: usize) {
        // If there is a single subtable and it is empty, don't create a new one
        if self.table.len() == 1
            && self
                .table
                .first()
                .is_none_or(|subtable| subtable.is_empty())
        {
            return;
        }
        let new_subtable = Vec::with_capacity(size_hint);
        self.table.insert(0, new_subtable);
    }

    pub fn get_reconstructed(&self) -> Vec<OpFormat>
    where
        OpFormat: Clone,
    {
        let mut reconstructed_table = Vec::with_capacity(self.size());
        for subtable in &self.table {
            reconstructed_table.extend(subtable.iter().cloned());
        }
        reconstructed_table
    }
}

impl<OpFormat> std::ops::Index<usize> for EccOpsTable<OpFormat> {
    type Output = OpFormat;

    fn index(&self, mut index: usize) -> &Self::Output {
        for subtable in &self.table {
            if index < subtable.len() {
                return &subtable[index];
            }
            index -= subtable.len();
        }
        panic!("Index out of bounds");
    }
}
#[derive(Clone, Default)]
pub struct ECCVMOperation<C: HonkCurve<TranscriptFieldType>> {
    pub op_code: EccOpCode,
    pub base_point: C::Affine,
    pub z1: BigUint,
    pub z2: BigUint,
    pub mul_scalar_full: C::ScalarField,
}

impl<C: HonkCurve<TranscriptFieldType>> PartialEq for ECCVMOperation<C> {
    fn eq(&self, other: &Self) -> bool {
        self.op_code == other.op_code
            && self.base_point == other.base_point
            && self.z1 == other.z1
            && self.z2 == other.z2
            && self.mul_scalar_full == other.mul_scalar_full
    }
}
#[derive(Clone)]
pub struct UltraOp<C: HonkCurve<TranscriptFieldType>> {
    pub op_code: EccOpCode,
    pub x_lo: C::ScalarField,
    pub x_hi: C::ScalarField,
    pub y_lo: C::ScalarField,
    pub y_hi: C::ScalarField,
    pub z_1: C::ScalarField,
    pub z_2: C::ScalarField,
    pub return_is_infinity: bool,
}

#[derive(Default, PartialEq, Eq, Clone, Debug)]
pub struct EccOpCode {
    pub add: bool,
    pub mul: bool,
    pub eq: bool,
    pub reset: bool,
}

impl EccOpCode {
    /// Returns the value of the opcode as a 32-bit integer.
    pub fn value(&self) -> u32 {
        let mut res = self.add as u32;
        res = (res << 1) + self.mul as u32;
        res = (res << 1) + self.eq as u32;
        res = (res << 1) + self.reset as u32;
        res
    }
}

#[derive(Default)]
pub struct EccvmRowTracker {
    cached_num_muls: u32,
    cached_active_msm_count: u32,
    num_transcript_rows: u32,
    num_precompute_table_rows: u32,
    num_msm_rows: u32,
}

impl EccvmRowTracker {
    pub fn new() -> Self {
        Self {
            cached_num_muls: 0,
            cached_active_msm_count: 0,
            num_transcript_rows: 0,
            num_precompute_table_rows: 0,
            num_msm_rows: 0,
        }
    }

    pub fn get_number_of_muls(&self) -> u32 {
        self.cached_num_muls + self.cached_active_msm_count
    }

    pub fn num_eccvm_msm_rows(msm_size: usize) -> u32 {
        let rows_per_wnaf_digit = (msm_size / ADDITIONS_PER_ROW)
            + if msm_size % ADDITIONS_PER_ROW != 0 {
                1
            } else {
                0
            };
        let num_rows_for_all_rounds = (NUM_WNAF_DIGITS_PER_SCALAR + 1) * rows_per_wnaf_digit;
        let num_double_rounds = NUM_WNAF_DIGITS_PER_SCALAR - 1;
        (num_rows_for_all_rounds + num_double_rounds) as u32
    }

    pub fn get_num_msm_rows(&self) -> usize {
        let mut msm_rows = self.num_msm_rows as usize + 2;
        if self.cached_active_msm_count > 0 {
            msm_rows += Self::num_eccvm_msm_rows(self.cached_active_msm_count as usize) as usize;
        }
        msm_rows
    }

    pub fn get_num_rows(&self) -> usize {
        let transcript_rows = self.num_transcript_rows as usize + 2;
        let mut msm_rows = self.num_msm_rows as usize + 2;
        let mut precompute_rows = self.num_precompute_table_rows as usize + 1;
        if self.cached_active_msm_count > 0 {
            msm_rows += Self::num_eccvm_msm_rows(self.cached_active_msm_count as usize) as usize;
            precompute_rows += Self::get_precompute_table_row_count_for_single_msm(
                self.cached_active_msm_count as usize,
            ) as usize;
        }
        std::cmp::max(transcript_rows, std::cmp::max(msm_rows, precompute_rows))
    }

    pub fn get_precompute_table_row_count_for_single_msm(msm_count: usize) -> u32 {
        let num_precompute_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;
        (msm_count * num_precompute_rows_per_scalar) as u32
    }
}

pub struct ECCOpQueue<C: HonkCurve<TranscriptFieldType>> {
    pub(crate) accumulator: C::Affine,
    pub(crate) eccvm_ops_table: EccvmOpsTable<C>,
    pub(crate) ultra_ops_table: UltraEccOpsTable<C>,
    pub(crate) eccvm_ops_reconstructed: Vec<ECCVMOperation<C>>,
    pub(crate) ultra_ops_reconstructed: Vec<UltraOp<C>>,
    pub(crate) eccvm_row_tracker: EccvmRowTracker,
}

impl<C: HonkCurve<TranscriptFieldType>> ECCOpQueue<C> {
    // Initialize a new subtable of ECCVM ops and Ultra ops corresponding to an individual circuit
    pub fn initialize_new_subtable(&mut self) {
        self.eccvm_ops_table.create_new_subtable(0);
        self.ultra_ops_table.create_new_subtable(0);
    }

    // Construct polynomials corresponding to the columns of the full aggregate ultra ecc ops table
    pub fn construct_ultra_ops_table_columns(&self) -> [Polynomial<C::ScalarField>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_table_columns()
    }

    // Construct polys corresponding to the columns of the aggregate ultra ops table, excluding the most recent subtable
    pub fn construct_previous_ultra_ops_table_columns(
        &self,
    ) -> [Polynomial<C::ScalarField>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_previous_table_columns()
    }

    // Construct polynomials corresponding to the columns of the current subtable of ultra ecc ops
    pub fn construct_current_ultra_ops_subtable_columns(
        &self,
    ) -> [Polynomial<C::ScalarField>; TABLE_WIDTH] {
        self.ultra_ops_table
            .construct_current_ultra_ops_subtable_columns()
    }

    // Reconstruct the full table of eccvm ops in contiguous memory from the independent subtables
    pub fn construct_full_eccvm_ops_table(&mut self) {
        self.eccvm_ops_reconstructed = self.eccvm_ops_table.get_reconstructed();
    }

    // Reconstruct the full table of ultra ops in contiguous memory from the independent subtables
    pub fn construct_full_ultra_ops_table(&mut self) {
        self.ultra_ops_reconstructed = self.ultra_ops_table.get_reconstructed();
    }

    pub fn get_ultra_ops_table_num_rows(&self) -> usize {
        self.ultra_ops_table.ultra_table_size()
    }

    pub fn get_current_ultra_ops_subtable_num_rows(&self) -> usize {
        self.ultra_ops_table.current_ultra_subtable_size()
    }

    // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1339): Consider making the ultra and eccvm ops getters
    // more memory efficient

    // Get the full table of ECCVM ops in contiguous memory; construct it if it has not been constructed already
    pub fn get_eccvm_ops(&mut self) -> &Vec<ECCVMOperation<C>> {
        if self.eccvm_ops_reconstructed.is_empty() {
            self.construct_full_eccvm_ops_table();
        }
        &self.eccvm_ops_reconstructed
    }

    pub fn get_ultra_ops(&mut self) -> &Vec<UltraOp<C>> {
        if self.ultra_ops_reconstructed.is_empty() {
            self.construct_full_ultra_ops_table();
        }
        &self.ultra_ops_reconstructed
    }

    /**
     * @brief Get the number of rows in the 'msm' column section, for all msms in the circuit
     */
    pub fn get_num_msm_rows(&self) -> usize {
        self.eccvm_row_tracker.get_num_msm_rows()
    }

    /**
     * @brief Get the number of rows for the current ECCVM circuit
     */
    pub fn get_num_rows(&self) -> usize {
        self.eccvm_row_tracker.get_num_rows()
    }

    /**
     * @brief get number of muls for the current ECCVM circuit
     */
    pub fn get_number_of_muls(&self) -> u32 {
        self.eccvm_row_tracker.get_number_of_muls()
    }

    /**
     * @brief A fuzzing only method for setting eccvm ops directly
     *
     */
    pub fn set_eccvm_ops_for_fuzzing(&mut self, eccvm_ops_in: Vec<ECCVMOperation<C>>) {
        self.eccvm_ops_reconstructed = eccvm_ops_in;
    }

    pub fn get_accumulator(&self) -> C::Affine {
        self.accumulator
    }
}
