use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::{One, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::TranscriptFieldType;
use co_builder::prelude::HonkCurve;
use co_builder::prelude::offset_generator;
use common::{
    ADDITIONS_PER_ROW, NUM_SCALAR_BITS, NUM_WNAF_DIGITS_PER_SCALAR, POINT_TABLE_SIZE,
    WNAF_DIGITS_PER_ROW,
};
use goblin::prelude::EccvmRowTracker;
use goblin::prelude::{EccOpCode, EccOpsTable};
use num_bigint::BigUint;
use std::array;

pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub type CoEccvmOpsTable<T, C> = EccOpsTable<CoVMOperation<T, C>>;

pub struct CoUltraEccOpsTable<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub table: EccOpsTable<CoUltraOp<T, C>>,
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>>
    CoUltraEccOpsTable<T, C>
{
    pub fn ultra_table_size(&self) -> usize {
        self.table.size() * NUM_ROWS_PER_OP
    }

    pub fn current_ultra_subtable_size(&self) -> usize {
        self.table.get()[0].len() * NUM_ROWS_PER_OP
    }

    pub fn create_new_subtable(&mut self, size_hint: usize) {
        self.table.create_new_subtable(size_hint);
    }
}

#[derive(Default)]
pub struct CoVMOperation<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub op_code: EccOpCode,
    pub base_point: T::NativeAcvmPoint<C>,
    pub z1: T::OtherAcvmType<C>,
    pub z2: T::OtherAcvmType<C>,
    pub z1_is_zero: bool,
    pub z2_is_zero: bool,
    pub base_point_is_zero: bool,
    pub mul_scalar_full: T::AcvmType,
}
impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Clone
    for CoVMOperation<T, C>
{
    fn clone(&self) -> Self {
        Self {
            op_code: self.op_code.clone(),
            base_point: self.base_point,
            z1: self.z1,
            z2: self.z2,
            mul_scalar_full: self.mul_scalar_full,
            z1_is_zero: self.z1_is_zero,
            z2_is_zero: self.z2_is_zero,
            base_point_is_zero: self.base_point_is_zero,
        }
    }
}

pub struct CoUltraOp<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub op_code: EccOpCode,
    pub x_lo: T::AcvmType,
    pub x_hi: T::AcvmType,
    pub y_lo: T::AcvmType,
    pub y_hi: T::AcvmType,
    pub z_1: T::AcvmType,
    pub z_2: T::AcvmType,
    pub return_is_infinity: bool,
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Clone
    for CoUltraOp<T, C>
{
    fn clone(&self) -> Self {
        Self {
            op_code: self.op_code.clone(),
            x_lo: self.x_lo,
            x_hi: self.x_hi,
            y_lo: self.y_lo,
            y_hi: self.y_hi,
            z_1: self.z_1,
            z_2: self.z_2,
            return_is_infinity: self.return_is_infinity,
        }
    }
}

pub struct CoECCOpQueue<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub eccvm_ops_table: CoEccvmOpsTable<T, C>,
    pub ultra_ops_table: CoUltraEccOpsTable<T, C>,
    pub accumulator: T::NativeAcvmPoint<C>,
    pub eccvm_ops_reconstructed: Vec<CoVMOperation<T, C>>,
    pub ultra_ops_reconstructed: Vec<CoUltraOp<T, C>>,
    pub eccvm_row_tracker: EccvmRowTracker,
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>>
    CoECCOpQueue<T, C>
{
    // Initialize a new subtable of ECCVM ops and Ultra ops corresponding to an individual circuit
    pub fn initialize_new_subtable(&mut self) {
        self.eccvm_ops_table.create_new_subtable(0);
        self.ultra_ops_table.create_new_subtable(0);
    }

    // Reconstruct the full table of eccvm ops in contiguous memory from the independent subtables
    pub fn construct_full_eccvm_ops_table(&mut self) {
        self.eccvm_ops_reconstructed = self.eccvm_ops_table.get_reconstructed();
    }

    // Reconstruct the full table of ultra ops in contiguous memory from the independent subtables
    pub fn construct_full_ultra_ops_table(&mut self) {
        self.ultra_ops_reconstructed = self.ultra_ops_table.table.get_reconstructed();
    }

    pub fn get_ultra_ops_table_num_rows(&self) -> usize {
        self.ultra_ops_table.ultra_table_size()
    }

    pub fn get_current_ultra_ops_subtable_num_rows(&self) -> usize {
        self.ultra_ops_table.current_ultra_subtable_size()
    }
    // Get the full table of ECCVM ops in contiguous memory; construct it if it has not been constructed already
    pub fn get_eccvm_ops(&mut self) -> &Vec<CoVMOperation<T, C>> {
        if self.eccvm_ops_reconstructed.is_empty() {
            self.construct_full_eccvm_ops_table();
        }
        &self.eccvm_ops_reconstructed
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
    pub fn set_eccvm_ops_for_fuzzing(&mut self, eccvm_ops_in: Vec<CoVMOperation<T, C>>) {
        self.eccvm_ops_reconstructed = eccvm_ops_in;
    }

    pub fn get_accumulator(&self) -> &T::NativeAcvmPoint<C> {
        &self.accumulator
    }

    pub fn get_ultra_ops(&mut self) -> &Vec<CoUltraOp<T, C>> {
        if self.ultra_ops_reconstructed.is_empty() {
            self.construct_full_ultra_ops_table();
        }
        &self.ultra_ops_reconstructed
    }
}
