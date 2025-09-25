use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::TranscriptFieldType;
use co_builder::prelude::HonkCurve;
use common::{mpc::NoirUltraHonkProver, shared_polynomial::SharedPolynomial};
use goblin::prelude::{EccOpCode, EccOpsTable, EccvmRowTracker};
use num_bigint::BigUint;
use std::array;

pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub(crate) type CoEccvmOpsTable<T, C> = EccOpsTable<CoVMOperation<T, C>>;

pub struct CoUltraEccOpsTable<
    T: NoirWitnessExtensionProtocol<C::BaseField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub table: EccOpsTable<CoUltraOp<T, C>>,
}

impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>>
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
    T: NoirWitnessExtensionProtocol<C::BaseField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub op_code: EccOpCode,
    pub base_point: T::AcvmPoint<C>,
    pub z1: T::AcvmType,
    pub z2: T::AcvmType,
    pub z1_is_zero: bool,
    pub z2_is_zero: bool,
    pub base_point_is_zero: bool,
    pub mul_scalar_full: T::OtherAcvmType<C>,
}
impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>> Clone
    for CoVMOperation<T, C>
{
    fn clone(&self) -> Self {
        Self {
            op_code: self.op_code.clone(),
            base_point: self.base_point.clone(),
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
    T: NoirWitnessExtensionProtocol<C::BaseField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub op_code: EccOpCode,
    pub x_lo: T::OtherAcvmType<C>,
    pub x_hi: T::OtherAcvmType<C>,
    pub y_lo: T::OtherAcvmType<C>,
    pub y_hi: T::OtherAcvmType<C>,
    pub z_1: T::OtherAcvmType<C>,
    pub z_2: T::OtherAcvmType<C>,
    pub return_is_infinity: bool,
}
impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>> Clone
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

#[derive(Default, PartialEq, Eq, Debug, Clone)]
// TACEO TODO: Fields should be BinaryShare
pub struct CoEccOpCode<T, C>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
{
    pub(crate) add: T::ArithmeticShare,
    pub(crate) mul: T::ArithmeticShare,
    pub(crate) eq: T::ArithmeticShare,
    pub(crate) reset: T::ArithmeticShare,
}

impl<T, C> CoEccOpCode<T, C>
where
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
{
    /// Returns the value of the opcode as a 32-bit integer.
    pub fn value(&self) -> T::ArithmeticShare {
        let mut res = self.add;
        res = T::add(T::mul_with_public(C::ScalarField::from(2), res), self.mul);
        res = T::add(T::mul_with_public(C::ScalarField::from(2), res), self.eq);
        res = T::add(T::mul_with_public(C::ScalarField::from(2), res), self.reset);
        res
    }
}

pub struct CoECCOpQueue<
    T: NoirWitnessExtensionProtocol<C::BaseField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub eccvm_ops_table: CoEccvmOpsTable<T, C>,
    pub ultra_ops_table: CoUltraEccOpsTable<T, C>,
    pub accumulator: T::AcvmPoint<C>,
    pub eccvm_ops_reconstructed: Vec<CoVMOperation<T, C>>,
    pub ultra_ops_reconstructed: Vec<CoUltraOp<T, C>>,
    pub eccvm_row_tracker: EccvmRowTracker,
}

impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>>
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

    pub fn get_accumulator(&self) -> &T::AcvmPoint<C> {
        &self.accumulator
    }

    pub fn get_ultra_ops(&mut self) -> &Vec<CoUltraOp<T, C>> {
        if self.ultra_ops_reconstructed.is_empty() {
            self.construct_full_ultra_ops_table();
        }
        &self.ultra_ops_reconstructed
    }
}
