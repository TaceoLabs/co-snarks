use crate::eccvm::{
    NUM_LIMB_BITS_IN_FIELD_SIMULATION,
    ecc_op_queue::{EccOpCode, EccOpsTable, EccvmRowTracker},
};
use ark_ec::CurveGroup;
use ark_ff::BigInt;
use ark_ff::FftField;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use common::honk_proof::{HonkProofResult, TranscriptFieldType};
use itertools::Itertools;
use std::array;
use std::ops::Shl;

pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub type CoEccvmOpsTable<T, C> = EccOpsTable<CoVMOperation<T, C>>;

#[derive(Debug)]
pub struct CoUltraEccOpsTable<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub table: EccOpsTable<CoUltraOp<T, C>>,
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Default
    for CoUltraEccOpsTable<T, C>
{
    fn default() -> Self {
        Self {
            table: EccOpsTable::<CoUltraOp<T, C>>::new(),
        }
    }
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

    pub fn previous_ultra_table_size(&self) -> usize {
        self.ultra_table_size() - self.current_ultra_subtable_size()
    }

    pub fn create_new_subtable(&mut self, size_hint: usize) {
        self.table.create_new_subtable(size_hint);
    }

    pub fn construct_table_columns(&self) -> [Vec<T::AcvmType>; TABLE_WIDTH] {
        let poly_size = self.ultra_table_size();
        let subtable_start_idx = 0; // include all subtables
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
        )
    }

    pub fn construct_previous_table_columns(&self) -> [Vec<T::AcvmType>; TABLE_WIDTH] {
        let poly_size = self.previous_ultra_table_size();
        let subtable_start_idx = 1; // exclude the 0th subtable
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
        )
    }

    pub fn construct_current_ultra_ops_subtable_columns(&self) -> [Vec<T::AcvmType>; TABLE_WIDTH] {
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
    ) -> [Vec<T::AcvmType>; TABLE_WIDTH] {
        let mut column_polynomials: [Vec<T::AcvmType>; TABLE_WIDTH] =
            array::from_fn(|_| vec![T::AcvmType::default(); poly_size]);

        let mut i = 0;
        for subtable_idx in subtable_start_idx..subtable_end_idx {
            let subtable = &self.table.get()[subtable_idx];
            for op in subtable {
                column_polynomials[0][i] = C::ScalarField::from(op.op_code.value()).into();
                column_polynomials[1][i] = op.x_lo;
                column_polynomials[2][i] = op.x_hi;
                column_polynomials[3][i] = op.y_lo;
                i += 1;
                column_polynomials[0][i] = T::AcvmType::default(); // only the first 'op' field is utilized
                column_polynomials[1][i] = op.y_hi;
                column_polynomials[2][i] = op.z_1;
                column_polynomials[3][i] = op.z_2;
                i += 1;
            }
        }
        column_polynomials
    }
}

#[derive(Debug)]
pub struct CoVMOperation<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub op_code: EccOpCode,
    pub base_point: T::OtherAcvmPoint<C>,
    pub z1: T::AcvmType,
    pub z2: T::AcvmType,
    pub mul_scalar_full: T::AcvmType,
    pub is_base_point_infinity: Option<bool>,
    pub is_z1_zero: Option<bool>,
    pub is_z2_zero: Option<bool>,
}

pub fn precompute_flags<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
>(
    ops: &mut Vec<&mut CoVMOperation<T, C>>,
    driver: &mut T,
) -> HonkProofResult<()> {
    let length = ops.len();

    // Only want to precompute flags for mul ops and only if they haven't already been computed
    let z_1_vec: Vec<T::AcvmType> = ops
        .iter()
        .filter(|op| (op.op_code.mul || op.op_code.add) && op.is_z1_zero.is_none())
        .map(|op| op.z1)
        .collect();
    let z_2_vec: Vec<T::AcvmType> = ops
        .iter()
        .filter(|op| (op.op_code.mul || op.op_code.add) && op.is_z2_zero.is_none())
        .map(|op| op.z2)
        .collect();
    let base_point_vec: Vec<T::OtherAcvmPoint<C>> = ops
        .iter()
        .filter(|op| (op.op_code.mul || op.op_code.add) && op.is_base_point_infinity.is_none())
        .map(|op| op.base_point.clone())
        .collect();

    let z_flags = driver.is_zero_many(&[z_1_vec, z_2_vec].concat())?;

    let base_point_flags = driver.is_point_at_infinity_many_other(&base_point_vec)?;

    let flags = driver.open_many_acvm_type(&[z_flags, base_point_flags].concat())?;

    let bool_flags: Vec<bool> = flags.iter().map(|f| !f.is_zero()).collect();

    for (i, op) in ops
        .iter_mut()
        .filter(|op| {
            (op.op_code.mul || op.op_code.add)
                && op.is_z1_zero.is_none()
                && op.is_z2_zero.is_none()
                && op.is_base_point_infinity.is_none()
        })
        .enumerate()
    {
        op.is_z1_zero = Some(bool_flags[i]);
        op.is_z2_zero = Some(bool_flags[i + length]);
        op.is_base_point_infinity = Some(bool_flags[i + 2 * length]);
    }
    Ok(())
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Clone
    for CoVMOperation<T, C>
{
    fn clone(&self) -> Self {
        Self {
            op_code: self.op_code.clone(),
            base_point: self.base_point.clone(),
            z1: self.z1,
            z2: self.z2,
            mul_scalar_full: self.mul_scalar_full,
            is_base_point_infinity: self.is_base_point_infinity,
            is_z1_zero: self.is_z1_zero,
            is_z2_zero: self.is_z2_zero,
        }
    }
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Default
    for CoVMOperation<T, C>
{
    fn default() -> Self {
        Self {
            op_code: EccOpCode::default(),
            base_point: T::OtherAcvmPoint::default(),
            z1: T::AcvmType::default(),
            z2: T::AcvmType::default(),
            mul_scalar_full: T::AcvmType::default(),
            is_base_point_infinity: None,
            is_z1_zero: None,
            is_z2_zero: None,
        }
    }
}

pub struct CoEccOpTuple<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub op: u32,
    pub x_lo: u32,
    pub x_hi: u32,
    pub y_lo: u32,
    pub y_hi: u32,
    pub z_1: u32,
    pub z_2: u32,
    pub return_is_infinity: T::AcvmType,
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Default
    for CoEccOpTuple<T, C>
{
    fn default() -> Self {
        Self {
            op: 0,
            x_lo: 0,
            x_hi: 0,
            y_lo: 0,
            y_hi: 0,
            z_1: 0,
            z_2: 0,
            return_is_infinity: T::AcvmType::default(),
        }
    }
}

#[derive(Default, Debug)]
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
    pub return_is_infinity: T::AcvmType,
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

impl EccvmRowTracker {
    /**
     * @brief Update cached_active_msm_count or update other row counts and reset cached_active_msm_count.
     * @details To the OpQueue, an MSM is a sequence of successive mul opcodes (note that mul might better be called
     * mul_add--its effect on the accumulator is += scalar * point).
     *
     * @param op
     */
    pub fn update_cached_msms<
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        C: CurveGroup<BaseField: PrimeField>,
    >(
        &mut self,
        op: &CoVMOperation<T, C>,
    ) {
        self.num_transcript_rows += 1;
        if op.op_code.mul
            && !op
                .is_base_point_infinity
                .expect("is_base_point_infinity should be precomputed")
        {
            if !op.is_z1_zero.expect("is_z1_zero should be precomputed") {
                self.cached_active_msm_count += 1;
            }
            if !op.is_z2_zero.expect("is_z2_zero should be precomputed") {
                self.cached_active_msm_count += 1;
            }
        } else if self.cached_active_msm_count != 0 {
            self.num_msm_rows +=
                EccvmRowTracker::num_eccvm_msm_rows(self.cached_active_msm_count as usize);
            self.num_precompute_table_rows +=
                EccvmRowTracker::get_precompute_table_row_count_for_single_msm(
                    self.cached_active_msm_count as usize,
                );
            self.cached_num_muls += self.cached_active_msm_count;
            self.cached_active_msm_count = 0;
        }
    }
}

#[derive(Debug)]
pub struct CoECCOpQueue<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub eccvm_ops_table: CoEccvmOpsTable<T, C>,
    pub ultra_ops_table: CoUltraEccOpsTable<T, C>,
    pub accumulator: T::OtherAcvmPoint<C>,
    pub eccvm_ops_reconstructed: Vec<CoVMOperation<T, C>>,
    pub ultra_ops_reconstructed: Vec<CoUltraOp<T, C>>,
    pub eccvm_row_tracker: EccvmRowTracker,
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Default
    for CoECCOpQueue<T, C>
{
    fn default() -> Self {
        Self {
            eccvm_ops_table: CoEccvmOpsTable::default(),
            ultra_ops_table: CoUltraEccOpsTable::default(),
            accumulator: T::OtherAcvmPoint::default(),
            eccvm_ops_reconstructed: Vec::new(),
            ultra_ops_reconstructed: Vec::new(),
            eccvm_row_tracker: EccvmRowTracker::default(),
        }
    }
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>>
    CoECCOpQueue<T, C>
{
    // Initialize a new subtable of ECCVM ops and Ultra ops corresponding to an individual circuit
    pub fn initialize_new_subtable(&mut self) {
        self.eccvm_ops_table.create_new_subtable(0);
        self.ultra_ops_table.create_new_subtable(0);
    }

    // Construct polynomials corresponding to the columns of the full aggregate ultra ecc ops table
    pub fn construct_ultra_ops_table_columns(&self) -> [Vec<T::AcvmType>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_table_columns()
    }

    // Construct polys corresponding to the columns of the aggregate ultra ops table, excluding the most recent subtable
    pub fn construct_previous_ultra_ops_table_columns(&self) -> [Vec<T::AcvmType>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_previous_table_columns()
    }

    // Construct polynomials corresponding to the columns of the current subtable of ultra ecc ops
    pub fn construct_current_ultra_ops_subtable_columns(&self) -> [Vec<T::AcvmType>; TABLE_WIDTH] {
        self.ultra_ops_table
            .construct_current_ultra_ops_subtable_columns()
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
     * @brief A fuzzing only method for setting eccvm ops directly
     *
     */
    pub fn set_eccvm_ops_for_fuzzing(&mut self, eccvm_ops_in: Vec<CoVMOperation<T, C>>) {
        self.eccvm_ops_reconstructed = eccvm_ops_in;
    }

    pub fn get_accumulator(&self) -> &T::OtherAcvmPoint<C> {
        &self.accumulator
    }

    pub fn append_eccvm_op(&mut self, ops: CoVMOperation<T, C>) {
        self.eccvm_row_tracker.update_cached_msms(&ops);
        self.eccvm_ops_table.push(ops);
    }

    pub fn append_eccvm_ops(&mut self, ops: Vec<CoVMOperation<T, C>>) {
        for op in ops {
            self.append_eccvm_op(op);
        }
    }
}

pub trait EndomorphismParams {
    const ENDO_G1_LO: u64;
    const ENDO_G1_MID: u64;
    const ENDO_G1_HI: u64;
    const ENDO_G2_LO: u64;
    const ENDO_G2_MID: u64;
    const ENDO_MINUS_B1_LO: u64;
    const ENDO_MINUS_B1_MID: u64;
    const ENDO_B2_LO: u64;
    const ENDO_B2_MID: u64;
}

pub struct Bn254ParamsFr;
pub struct Bn254ParamsFq;

impl EndomorphismParams for Bn254ParamsFr {
    const ENDO_G1_LO: u64 = 0x7a7bd9d4391eb18d;
    const ENDO_G1_MID: u64 = 0x4ccef014a773d2cf;
    const ENDO_G1_HI: u64 = 0x0000000000000002;
    const ENDO_G2_LO: u64 = 0xd91d232ec7e0b3d7;
    const ENDO_G2_MID: u64 = 0x0000000000000002;
    const ENDO_MINUS_B1_LO: u64 = 0x8211bbeb7d4f1128;
    const ENDO_MINUS_B1_MID: u64 = 0x6f4d8248eeb859fc;
    const ENDO_B2_LO: u64 = 0x89d3256894d213e3;
    const ENDO_B2_MID: u64 = 0x0000000000000000;
}

impl EndomorphismParams for Bn254ParamsFq {
    const ENDO_G1_LO: u64 = 0x7a7bd9d4391eb18d;
    const ENDO_G1_MID: u64 = 0x4ccef014a773d2cf;
    const ENDO_G1_HI: u64 = 0x0000000000000002;
    const ENDO_G2_LO: u64 = 0xd91d232ec7e0b3d2;
    const ENDO_G2_MID: u64 = 0x0000000000000002;
    const ENDO_MINUS_B1_LO: u64 = 0x8211bbeb7d4f1129;
    const ENDO_MINUS_B1_MID: u64 = 0x6f4d8248eeb859fc;
    const ENDO_B2_LO: u64 = 0x89d3256894d213e2;
    const ENDO_B2_MID: u64 = 0x0000000000000000;
}

impl<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField, ScalarField = TranscriptFieldType>,
> CoECCOpQueue<T, C>
{
    /**
     * @brief Write point addition op to queue and natively perform addition
     *
     * @param to_add
     */
    pub fn add_accumulate(
        &mut self,
        to_add: T::OtherAcvmPoint<C>,
        driver: &mut T,
    ) -> HonkProofResult<CoUltraOp<T, C>> {
        // Update the accumulator natively
        self.accumulator = driver.add_points_other(self.accumulator.clone(), to_add.clone());
        let op_code = EccOpCode {
            add: true,
            ..Default::default()
        };

        // Store the eccvm operation
        self.append_eccvm_op(CoVMOperation {
            op_code: op_code.clone(),
            base_point: to_add.clone(),
            ..Default::default()
        });

        // Construct and store the operation in the ultra op format
        self.construct_and_populate_ultra_ops(op_code, to_add, None, driver)
    }

    /**
     * @brief Write point addition op to queue and natively perform addition
     *
     * @param to_add
     */
    pub fn add_accumulate_no_store(
        &mut self,
        to_add: T::OtherAcvmPoint<C>,
        driver: &mut T,
    ) -> HonkProofResult<(CoUltraOp<T, C>, CoVMOperation<T, C>)> {
        // Update the accumulator natively
        self.accumulator = driver.add_points_other(self.accumulator.clone(), to_add.clone());
        let op_code = EccOpCode {
            add: true,
            ..Default::default()
        };

        // Construct and store the operation in the ultra op format
        let ultra_op =
            self.construct_and_populate_ultra_ops(op_code.clone(), to_add.clone(), None, driver)?;

        let eccvm_op = CoVMOperation {
            op_code,
            base_point: to_add,
            ..Default::default()
        };

        Ok((ultra_op, eccvm_op))
    }

    pub fn mul_accumulate_no_store(
        &mut self,
        to_mul: T::OtherAcvmPoint<C>,
        scalar: T::AcvmType,
        driver: &mut T,
    ) -> HonkProofResult<(CoUltraOp<T, C>, CoVMOperation<T, C>)> {
        // Update the accumulator natively
        let tmp = driver.scale_point_other(to_mul.clone(), scalar)?;
        self.accumulator = driver.add_points_other(self.accumulator.clone(), tmp);

        let op_code = EccOpCode {
            mul: true,
            ..Default::default()
        };

        // Construct and store the operation in the ultra op format
        let ultra_op = self.construct_and_populate_ultra_ops(
            op_code.clone(),
            to_mul.clone(),
            Some(scalar),
            driver,
        )?;

        let eccvm_op = CoVMOperation {
            op_code,
            base_point: to_mul,
            z1: ultra_op.z_1,
            z2: ultra_op.z_2,
            mul_scalar_full: scalar,
            ..Default::default()
        };

        Ok((ultra_op, eccvm_op))
    }

    /**
     * @brief Writes a no op (i.e. two zero rows) to the ultra ops table but adds no eccvm operations.
     *
     * @details We want to be able to add zero rows (and, eventually, random rows
     * <https://github.com/AztecProtocol/barretenberg/issues/1360>) to the ultra ops table without affecting the
     * operations in the ECCVM.
     */
    pub fn no_op_ultra_only(&mut self, driver: &mut T) -> HonkProofResult<CoUltraOp<T, C>> {
        self.construct_and_populate_ultra_ops(
            EccOpCode::default(),
            self.accumulator.clone(),
            None,
            driver,
        )
    }

    /**
     * @brief Write equality op using internal accumulator point
     *
     * @return current internal accumulator point (prior to reset to 0)
     */
    pub fn eq_and_reset(&mut self, driver: &mut T) -> HonkProofResult<CoUltraOp<T, C>> {
        let expected = self.accumulator.clone();

        self.accumulator = T::OtherAcvmPoint::default();
        let op_code = EccOpCode {
            eq: true,
            reset: true,
            ..Default::default()
        };

        // Store the eccvm operation
        self.append_eccvm_op(CoVMOperation {
            op_code: op_code.clone(),
            base_point: expected.clone(),
            ..Default::default()
        });

        // Construct and store the operation in the ultra op format
        self.construct_and_populate_ultra_ops(op_code, expected, None, driver)
    }

    /**
     * @brief Given an ecc operation and its inputs, decompose into ultra format and populate ultra_ops
     *
     * @param op_code
     * @param point
     * @param scalar
     * @return UltraOp
     */
    pub fn construct_and_populate_ultra_ops(
        &mut self,
        op_code: EccOpCode,
        point: T::OtherAcvmPoint<C>,
        scalar: Option<T::AcvmType>,
        driver: &mut T,
    ) -> HonkProofResult<CoUltraOp<T, C>> {
        let (x, y, is_point_at_infinity) = driver
            .other_pointshare_to_other_field_shares(point)
            .expect("Error converting point to field shares");

        // Decompose point coordinates (Fq) into hi-lo chunks (Fr)
        const CHUNK_SIZE: usize = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION;
        let [x_lo, x_hi] = driver
            .other_field_shares_to_field_shares::<CHUNK_SIZE, _>(x)?
            .try_into()
            .unwrap();
        let [y_lo, y_hi] = driver
            .other_field_shares_to_field_shares::<CHUNK_SIZE, _>(y)?
            .try_into()
            .unwrap();
        let [return_is_infinity, _] = driver
            .other_field_shares_to_field_shares::<CHUNK_SIZE, _>(is_point_at_infinity)?
            .try_into()
            .unwrap();

        let mut one_minus_return_is_infinity = return_is_infinity;
        driver.negate_inplace(&mut one_minus_return_is_infinity);
        driver.add_assign_with_public(C::ScalarField::ONE, &mut one_minus_return_is_infinity);

        let [x_lo, x_hi, y_lo, y_hi] = driver
            .mul_many(
                &[x_lo, x_hi, y_lo, y_hi],
                &std::iter::repeat_n(one_minus_return_is_infinity, 4).collect_vec(),
            )?
            .try_into()
            .unwrap();

        let (z_1, z_2) = Self::compute_zetas(scalar, driver)?;

        let co_ultra_op = CoUltraOp {
            op_code,
            x_lo,
            x_hi,
            y_lo,
            y_hi,
            z_1,
            z_2,
            return_is_infinity,
        };

        self.ultra_ops_table.table.push(co_ultra_op.clone());
        Ok(co_ultra_op)
    }

    fn compute_zetas(
        scalar: Option<T::AcvmType>,
        driver: &mut T,
    ) -> HonkProofResult<(T::AcvmType, T::AcvmType)> {
        if scalar.is_none() {
            return Ok((T::AcvmType::default(), T::AcvmType::default()));
        }

        let scalar = scalar.unwrap();
        let converted = CoECCOpQueue::<T, C>::from_montgomery_form(scalar, driver);

        let (k_1, k_2) = CoECCOpQueue::<T, C>::split_into_endomorphism_scalars::<Bn254ParamsFr>(
            converted, driver,
        )?;

        let rhs = C::ScalarField::from(2).pow([128]);
        let cond = driver.le(converted, rhs.into()).unwrap();

        let (mont_k1, mont_k2) = (
            Self::to_montgomery_form(k_1, driver),
            Self::to_montgomery_form(k_2, driver),
        );
        let [k1, k2] = driver
            .cmux_many(cond, &[scalar, T::AcvmType::default()], &[mont_k1, mont_k2])?
            .try_into()
            .unwrap();
        Ok((k1, k2))
    }

    /**
     * For short Weierstrass curves y^2 = x^3 + b mod r, if there exists a cube root of unity mod r,
     * we can take advantage of an enodmorphism to decompose a 254 bit scalar into 2 128 bit scalars.
     * \beta = cube root of 1, mod q (q = order of fq)
     * \lambda = cube root of 1, mod r (r = order of fr)
     *
     * For a point P1 = (X, Y), where Y^2 = X^3 + b, we know that
     * the point P2 = (X * \beta, Y) is also a point on the curve
     * We can represent P2 as a scalar multiplication of P1, where P2 = \lambda * P1
     *
     * For a generic multiplication of P1 by a 254 bit scalar k, we can decompose k
     * into 2 127 bit scalars (k1, k2), such that k = k1 - (k2 * \lambda)
     *
     * We can now represent (k * P1) as (k1 * P1) - (k2 * P2), where P2 = (X * \beta, Y).
     * As k1, k2 have half the bit length of k, we have reduced the number of loop iterations of our
     * scalar multiplication algorithm in half
     *
     * To find k1, k2, We use the extended euclidean algorithm to find 4 short scalars [a1, a2], [b1, b2] such that
     * modulus = (a1 * b2) - (b1 * a2)
     * We then compute scalars c1 = round(b2 * k / r), c2 = round(b1 * k / r), where
     * k1 = (c1 * a1) + (c2 * a2), k2 = -((c1 * b1) + (c2 * b2))
     * We pre-compute scalars g1 = (2^256 * b1) / n, g2 = (2^256 * b2) / n, to avoid having to perform long division
     * on 512-bit scalars
     **/
    pub fn split_into_endomorphism_scalars<Params: EndomorphismParams>(
        scalar: T::AcvmType,
        driver: &mut T,
    ) -> HonkProofResult<(T::AcvmType, T::AcvmType)> {
        let endo_g1 = BigInt([
            Params::ENDO_G1_LO,
            Params::ENDO_G1_MID,
            Params::ENDO_G1_HI,
            0,
        ]);
        let endo_g2 = BigInt([Params::ENDO_G2_LO, Params::ENDO_G2_MID, 0, 0]);
        let endo_minus_b1 = BigInt([Params::ENDO_MINUS_B1_LO, Params::ENDO_MINUS_B1_MID, 0, 0]);
        let endo_b2 = BigInt([Params::ENDO_B2_LO, Params::ENDO_B2_MID, 0, 0]);

        let scalar_montgomery = CoECCOpQueue::<T, C>::to_montgomery_form(scalar, driver);
        let scalar_chunks: [T::AcvmType; 4] = driver
            .decompose_acvm_type(
                scalar_montgomery,
                C::ScalarField::MODULUS_BIT_SIZE as usize,
                u64::BITS as usize,
            )?
            .try_into()
            .expect("Failed to convert scalar chunks");

        let c1 = CoECCOpQueue::<T, C>::mul_high(scalar_chunks, endo_g2, driver)?;
        let c2 = CoECCOpQueue::<T, C>::mul_high(scalar_chunks, endo_g1, driver)?;
        let q1 = CoECCOpQueue::<T, C>::mul_low(c1, endo_minus_b1, driver)?;
        let q2 = CoECCOpQueue::<T, C>::mul_low(c2, endo_b2, driver)?;

        let q1 = CoECCOpQueue::<T, C>::recompose_shares(q1, driver);
        let q2 = CoECCOpQueue::<T, C>::recompose_shares(q2, driver);

        let q1 = CoECCOpQueue::<T, C>::from_montgomery_form(q1, driver);
        let q2 = CoECCOpQueue::<T, C>::from_montgomery_form(q2, driver);

        let t1 = driver.sub(q2, q1);

        let beta = C::ScalarField::get_root_of_unity(3).unwrap();

        let tmp = driver.mul_with_public(beta, t1);
        let t2 = driver.add(tmp, scalar);
        Ok((t2, t1))
    }

    fn recompose_shares(x: [T::AcvmType; 4], driver: &mut T) -> T::AcvmType {
        let mut res = T::AcvmType::default();
        for (i, chunk) in x.into_iter().enumerate() {
            let shift = C::ScalarField::from_bigint(
                BigInt::from(1u64).shl((i * u64::BITS as usize).try_into().unwrap()),
            )
            .unwrap();
            let tmp = driver.mul_with_public(shift, chunk);
            res = driver.add(res, tmp);
        }
        res
    }

    // TACEO TODO: Optimize this function to avoid decomposing so much
    fn mul(x: [T::AcvmType; 4], y: BigInt<4>, driver: &mut T) -> HonkProofResult<[T::AcvmType; 8]> {
        let mut res = [T::AcvmType::default(); 8];
        let mut prev_column_carry = Vec::new();
        for col in 0..7 {
            let mut column_values = Vec::new();
            let mut row_carries = Vec::new();

            // Fill each column
            for (i, x_limb) in x.iter().enumerate() {
                for (j, y_limb) in y.0.iter().enumerate() {
                    if i + j == col {
                        let (product, row_carry) = CoECCOpQueue::<T, C>::mul_carry(
                            *x_limb,
                            *y_limb,
                            prev_column_carry.pop().unwrap_or_default(),
                            driver,
                        )?;
                        column_values.push(product);
                        row_carries.push(row_carry);
                    }
                }
            }

            // Update previous column carry
            prev_column_carry = row_carries;

            // Add all values and previous carry
            let (column_sum, column_carry) =
                CoECCOpQueue::<T, C>::add_many_carry(column_values, res[col], driver)?;
            res[col] = column_sum;

            // Add carry to next column
            if col < 7 {
                res[col + 1] = column_carry;
            }
        }
        Ok(res)
    }

    fn mul_low(
        x: [T::AcvmType; 4],
        y: BigInt<4>,
        driver: &mut T,
    ) -> HonkProofResult<[T::AcvmType; 4]> {
        CoECCOpQueue::<T, C>::mul(x, y, driver).map(|res| {
            res[..4]
                .try_into()
                .expect("Failed to convert scalar chunks")
        })
    }

    fn mul_high(
        x: [T::AcvmType; 4],
        y: BigInt<4>,
        driver: &mut T,
    ) -> HonkProofResult<[T::AcvmType; 4]> {
        CoECCOpQueue::<T, C>::mul(x, y, driver).map(|res| {
            res[4..]
                .try_into()
                .expect("Failed to convert scalar chunks")
        })
    }

    fn mul_carry(
        x: T::AcvmType,
        y: u64,
        carry: T::AcvmType,
        driver: &mut T,
    ) -> HonkProofResult<(T::AcvmType, T::AcvmType)> {
        let tmp = driver.mul_with_public(C::ScalarField::from(y), x);
        let total_res = driver.add(tmp, carry);

        let [result, carry, _, _] = driver
            .decompose_acvm_type(
                total_res,
                C::ScalarField::MODULUS_BIT_SIZE as usize,
                u64::BITS as usize,
            )?
            .try_into()
            .expect("Failed to convert scalar chunks");

        Ok((result, carry))
    }

    fn add_many_carry(
        x: Vec<T::AcvmType>,
        carry: T::AcvmType,
        driver: &mut T,
    ) -> HonkProofResult<(T::AcvmType, T::AcvmType)> {
        let total_res = driver.add(
            x.into_iter().reduce(|a, b| driver.add(a, b)).unwrap(),
            carry,
        );

        let [result, carry, _, _] = driver
            .decompose_acvm_type(
                total_res,
                C::ScalarField::MODULUS_BIT_SIZE as usize,
                u64::BITS as usize,
            )?
            .try_into()
            .expect("Failed to convert scalar chunks");

        Ok((result, carry))
    }

    fn from_montgomery_form(x: T::AcvmType, driver: &mut T) -> T::AcvmType {
        let mont_r: C::ScalarField = C::ScalarField::MODULUS.montgomery_r().into();
        driver.mul_with_public(mont_r.inverse().unwrap(), x)
    }

    fn to_montgomery_form(x: T::AcvmType, driver: &mut T) -> T::AcvmType {
        let mont_r = C::ScalarField::MODULUS.montgomery_r().into();
        driver.mul_with_public(mont_r, x)
    }
}

#[cfg(test)]
mod test {
    use std::thread;

    use crate::eccvm::co_ecc_op_queue::Bn254ParamsFr;
    use crate::eccvm::{co_ecc_op_queue::CoECCOpQueue, ecc_op_queue::EccOpCode};
    use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
    use ark_ec::pairing::Pairing;
    use co_acvm::{Rep3AcvmPoint, Rep3AcvmSolver, Rep3AcvmType, mpc::NoirWitnessExtensionProtocol};
    use itertools::izip;
    use mpc_core::{
        gadgets::field_from_hex_string,
        protocols::rep3::{conversion::A2BType, share_curve_point, share_field_element},
    };
    use mpc_net::local::LocalNetwork;
    use rand::thread_rng;

    type P = Bn254;
    type Bn254G1 = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;
    type Scalar = <P as Pairing>::ScalarField;
    type Driver<'a> = Rep3AcvmSolver<'a, Fr, LocalNetwork>;

    #[test]
    fn test_construct_and_populate_ultra_ops() {
        // Point: (0x211561d55817d8e259180a3e684611e49f458da76ade6a1f5a2bad3dd20ed047, 0x1eab68c1f7807f482ffc7dd13fd9a0ce3bf26240230270ac781e2dc5c5460b3f)
        // Scalar: 0x02d9b5973384d81dc3e502de86b99ff96c38b15c4b1c4520d2a3147c7777ce1f
        // x_lo: 0x000000000000000000000000000000e49f458da76ade6a1f5a2bad3dd20ed047
        // x_hi: 0x0000000000000000000000000000000000211561d55817d8e259180a3e684611
        // y_lo: 0x000000000000000000000000000000ce3bf26240230270ac781e2dc5c5460b3f
        // y_hi: 0x00000000000000000000000000000000001eab68c1f7807f482ffc7dd13fd9a0
        // z_1: 0x0000000000000000000000000000000018ffbbc11990c665e3edc805f6d1ccf9
        // z_2: 0x000000000000000000000000000000004f9333cd430dea1bc75410733863e4f1

        let point: G1Projective = G1Affine {
            x: field_from_hex_string(
                "0x211561d55817d8e259180a3e684611e49f458da76ade6a1f5a2bad3dd20ed047",
            )
            .unwrap(),
            y: field_from_hex_string(
                "0x1eab68c1f7807f482ffc7dd13fd9a0ce3bf26240230270ac781e2dc5c5460b3f",
            )
            .unwrap(),
            infinity: false,
        }
        .into();

        let shared_point = share_curve_point(point, &mut thread_rng());

        let scalar = field_from_hex_string(
            "0x02d9b5973384d81dc3e502de86b99ff96c38b15c4b1c4520d2a3147c7777ce1f",
        )
        .unwrap();

        let shared_scalar = share_field_element(scalar, &mut thread_rng());

        let expected_result: [Fr; 6] = [
            field_from_hex_string(
                "0x000000000000000000000000000000e49f458da76ade6a1f5a2bad3dd20ed047",
            )
            .unwrap(),
            field_from_hex_string(
                "0x0000000000000000000000000000000000211561d55817d8e259180a3e684611",
            )
            .unwrap(),
            field_from_hex_string(
                "0x000000000000000000000000000000ce3bf26240230270ac781e2dc5c5460b3f",
            )
            .unwrap(),
            field_from_hex_string(
                "0x00000000000000000000000000000000001eab68c1f7807f482ffc7dd13fd9a0",
            )
            .unwrap(),
            field_from_hex_string(
                "0x0000000000000000000000000000000018ffbbc11990c665e3edc805f6d1ccf9",
            )
            .unwrap(),
            field_from_hex_string(
                "0x000000000000000000000000000000004f9333cd430dea1bc75410733863e4f1",
            )
            .unwrap(),
        ];

        let nets = LocalNetwork::new_3_parties();
        let mut threads = Vec::with_capacity(3);

        for (net, point_share, scalar_share) in izip!(nets.into_iter(), shared_point, shared_scalar)
        {
            threads.push(thread::spawn(move || {
                let mut driver = Driver::new(&net, &net, A2BType::default()).unwrap();
                let mut op_queue = CoECCOpQueue::<Driver, Bn254G1>::default();
                let co_ultra_op = op_queue
                    .construct_and_populate_ultra_ops(
                        EccOpCode::default(),
                        Rep3AcvmPoint::Shared(point_share),
                        Some(scalar_share.into()),
                        &mut driver,
                    )
                    .unwrap();

                let result = [
                    co_ultra_op.x_lo,
                    co_ultra_op.x_hi,
                    co_ultra_op.y_lo,
                    co_ultra_op.y_hi,
                    co_ultra_op.z_1,
                    co_ultra_op.z_2,
                ];

                driver.open_many_acvm_type(&result).unwrap()
            }));
        }

        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(results.into_iter().all(|res| res == expected_result));
    }

    #[test]
    fn test_split_into_endomorphism_scalars() {
        // Scalar: 0x1a7855215e6c4b0cf02a37d1d2c8fb001f24f29e98a784096786558e824ee6b3
        // t1: 0x1ba2c8d6ff259fa8c79d53093767cd1002d67810d1cb07c131d4fbfac46bf8c9
        // t2: 0x0b8ab330373e7c36cab04db25e7f2a1119d7820f8941279a4ec3718c0ebe742c

        let scalar = field_from_hex_string(
            "0x1a7855215e6c4b0cf02a37d1d2c8fb001f24f29e98a784096786558e824ee6b3",
        )
        .unwrap();

        let scalar_shares = share_field_element(scalar, &mut thread_rng());

        let expected_result: Vec<Scalar> = vec![
            field_from_hex_string(
                "0x0b8ab330373e7c36cab04db25e7f2a1119d7820f8941279a4ec3718c0ebe742c",
            )
            .unwrap(),
            field_from_hex_string(
                "0x1ba2c8d6ff259fa8c79d53093767cd1002d67810d1cb07c131d4fbfac46bf8c9",
            )
            .unwrap(),
        ];

        let nets = LocalNetwork::new_3_parties();
        let mut threads = Vec::with_capacity(3);

        for (net, share) in nets.into_iter().zip(scalar_shares.into_iter()) {
            threads.push(thread::spawn(move || {
                let mut driver = Driver::new(&net, &net, A2BType::default()).unwrap();
                let (a, b) = CoECCOpQueue::<Driver, Bn254G1>::split_into_endomorphism_scalars::<
                    Bn254ParamsFr,
                >(Rep3AcvmType::Shared(share), &mut driver)
                .unwrap();
                driver.open_many_acvm_type(&[a, b]).unwrap()
            }));
        }

        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

        assert!(results.into_iter().all(|res| res == expected_result));
    }
}
