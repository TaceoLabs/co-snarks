use crate::eccvm::{NUM_WNAF_DIGITS_PER_SCALAR, POINT_TABLE_SIZE, WNAF_DIGITS_PER_ROW};
use crate::{
    eccvm::{
        ADDITIONS_PER_ROW, NUM_LIMB_BITS_IN_FIELD_SIMULATION, NUM_SCALAR_BITS,
        ecc_op_queue::{EccOpCode, EccOpsTable, EccvmRowTracker},
    },
    prelude::offset_generator,
};
use ark_ec::CurveGroup;
use ark_ff::BigInt;
use ark_ff::FftField;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use itertools::Itertools;
use num_bigint::BigUint;
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
    pub base_point: T::NativeAcvmPoint<C>,
    pub z1: T::OtherAcvmType<C>,
    pub z2: T::OtherAcvmType<C>,
    pub mul_scalar_full: T::AcvmType,
    pub base_point_is_infinity: Option<bool>,
    pub z1_is_zero: Option<bool>,
    pub z2_is_zero: Option<bool>,
}

pub fn precompute_flags<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
>(
    ops: &mut [CoVMOperation<T, C>],
    driver: &mut T,
) -> HonkProofResult<()> {
    let length = ops.len();

    // Only want to precompute flags for mul ops and only if they haven't already been computed
    let z_1_vec: Vec<T::OtherAcvmType<C>> = ops
        .iter()
        .filter(|op| (op.op_code.mul || op.op_code.add) && op.z1_is_zero.is_none())
        .map(|op| op.z1)
        .collect();
    let z_2_vec: Vec<T::OtherAcvmType<C>> = ops
        .iter()
        .filter(|op| (op.op_code.mul || op.op_code.add) && op.z2_is_zero.is_none())
        .map(|op| op.z2)
        .collect();
    let base_point_vec: Vec<T::NativeAcvmPoint<C>> = ops
        .iter()
        .filter(|op| (op.op_code.mul || op.op_code.add) && op.base_point_is_infinity.is_none())
        .map(|op| op.base_point)
        .collect();

    // TACEO TODO: Batch these four together into a single call to the MPC backend
    let z_flags = driver.is_zero_many_other(&[z_1_vec, z_2_vec].concat())?;

    let base_point_flags = driver.is_native_point_at_infinity_many(&base_point_vec)?;

    // NOTE: At this point we open (reveal) which points are at infinity, which scalars are zero, and which scalars
    // are less than 128 bits (c.f. `compute_zetas` at the end of this file). This is acceptable leakage because
    // the points at infinity naturally occur during the first round of the merge prover when previous_ultra_ops_table_columns
    // are empty, as well as during the process of batching proofs to constant size.
    // In src/barretenberg/stdlib/honk_verifier/decider_recursive_verifier.cpp, the function
    // `compute_padding_indicator_array<Curve, CONST_PROOF_SIZE_LOG_N>(accumulator->verification_key->log_circuit_size)`
    // calculates a padding array that depends only on circuit size, which for our test case has 10 zeros at the back of the array.
    // Along with the 4 infinity points from the first merge prover round, this accounts for all the infinity points we expect to see.
    // The case where scalar!=0 in `construct_and_populate_ultra_ops` and simultaneously z1=0 or z2=0 in the else branch
    // (where we split into endomorphism scalars) never actually occurs in practice.
    let z_flags: Vec<bool> = driver
        .open_many_other_acvm_type(&z_flags)?
        .iter()
        .map(|f| !f.is_zero())
        .collect();
    let base_point_flags: Vec<bool> = driver
        .open_many_acvm_type(&base_point_flags)?
        .iter()
        .map(|f| !f.is_zero())
        .collect();

    let bool_flags = [z_flags, base_point_flags].concat();

    for (i, op) in ops
        .iter_mut()
        .filter(|op| {
            (op.op_code.mul || op.op_code.add)
                && op.z1_is_zero.is_none()
                && op.z2_is_zero.is_none()
                && op.base_point_is_infinity.is_none()
        })
        .enumerate()
    {
        op.z1_is_zero = Some(bool_flags[i]);
        op.z2_is_zero = Some(bool_flags[i + length]);
        op.base_point_is_infinity = Some(bool_flags[i + 2 * length]);
    }
    Ok(())
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
            base_point_is_infinity: self.base_point_is_infinity,
            z1_is_zero: self.z1_is_zero,
            z2_is_zero: self.z2_is_zero,
        }
    }
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Default
    for CoVMOperation<T, C>
{
    fn default() -> Self {
        Self {
            op_code: EccOpCode::default(),
            base_point: T::NativeAcvmPoint::default(),
            z1: T::OtherAcvmType::default(),
            z2: T::OtherAcvmType::default(),
            mul_scalar_full: T::AcvmType::default(),
            base_point_is_infinity: None,
            z1_is_zero: None,
            z2_is_zero: None,
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
                .base_point_is_infinity
                .expect("base_point_is_infinity should be precomputed")
        {
            if !op.z1_is_zero.expect("z1_is_zero should be precomputed") {
                self.cached_active_msm_count += 1;
            }
            if !op.z2_is_zero.expect("z2_is_zero should be precomputed") {
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
    pub accumulator: T::NativeAcvmPoint<C>,
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
            accumulator: T::NativeAcvmPoint::default(),
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
    pub fn get_eccvm_ops(&mut self) -> &mut Vec<CoVMOperation<T, C>> {
        if self.eccvm_ops_reconstructed.is_empty() {
            self.construct_full_eccvm_ops_table();
        }
        &mut self.eccvm_ops_reconstructed
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

    pub fn append_eccvm_op(&mut self, ops: CoVMOperation<T, C>) {
        self.eccvm_row_tracker.update_cached_msms(&ops);
        self.eccvm_ops_table.push(ops);
    }

    pub fn append_eccvm_ops(&mut self, ops: Vec<CoVMOperation<T, C>>) {
        for op in ops {
            self.append_eccvm_op(op);
        }
    }

    pub fn get_ultra_ops(&mut self) -> &Vec<CoUltraOp<T, C>> {
        if self.ultra_ops_reconstructed.is_empty() {
            self.construct_full_ultra_ops_table();
        }
        &self.ultra_ops_reconstructed
    }
}

pub struct CoScalarMul<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub pc: u32,
    pub scalar: T::OtherAcvmType<C>,
    pub base_point: T::NativeAcvmPoint<C>,
    pub wnaf_digits: [T::OtherAcvmType<C>; NUM_WNAF_DIGITS_PER_SCALAR],
    pub wnaf_digits_sign: [T::OtherAcvmType<C>; NUM_WNAF_DIGITS_PER_SCALAR],
    pub wnaf_si: [T::OtherAcvmType<C>; 8 * (NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW)],
    pub wnaf_skew: T::OtherAcvmType<C>,
    pub row_chunks: [T::OtherAcvmType<C>; NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW],
    pub row_chunks_sign: [T::OtherAcvmType<C>; NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW],
    // size bumped by 1 to record base_point.dbl()
    pub precomputed_table: [T::NativeAcvmPoint<C>; POINT_TABLE_SIZE + 1],
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Default
    for CoScalarMul<T, C>
{
    fn default() -> Self {
        Self {
            pc: 0,
            scalar: T::OtherAcvmType::<C>::default(),
            base_point: T::NativeAcvmPoint::<C>::default(),
            wnaf_digits: [T::OtherAcvmType::<C>::default(); NUM_WNAF_DIGITS_PER_SCALAR],
            wnaf_skew: T::OtherAcvmType::<C>::default(),
            precomputed_table: [T::NativeAcvmPoint::<C>::default(); POINT_TABLE_SIZE + 1],
            wnaf_digits_sign: [T::OtherAcvmType::<C>::default(); NUM_WNAF_DIGITS_PER_SCALAR],
            wnaf_si: [T::OtherAcvmType::<C>::default();
                8 * (NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW)],
            row_chunks: [T::OtherAcvmType::<C>::default();
                NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW],
            row_chunks_sign: [T::OtherAcvmType::<C>::default();
                NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW],
        }
    }
}
impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Clone
    for CoScalarMul<T, C>
{
    fn clone(&self) -> Self {
        Self {
            pc: self.pc,
            scalar: self.scalar,
            base_point: self.base_point,
            wnaf_digits: self.wnaf_digits,
            wnaf_skew: self.wnaf_skew,
            precomputed_table: self.precomputed_table,
            wnaf_digits_sign: self.wnaf_digits_sign,
            wnaf_si: self.wnaf_si,
            row_chunks: self.row_chunks,
            row_chunks_sign: self.row_chunks_sign,
        }
    }
}

pub(crate) type Msm<C, T> = Vec<CoScalarMul<T, C>>;

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: HonkCurve<TranscriptFieldType>>
    CoECCOpQueue<T, C>
{
    pub fn get_msms(&mut self, driver: &mut T) -> eyre::Result<Vec<Msm<C, T>>> {
        let num_muls = self.get_number_of_muls();

        let compute_precomputed_table = |base_point: T::NativeAcvmPoint<C>,
                                         driver: &mut T|
         -> eyre::Result<
            [T::NativeAcvmPoint<C>; POINT_TABLE_SIZE + 1],
        > {
            let d2 = driver
                .scale_native_point(base_point, T::AcvmType::from(C::ScalarField::from(2u32)))?;
            let mut table = [T::NativeAcvmPoint::<C>::default(); POINT_TABLE_SIZE + 1];
            table[POINT_TABLE_SIZE] = d2;
            table[POINT_TABLE_SIZE / 2] = base_point;

            for i in 1..(POINT_TABLE_SIZE / 2) {
                table[i + POINT_TABLE_SIZE / 2] =
                    driver.add_points_other(table[i + POINT_TABLE_SIZE / 2 - 1], d2);
            }

            for i in 0..(POINT_TABLE_SIZE / 2) {
                table[i] = driver.scale_native_point(
                    table[POINT_TABLE_SIZE - 1 - i],
                    T::AcvmType::from(-C::ScalarField::one()),
                )?;
            }

            Ok(table)
        };

        let mut msm_count = 0;
        let mut active_mul_count = 0;
        let mut msm_opqueue_index = Vec::new();
        let mut msm_mul_index = Vec::new();
        let mut msm_sizes = Vec::new();

        let eccvm_ops = self.get_eccvm_ops();

        // Open all the `is_zero` and `is_infinity` flags
        precompute_flags(eccvm_ops, driver)?;

        for (op_idx, op) in eccvm_ops.iter().enumerate() {
            let z1_is_zero = op.z1_is_zero.expect("z1_is_zero should be precomputed");
            let z2_is_zero = op.z2_is_zero.expect("z2_is_zero should be precomputed");
            let base_point_is_infinity = op
                .base_point_is_infinity
                .expect("base_point_is_infinity should be precomputed");
            if op.op_code.mul {
                if (!z1_is_zero || !z2_is_zero) && !base_point_is_infinity {
                    msm_opqueue_index.push(op_idx);
                    msm_mul_index.push((msm_count, active_mul_count));
                    active_mul_count += (!z1_is_zero) as usize + (!z2_is_zero) as usize;
                }
            } else if active_mul_count > 0 {
                msm_sizes.push(active_mul_count);
                msm_count += 1;
                active_mul_count = 0;
            }
        }

        if eccvm_ops.last().is_some_and(|op| op.op_code.mul) && active_mul_count > 0 {
            msm_sizes.push(active_mul_count);
            msm_count += 1;
        }

        let mut result: Vec<Msm<C, T>> = Vec::with_capacity(msm_count);
        for size in &msm_sizes {
            result.push(vec![CoScalarMul::default(); *size]);
        }

        let mut z1_and_z2 = Vec::with_capacity(2 * eccvm_ops.len());
        for op in eccvm_ops.iter() {
            if !op.z1_is_zero.expect("z1_is_zero should be precomputed")
                && !op
                    .base_point_is_infinity
                    .expect("base_point_is_infinity should be precomputed")
            {
                z1_and_z2.push(op.z1);
            }
        }
        let z1_len = z1_and_z2.len();
        for op in eccvm_ops.iter() {
            if !op.z2_is_zero.expect("z2_is_zero should be precomputed")
                && !op
                    .base_point_is_infinity
                    .expect("base_point_is_infinity should be precomputed")
            {
                z1_and_z2.push(op.z2);
            }
        }

        // TACEO TODO: this is another bottleneck as it is a pretty large gc
        let wnaf_result =
            T::compute_wnaf_digits_and_compute_rows_many(driver, &z1_and_z2, NUM_SCALAR_BITS)?;

        let (z1_even, z2_even) = wnaf_result.0.split_at(z1_len);
        let (z1_wnaf_digits, z2_wnaf_digits) = wnaf_result.1.split_at(z1_len);
        let (z1_wnaf_digits_sign, z2_wnaf_digits_sign) = wnaf_result.2.split_at(z1_len);
        let (z1_wnaf_s_i, z2_wnaf_s_i) = wnaf_result.3.split_at(z1_len);
        let (z1_row_chunks, z2_row_chunks) = wnaf_result.4.split_at(z1_len);
        let (z1_row_chunks_sign, z2_row_chunks_sign) = wnaf_result.5.split_at(z1_len);

        let mut z1_index = 0;
        let mut z2_index = 0;

        for (i, &op_idx) in msm_opqueue_index.iter().enumerate() {
            let op = &eccvm_ops[op_idx];
            let (msm_index, mut mul_index) = msm_mul_index[i];

            if !op.z1_is_zero.expect("z1_is_zero should be precomputed")
                && !op
                    .base_point_is_infinity
                    .expect("base_point_is_infinity should be precomputed")
            {
                result[msm_index][mul_index] = CoScalarMul {
                    pc: 0,
                    scalar: op.z1,
                    base_point: op.base_point,
                    wnaf_digits: z1_wnaf_digits[z1_index],
                    wnaf_skew: z1_even[z1_index],
                    wnaf_digits_sign: z1_wnaf_digits_sign[z1_index],
                    wnaf_si: z1_wnaf_s_i[z1_index],
                    precomputed_table: compute_precomputed_table(op.base_point, driver)?,
                    row_chunks: z1_row_chunks[z1_index],
                    row_chunks_sign: z1_row_chunks_sign[z1_index],
                };
                mul_index += 1;
                z1_index += 1;
            }

            if !op.z2_is_zero.expect("z2_is_zero should be precomputed")
                && !op
                    .base_point_is_infinity
                    .expect("base_point_is_infinity should be precomputed")
            {
                let endo_point =
                    T::compute_endo_point(&op.base_point, C::get_cube_root_of_unity())?;
                // endo_point = C::g1_affine_from_xy(
                //     op.base_point.x().expect("BasePoint should not be zero")
                //         * C::get_cube_root_of_unity(),
                //     -op.base_point.y().expect("BasePoint should not be zero"),
                // );

                result[msm_index][mul_index] = CoScalarMul {
                    pc: 0,
                    scalar: op.z2,
                    base_point: endo_point,
                    wnaf_digits: z2_wnaf_digits[z2_index],
                    wnaf_skew: z2_even[z2_index],
                    precomputed_table: compute_precomputed_table(endo_point, driver)?,
                    wnaf_digits_sign: z2_wnaf_digits_sign[z2_index],
                    wnaf_si: z2_wnaf_s_i[z2_index],
                    row_chunks: z2_row_chunks[z2_index],
                    row_chunks_sign: z2_row_chunks_sign[z2_index],
                };
                z2_index += 1;
            }
        }

        let mut pc = num_muls;
        for msm in &mut result {
            for mul in msm {
                mul.pc = pc;
                pc -= 1;
            }
        }

        Ok(result)
    }
}
pub struct AddState<
    C: CurveGroup<BaseField: PrimeField>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub add: bool,
    pub slice: T::OtherAcvmType<C>,
    pub point: T::NativeAcvmPoint<C>,
    pub lambda: T::OtherAcvmType<C>,
    pub collision_inverse: T::OtherAcvmType<C>,
}
impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Default
    for AddState<C, T>
{
    fn default() -> Self {
        Self {
            add: false,
            slice: T::OtherAcvmType::<C>::default(),
            point: T::NativeAcvmPoint::<C>::default(),
            lambda: T::OtherAcvmType::<C>::default(),
            collision_inverse: T::OtherAcvmType::<C>::default(),
        }
    }
}
impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Clone
    for AddState<C, T>
{
    fn clone(&self) -> Self {
        Self {
            add: self.add,
            slice: self.slice,
            point: self.point,
            lambda: self.lambda,
            collision_inverse: self.collision_inverse,
        }
    }
}

pub struct MSMRow<
    C: CurveGroup<BaseField: PrimeField>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    // Counter over all half-length scalar muls used to compute the required MSMs
    pub pc: usize,
    // The number of points that will be scaled and summed
    pub msm_size: u32,
    pub msm_count: u32,
    pub msm_round: u32,
    pub msm_transition: bool,
    pub q_add: bool,
    pub q_double: bool,
    pub q_skew: bool,
    pub add_state: [AddState<C, T>; 4],
    pub accumulator_x: T::OtherAcvmType<C>,
    pub accumulator_y: T::OtherAcvmType<C>,
    phantom: std::marker::PhantomData<T>,
}
impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Default
    for MSMRow<C, T>
{
    fn default() -> Self {
        Self {
            pc: 0,
            msm_size: 0,
            msm_count: 0,
            msm_round: 0,
            msm_transition: false,
            q_add: false,
            q_double: false,
            q_skew: false,
            add_state: array::from_fn(|_| AddState::default()),
            accumulator_x: T::OtherAcvmType::<C>::default(),
            accumulator_y: T::OtherAcvmType::<C>::default(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: CurveGroup<BaseField: PrimeField>> Clone
    for MSMRow<C, T>
{
    fn clone(&self) -> Self {
        Self {
            pc: self.pc,
            msm_size: self.msm_size,
            msm_count: self.msm_count,
            msm_round: self.msm_round,
            msm_transition: self.msm_transition,
            q_add: self.q_add,
            q_double: self.q_double,
            q_skew: self.q_skew,
            add_state: self.add_state.clone(),
            accumulator_x: self.accumulator_x,
            accumulator_y: self.accumulator_y,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: HonkCurve<TranscriptFieldType>>
    MSMRow<C, T>
{
    #[expect(clippy::type_complexity)]
    pub fn compute_rows_msms(
        msms: &[Msm<C, T>],
        total_number_of_muls: u32,
        num_msm_rows: usize,
        driver: &mut T,
    ) -> eyre::Result<(Vec<Self>, [Vec<T::OtherAcvmType<C>>; 2])> {
        let num_rows_in_read_counts_table =
            (total_number_of_muls as usize) * (POINT_TABLE_SIZE / 2);
        let mut point_table_read_counts =
            vec![T::OtherAcvmType::<C>::default(); num_rows_in_read_counts_table * 2];

        let update_read_count = |point_idx: usize,
                                 mut index: T::OtherAcvmType<C>,
                                 is_negative: T::OtherAcvmType<C>,
                                 point_table_read_counts: &mut [T::OtherAcvmType<C>],
                                 driver: &mut T|
         -> eyre::Result<()> {
            let row_index_offset = point_idx * 8;

            // we mimic this functionality:
            // let digit_is_negative = slice < 0;
            // let relative_row_idx = ((slice + 15) / 2) as usize; // This is already done in the gc
            // let column_index = if digit_is_negative { 1 } else { 0 };

            // if digit_is_negative {
            //     point_table_read_counts[column_index][row_index_offset + relative_row_idx] += 1;
            // } else {
            //     point_table_read_counts[column_index][row_index_offset + 15 - relative_row_idx] +=
            //         1;
            // }

            let column_index = driver.mul_with_public_other(
                C::BaseField::from(num_rows_in_read_counts_table as u32),
                is_negative,
            );

            driver.add_assign_other(&mut index, column_index);
            driver.add_assign_other(
                &mut index,
                T::OtherAcvmType::<C>::from(C::BaseField::from(row_index_offset as u32)),
            );

            if T::is_shared_other(&index) {
                let ohv = driver.one_hot_vector_from_shared_index_other(
                    T::get_shared_other(&index).expect("Checked it is shared"),
                    num_rows_in_read_counts_table * 2,
                )?;
                for (point_table_read_count, x) in
                    point_table_read_counts.iter_mut().zip(ohv.iter())
                {
                    let tmp = T::OtherAcvmType::<C>::from(x.to_owned());
                    driver.add_assign_other(point_table_read_count, tmp);
                }
            } else {
                let index_value: BigUint = T::get_public_other(&index)
                    .expect("Checked it is public")
                    .into();
                let index_value = usize::try_from(index_value)
                    .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;
                driver.add_assign_other(
                    &mut point_table_read_counts[index_value],
                    T::OtherAcvmType::<C>::from(C::BaseField::one()),
                );
            }

            Ok(())
        };

        let update_read_count_negative = |point_idx: usize,
                                          slice: T::OtherAcvmType<C>,
                                          point_table_read_counts: &mut [T::OtherAcvmType<C>],
                                          driver: &mut T|
         -> eyre::Result<()> {
            // we mimic this functionality, but we already know that we are in the negative branch:
            // let digit_is_negative = slice < 0;
            // let relative_row_idx = ((slice + 15) / 2) as usize; //Attention FLORIN, this is already done for the slices
            // let column_index = if digit_is_negative { 1 } else { 0 };

            // if digit_is_negative {
            //     point_table_read_counts[column_index][row_index_offset + relative_row_idx] += 1;
            // } else {
            //     point_table_read_counts[column_index][row_index_offset + 15 - relative_row_idx] +=
            //         1;
            // }

            let row_index_offset = point_idx * 8;
            let relative_row_idx = driver.add_other(
                slice,
                T::OtherAcvmType::<C>::from(C::BaseField::from(15u32)),
            );
            let two_inverse = C::BaseField::from(2u32)
                .inverse()
                .expect("2 has an inverse");
            let relative_row_idx = driver.mul_with_public_other(two_inverse, relative_row_idx);

            let index = driver.add_other(
                relative_row_idx,
                T::OtherAcvmType::<C>::from(C::BaseField::from(row_index_offset as u32)),
            );
            if T::is_shared_other(&index) {
                let ohv = driver.one_hot_vector_from_shared_index_other(
                    T::get_shared_other(&index).expect("Checked it is shared"),
                    num_rows_in_read_counts_table,
                )?;
                for (point_table_read_count, x) in point_table_read_counts
                    [num_rows_in_read_counts_table..] // we are in the negative branch
                    .iter_mut()
                    .zip(ohv.iter())
                {
                    let tmp = T::OtherAcvmType::<C>::from(x.to_owned());
                    driver.add_assign_other(point_table_read_count, tmp);
                }
            } else {
                let index_value: BigUint = T::get_public_other(&index)
                    .expect("Checked it is public")
                    .into();
                let mut index_value =
                    usize::try_from(index_value).expect("Index to large for usize");
                index_value += num_rows_in_read_counts_table; // we are in the negative branch
                driver.add_assign_other(
                    &mut point_table_read_counts[index_value],
                    T::OtherAcvmType::<C>::from(C::BaseField::one()),
                );
            }

            Ok(())
        };

        let mut msm_row_counts = Vec::with_capacity(msms.len() + 1);
        msm_row_counts.push(1);

        let mut pc_values = Vec::with_capacity(msms.len() + 1);
        pc_values.push(total_number_of_muls);

        for msm in msms {
            let num_rows_required = EccvmRowTracker::num_eccvm_msm_rows(msm.len());
            msm_row_counts.push(
                msm_row_counts
                    .last()
                    .expect("msm_row_counts should not be empty")
                    + num_rows_required as usize,
            );
            pc_values
                .push(pc_values.last().expect("pc_values should not be empty") - msm.len() as u32);
        }

        let mut msm_rows = vec![MSMRow::default(); num_msm_rows];
        msm_rows[0] = MSMRow::default();

        let mut slices_for_cmux = Vec::with_capacity(msms.len() * NUM_WNAF_DIGITS_PER_SCALAR);
        let mut signs_for_cmux = Vec::with_capacity(msms.len() * NUM_WNAF_DIGITS_PER_SCALAR);
        for msm in msms.iter() {
            for digit_idx in 0..NUM_WNAF_DIGITS_PER_SCALAR {
                let msm_size = msm.len();
                let num_rows_per_digit = (msm_size / ADDITIONS_PER_ROW)
                    + if msm_size % ADDITIONS_PER_ROW != 0 {
                        1
                    } else {
                        0
                    };
                for relative_row_idx in 0..num_rows_per_digit {
                    let num_points_in_row = if (relative_row_idx + 1) * ADDITIONS_PER_ROW > msm_size
                    {
                        msm_size % ADDITIONS_PER_ROW
                    } else {
                        ADDITIONS_PER_ROW
                    };
                    let offset = relative_row_idx * ADDITIONS_PER_ROW;
                    for relative_point_idx in 0..ADDITIONS_PER_ROW {
                        let point_idx = offset + relative_point_idx;
                        let add = num_points_in_row > relative_point_idx;
                        if add {
                            slices_for_cmux.push(msm[point_idx].wnaf_digits[digit_idx]);
                            signs_for_cmux.push(msm[point_idx].wnaf_digits_sign[digit_idx]);
                        }
                    }
                }
            }
        }
        let cmux_results = driver.cmux_many_other(
            &signs_for_cmux,
            &slices_for_cmux,
            &slices_for_cmux
                .iter()
                .map(|x| {
                    driver.sub_other(T::OtherAcvmType::<C>::from(C::BaseField::from(15u32)), *x)
                })
                .collect::<Vec<_>>(),
        )?;
        let mut j = 0;

        // TACEO TODO: this loop is a/the bottleneck in the ECCVM part, as we are creating a ohv for each update_read_count
        for (msm_idx, msm) in msms.iter().enumerate() {
            for digit_idx in 0..NUM_WNAF_DIGITS_PER_SCALAR {
                let pc = pc_values[msm_idx];
                let msm_size = msm.len();
                let num_rows_per_digit = (msm_size / ADDITIONS_PER_ROW)
                    + if msm_size % ADDITIONS_PER_ROW != 0 {
                        1
                    } else {
                        0
                    };

                for relative_row_idx in 0..num_rows_per_digit {
                    let num_points_in_row = if (relative_row_idx + 1) * ADDITIONS_PER_ROW > msm_size
                    {
                        msm_size % ADDITIONS_PER_ROW
                    } else {
                        ADDITIONS_PER_ROW
                    };
                    let offset = relative_row_idx * ADDITIONS_PER_ROW;

                    for relative_point_idx in 0..ADDITIONS_PER_ROW {
                        let point_idx = offset + relative_point_idx;
                        let add = num_points_in_row > relative_point_idx;
                        if add {
                            update_read_count(
                                (total_number_of_muls - pc) as usize + point_idx,
                                cmux_results[j],
                                msm[point_idx].wnaf_digits_sign[digit_idx],
                                &mut point_table_read_counts,
                                driver,
                            )?;
                            j += 1;
                        }
                    }
                }

                if digit_idx == NUM_WNAF_DIGITS_PER_SCALAR - 1 {
                    let mut cmux = Vec::with_capacity(num_rows_per_digit * ADDITIONS_PER_ROW);

                    for row_idx in 0..num_rows_per_digit {
                        let num_points_in_row = if (row_idx + 1) * ADDITIONS_PER_ROW > msm_size {
                            msm_size % ADDITIONS_PER_ROW
                        } else {
                            ADDITIONS_PER_ROW
                        };
                        let offset = row_idx * ADDITIONS_PER_ROW;
                        for relative_point_idx in 0..ADDITIONS_PER_ROW {
                            let add = num_points_in_row > relative_point_idx;
                            let point_idx = offset + relative_point_idx;
                            if add {
                                cmux.push(msm[point_idx].wnaf_skew);
                            }
                        }
                    }
                    let cmux_result = driver.cmux_many_other(
                        &cmux,
                        &vec![T::OtherAcvmType::<C>::from(-C::BaseField::from(1u32)); cmux.len()],
                        &vec![T::OtherAcvmType::<C>::from(-C::BaseField::from(15u32)); cmux.len()],
                    )?;

                    let mut i = 0;
                    for row_idx in 0..num_rows_per_digit {
                        let num_points_in_row = if (row_idx + 1) * ADDITIONS_PER_ROW > msm_size {
                            msm_size % ADDITIONS_PER_ROW
                        } else {
                            ADDITIONS_PER_ROW
                        };
                        let offset = row_idx * ADDITIONS_PER_ROW;

                        for relative_point_idx in 0..ADDITIONS_PER_ROW {
                            let add = num_points_in_row > relative_point_idx;
                            let point_idx = offset + relative_point_idx;
                            if add {
                                let slice = cmux_result[i];
                                //if msm[point_idx].wnaf_skew { -1 } else { -15 };
                                update_read_count_negative(
                                    (total_number_of_muls - pc) as usize + point_idx,
                                    slice, //slice will always be negative here
                                    &mut point_table_read_counts,
                                    driver,
                                )?;
                                i += 1;
                            }
                        }
                    }
                }
            }
        }

        // The execution trace data for the MSM columns requires knowledge of intermediate values from *affine* point
        // addition. The naive solution to compute this data requires 2 field inversions per in-circuit group addition
        // evaluation. This is bad! To avoid this, we split the witness computation algorithm into 3 steps.
        //   Step 1: compute the execution trace group operations in *projective* coordinates
        //   Step 2: use batch inversion trick to convert all points into affine coordinates
        //   Step 3: populate the full execution trace, including the intermediate values from affine group operations
        // This section sets up the data structures we need to store all intermediate ECC operations in projective form
        let num_point_adds_and_doubles = (num_msm_rows - 2) * 4;
        let num_accumulators = num_msm_rows - 1;
        // In what fallows, either p1 + p2 = p3, or p1.dbl() = p3
        // We create 1 vector to store the entire point trace. We split into multiple containers using std::span
        // (we want 1 vector object to more efficiently batch normalize points)

        let mut p1_trace = vec![T::NativeAcvmPoint::<C>::default(); num_point_adds_and_doubles];
        let mut p2_trace = vec![T::NativeAcvmPoint::<C>::default(); num_point_adds_and_doubles];
        let mut p3_trace = vec![T::NativeAcvmPoint::<C>::default(); num_point_adds_and_doubles];
        // operation_trace records whether an entry in the p1/p2/p3 trace represents a point addition or doubling
        let mut operation_trace = vec![false; num_point_adds_and_doubles];
        // accumulator_trace tracks the value of the ECCVM accumulator for each row
        let mut accumulator_trace = vec![T::NativeAcvmPoint::<C>::default(); num_accumulators];

        // we start the accumulator at the offset generator point. This ensures we can support an MSM that produces a
        let offset_generator = T::NativeAcvmPoint::from(offset_generator::<C>().into());
        accumulator_trace[0] = offset_generator;

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/973): Reinstate multitreading?
        // populate point trace, and the components of the MSM execution trace that do not relate to affine point
        // operations

        let wnaf_skews: Vec<_> = msms
            .iter()
            .flat_map(|msm| msm.iter().map(|mul| mul.wnaf_skew))
            .collect();
        let wnaf_digits: Vec<_> = msms
            .iter()
            .flat_map(|msm| msm.iter().flat_map(|mul| mul.wnaf_digits.iter().copied()))
            .collect();
        let wnaf_digits_len = wnaf_digits.len();

        let mut to_convert = Vec::with_capacity(wnaf_digits.len() + wnaf_skews.len());
        to_convert.extend(wnaf_digits);
        to_convert.extend(wnaf_skews);

        let converted = driver.convert_fields::<C>(&to_convert)?;
        let (converted_wnaf_digits, converted_wnaf_skews) = converted.split_at(wnaf_digits_len);

        let mut msm_offset_wnaf_digits = 0;
        let mut msm_offset_wnaf_skews = 0;

        //TACEO TODO: This loop is another bottleneck because of the calls to read_lut_by_acvm_point
        for msm_idx in 0..msms.len() {
            let mut accumulator = offset_generator;
            let msm = &msms[msm_idx];
            let mut msm_row_index = msm_row_counts[msm_idx];
            let msm_size = msm.len();
            let num_rows_per_digit = (msm_size / ADDITIONS_PER_ROW)
                + if msm_size % ADDITIONS_PER_ROW != 0 {
                    1
                } else {
                    0
                };
            let mut trace_index = (msm_row_counts[msm_idx] - 1) * 4;

            for digit_idx in 0..NUM_WNAF_DIGITS_PER_SCALAR {
                let pc = pc_values[msm_idx];
                for row_idx in 0..num_rows_per_digit {
                    let num_points_in_row = if (row_idx + 1) * ADDITIONS_PER_ROW > msm_size {
                        msm_size % ADDITIONS_PER_ROW
                    } else {
                        ADDITIONS_PER_ROW
                    };
                    let row = &mut msm_rows[msm_row_index];
                    let offset = row_idx * ADDITIONS_PER_ROW;
                    row.msm_transition = (digit_idx == 0) && (row_idx == 0);

                    for point_idx in 0..ADDITIONS_PER_ROW {
                        let add_state = &mut row.add_state[point_idx];
                        add_state.add = num_points_in_row > point_idx;
                        let slice = if add_state.add {
                            msm[offset + point_idx].wnaf_digits[digit_idx]
                        } else {
                            T::OtherAcvmType::default()
                        };
                        // In the MSM columns in the ECCVM circuit, we can add up to 4 points per row.
                        // if `row.add_state[point_idx].add = true`, this indicates that we want to add the
                        // `point_idx`'th point in the MSM columns into the MSM accumulator.
                        // `add_state.slice` = A 4-bit WNAF slice of the scalar multiplier associated with the point we are adding
                        // (the specific slice chosen depends on the value of msm_round).
                        // (WNAF = windowed-non-adjacent-form. Value range is `-15, -13, ..., 15`).
                        // If `add_state.add = true`, we want `add_state.slice` to be the *compressed*
                        // form of the WNAF slice value. (compressed = no gaps in the value range. i.e. -15,
                        // -13, ..., 15 maps to 0, ..., 15).
                        add_state.slice = if add_state.add {
                            slice
                        } else {
                            T::OtherAcvmType::default()
                        };
                        add_state.point = if add_state.add {
                            let lut = driver.init_lut_by_acvm_point(
                                msm[offset + point_idx].precomputed_table.to_vec(),
                            );
                            let index = converted_wnaf_digits[msm_offset_wnaf_digits
                                + (offset + point_idx) * NUM_WNAF_DIGITS_PER_SCALAR
                                + digit_idx];
                            driver.read_lut_by_acvm_point(index, &lut)?
                        } else {
                            T::NativeAcvmPoint::<C>::default()
                        };

                        let p1 = accumulator;
                        let p2 = add_state.point;
                        accumulator = if add_state.add {
                            driver.add_points_other(accumulator, add_state.point)
                        } else {
                            p1
                        };
                        p1_trace[trace_index] = p1;
                        p2_trace[trace_index] = p2;
                        p3_trace[trace_index] = accumulator;
                        operation_trace[trace_index] = false;
                        trace_index += 1;
                    }
                    accumulator_trace[msm_row_index] = accumulator;
                    row.q_add = true;
                    row.q_double = false;
                    row.q_skew = false;
                    row.msm_round = digit_idx as u32;
                    row.msm_size = msm_size as u32;
                    row.msm_count = offset as u32;
                    row.pc = pc as usize;
                    msm_row_index += 1;
                }
                // doubling
                if digit_idx < NUM_WNAF_DIGITS_PER_SCALAR - 1 {
                    let row = &mut msm_rows[msm_row_index];
                    row.msm_transition = false;
                    row.msm_round = (digit_idx + 1) as u32;
                    row.msm_size = msm_size as u32;
                    row.msm_count = 0_u32;
                    row.q_add = false;
                    row.q_double = true;
                    row.q_skew = false;
                    for point_idx in 0..ADDITIONS_PER_ROW {
                        let add_state = &mut row.add_state[point_idx];
                        add_state.add = false;
                        add_state.slice = T::OtherAcvmType::default();
                        add_state.point = T::NativeAcvmPoint::default();
                        add_state.collision_inverse = T::OtherAcvmType::default();
                        p1_trace[trace_index] = accumulator;
                        p2_trace[trace_index] = accumulator;
                        accumulator = driver.add_points_other(accumulator, accumulator);
                        p3_trace[trace_index] = accumulator;
                        operation_trace[trace_index] = true;
                        trace_index += 1;
                    }
                    accumulator_trace[msm_row_index] = accumulator;
                    msm_row_index += 1;
                } else {
                    for row_idx in 0..num_rows_per_digit {
                        let row = &mut msm_rows[msm_row_index];

                        let num_points_in_row = if (row_idx + 1) * ADDITIONS_PER_ROW > msm_size {
                            msm_size % ADDITIONS_PER_ROW
                        } else {
                            ADDITIONS_PER_ROW
                        };
                        let offset = row_idx * ADDITIONS_PER_ROW;
                        row.msm_transition = false;
                        for point_idx in 0..ADDITIONS_PER_ROW {
                            let add_state = &mut row.add_state[point_idx];
                            add_state.add = num_points_in_row > point_idx;
                            add_state.slice = if add_state.add {
                                driver.mul_with_public_other(
                                    C::BaseField::from(7),
                                    msm[offset + point_idx].wnaf_skew,
                                )
                            } else {
                                T::OtherAcvmType::default()
                            };
                            let converted_wnaf_skew = if add_state.add {
                                converted_wnaf_skews[msm_offset_wnaf_skews + offset + point_idx]
                            } else {
                                T::AcvmType::default()
                            };
                            add_state.point = if add_state.add {
                                // msm[offset + point_idx].precomputed_table[add_state.slice as usize]
                                let lut = driver.init_lut_by_acvm_point(
                                    msm[offset + point_idx].precomputed_table.to_vec(),
                                );
                                let index = driver
                                    .mul_with_public(C::ScalarField::from(7), converted_wnaf_skew);
                                driver.read_lut_by_acvm_point(index, &lut)?
                            } else {
                                T::NativeAcvmPoint::<C>::default()
                            };

                            let p1 = accumulator;
                            accumulator = {
                                let added_points =
                                    driver.add_points_other(accumulator, add_state.point);
                                let add_predicate_inverted = driver.sub(
                                    T::AcvmType::from(C::ScalarField::one()),
                                    converted_wnaf_skew,
                                );
                                driver.msm(
                                    &[accumulator, added_points],
                                    &[add_predicate_inverted, converted_wnaf_skew],
                                )?
                            };
                            p1_trace[trace_index] = p1;
                            p2_trace[trace_index] = add_state.point;
                            p3_trace[trace_index] = accumulator;
                            operation_trace[trace_index] = false;
                            trace_index += 1;
                        }
                        row.q_add = false;
                        row.q_double = false;
                        row.q_skew = true;
                        row.msm_round = (digit_idx + 1) as u32;
                        row.msm_size = msm_size as u32;
                        row.msm_count = offset as u32;
                        row.pc = pc as usize;
                        accumulator_trace[msm_row_index] = accumulator;
                        msm_row_index += 1;
                    }
                }
            }
            msm_offset_wnaf_digits += msm.len() * NUM_WNAF_DIGITS_PER_SCALAR;
            msm_offset_wnaf_skews += msm.len();
        }

        // inverse_trace is used to compute the value of the `collision_inverse` column in the ECCVM.
        let mut inverse_trace = Vec::with_capacity(num_point_adds_and_doubles);
        let mut tmp = Vec::with_capacity(num_point_adds_and_doubles * 2 + num_accumulators);
        tmp.extend_from_slice(&p1_trace);
        tmp.extend_from_slice(&p2_trace);
        tmp.extend_from_slice(&accumulator_trace);
        let (xs, ys, _) = driver.other_pointshare_to_other_field_shares_many(&tmp)?;
        let (p1_xs, rest) = xs.split_at(num_point_adds_and_doubles);
        let (p2_xs, acc_xs) = rest.split_at(num_point_adds_and_doubles);
        let (p1_ys, rest) = ys.split_at(num_point_adds_and_doubles);
        let (p2_ys, acc_ys) = rest.split_at(num_point_adds_and_doubles);

        for operation_idx in 0..num_point_adds_and_doubles {
            let (tmp1_x, tmp1_y) = (p1_xs[operation_idx], p1_ys[operation_idx]);
            let tmp2_x = p2_xs[operation_idx];

            if operation_trace[operation_idx] {
                inverse_trace.push(driver.add_other(tmp1_y, tmp1_y));
            } else {
                inverse_trace.push(driver.sub_other(tmp2_x, tmp1_x));
            }
        }

        let inverse_trace = driver.inverse_or_zero_many_other(&inverse_trace)?;

        // complete the computation of the ECCVM execution trace, by adding the affine intermediate point data
        // i.e. row.accumulator_x, row.accumulator_y, row.add_state[0...3].collision_inverse,
        // row.add_state[0...3].lambda
        for msm_idx in 0..msms.len() {
            let msm = &msms[msm_idx];
            let mut trace_index = (msm_row_counts[msm_idx] - 1) * ADDITIONS_PER_ROW;
            let mut msm_row_index = msm_row_counts[msm_idx];
            // 1st MSM row will have accumulator equal to the previous MSM output
            // (or point at infinity for 1st MSM)
            let mut accumulator_index = msm_row_counts[msm_idx] - 1;
            let msm_size = msm.len();
            let num_rows_per_digit = (msm_size / ADDITIONS_PER_ROW)
                + (if msm_size % ADDITIONS_PER_ROW != 0 {
                    1
                } else {
                    0
                });

            for digit_idx in 0..NUM_WNAF_DIGITS_PER_SCALAR {
                for _ in 0..num_rows_per_digit {
                    let row = &mut msm_rows[msm_row_index];
                    let (normalized_accumulator_x, normalized_accumulator_y) =
                        (acc_xs[accumulator_index], acc_ys[accumulator_index]);

                    row.accumulator_x = normalized_accumulator_x;
                    row.accumulator_y = normalized_accumulator_y;
                    for point_idx in 0..ADDITIONS_PER_ROW {
                        let add_state = &mut row.add_state[point_idx];
                        let inverse = &inverse_trace[trace_index];
                        add_state.collision_inverse = if add_state.add {
                            *inverse
                        } else {
                            T::OtherAcvmType::default()
                        };
                        add_state.lambda = if add_state.add {
                            let p1_y = p1_ys[trace_index];
                            let p2_y = p2_ys[trace_index];
                            let sub = driver.sub_other(p2_y, p1_y);
                            driver.mul_other(sub, *inverse)?
                        } else {
                            T::OtherAcvmType::default()
                        };
                        trace_index += 1;
                    }
                    accumulator_index += 1;
                    msm_row_index += 1;
                }

                if digit_idx < NUM_WNAF_DIGITS_PER_SCALAR - 1 {
                    let row = &mut msm_rows[msm_row_index];
                    let (normalized_accumulator_x, normalized_accumulator_y) =
                        (acc_xs[accumulator_index], acc_ys[accumulator_index]);
                    let acc_x = normalized_accumulator_x;
                    let acc_y = normalized_accumulator_y;
                    row.accumulator_x = acc_x;
                    row.accumulator_y = acc_y;

                    let p1_x_s = &p1_xs[trace_index..trace_index + ADDITIONS_PER_ROW];
                    let inverses = &inverse_trace[trace_index..trace_index + ADDITIONS_PER_ROW];
                    let three_dx = driver.scale_many_other(p1_x_s, C::BaseField::from(3));
                    //TACEO TODO batch these multiplications outside
                    let three_dx_dx = driver.mul_many_other(&three_dx, p1_x_s)?;
                    let res = driver.mul_many_other(&three_dx_dx, inverses)?; //((*dx + dx + dx) * dx) * inverse;
                    for (point_idx, point) in res.iter().enumerate().take(ADDITIONS_PER_ROW) {
                        let add_state = &mut row.add_state[point_idx];
                        add_state.collision_inverse = T::OtherAcvmType::default();
                        add_state.lambda = *point;
                        trace_index += 1;
                    }
                    accumulator_index += 1;
                    msm_row_index += 1;
                } else {
                    for row_idx in 0..num_rows_per_digit {
                        let row = &mut msm_rows[msm_row_index];
                        let offset = row_idx * ADDITIONS_PER_ROW;
                        let (normalized_accumulator_x, normalized_accumulator_y) =
                            (acc_xs[accumulator_index], acc_ys[accumulator_index]);
                        row.accumulator_x = normalized_accumulator_x;
                        row.accumulator_y = normalized_accumulator_y;
                        let p1_ys = &p1_ys[trace_index..trace_index + ADDITIONS_PER_ROW];
                        let p2_ys = &p2_ys[trace_index..trace_index + ADDITIONS_PER_ROW];
                        let inverses = &inverse_trace[trace_index..trace_index + ADDITIONS_PER_ROW];
                        let sub = driver.sub_many_other(p2_ys, p1_ys);
                        let add_predicates = row.add_state[0..ADDITIONS_PER_ROW]
                            .iter()
                            .enumerate()
                            .map(|(point_idx, s)| {
                                if s.add {
                                    msm[offset + point_idx].wnaf_skew
                                } else {
                                    T::OtherAcvmType::default()
                                }
                            })
                            .collect::<Vec<T::OtherAcvmType<C>>>();
                        //TACEO TODO batch these multiplications outside
                        let res = driver.mul_many_other(
                            &[sub, add_predicates.clone()].concat(),
                            &[inverses, inverses].concat(),
                        )?;
                        let first_half = &res[0..ADDITIONS_PER_ROW];
                        let second_half = &res[ADDITIONS_PER_ROW..];
                        let res = driver.mul_many_other(first_half, &add_predicates)?;

                        for point_idx in 0..ADDITIONS_PER_ROW {
                            let add_state = &mut row.add_state[point_idx];

                            add_state.lambda = res[point_idx];
                            add_state.collision_inverse = second_half[point_idx];

                            trace_index += 1;
                        }
                        accumulator_index += 1;
                        msm_row_index += 1;
                    }
                }
            }
        }

        // populate the final row in the MSM execution trace.
        // we always require 1 extra row at the end of the trace, because the accumulator x/y coordinates for row `i`
        // are present at row `i+1`
        let final_accumulator = accumulator_trace
            .last()
            .expect("Should have at least one accumulator");
        let final_row = &mut msm_rows.last_mut().expect("Should have at least one row");
        final_row.pc = *pc_values.last().expect("Should have at least one pc value") as usize;
        final_row.msm_transition = true;
        let (final_x, final_y, _) =
            driver.other_pointshare_to_other_field_share(final_accumulator)?;
        final_row.accumulator_x = final_x;
        final_row.accumulator_y = final_y;
        final_row.msm_size = 0;
        final_row.msm_count = 0;
        final_row.q_add = false;
        final_row.q_double = false;
        final_row.q_skew = false;
        final_row.add_state = [
            AddState {
                add: false,
                slice: T::OtherAcvmType::default(),
                point: T::NativeAcvmPoint::<C>::default(),
                lambda: T::OtherAcvmType::default(),
                collision_inverse: T::OtherAcvmType::default(),
            },
            AddState {
                add: false,
                slice: T::OtherAcvmType::default(),
                point: T::NativeAcvmPoint::<C>::default(),
                lambda: T::OtherAcvmType::default(),
                collision_inverse: T::OtherAcvmType::default(),
            },
            AddState {
                add: false,
                slice: T::OtherAcvmType::default(),
                point: T::NativeAcvmPoint::<C>::default(),
                lambda: T::OtherAcvmType::default(),
                collision_inverse: T::OtherAcvmType::default(),
            },
            AddState {
                add: false,
                slice: T::OtherAcvmType::default(),
                point: T::NativeAcvmPoint::<C>::default(),
                lambda: T::OtherAcvmType::default(),
                collision_inverse: T::OtherAcvmType::default(),
            },
        ];

        let point_table_read_counts = [
            point_table_read_counts[0..num_rows_in_read_counts_table].to_vec(),
            point_table_read_counts
                [num_rows_in_read_counts_table..num_rows_in_read_counts_table * 2]
                .to_vec(),
        ];
        Ok((msm_rows, point_table_read_counts))
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
        to_add: T::NativeAcvmPoint<C>,
        precomputed_point_limbs: Option<[T::AcvmType; 5]>,
        driver: &mut T,
    ) -> HonkProofResult<CoUltraOp<T, C>> {
        // Update the accumulator natively
        self.accumulator = driver.add_points_other(self.accumulator, to_add);
        let op_code = EccOpCode {
            add: true,
            ..Default::default()
        };

        // Store the eccvm operation
        self.append_eccvm_op(CoVMOperation {
            op_code: op_code.clone(),
            base_point: to_add,
            ..Default::default()
        });

        // Construct and store the operation in the ultra op format
        self.construct_and_populate_ultra_ops(
            op_code,
            to_add,
            precomputed_point_limbs,
            None,
            driver,
        )
    }

    /**
     * @brief Write point addition op to queue and natively perform addition
     *
     * @param to_add
     */
    pub fn add_accumulate_no_store(
        &mut self,
        to_add: T::NativeAcvmPoint<C>,
        precomputed_point_limbs: Option<[T::AcvmType; 5]>,
        driver: &mut T,
    ) -> HonkProofResult<(CoUltraOp<T, C>, CoVMOperation<T, C>)> {
        // Update the accumulator natively
        self.accumulator = driver.add_points_other(self.accumulator, to_add);
        let op_code = EccOpCode {
            add: true,
            ..Default::default()
        };

        // Construct and store the operation in the ultra op format
        let ultra_op = self.construct_and_populate_ultra_ops(
            op_code.clone(),
            to_add,
            precomputed_point_limbs,
            None,
            driver,
        )?;

        let eccvm_op = CoVMOperation {
            op_code,
            base_point: to_add,
            ..Default::default()
        };

        Ok((ultra_op, eccvm_op))
    }

    pub fn mul_accumulate_no_store(
        &mut self,
        to_mul: T::NativeAcvmPoint<C>,
        precomputed_point_limbs: Option<[T::AcvmType; 5]>,
        scalar: T::AcvmType,
        driver: &mut T,
    ) -> HonkProofResult<(CoUltraOp<T, C>, CoVMOperation<T, C>)> {
        // Update the accumulator natively
        let tmp = driver.scale_native_point(to_mul, scalar)?;
        self.accumulator = driver.add_points_other(self.accumulator, tmp);

        let op_code = EccOpCode {
            mul: true,
            ..Default::default()
        };

        // Construct and store the operation in the ultra op format
        let ultra_op = self.construct_and_populate_ultra_ops(
            op_code.clone(),
            to_mul,
            precomputed_point_limbs,
            Some(scalar),
            driver,
        )?;

        let [z1, z2] = driver
            .acvm_type_to_other_acvm_type_many(&[ultra_op.z_1, ultra_op.z_2])?
            .try_into()
            .expect("Failed to convert z1, z2");
        let eccvm_op = CoVMOperation {
            op_code,
            base_point: to_mul,
            z1,
            z2,
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
            self.accumulator,
            None,
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
        let expected = self.accumulator;
        self.accumulator = T::NativeAcvmPoint::default();
        let op_code = EccOpCode {
            eq: true,
            reset: true,
            ..Default::default()
        };

        // Store the eccvm operation
        self.append_eccvm_op(CoVMOperation {
            op_code: op_code.clone(),
            base_point: expected,
            ..Default::default()
        });

        // Construct and store the operation in the ultra op format
        self.construct_and_populate_ultra_ops(op_code, expected, None, None, driver)
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
        point: T::NativeAcvmPoint<C>,
        precomputed_point_limbs: Option<[T::AcvmType; 5]>,
        scalar: Option<T::AcvmType>,
        driver: &mut T,
    ) -> HonkProofResult<CoUltraOp<T, C>> {
        let [x_lo, x_hi, y_lo, y_hi, return_is_infinity] =
            if let Some(limbs) = precomputed_point_limbs {
                limbs
            } else {
                Self::compute_point_limbs(point, driver)?
            };

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

    fn compute_point_limbs(
        point: T::NativeAcvmPoint<C>,
        driver: &mut T,
    ) -> HonkProofResult<[T::AcvmType; 5]> {
        let (x, y, is_point_at_infinity) = driver
            .native_point_to_other_acvm_types(point)
            .expect("Error converting point to field shares");

        // Decompose point coordinates (Fq) into hi-lo chunks (Fr)
        // TACEO TODO: Batch these conversions into one `other_field_shares_to_field_shares_many`
        const CHUNK_SIZE: usize = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION;
        let [x_lo, x_hi] = driver
            .other_field_shares_to_field_shares::<CHUNK_SIZE, _>(x)?
            .try_into()
            .expect("Failed to convert x_lo, x_hi");
        let [y_lo, y_hi] = driver
            .other_field_shares_to_field_shares::<CHUNK_SIZE, _>(y)?
            .try_into()
            .expect("Failed to convert y_lo, y_hi");
        let [is_infinity, _] = driver
            .other_field_shares_to_field_shares::<CHUNK_SIZE, _>(is_point_at_infinity)?
            .try_into()
            .expect("Failed to convert is_point_at_infinity");

        let mut one_minus_is_infinity = is_infinity;
        driver.negate_inplace(&mut one_minus_is_infinity);
        driver.add_assign_with_public(C::ScalarField::ONE, &mut one_minus_is_infinity);

        let [x_lo, x_hi, y_lo, y_hi] = driver
            .mul_many(
                &[x_lo, x_hi, y_lo, y_hi],
                &std::iter::repeat_n(one_minus_is_infinity, 4).collect_vec(),
            )?
            .try_into()
            .expect("Failed to convert x_lo, x_hi, y_lo, y_hi");

        Ok([x_lo, x_hi, y_lo, y_hi, is_infinity])
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
        let cond = driver.le(converted, rhs.into())?;

        let (mont_k1, mont_k2) = (
            Self::to_montgomery_form(k_1, driver),
            Self::to_montgomery_form(k_2, driver),
        );
        let [k1, k2] = driver
            .cmux_many(cond, &[scalar, T::AcvmType::default()], &[mont_k1, mont_k2])?
            .try_into()
            .expect("Failed to convert k1, k2");
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

        let beta = C::ScalarField::get_root_of_unity(3).expect("No cube root of unity");

        let tmp = driver.mul_with_public(beta, t1);
        let t2 = driver.add(tmp, scalar);
        Ok((t2, t1))
    }

    fn recompose_shares(x: [T::AcvmType; 4], driver: &mut T) -> T::AcvmType {
        let mut res = T::AcvmType::default();
        for (i, chunk) in x.into_iter().enumerate() {
            let shift = C::ScalarField::from_bigint(
                BigInt::from(1u64).shl(
                    (i * u64::BITS as usize)
                        .try_into()
                        .expect("Failed to compute shift"),
                ),
            )
            .expect("Failed to parse bigint");
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
        driver.mul_with_public(
            mont_r
                .inverse()
                .expect("Montgomery R should have an inverse"),
            x,
        )
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
                        None,
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
