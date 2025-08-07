use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::{One, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::TranscriptFieldType;
use co_builder::prelude::HonkCurve;
use co_builder::prelude::offset_generator;
use goblin::WNAF_DIGITS_PER_ROW;
use goblin::prelude::EccvmRowTracker;
use goblin::{
    ADDITIONS_PER_ROW, NUM_WNAF_DIGITS_PER_SCALAR, POINT_TABLE_SIZE,
    prelude::{EccOpCode, EccOpsTable},
};
use itertools::Itertools;
use num_bigint::BigUint;
use std::array;

pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub type CoEccvmOpsTable<T, C> = EccOpsTable<CoVMOperation<T, C>>;

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
}

pub(crate) struct CoScalarMul<
    T: NoirWitnessExtensionProtocol<C::BaseField>,
    C: CurveGroup<BaseField: PrimeField>,
> {
    pub(crate) pc: u32,
    pub(crate) scalar: T::AcvmType,
    pub(crate) base_point: T::AcvmPoint<C>,
    pub(crate) wnaf_digits: [T::AcvmType; NUM_WNAF_DIGITS_PER_SCALAR],
    pub(crate) wnaf_digits_sign: [T::AcvmType; NUM_WNAF_DIGITS_PER_SCALAR],
    pub(crate) wnaf_si: [T::AcvmType; 8 * (NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW)],
    pub(crate) wnaf_skew: T::AcvmType,
    pub(crate) row_chunks: [T::AcvmType; NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW],
    pub(crate) row_chunks_sign: [T::AcvmType; NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW],
    // size bumped by 1 to record base_point.dbl()
    pub(crate) precomputed_table: [T::AcvmPoint<C>; POINT_TABLE_SIZE + 1],
}

impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>> Default
    for CoScalarMul<T, C>
{
    fn default() -> Self {
        Self {
            pc: 0,
            scalar: T::AcvmType::default(),
            base_point: T::AcvmPoint::<C>::default(),
            wnaf_digits: [T::AcvmType::default(); NUM_WNAF_DIGITS_PER_SCALAR],
            wnaf_skew: T::AcvmType::default(),
            precomputed_table: [T::AcvmPoint::<C>::default(); POINT_TABLE_SIZE + 1],
            wnaf_digits_sign: [T::AcvmType::default(); NUM_WNAF_DIGITS_PER_SCALAR],
            wnaf_si: [T::AcvmType::default();
                8 * (NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW)],
            row_chunks: [T::AcvmType::default(); NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW],
            row_chunks_sign: [T::AcvmType::default();
                NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW],
        }
    }
}
impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>> Clone
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

impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: HonkCurve<TranscriptFieldType>>
    CoECCOpQueue<T, C>
{
    pub(crate) fn get_msms(&mut self, driver: &mut T) -> eyre::Result<Vec<Msm<C, T>>> {
        let num_muls = self.get_number_of_muls();

        let compute_precomputed_table = |base_point: T::AcvmPoint<C>,
                                         driver: &mut T|
         -> [T::AcvmPoint<C>; POINT_TABLE_SIZE + 1] {
            let d2 = driver.msm_public_scalar(base_point, C::ScalarField::from(2u32));
            let mut table = [T::AcvmPoint::default(); POINT_TABLE_SIZE + 1];
            table[POINT_TABLE_SIZE] = d2;
            table[POINT_TABLE_SIZE / 2] = base_point;

            for i in 1..(POINT_TABLE_SIZE / 2) {
                table[i + POINT_TABLE_SIZE / 2] =
                    driver.add_points(table[i + POINT_TABLE_SIZE / 2 - 1], d2);
            }

            for i in 0..(POINT_TABLE_SIZE / 2) {
                table[i] = driver
                    .msm_public_scalar(table[POINT_TABLE_SIZE - 1 - i], -C::ScalarField::one());
            }

            table
        };

        let mut msm_count = 0;
        let mut active_mul_count = 0;
        let mut msm_opqueue_index = Vec::new();
        let mut msm_mul_index = Vec::new();
        let mut msm_sizes = Vec::new();

        let eccvm_ops = self.get_eccvm_ops();
        for (op_idx, op) in eccvm_ops.iter().enumerate() {
            if op.op_code.mul {
                if (!op.z1_is_zero || !op.z2_is_zero) && !op.base_point_is_zero {
                    msm_opqueue_index.push(op_idx);
                    msm_mul_index.push((msm_count, active_mul_count));
                    active_mul_count += (!op.z1_is_zero) as usize + (!op.z2_is_zero) as usize;
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
        for op in eccvm_ops {
            if !op.z1_is_zero && !op.base_point_is_zero {
                z1_and_z2.push(op.z1);
            }
        }
        let z1_len = z1_and_z2.len();
        for op in eccvm_ops {
            if !op.z2_is_zero && !op.base_point_is_zero {
                z1_and_z2.push(op.z2);
            }
        }

        let wnaf_result = T::compute_wnaf_digits_and_compute_rows_many(
            driver,
            &z1_and_z2,
            goblin::NUM_SCALAR_BITS,
        )?;

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

            if !op.z1_is_zero && !op.base_point_is_zero {
                result[msm_index][mul_index] = CoScalarMul {
                    pc: 0,
                    scalar: op.z1,
                    base_point: op.base_point,
                    wnaf_digits: z1_wnaf_digits[z1_index],
                    wnaf_skew: z1_even[z1_index],
                    wnaf_digits_sign: z1_wnaf_digits_sign[z1_index],
                    wnaf_si: z1_wnaf_s_i[z1_index],
                    precomputed_table: compute_precomputed_table(op.base_point, driver),
                    row_chunks: z1_row_chunks[z1_index],
                    row_chunks_sign: z1_row_chunks_sign[z1_index],
                };
                mul_index += 1;
                z1_index += 1;
            }

            if !op.z2_is_zero && !op.base_point_is_zero {
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
                    precomputed_table: compute_precomputed_table(endo_point, driver),
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
pub(crate) struct AddState<
    C: CurveGroup<BaseField: PrimeField>,
    T: NoirWitnessExtensionProtocol<C::BaseField>,
> {
    pub add: bool,
    pub slice: T::AcvmType,
    pub point: T::AcvmPoint<C>,
    pub lambda: T::AcvmType,
    pub collision_inverse: T::AcvmType,
}
impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>> Default
    for AddState<C, T>
{
    fn default() -> Self {
        Self {
            add: false,
            slice: T::AcvmType::default(),
            point: T::AcvmPoint::<C>::default(),
            lambda: T::AcvmType::default(),
            collision_inverse: T::AcvmType::default(),
        }
    }
}
impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>> Clone
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

pub(crate) struct MSMRow<
    C: CurveGroup<BaseField: PrimeField>,
    T: NoirWitnessExtensionProtocol<C::BaseField>,
> {
    // Counter over all half-length scalar muls used to compute the required MSMs
    pub(crate) pc: usize,
    // The number of points that will be scaled and summed
    pub(crate) msm_size: u32,
    pub(crate) msm_count: u32,
    pub(crate) msm_round: u32,
    pub(crate) msm_transition: bool,
    pub(crate) q_add: bool,
    pub(crate) q_double: bool,
    pub(crate) q_skew: bool,
    pub(crate) add_state: [AddState<C, T>; 4],
    pub(crate) accumulator_x: T::AcvmType,
    pub(crate) accumulator_y: T::AcvmType,
    phantom: std::marker::PhantomData<T>,
}
impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>> Default
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
            accumulator_x: T::AcvmType::default(),
            accumulator_y: T::AcvmType::default(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: CurveGroup<BaseField: PrimeField>> Clone
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

impl<T: NoirWitnessExtensionProtocol<C::BaseField>, C: HonkCurve<TranscriptFieldType>>
    MSMRow<C, T>
{
    #[expect(clippy::type_complexity)]
    pub(crate) fn compute_rows_msms(
        msms: &[Msm<C, T>],
        total_number_of_muls: u32,
        num_msm_rows: usize,
        driver: &mut T,
    ) -> eyre::Result<(Vec<Self>, [Vec<T::AcvmType>; 2])> {
        let num_rows_in_read_counts_table =
            (total_number_of_muls as usize) * (POINT_TABLE_SIZE / 2);
        let mut point_table_read_counts =
            vec![T::AcvmType::default(); num_rows_in_read_counts_table * 2];

        let update_read_count = |point_idx: usize,
                                 slice: T::AcvmType,
                                 is_negative: T::AcvmType,
                                 point_table_read_counts: &mut [T::AcvmType],
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

            let column_index = driver.mul_with_public(
                C::BaseField::from(num_rows_in_read_counts_table as u32),
                is_negative,
            );
            let summand = driver.mul_many(
                &[
                    is_negative,
                    driver.sub(T::AcvmType::from(C::BaseField::one()), is_negative),
                ],
                &[
                    slice,
                    driver.sub(T::AcvmType::from(C::BaseField::from(15u32)), slice),
                ],
            )?;
            let mut index = driver.add(column_index, driver.add(summand[0], summand[1]));
            driver.add_assign(
                &mut index,
                T::AcvmType::from(C::BaseField::from(row_index_offset as u32)),
            );

            if T::is_shared(&index) {
                let ohv = driver.one_hot_vector_from_shared_index(
                    T::get_shared(&index).expect("Checked it is shared"),
                    num_rows_in_read_counts_table * 2,
                )?;
                for (point_table_read_count, x) in
                    point_table_read_counts.iter_mut().zip(ohv.iter())
                {
                    let tmp = T::AcvmType::from(x.to_owned());
                    driver.add_assign(point_table_read_count, tmp);
                }
            } else {
                let index_value: BigUint =
                    T::get_public(&index).expect("Checked it is public").into();
                let index_value = usize::try_from(index_value)
                    .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;
                driver.add_assign(
                    &mut point_table_read_counts[index_value],
                    T::AcvmType::from(C::BaseField::one()),
                );
            }

            Ok(())
        };

        let update_read_count_negative = |point_idx: usize,
                                          slice: T::AcvmType,
                                          point_table_read_counts: &mut [T::AcvmType],
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
            let relative_row_idx = driver.add(slice, T::AcvmType::from(C::BaseField::from(15u32)));
            let two_inverse = C::BaseField::from(2u32)
                .inverse()
                .expect("2 has an inverse");
            let relative_row_idx = driver.mul_with_public(two_inverse, relative_row_idx);

            let index = driver.add(
                relative_row_idx,
                T::AcvmType::from(C::BaseField::from(row_index_offset as u32)),
            );
            if T::is_shared(&index) {
                let ohv = driver.one_hot_vector_from_shared_index(
                    T::get_shared(&index).expect("Checked it is shared"),
                    num_rows_in_read_counts_table,
                )?;
                for (point_table_read_count, x) in point_table_read_counts
                    [num_rows_in_read_counts_table..] // we are in the negative branch
                    .iter_mut()
                    .zip(ohv.iter())
                {
                    let tmp = T::AcvmType::from(x.to_owned());
                    driver.add_assign(point_table_read_count, tmp);
                }
            } else {
                let index_value: BigUint =
                    T::get_public(&index).expect("Checked it is public").into();
                let mut index_value =
                    usize::try_from(index_value).expect("Index to large for usize");
                index_value += num_rows_in_read_counts_table; // we are in the negative branch
                driver.add_assign(
                    &mut point_table_read_counts[index_value],
                    T::AcvmType::from(C::BaseField::one()),
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
                            let slice = msm[point_idx].wnaf_digits[digit_idx];
                            let is_negative = msm[point_idx].wnaf_digits_sign[digit_idx];
                            update_read_count(
                                (total_number_of_muls - pc) as usize + point_idx,
                                slice,
                                is_negative,
                                &mut point_table_read_counts,
                                driver,
                            )?;
                        }
                    }
                }

                if digit_idx == NUM_WNAF_DIGITS_PER_SCALAR - 1 {
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
                                // TACEO TODO batch this outside the loop
                                let slice = driver.cmux(
                                    msm[point_idx].wnaf_skew,
                                    T::AcvmType::from(-C::BaseField::from(1u32)),
                                    T::AcvmType::from(-C::BaseField::from(15u32)),
                                )?;
                                //if msm[point_idx].wnaf_skew { -1 } else { -15 };
                                update_read_count_negative(
                                    (total_number_of_muls - pc) as usize + point_idx,
                                    slice, //slice will always be negative here
                                    &mut point_table_read_counts,
                                    driver,
                                )?;
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

        let mut p1_trace = vec![T::AcvmPoint::<C>::default(); num_point_adds_and_doubles];
        let mut p2_trace = vec![T::AcvmPoint::<C>::default(); num_point_adds_and_doubles];
        let mut p3_trace = vec![T::AcvmPoint::<C>::default(); num_point_adds_and_doubles];
        // operation_trace records whether an entry in the p1/p2/p3 trace represents a point addition or doubling
        let mut operation_trace = vec![false; num_point_adds_and_doubles];
        // accumulator_trace tracks the value of the ECCVM accumulator for each row
        let mut accumulator_trace = vec![T::AcvmPoint::<C>::default(); num_accumulators];

        // we start the accumulator at the offset generator point. This ensures we can support an MSM that produces a
        let offset_generator = T::AcvmPoint::from(offset_generator::<C>().into());
        accumulator_trace[0] = offset_generator;

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/973): Reinstate multitreading?
        // populate point trace, and the components of the MSM execution trace that do not relate to affine point
        // operations

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
                            T::AcvmType::default()
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
                            // let mut tmp = slice; //((slice + 15) / 2) as usize; //Attention FLORIN, this is already done for the slices
                            // driver.add_assign_with_public(C::BaseField::from(15), &mut tmp);
                            // tmp = driver.mul_with_public(
                            //     C::BaseField::from(2)
                            //         .inverse()
                            //         .expect("2 should have an inverse..."),
                            //     tmp,
                            // );
                            // tmp
                            slice
                        } else {
                            T::AcvmType::default()
                        };
                        add_state.point = if add_state.add {
                            let lut = driver.init_lut_by_acvm_point(
                                msm[offset + point_idx].precomputed_table.to_vec(),
                            );
                            //TODO FLORIN: Batch this outside the loop
                            let index = driver.convert_fields::<C>(&[add_state.slice])?[0];
                            driver.read_lut_by_acvm_point(index, &lut)?
                        } else {
                            T::AcvmPoint::<C>::default()
                        };

                        let p1 = accumulator;
                        let p2 = add_state.point;
                        accumulator = if add_state.add {
                            driver.add_points(accumulator, add_state.point)
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
                        add_state.slice = T::AcvmType::default();
                        add_state.point = T::AcvmPoint::default();
                        add_state.collision_inverse = T::AcvmType::default();
                        p1_trace[trace_index] = accumulator;
                        p2_trace[trace_index] = accumulator;
                        accumulator = driver.add_points(accumulator, accumulator);
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
                                driver.mul_with_public(
                                    C::BaseField::from(7),
                                    msm[offset + point_idx].wnaf_skew,
                                )
                                // if msm[offset + point_idx].wnaf_skew {
                                //     T::AcvmType::from(C::BaseField::from(7))
                                // } else {
                                //     T::AcvmType::default()
                                // }
                            } else {
                                T::AcvmType::default()
                            };

                            add_state.point = if add_state.add {
                                // msm[offset + point_idx].precomputed_table[add_state.slice as usize]
                                let lut = driver.init_lut_by_acvm_point(
                                    msm[offset + point_idx].precomputed_table.to_vec(),
                                );
                                //TODO FLORIN: Batch this outside the loop
                                let index = driver.convert_fields::<C>(&[add_state.slice])?[0];
                                driver.read_lut_by_acvm_point(index, &lut)?
                            } else {
                                T::AcvmPoint::<C>::default()
                            };
                            let add_predicate = if add_state.add {
                                msm[offset + point_idx].wnaf_skew
                            } else {
                                T::AcvmType::default()
                            };
                            let p1 = accumulator;
                            accumulator = {
                                let added_points = driver.add_points(accumulator, add_state.point);
                                let converted_add_predicate: T::OtherAcvmType<_> =
                                    driver.convert_fields::<C>(&[add_predicate])?[0];
                                let add_predicate_inverted = driver.sub_other(
                                    T::OtherAcvmType::from(C::ScalarField::one()),
                                    converted_add_predicate,
                                );
                                let result = driver.msm(
                                    &[accumulator, added_points],
                                    &[add_predicate_inverted, converted_add_predicate],
                                )?;
                                driver.add_points(result[0], result[1])
                            };
                            //  if add_predicate {
                            //     driver.add_points(accumulator, add_state.point)
                            // } else {
                            //     accumulator
                            // };
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
        }

        // inverse_trace is used to compute the value of the `collision_inverse` column in the ECCVM.
        let mut inverse_trace = Vec::with_capacity(num_point_adds_and_doubles);
        let mut tmp = Vec::with_capacity(num_point_adds_and_doubles * 2 + num_accumulators);
        tmp.extend_from_slice(&p1_trace);
        tmp.extend_from_slice(&p2_trace);
        tmp.extend_from_slice(&accumulator_trace);
        let (xs, ys, _) = driver.pointshare_to_field_shares_many(&tmp)?;
        let (p1_xs, rest) = xs.split_at(num_point_adds_and_doubles);
        let (p2_xs, acc_xs) = rest.split_at(num_point_adds_and_doubles);
        let (p1_ys, rest) = ys.split_at(num_point_adds_and_doubles);
        let (p2_ys, acc_ys) = rest.split_at(num_point_adds_and_doubles);

        for operation_idx in 0..num_point_adds_and_doubles {
            //TODO FLORIN: BATCH THIS outside the loop
            let (tmp1_x, tmp1_y) = (p1_xs[operation_idx], p1_ys[operation_idx]);
            let tmp2_x = p2_xs[operation_idx];

            if operation_trace[operation_idx] {
                inverse_trace.push(driver.add(tmp1_y, tmp1_y));
            } else {
                inverse_trace.push(driver.sub(tmp2_x, tmp1_x));
            }
        }

        let inverse_trace = driver.inverse_or_zero_many(&inverse_trace)?;

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
                            T::AcvmType::default()
                        };
                        add_state.lambda = if add_state.add {
                            let p1_y = p1_ys[trace_index];
                            let p2_y = p2_ys[trace_index];
                            let sub = driver.sub(p2_y, p1_y);
                            driver.mul(sub, *inverse)?
                        } else {
                            T::AcvmType::default()
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
                    for point_idx in 0..ADDITIONS_PER_ROW {
                        let add_state = &mut row.add_state[point_idx];
                        add_state.collision_inverse = T::AcvmType::default();
                        let p1_x = p1_xs[trace_index];
                        let dx = &p1_x;
                        let inverse = &inverse_trace[trace_index];
                        // TODO FLORIN: BATCH THIS
                        let three_dx = driver.mul_with_public(C::BaseField::from(3), *dx);
                        let three_dx_dx = driver.mul(three_dx, *dx)?;
                        add_state.lambda = driver.mul(three_dx_dx, *inverse)?; //((*dx + dx + dx) * dx) * inverse;
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
                        for point_idx in 0..ADDITIONS_PER_ROW {
                            let add_state = &mut row.add_state[point_idx];
                            let add_predicate = if add_state.add {
                                msm[offset + point_idx].wnaf_skew
                            } else {
                                T::AcvmType::default()
                            };

                            let inverse = &inverse_trace[trace_index];
                            add_state.collision_inverse = driver.mul(*inverse, add_predicate)?; //TODO FLORIN BATCH THIS
                            // if add_predicate {
                            //     *inverse
                            // } else {
                            //     T::AcvmType::default()
                            // };
                            //TODO FLORIN: BATCH THIS
                            add_state.lambda = {
                                let p1_y = p1_ys[trace_index];
                                let p2_y = p2_ys[trace_index];
                                let sub = driver.sub(p2_y, p1_y);
                                let inverse = driver.mul(sub, *inverse)?;
                                driver.mul(inverse, add_predicate)?
                            };

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
        let (final_x, final_y, _) = driver.pointshare_to_field_shares(*final_accumulator)?;
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
                slice: T::AcvmType::default(),
                point: T::AcvmPoint::<C>::default(),
                lambda: T::AcvmType::default(),
                collision_inverse: T::AcvmType::default(),
            },
            AddState {
                add: false,
                slice: T::AcvmType::default(),
                point: T::AcvmPoint::<C>::default(),
                lambda: T::AcvmType::default(),
                collision_inverse: T::AcvmType::default(),
            },
            AddState {
                add: false,
                slice: T::AcvmType::default(),
                point: T::AcvmPoint::<C>::default(),
                lambda: T::AcvmType::default(),
                collision_inverse: T::AcvmType::default(),
            },
            AddState {
                add: false,
                slice: T::AcvmType::default(),
                point: T::AcvmPoint::<C>::default(),
                lambda: T::AcvmType::default(),
                collision_inverse: T::AcvmType::default(),
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
