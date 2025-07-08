#![expect(unused)]
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use co_builder::prelude::Polynomial;
use num_bigint::BigUint;
use std::array;

const NUM_LIMB_BITS_IN_FIELD_SIMULATION: usize = 68;
const NUM_SCALAR_BITS: usize = 128; // The length of scalars handled by the ECCVVM
const NUM_WNAF_DIGIT_BITS: usize = 4; // Scalars are decompose into base 16 in wNAF form
const NUM_WNAF_DIGITS_PER_SCALAR: usize = NUM_SCALAR_BITS / NUM_WNAF_DIGIT_BITS; // 32
const WNAF_MASK: u64 = (1 << NUM_WNAF_DIGIT_BITS) - 1;
const POINT_TABLE_SIZE: usize = 1 << (NUM_WNAF_DIGIT_BITS);
const WNAF_DIGITS_PER_ROW: usize = 4;
const ADDITIONS_PER_ROW: usize = 4;
pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub(crate) type EccvmOpsTable<P> = EccOpsTable<ECCVMOperation<P>>;
pub(crate) struct UltraEccOpsTable<P: Pairing> {
    table: EccOpsTable<UltraOp<P>>,
}

impl<P: Pairing> UltraEccOpsTable<P> {
    pub fn new() -> Self {
        Self {
            table: EccOpsTable::new(),
        }
    }

    pub fn size(&self) -> usize {
        self.table.size()
    }

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

    pub fn push(&mut self, op: UltraOp<P>) {
        self.table.push(op);
    }

    pub fn get_reconstructed(&self) -> Vec<UltraOp<P>>
    where
        UltraOp<P>: Clone,
    {
        self.table.get_reconstructed()
    }

    pub fn construct_table_columns(&self) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
        let poly_size = self.ultra_table_size();
        let subtable_start_idx = 0; // include all subtables
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
        )
    }

    pub fn construct_previous_table_columns(&self) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
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
    ) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
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
    ) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
        let mut column_polynomials: [Polynomial<P::ScalarField>; TABLE_WIDTH] =
            array::from_fn(|_| Polynomial::new(vec![P::ScalarField::zero(); poly_size]));

        let mut i = 0;
        for subtable_idx in subtable_start_idx..subtable_end_idx {
            let subtable = &self.table.get()[subtable_idx];
            for op in subtable {
                column_polynomials[0][i] = P::ScalarField::from(op.op_code.value());
                column_polynomials[1][i] = op.x_lo;
                column_polynomials[2][i] = op.x_hi;
                column_polynomials[3][i] = op.y_lo;
                i += 1;
                column_polynomials[0][i] = P::ScalarField::zero(); // only the first 'op' field is utilized
                column_polynomials[1][i] = op.y_hi;
                column_polynomials[2][i] = op.z_1;
                column_polynomials[3][i] = op.z_2;
                i += 1;
            }
        }
        column_polynomials
    }
}

pub(crate) struct EccOpsTable<OpFormat> {
    table: Vec<Vec<OpFormat>>,
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

    pub fn push(&mut self, op: OpFormat) {
        if let Some(front) = self.table.first_mut() {
            front.push(op);
        }
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
pub struct ECCVMOperation<P: Pairing> {
    pub op_code: EccOpCode,
    pub base_point: P::G1Affine,
    pub z1: BigUint,
    pub z2: BigUint,
    pub mul_scalar_full: P::ScalarField,
}

impl<P: Pairing> PartialEq for ECCVMOperation<P> {
    fn eq(&self, other: &Self) -> bool {
        self.op_code == other.op_code
            && self.base_point == other.base_point
            && self.z1 == other.z1
            && self.z2 == other.z2
            && self.mul_scalar_full == other.mul_scalar_full
    }
}
#[derive(Clone)]
pub(crate) struct UltraOp<P: Pairing> {
    pub op_code: EccOpCode,
    pub x_lo: P::ScalarField,
    pub x_hi: P::ScalarField,
    pub y_lo: P::ScalarField,
    pub y_hi: P::ScalarField,
    pub z_1: P::ScalarField,
    pub z_2: P::ScalarField,
    pub return_is_infinity: bool,
}

impl<P: Pairing> UltraOp<P> {
    /**
     * @brief Get the point in standard form i.e. as two coordinates x and y in the base field or as a point at
     * infinity whose coordinates are set to (0,0).
     *
     */
    pub fn get_base_point_standard_form(&self) -> [P::BaseField; 2] {
        if self.return_is_infinity {
            return [P::BaseField::zero(), P::BaseField::zero()];
        }
        todo!()
        // auto x = Fq((uint256_t(x_hi) << 2 * stdlib::NUM_LIMB_BITS_IN_FIELD_SIMULATION) + uint256_t(x_lo));
        // auto y = Fq((uint256_t(y_hi) << 2 * stdlib::NUM_LIMB_BITS_IN_FIELD_SIMULATION) + uint256_t(y_lo));

        // return { x, y };
    }
}

#[derive(Default, PartialEq, Eq, Clone, Debug)]
pub struct EccOpCode {
    add: bool,
    mul: bool,
    eq: bool,
    reset: bool,
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

    pub fn update_cached_msms<P: Pairing>(&mut self, op: &ECCVMOperation<P>) {
        // self.num_transcript_rows += 1;
        // if op.op_code.mul {
        //     if op.z1 != P::ScalarField::zero().into() && !op.base_point.is_point_at_infinity() {
        //         self.cached_active_msm_count += 1;
        //     }
        //     if op.z2 != P::ScalarField::zero().into() && !op.base_point.is_point_at_infinity() {
        //         self.cached_active_msm_count += 1;
        //     }
        // } else if self.cached_active_msm_count != 0 {
        //     self.num_msm_rows += Self::num_eccvm_msm_rows(self.cached_active_msm_count as usize);
        //     self.num_precompute_table_rows += Self::get_precompute_table_row_count_for_single_msm(
        //         self.cached_active_msm_count as usize,
        //     );
        //     self.cached_num_muls += self.cached_active_msm_count;
        //     self.cached_active_msm_count = 0;
        // }
        todo!()
    }

    pub fn get_precompute_table_row_count_for_single_msm(msm_count: usize) -> u32 {
        let num_precompute_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;
        (msm_count * num_precompute_rows_per_scalar) as u32
    }
}

pub struct ECCOpQueue<P: Pairing> {
    point_at_infinity: P::G1Affine,
    accumulator: P::G1Affine,
    eccvm_ops_table: EccvmOpsTable<P>,
    ultra_ops_table: UltraEccOpsTable<P>,
    eccvm_ops_reconstructed: Vec<ECCVMOperation<P>>,
    ultra_ops_reconstructed: Vec<UltraOp<P>>,
    eccvm_row_tracker: EccvmRowTracker,
}

impl<P: Pairing> ECCOpQueue<P> {
    // Constructor that instantiates an initial ECC op subtable
    // pub fn new() -> Self {
    //     let mut queue = Self {
    //         point_at_infinity: P::Group::affine_point_at_infinity(),
    //         accumulator: P::Group::affine_point_at_infinity(),
    //         eccvm_ops_table: EccvmOpsTable::new(),
    //         ultra_ops_table: UltraEccOpsTable::new(),
    //         eccvm_ops_reconstructed: Vec::new(),
    //         ultra_ops_reconstructed: Vec::new(),
    //         eccvm_row_tracker: EccvmRowTracker::new(),
    //     };
    //     queue.initialize_new_subtable();
    //     queue
    // }

    // Initialize a new subtable of ECCVM ops and Ultra ops corresponding to an individual circuit
    pub fn initialize_new_subtable(&mut self) {
        self.eccvm_ops_table.create_new_subtable(0);
        self.ultra_ops_table.create_new_subtable(0);
    }

    // Construct polynomials corresponding to the columns of the full aggregate ultra ecc ops table
    pub fn construct_ultra_ops_table_columns(&self) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_table_columns()
    }

    // Construct polys corresponding to the columns of the aggregate ultra ops table, excluding the most recent subtable
    pub fn construct_previous_ultra_ops_table_columns(
        &self,
    ) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_previous_table_columns()
    }

    // Construct polynomials corresponding to the columns of the current subtable of ultra ecc ops
    pub fn construct_current_ultra_ops_subtable_columns(
        &self,
    ) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
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
    pub fn get_eccvm_ops(&mut self) -> &Vec<ECCVMOperation<P>> {
        if self.eccvm_ops_reconstructed.is_empty() {
            self.construct_full_eccvm_ops_table();
        }
        &self.eccvm_ops_reconstructed
    }

    pub fn get_ultra_ops(&mut self) -> &Vec<UltraOp<P>> {
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
    pub fn set_eccvm_ops_for_fuzzing(&mut self, eccvm_ops_in: Vec<ECCVMOperation<P>>) {
        self.eccvm_ops_reconstructed = eccvm_ops_in;
    }

    pub fn get_accumulator(&self) -> P::G1Affine {
        self.accumulator
    }

    /*
     * @brief Write point addition op to queue and natively perform addition
     *
     * @param to_add
     */
    // pub fn add_accumulate(&mut self, to_add: &P::G1Affine) -> UltraOp<P> {
    //     // Update the accumulator natively
    //     self.accumulator = (self.accumulator + *to_add).into();
    //     let op_code = EccOpCode {
    //         add: true,
    //         ..Default::default()
    //     };
    //     // Store the eccvm operation
    //     self.append_eccvm_op(ECCVMOperation {
    //         op_code,
    //         base_point: *to_add,
    //         ..Default::default()
    //     });

    //     // Construct and store the operation in the ultra op format
    //     self.construct_and_populate_ultra_ops(op_code, to_add, &P::ScalarField::zero())
    // }

    /*
     * @brief Write multiply and add op to queue and natively perform operation
     *
     * @param to_add
     */
    // pub fn mul_accumulate(&mut self, to_mul: &P::G1Affine, scalar: &P::ScalarField) -> UltraOp<P> {
    //     // Update the accumulator natively
    //     self.accumulator = (self.accumulator + *to_mul * *scalar).into();
    //     let op_code = EccOpCode {
    //         mul: true,
    //         ..Default::default()
    //     };

    //     // Construct and store the operation in the ultra op format
    //     let ultra_op = self.construct_and_populate_ultra_ops(op_code, to_mul, scalar);

    //     // Store the eccvm operation
    //     self.append_eccvm_op(ECCVMOperation {
    //         op_code,
    //         base_point: *to_mul,
    //         z1: ultra_op.z_1.into(),
    //         z2: ultra_op.z_2.into(),
    //         mul_scalar_full: *scalar,
    //     });

    //     ultra_op
    // }

    /*
     * @brief Writes a no op (i.e. two zero rows) to the ultra ops table but adds no eccvm operations.
     *
     * @details We want to be able to add zero rows (and, eventually, random rows
     * https://github.com/AztecProtocol/barretenberg/issues/1360) to the ultra ops table without affecting the
     * operations in the ECCVM.
     */
    // pub fn no_op_ultra_only(&mut self) -> UltraOp<P> {
    //     let op_code = EccOpCode::default();

    //     // Construct and store the operation in the ultra op format
    //     self.construct_and_populate_ultra_ops(
    //         op_code,
    //         &self.accumulator.to_owned(),
    //         &P::ScalarField::zero(),
    //     )
    // }

    /*
     * @brief Write equality op using internal accumulator point
     *
     * @return current internal accumulator point (prior to reset to 0)
     */
    // pub fn eq_and_reset(&mut self) -> UltraOp<P> {
    //     let expected = self.accumulator;
    //     // self.accumulator = P::Group::affine_point_at_infinity(); TODO FLORIN
    //     let op_code = EccOpCode {
    //         eq: true,
    //         reset: true,
    //         ..Default::default()
    //     };
    //     // Store eccvm operation
    //     self.append_eccvm_op(ECCVMOperation {
    //         op_code,
    //         base_point: expected,
    //         ..Default::default()
    //     });

    //     // Construct and store the operation in the ultra op format
    //     self.construct_and_populate_ultra_ops(&op_code, &expected, &P::ScalarField::zero())
    // }

    /**
     * @brief Append an eccvm operation to the eccvm ops table; update the eccvm row tracker
     *
     */
    fn append_eccvm_op(&mut self, op: ECCVMOperation<P>) {
        self.eccvm_row_tracker.update_cached_msms(&op);
        self.eccvm_ops_table.push(op);
    }

    // /**
    //  * @brief Given an ecc operation and its inputs, decompose into ultra format and populate ultra_ops
    //  *
    //  * @param op_code
    //  * @param point
    //  * @param scalar
    //  * @return UltraOp
    //  */
    // fn construct_and_populate_ultra_ops(
    //     &mut self,
    //     op_code: &EccOpCode,
    //     point: &P::G1Affine,
    //     scalar: &P::ScalarField,
    // ) -> UltraOp<P> {
    //     let mut ultra_op = UltraOp::default();
    //     ultra_op.op_code = op_code;

    //     // Decompose point coordinates (Fq) into hi-lo chunks (Fr)
    //     const CHUNK_SIZE: usize = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION;
    //     let x_256 = uint256_t::from(point.x);
    //     let y_256 = uint256_t::from(point.y);
    //     ultra_op.return_is_infinity = point.is_point_at_infinity();
    //     // if we have a point at infinity, set x/y to zero
    //     // in the biggroup_goblin class we use `assert_equal` statements to validate
    //     // the original in-circuit coordinate values are also zero
    //     if point.is_point_at_infinity() {
    //         x_256 = uint256_t::zero();
    //         y_256 = uint256_t::zero();
    //     }
    //     ultra_op.x_lo = P::ScalarField::from(x_256.slice(0, CHUNK_SIZE));
    //     ultra_op.x_hi = P::ScalarField::from(x_256.slice(CHUNK_SIZE, CHUNK_SIZE * 2));
    //     ultra_op.y_lo = P::ScalarField::from(y_256.slice(0, CHUNK_SIZE));
    //     ultra_op.y_hi = P::ScalarField::from(y_256.slice(CHUNK_SIZE, CHUNK_SIZE * 2));

    //     // Split scalar into 128 bit endomorphism scalars
    //     let mut z_1 = P::ScalarField::zero();
    //     let mut z_2 = P::ScalarField::zero();
    //     let converted = scalar.from_montgomery_form();
    //     let converted_u256 = uint256_t::from(*scalar);
    //     if converted_u256.get_msb() <= 128 {
    //         ultra_op.z_1 = *scalar;
    //         ultra_op.z_2 = P::ScalarField::zero();
    //     } else {
    //         P::ScalarField::split_into_endomorphism_scalars(&converted, &mut z_1, &mut z_2);
    //         ultra_op.z_1 = z_1.to_montgomery_form();
    //         ultra_op.z_2 = z_2.to_montgomery_form();
    //     }

    //     self.ultra_ops_table.push(ultra_op.clone());

    //     ultra_op
    // }
}
