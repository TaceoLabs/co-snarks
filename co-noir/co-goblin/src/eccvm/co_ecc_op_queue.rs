use co_builder::TranscriptFieldType;
use co_builder::prelude::HonkCurve;
use common::{mpc::NoirUltraHonkProver, shared_polynomial::SharedPolynomial};
use goblin::eccvm::ecc_op_queue::{EccOpsTable, EccvmRowTracker};
use num_bigint::BigUint;
use std::array;

pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub(crate) type CoEccvmOpsTable<T, C> = EccOpsTable<CoECCVMOperation<T, C>>;

pub(crate) struct CoUltraEccOpsTable<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>> {
    pub(crate) table: EccOpsTable<CoUltraOp<T, C>>,
}

impl<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>> CoUltraEccOpsTable<T, C> {
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

    pub fn construct_table_columns(&self) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let poly_size = self.ultra_table_size();
        let subtable_start_idx = 0; // include all subtables
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
        )
    }

    pub fn construct_previous_table_columns(&self) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
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
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
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
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let mut column_polynomials: [SharedPolynomial<T, C>; TABLE_WIDTH] =
            array::from_fn(|_| SharedPolynomial::new_zero(poly_size));

        let mut i = 0;
        for subtable_idx in subtable_start_idx..subtable_end_idx {
            let subtable = &self.table.get()[subtable_idx];
            for op in subtable {
                column_polynomials[0][i] = op.op_code.value();
                column_polynomials[1][i] = op.x_lo;
                column_polynomials[2][i] = op.x_hi;
                column_polynomials[3][i] = op.y_lo;
                i += 1;
                column_polynomials[0][i] = T::ArithmeticShare::default(); // only the first 'op' field is utilized
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
pub struct CoECCVMOperation<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>> {
    pub op_code: CoEccOpCode<T, C>,
    pub base_point: C::G1Affine,
    pub z1: BigUint,
    pub z2: BigUint,
    pub mul_scalar_full: C::ScalarField,
}

#[derive(Clone)]
pub struct CoUltraOp<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>> {
    pub op_code: CoEccOpCode<T, C>,
    pub x_lo: T::ArithmeticShare,
    pub x_hi: T::ArithmeticShare,
    pub y_lo: T::ArithmeticShare,
    pub y_hi: T::ArithmeticShare,
    pub z_1: T::ArithmeticShare,
    pub z_2: T::ArithmeticShare,
    pub return_is_infinity: bool,
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

pub struct CoECCOpQueue<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>> {
    pub(crate) ultra_ops_table: CoUltraEccOpsTable<T, C>,
    pub(crate) eccvm_ops_table: CoEccvmOpsTable<T, C>,
    pub(crate) accumulator: C::G1Affine,
    pub(crate) eccvm_ops_reconstructed: Vec<CoECCVMOperation<T, C>>,
    pub(crate) eccvm_row_tracker: EccvmRowTracker,
}

impl<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>> CoECCOpQueue<T, C> {
    // Initialize a new subtable of ECCVM ops and Ultra ops corresponding to an individual circuit
    pub fn initialize_new_subtable(&mut self) {
        self.eccvm_ops_table.create_new_subtable(0);
        self.ultra_ops_table.create_new_subtable(0);
    }

    // Construct polynomials corresponding to the columns of the full aggregate ultra ecc ops table
    pub fn construct_ultra_ops_table_columns(&self) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_table_columns()
    }

    // Construct polys corresponding to the columns of the aggregate ultra ops table, excluding the most recent subtable
    pub fn construct_previous_ultra_ops_table_columns(
        &self,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_previous_table_columns()
    }

    // Construct polynomials corresponding to the columns of the current subtable of ultra ecc ops
    pub fn construct_current_ultra_ops_subtable_columns(
        &self,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table
            .construct_current_ultra_ops_subtable_columns()
    }

    pub fn get_ultra_ops_table_num_rows(&self) -> usize {
        self.ultra_ops_table.ultra_table_size()
    }

    pub fn get_current_ultra_ops_subtable_num_rows(&self) -> usize {
        self.ultra_ops_table.current_ultra_subtable_size()
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
    pub fn set_eccvm_ops_for_fuzzing(&mut self, eccvm_ops_in: Vec<CoECCVMOperation<T, C>>) {
        self.eccvm_ops_reconstructed = eccvm_ops_in;
    }

    pub fn get_accumulator(&self) -> C::G1Affine {
        self.accumulator
    }
}
