use ark_ec::CurveGroup;
use co_builder::TranscriptFieldType;
use co_builder::prelude::HonkCurve;
use common::{mpc::NoirUltraHonkProver, shared_polynomial::SharedPolynomial};
use goblin::{
    ADDITIONS_PER_ROW, NUM_WNAF_DIGITS_PER_SCALAR,
    prelude::{EccOpCode, EccOpsTable},
};
use mpc_core::MpcState;
use std::array;

pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub(crate) type CoEccvmOpsTable<T, C> = EccOpsTable<CoVMOperation<T, C>>;

pub(crate) struct CoUltraEccOpsTable<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub(crate) table: EccOpsTable<CoUltraOp<T, C>>,
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> CoUltraEccOpsTable<T, C> {
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

    pub fn construct_table_columns(
        &self,
        id: <T::State as MpcState>::PartyID,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let poly_size = self.ultra_table_size();
        let subtable_start_idx = 0; // include all subtables
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
            id,
        )
    }

    pub fn construct_previous_table_columns(
        &self,
        id: <T::State as MpcState>::PartyID,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let poly_size = self.previous_ultra_table_size();
        let subtable_start_idx = 1; // exclude the 0th subtable
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
            id,
        )
    }

    pub fn construct_current_ultra_ops_subtable_columns(
        &self,
        id: <T::State as MpcState>::PartyID,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let poly_size = self.current_ultra_subtable_size();
        let subtable_start_idx = 0;
        let subtable_end_idx = 1; // include only the 0th subtable

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
            id,
        )
    }

    fn construct_column_polynomials_from_subtables(
        &self,
        poly_size: usize,
        subtable_start_idx: usize,
        subtable_end_idx: usize,
        id: <T::State as MpcState>::PartyID,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let mut column_polynomials: [SharedPolynomial<T, C>; TABLE_WIDTH] =
            array::from_fn(|_| SharedPolynomial::new_zero(poly_size));

        let mut i = 0;
        for subtable_idx in subtable_start_idx..subtable_end_idx {
            let subtable = &self.table.get()[subtable_idx];
            for op in subtable {
                column_polynomials[0][i] =
                    T::promote_to_trivial_share(id, C::ScalarField::from(op.op_code.value()));
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
pub struct CoVMOperation<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub op_code: EccOpCode,
    pub base_point: T::PointShare,
    pub z1: T::ArithmeticShare, //TODO FLORIN: I think this does not have to be a binary share (It is a uint256 in bb)
    pub z2: T::ArithmeticShare, //TODO FLORIN: I think this does not have to be a binary share (It is a uint256 in bb)
    pub mul_scalar_full: T::ArithmeticShare,
}
impl<T: NoirUltraHonkProver<C>, C: CurveGroup> Clone for CoVMOperation<T, C> {
    fn clone(&self) -> Self {
        Self {
            op_code: self.op_code.clone(),
            base_point: self.base_point.clone(),
            z1: self.z1.clone(),
            z2: self.z2.clone(),
            mul_scalar_full: self.mul_scalar_full,
        }
    }
}

pub struct CoUltraOp<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub op_code: EccOpCode,
    pub x_lo: T::ArithmeticShare,
    pub x_hi: T::ArithmeticShare,
    pub y_lo: T::ArithmeticShare,
    pub y_hi: T::ArithmeticShare,
    pub z_1: T::ArithmeticShare,
    pub z_2: T::ArithmeticShare,
    pub return_is_infinity: T::ArithmeticShare,
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> Clone for CoUltraOp<T, C> {
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

#[derive(Debug)]
pub struct CoEccvmRowTracker<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub cached_num_muls: T::ArithmeticShare,
    pub cached_active_msm_count: T::ArithmeticShare,
    pub num_transcript_rows: u32,
    pub num_precompute_table_rows: T::ArithmeticShare,
    pub num_msm_rows: T::ArithmeticShare,
}
impl<T: NoirUltraHonkProver<C>, C: CurveGroup> Default for CoEccvmRowTracker<T, C> {
    fn default() -> Self {
        Self {
            cached_num_muls: T::ArithmeticShare::default(),
            cached_active_msm_count: T::ArithmeticShare::default(),
            num_transcript_rows: 0,
            num_precompute_table_rows: T::ArithmeticShare::default(),
            num_msm_rows: T::ArithmeticShare::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> CoEccvmRowTracker<T, C> {
    pub fn get_number_of_muls(&self) -> T::ArithmeticShare {
        T::add(self.cached_num_muls, self.cached_active_msm_count)
    }

    pub fn num_eccvm_msm_rows(
        msm_size: T::ArithmeticShare,
        id: <T::State as MpcState>::PartyID,
    ) -> T::ArithmeticShare {
        // let rows_per_wnaf_digit = (msm_size / ADDITIONS_PER_ROW)
        //     + if msm_size % ADDITIONS_PER_ROW != 0 {
        //         1
        //     } else {
        //         0
        //     };
        // let num_rows_for_all_rounds = (NUM_WNAF_DIGITS_PER_SCALAR + 1) * rows_per_wnaf_digit;
        // let num_double_rounds = NUM_WNAF_DIGITS_PER_SCALAR - 1;
        // T::add_with_public(
        //     C::ScalarField::from(num_double_rounds as u32),
        //     num_rows_for_all_rounds,
        //     id,
        // )
        todo!()
    }

    pub fn get_num_msm_rows(&self) -> T::ArithmeticShare {
        // let mut msm_rows = self.num_msm_rows as usize + 2;
        // if self.cached_active_msm_count > 0 {
        //     msm_rows += Self::num_eccvm_msm_rows(self.cached_active_msm_count as usize) as usize;
        // }
        // msm_rows
        todo!()
    }

    pub fn get_num_rows(&self) -> T::ArithmeticShare {
        // let transcript_rows = self.num_transcript_rows as usize + 2;
        // let mut msm_rows = self.num_msm_rows as usize + 2;
        // let mut precompute_rows = self.num_precompute_table_rows as usize + 1;
        // if self.cached_active_msm_count > 0 {
        //     msm_rows += Self::num_eccvm_msm_rows(self.cached_active_msm_count as usize) as usize;
        //     precompute_rows += Self::get_precompute_table_row_count_for_single_msm(
        //         self.cached_active_msm_count as usize,
        //     ) as usize;
        // }
        // std::cmp::max(transcript_rows, std::cmp::max(msm_rows, precompute_rows))
        todo!()
    }

    pub fn get_precompute_table_row_count_for_single_msm(
        msm_count: T::ArithmeticShare,
    ) -> T::ArithmeticShare {
        // let num_precompute_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;
        // (msm_count * num_precompute_rows_per_scalar) as u32
        todo!()
    }
}

pub struct CoECCOpQueue<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub(crate) eccvm_ops_table: CoEccvmOpsTable<T, C>,
    pub(crate) ultra_ops_table: CoUltraEccOpsTable<T, C>,
    pub(crate) accumulator: T::PointShare,
    pub(crate) eccvm_ops_reconstructed: Vec<CoVMOperation<T, C>>,
    pub ultra_ops_reconstructed: Vec<CoUltraOp<T, C>>,
    pub(crate) eccvm_row_tracker: CoEccvmRowTracker<T, C>,
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> CoECCOpQueue<T, C> {
    // Initialize a new subtable of ECCVM ops and Ultra ops corresponding to an individual circuit
    pub fn initialize_new_subtable(&mut self) {
        self.eccvm_ops_table.create_new_subtable(0);
        self.ultra_ops_table.create_new_subtable(0);
    }

    // Construct polynomials corresponding to the columns of the full aggregate ultra ecc ops table
    pub fn construct_ultra_ops_table_columns(
        &self,
        id: <T::State as MpcState>::PartyID,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_table_columns(id)
    }

    // Construct polys corresponding to the columns of the aggregate ultra ops table, excluding the most recent subtable
    pub fn construct_previous_ultra_ops_table_columns(
        &self,
        id: <T::State as MpcState>::PartyID,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_previous_table_columns(id)
    }

    // Construct polynomials corresponding to the columns of the current subtable of ultra ecc ops
    pub fn construct_current_ultra_ops_subtable_columns(
        &self,
        id: <T::State as MpcState>::PartyID,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table
            .construct_current_ultra_ops_subtable_columns(id)
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
    pub fn get_num_msm_rows(&self) -> T::ArithmeticShare {
        self.eccvm_row_tracker.get_num_msm_rows()
    }

    /**
     * @brief Get the number of rows for the current ECCVM circuit
     */
    pub fn get_num_rows(&self) -> T::ArithmeticShare {
        self.eccvm_row_tracker.get_num_rows()
    }

    /**
     * @brief get number of muls for the current ECCVM circuit
     */
    pub fn get_number_of_muls(&self) -> T::ArithmeticShare {
        self.eccvm_row_tracker.get_number_of_muls()
    }

    /**
     * @brief A fuzzing only method for setting eccvm ops directly
     *
     */
    pub fn set_eccvm_ops_for_fuzzing(&mut self, eccvm_ops_in: Vec<CoVMOperation<T, C>>) {
        self.eccvm_ops_reconstructed = eccvm_ops_in;
    }

    pub fn get_accumulator(&self) -> &T::PointShare {
        &self.accumulator
    }
}
