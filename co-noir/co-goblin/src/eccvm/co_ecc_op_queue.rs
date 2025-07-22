#![expect(unused)]
use ark_ec::AdditiveGroup;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use co_builder::prelude::Polynomial;
use co_ultrahonk::prelude::{NoirUltraHonkProver, SharedPolynomial};
use mpc_core::protocols::rep3::conversion::b2a;
use mpc_net::Network;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{array, ops::Shl};

// TODO FLORIN: Find out which functions in this are actually needed

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

pub(crate) type CoEccvmOpsTable<T, C> = EccOpsTable<CoECCVMOperation<T, C>>;

pub(crate) struct CoUltraEccOpsTable<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub(crate) table: EccOpsTable<CoUltraOp<T, C>>,
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> CoUltraEccOpsTable<T, C> {
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

    pub fn push(&mut self, op: CoUltraOp<T, C>) {
        self.table.push(op);
    }

    pub fn get_reconstructed(&self) -> Vec<CoUltraOp<T, C>>
    where
        CoUltraOp<T, C>: Clone,
    {
        self.table.get_reconstructed()
    }

    pub fn construct_table_columns<N: Network>(
        &self,
        network: &N,
        state: &mut T::State,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let poly_size = self.ultra_table_size();
        let subtable_start_idx = 0; // include all subtables
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
            network,
            state,
        )
    }

    pub fn construct_previous_table_columns<N: Network>(
        &self,
        network: &N,
        state: &mut T::State,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let poly_size = self.previous_ultra_table_size();
        let subtable_start_idx = 1; // exclude the 0th subtable
        let subtable_end_idx = self.table.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
            network,
            state,
        )
    }

    pub fn construct_current_ultra_ops_subtable_columns<N: Network>(
        &self,
        network: &N,
        state: &mut T::State,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let poly_size = self.current_ultra_subtable_size();
        let subtable_start_idx = 0;
        let subtable_end_idx = 1; // include only the 0th subtable

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
            network,
            state,
        )
    }

    fn construct_column_polynomials_from_subtables<N: Network>(
        &self,
        poly_size: usize,
        subtable_start_idx: usize,
        subtable_end_idx: usize,
        network: &N,
        state: &mut T::State,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        let mut column_polynomials: [SharedPolynomial<T, C>; TABLE_WIDTH] =
            array::from_fn(|_| SharedPolynomial::new_zero(poly_size));

        let mut i = 0;
        for subtable_idx in subtable_start_idx..subtable_end_idx {
            let subtable = &self.table.get()[subtable_idx];
            for op in subtable {
                column_polynomials[0][i] = op.op_code.value(network, state);
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

pub(crate) struct EccOpsTable<T> {
    pub(crate) table: Vec<Vec<T>>,
}

impl<T> EccOpsTable<T> {
    pub fn new() -> Self {
        Self { table: Vec::new() }
    }

    pub fn size(&self) -> usize {
        self.table.iter().map(|subtable| subtable.len()).sum()
    }

    pub fn num_subtables(&self) -> usize {
        self.table.len()
    }

    pub fn get(&self) -> &Vec<Vec<T>> {
        &self.table
    }

    pub fn push(&mut self, op: T) {
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

    pub fn get_reconstructed(&self) -> Vec<T>
    where
        T: Clone,
    {
        let mut reconstructed_table = Vec::with_capacity(self.size());
        for subtable in &self.table {
            reconstructed_table.extend(subtable.iter().cloned());
        }
        reconstructed_table
    }
}

impl<T> std::ops::Index<usize> for EccOpsTable<T> {
    type Output = T;

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
#[derive(Default)]
pub struct CoECCVMOperation<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub op_code: CoEccOpCode<T, C>,
    pub base_point: C::Affine,
    pub z1: BigUint,
    pub z2: BigUint,
    pub mul_scalar_full: C::ScalarField,
}

#[derive(Clone)]
pub(crate) struct CoUltraOp<T: NoirUltraHonkProver<C>, C: CurveGroup> {
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
    C: CurveGroup,
{
    pub(crate) add: T::ArithmeticShare,
    pub(crate) mul: T::ArithmeticShare,
    pub(crate) eq: T::ArithmeticShare,
    pub(crate) reset: T::ArithmeticShare,
}

impl<T, C> CoEccOpCode<T, C>
where
    T: NoirUltraHonkProver<C>,
    C: CurveGroup,
{
    /// Returns the value of the opcode as a 32-bit integer.
    pub fn value<N: Network>(&self, net: &N, state: &mut T::State) -> T::ArithmeticShare {
        let mut res = self.add;
        res = T::add(T::mul_with_public(C::ScalarField::from(2), res), self.mul);
        res = T::add(T::mul_with_public(C::ScalarField::from(2), res), self.eq);
        res = T::add(T::mul_with_public(C::ScalarField::from(2), res), self.reset);
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

    pub fn get_precompute_table_row_count_for_single_msm(msm_count: usize) -> u32 {
        let num_precompute_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;
        (msm_count * num_precompute_rows_per_scalar) as u32
    }
}

pub struct CoECCOpQueue<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub(crate) ultra_ops_table: CoUltraEccOpsTable<T, C>,
    pub(crate) eccvm_ops_table: CoEccvmOpsTable<T, C>,
    pub(crate) point_at_infinity: C::Affine,
    pub(crate) accumulator: C::Affine,
    pub(crate) eccvm_ops_reconstructed: Vec<CoECCVMOperation<T, C>>,
    pub(crate) ultra_ops_reconstructed: Vec<CoUltraOp<T, C>>,
    pub(crate) eccvm_row_tracker: EccvmRowTracker,
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> CoECCOpQueue<T, C> {
    // Initialize a new subtable of ECCVM ops and Ultra ops corresponding to an individual circuit
    pub fn initialize_new_subtable(&mut self) {
        self.eccvm_ops_table.create_new_subtable(0);
        self.ultra_ops_table.create_new_subtable(0);
    }

    // Construct polynomials corresponding to the columns of the full aggregate ultra ecc ops table
    pub fn construct_ultra_ops_table_columns<N: Network>(
        &self,
        network: &N,
        state: &mut T::State,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table.construct_table_columns(network, state)
    }

    // Construct polys corresponding to the columns of the aggregate ultra ops table, excluding the most recent subtable
    pub fn construct_previous_ultra_ops_table_columns<N: Network>(
        &self,
        network: &N,
        state: &mut T::State,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table
            .construct_previous_table_columns(network, state)
    }

    // Construct polynomials corresponding to the columns of the current subtable of ultra ecc ops
    pub fn construct_current_ultra_ops_subtable_columns<N: Network>(
        &self,
        network: &N,
        state: &mut T::State,
    ) -> [SharedPolynomial<T, C>; TABLE_WIDTH] {
        self.ultra_ops_table
            .construct_current_ultra_ops_subtable_columns(network, state)
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

    pub fn get_accumulator(&self) -> C::Affine {
        self.accumulator
    }
}
