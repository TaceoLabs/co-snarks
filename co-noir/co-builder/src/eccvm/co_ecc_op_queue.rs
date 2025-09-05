use crate::eccvm::{
    NUM_LIMB_BITS_IN_FIELD_SIMULATION,
    ecc_op_queue::{
        EccOpCode, EccOpsTable, EndomorphismParams,
    },
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::{ BigInt};
use common::{
    CoUtils, honk_curve::HonkCurve, honk_proof::TranscriptFieldType, mpc::NoirUltraHonkProver,
    polynomials::shared_polynomial::SharedPolynomial,
};
use mpc_core::MpcState;
use mpc_net::Network;
use num_bigint::BigUint;
use std::array;
use std::ops::Shl;

pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

pub type CoEccvmOpsTable<T, C> = EccOpsTable<CoVMOperation<T, C>>;

pub struct CoUltraEccOpsTable<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub table: EccOpsTable<CoUltraOp<T, C>>,
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

pub struct CoVMOperation<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub op_code: EccOpCode,
    pub base_point: T::PointShare,
    pub z1: T::BaseFieldArithmeticShare, //TODO FLORIN: I think this does not have to be a binary share (It is a uint256 in bb)
    pub z2: T::BaseFieldArithmeticShare, //TODO FLORIN: I think this does not have to be a binary share (It is a uint256 in bb)
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

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> Default for CoVMOperation<T, C> {
    fn default() -> Self {
        Self {
            op_code: EccOpCode::default(),
            base_point: T::PointShare::default(),
            z1: T::BaseFieldArithmeticShare::default(),
            z2: T::BaseFieldArithmeticShare::default(),
            mul_scalar_full: T::ArithmeticShare::default(),
        }
    }
}

#[derive(Default)]
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
    pub eccvm_ops_table: CoEccvmOpsTable<T, C>,
    pub ultra_ops_table: CoUltraEccOpsTable<T, C>,
    pub accumulator: T::PointShare,
    pub eccvm_ops_reconstructed: Vec<CoVMOperation<T, C>>,
    pub ultra_ops_reconstructed: Vec<CoUltraOp<T, C>>,
    pub eccvm_row_tracker: CoEccvmRowTracker<T, C>,
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

    /**
     * @brief Write point addition op to queue and natively perform addition
     *
     * @param to_add
     */
    pub fn add_accumulate<N: Network>(
        &mut self,
        to_add: T::PointShare,
        net: &N,
        state: &mut T::State,
    ) -> CoUltraOp<T, C> {
        // Update the accumulator natively
        T::add_point_assign(&mut self.accumulator, to_add.clone());
        let op_code = EccOpCode {
            add: true,
            ..Default::default()
        };

        // Store the eccvm operation
        self.eccvm_ops_table.push(CoVMOperation {
            op_code: op_code.clone(),
            base_point: to_add.clone(),
            ..Default::default()
        });

        // Construct and store the operation in the ultra op format
        self.construct_and_populate_ultra_ops(
            op_code,
            to_add,
            T::ArithmeticShare::default(),
            net,
            state,
        )
    }

    /**
     * @brief Write multiply and add op to queue and natively perform operation
     *
     * @param to_mul
     */
    pub fn mul_accumulate<N: Network>(
        &mut self,
        to_mul: T::PointShare,
        scalar: T::ArithmeticShare,
        net: &N,
        state: &mut T::State,
    ) -> CoUltraOp<T, C> {
        // Update the accumulator natively
        T::add_point_assign(
            &mut self.accumulator,
            // TODO CESAR: Handle this mul
            T::mul_point_and_field(to_mul.clone(), scalar, net, state)
                .expect("Error in mul_point_and_field"),
        );
        let op_code = EccOpCode {
            mul: true,
            ..Default::default()
        };

        // Construct and store the operation in the ultra op format
        let ultra_op = self.construct_and_populate_ultra_ops(
            op_code.clone(),
            to_mul.clone(),
            scalar,
            net,
            state,
        );

        // Store the eccvm operation
        self.eccvm_ops_table.push(CoVMOperation {
            op_code,
            base_point: to_mul,
            // TODO CESAR: Ask Floring about this, how do we convert a Arithmetic share into a BaseFieldShare
            z1: todo!("ultra_op.z_1.into()"),
            z2: todo!("ultra_op.z_2.into()"),
            mul_scalar_full: scalar,
        });
        ultra_op
    }

    /**
     * @brief Writes a no op (i.e. two zero rows) to the ultra ops table but adds no eccvm operations.
     *
     * @details We want to be able to add zero rows (and, eventually, random rows
     * https://github.com/AztecProtocol/barretenberg/issues/1360) to the ultra ops table without affecting the
     * operations in the ECCVM.
     */
    pub fn no_op_ultra_only<N: Network>(
        &mut self,
        net: &N,
        state: &mut T::State,
    ) -> CoUltraOp<T, C> {
        return self.construct_and_populate_ultra_ops(
            EccOpCode::default(),
            self.accumulator.clone(),
            T::ArithmeticShare::default(),
            net,
            state,
        );
    }

    /**
     * @brief Write equality op using internal accumulator point
     *
     * @return current internal accumulator point (prior to reset to 0)
     */
    pub fn eq_and_reset<N: Network>(&mut self, net: &N, state: &mut T::State) -> CoUltraOp<T, C> {
        let expected = self.accumulator.clone();
        // TODO CESAR: Check if this is correct
        self.accumulator = T::PointShare::default();
        let op_code = EccOpCode {
            eq: true,
            reset: true,
            ..Default::default()
        };

        // Store the eccvm operation
        self.eccvm_ops_table.push(CoVMOperation {
            op_code: op_code.clone(),
            base_point: expected.clone(),
            ..Default::default()
        });

        // Construct and store the operation in the ultra op format
        self.construct_and_populate_ultra_ops(
            op_code,
            expected,
            T::ArithmeticShare::default(),
            net,
            state,
        )
    }

    /**
     * @brief Given an ecc operation and its inputs, decompose into ultra format and populate ultra_ops
     *
     * @param op_code
     * @param point
     * @param scalar
     * @return UltraOp
     */
    pub fn construct_and_populate_ultra_ops<N: Network>(
        &mut self,
        op_code: EccOpCode,
        point: T::PointShare,
        scalar: T::ArithmeticShare,
        net: &N,
        state: &mut T::State,
    ) -> CoUltraOp<T, C> {
        // TODO CESAR: Handle unwrap
        let (x, y, is_point_at_infinity) = T::point_share_to_fieldshare(point, net, state).unwrap();

        // // Decompose point coordinates (Fq) into hi-lo chunks (Fr)
        // const CHUNK_SIZE: u8 = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION as u8;
        // let [x_lo, x_hi, _] = T::slice(
        //     x,
        //     2 * CHUNK_SIZE - 1, // Includes msb in the slice
        //     CHUNK_SIZE,
        //     2 * CHUNK_SIZE as usize,
        //     state,
        //     net,
        // ).unwrap();
        // let [y_lo, y_hi, _] = T::slice(
        //     y,
        //     2 * CHUNK_SIZE - 1, // Includes msb in the slice
        //     CHUNK_SIZE,
        //     2 * CHUNK_SIZE as usize,
        //     state,
        //     net,
        // ).unwrap();

        // Construct the ultra operation
        todo!("Implement ultra operation construction")
    }
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup<ScalarField = TranscriptFieldType>>
    CoECCOpQueue<T, C>
{
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
    pub fn split_into_endomorphism_scalars<N: Network, Params: EndomorphismParams>(
        scalar: T::ArithmeticShare,
        net: &N,
        state: &mut T::State,
    ) -> (T::ArithmeticShare, T::ArithmeticShare) {
        let endo_g1 = BigInt([
            Params::ENDO_G1_LO,
            Params::ENDO_G1_MID,
            Params::ENDO_G1_HI,
            0,
        ]);
        let endo_g2 = BigInt([Params::ENDO_G2_LO, Params::ENDO_G2_MID, 0, 0]);
        let endo_minus_b1 = BigInt([Params::ENDO_MINUS_B1_LO, Params::ENDO_MINUS_B1_MID, 0, 0]);
        let endo_b2 = BigInt([Params::ENDO_B2_LO, Params::ENDO_B2_MID, 0, 0]);

        let scalar_montgomery = CoECCOpQueue::<T, C>::to_montgomery_form(scalar);
        let scalar_chunks: [T::ArithmeticShare; 4] = T::decompose_arithmetic(
            scalar_montgomery,
            C::ScalarField::MODULUS_BIT_SIZE as usize,
            u64::BITS as usize,
            net,
            state,
        )
        .expect("Failed to decompose scalar")
        .try_into()
        .expect("Failed to convert scalar chunks");

        let c1 = CoECCOpQueue::<T, C>::mul_high(scalar_chunks, endo_g2, net, state);
        let c2 = CoECCOpQueue::<T, C>::mul_high(scalar_chunks, endo_g1, net, state);
        let q1 = CoECCOpQueue::<T, C>::mul_low(c1, endo_minus_b1, net, state);
        let q2 = CoECCOpQueue::<T, C>::mul_low(c2, endo_b2, net, state);

        let q1 = CoECCOpQueue::<T, C>::recompose_shares(q1);
        let q2 = CoECCOpQueue::<T, C>::recompose_shares(q2);

        let q1 = CoECCOpQueue::<T, C>::from_montgomery_form(q1);
        let q2 = CoECCOpQueue::<T, C>::from_montgomery_form(q2);

        let t1 = T::sub(q2, q1);

        let beta = C::ScalarField::get_root_of_unity(3).unwrap();
        let t2 = T::add(T::mul_with_public(beta, t1), scalar);
        (t1, t2)
    }

    fn recompose_shares(x: [T::ArithmeticShare; 4]) -> T::ArithmeticShare {
        let mut res = T::ArithmeticShare::default();
        for (i, chunk) in x.into_iter().enumerate() {
            let shift = C::ScalarField::from_bigint(
                BigInt::from(1u64).shl((i * u64::BITS as usize).try_into().unwrap()),
            )
            .unwrap();
            T::add_assign(&mut res, T::mul_with_public(shift, chunk));
        }
        res
    }

    // TODO CESAR: Verify this is correct and optimal (likely not)
    fn mul<N: Network>(
        x: [T::ArithmeticShare; 4],
        y: BigInt<4>,
        net: &N,
        state: &mut T::State,
    ) -> [T::ArithmeticShare; 8] {
        let mut res = [T::ArithmeticShare::default(); 8];
        let mut prev_column_carry = Vec::new();
        for col in 0..7 {
            let mut column_values = Vec::new();
            let mut row_carries = Vec::new();

            // Fill each column
            for i in 0..4 {
                for j in 0..4 {
                    if i + j == col {
                        let (product, row_carry) = CoECCOpQueue::<T, C>::mul_carry(
                            x[i],
                            y.0[j],
                            prev_column_carry.pop().unwrap_or_default(),
                            net,
                            state,
                        );
                        column_values.push(product);
                        row_carries.push(row_carry);
                    }
                }
            }

            // Update previous column carry
            prev_column_carry = row_carries;

            // Add all values and previous carry
            let (column_sum, column_carry) =
                CoECCOpQueue::<T, C>::add_many_carry(column_values, res[col], net, state);
            res[col] = column_sum;

            // Add carry to next column
            if col < 7 {
                res[col + 1] = column_carry;
            }
        }
        res
    }

    fn mul_low<N: Network>(
        x: [T::ArithmeticShare; 4],
        y: BigInt<4>,
        net: &N,
        state: &mut T::State,
    ) -> [T::ArithmeticShare; 4] {
        CoECCOpQueue::<T, C>::mul(x, y, net, state)[..4]
            .try_into()
            .expect("Failed to convert scalar chunks")
    }

    fn mul_high<N: Network>(
        x: [T::ArithmeticShare; 4],
        y: BigInt<4>,
        net: &N,
        state: &mut T::State,
    ) -> [T::ArithmeticShare; 4] {
        CoECCOpQueue::<T, C>::mul(x, y, net, state)[4..]
            .try_into()
            .expect("Failed to convert scalar chunks")
    }

    fn mul_carry<N: Network>(
        x: T::ArithmeticShare,
        y: u64,
        carry: T::ArithmeticShare,
        net: &N,
        state: &mut T::State,
    ) -> (T::ArithmeticShare, T::ArithmeticShare) {
        let total_res = T::add(T::mul_with_public(C::ScalarField::from(y), x), carry);

        let [result, carry, _, _] = T::decompose_arithmetic(
            total_res,
            C::ScalarField::MODULUS_BIT_SIZE as usize,
            u64::BITS as usize,
            net,
            state,
        )
        .expect("Failed to decompose scalar")
        .try_into()
        .expect("Failed to convert scalar chunks");

        (result, carry)
    }

    fn add_many_carry<N: Network>(
        x: Vec<T::ArithmeticShare>,
        carry: T::ArithmeticShare,
        net: &N,
        state: &mut T::State,
    ) -> (T::ArithmeticShare, T::ArithmeticShare) {
        let total_res = T::add(x.into_iter().reduce(T::add).unwrap(), carry);

        let [result, carry, _, _] = T::decompose_arithmetic(
            total_res,
            C::ScalarField::MODULUS_BIT_SIZE as usize,
            u64::BITS as usize,
            net,
            state,
        )
        .expect("Failed to decompose scalar")
        .try_into()
        .expect("Failed to convert scalar chunks");

        (result, carry)
    }

    fn from_montgomery_form(x: T::ArithmeticShare) -> T::ArithmeticShare {
        let mont_r: C::ScalarField = C::ScalarField::MODULUS.montgomery_r().into();
        T::mul_with_public(mont_r.inverse().unwrap(), x)
    }

    fn to_montgomery_form(x: T::ArithmeticShare) -> T::ArithmeticShare {
        let mont_r = C::ScalarField::MODULUS.montgomery_r().into();
        T::mul_with_public(mont_r, x)
    }
}

mod test {
    use std::thread;

    use ark_bn254::Bn254;
    use ark_ec::{pairing::Pairing, short_weierstrass::Affine};
    use common::mpc::{NoirUltraHonkProver, rep3::Rep3UltraHonkDriver};
    use mpc_core::{
        gadgets::field_from_hex_string,
        protocols::rep3::{Rep3State, conversion::A2BType, share_field_element},
    };
    use mpc_net::local::LocalNetwork;
    use rand::thread_rng;

    use crate::eccvm::ecc_op_queue::Bn254ParamsFr;
    use crate::eccvm::{
        co_ecc_op_queue::CoECCOpQueue,
        ecc_op_queue::{EccOpCode, UltraOp},
    };
    use ark_ff::PrimeField;

    type P = Bn254;
    type Bn254G1 = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;
    type Scalar = <P as Pairing>::ScalarField;

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
                "0x1ba2c8d6ff259fa8c79d53093767cd1002d67810d1cb07c131d4fbfac46bf8c9",
            )
            .unwrap(),
            field_from_hex_string(
                "0x0b8ab330373e7c36cab04db25e7f2a1119d7820f8941279a4ec3718c0ebe742c",
            )
            .unwrap(),
        ];

        let nets = LocalNetwork::new_3_parties();
        let mut threads = Vec::with_capacity(3);

        for (net, share) in nets.into_iter().zip(scalar_shares.into_iter()) {
            threads.push(thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let (a, b) =
                    CoECCOpQueue::<Rep3UltraHonkDriver, Bn254G1>::split_into_endomorphism_scalars::<
                        LocalNetwork,
                        Bn254ParamsFr,
                    >(share, &net, &mut state);
                <Rep3UltraHonkDriver as NoirUltraHonkProver<Bn254G1>>::open_many(
                    &[a, b],
                    &net,
                    &mut state,
                )
                .unwrap()
            }));
        }

        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

        assert!(results.into_iter().all(|res| res == expected_result));
    }
}
