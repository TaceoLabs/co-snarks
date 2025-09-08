use crate::eccvm::NUM_LIMB_BITS_IN_FIELD_SIMULATION;
use crate::eccvm::{
    ADDITIONS_PER_ROW, NUM_ROWS_PER_OP, NUM_WNAF_DIGIT_BITS, NUM_WNAF_DIGITS_PER_SCALAR,
    POINT_TABLE_SIZE, TABLE_WIDTH, WNAF_DIGITS_PER_ROW, WNAF_MASK,
};
use crate::prelude::offset_generator;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::AdditiveGroup;
use ark_ff::BigInteger;
use ark_ff::FftField;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_ff::{BigInt, One};
use common::{
    honk_curve::HonkCurve, honk_proof::TranscriptFieldType, polynomials::polynomial::Polynomial,
    utils::Utils,
};
use num_bigint::BigUint;
use serde::Deserialize;
use serde::Serialize;
use std::array;

#[derive(Clone, Default)]
#[expect(dead_code)]
pub struct ScalarMul<C: CurveGroup> {
    pub pc: u32,
    pub scalar: BigUint,
    pub base_point: C::Affine,
    pub wnaf_digits: [i32; NUM_WNAF_DIGITS_PER_SCALAR],
    pub wnaf_skew: bool,
    // size bumped by 1 to record base_point.dbl()
    pub precomputed_table: [C::Affine; POINT_TABLE_SIZE + 1],
}

pub(crate) type Msm<C> = Vec<ScalarMul<C>>;
#[derive(Default, Clone)]

pub struct AddState<C: CurveGroup> {
    pub add: bool,
    pub slice: i32,
    pub point: C::Affine,
    pub lambda: C::BaseField,
    pub collision_inverse: C::BaseField,
}
#[derive(Default, Clone)]
pub struct MSMRow<C: CurveGroup> {
    // Counter over all half-length scalar muls used to compute the required MSMs
    pub pc: u32,
    // The number of points that will be scaled and summed
    pub msm_size: u32,
    pub msm_count: u32,
    pub msm_round: u32,
    pub msm_transition: bool,
    pub q_add: bool,
    pub q_double: bool,
    pub q_skew: bool,
    pub add_state: [AddState<C>; 4],
    pub accumulator_x: C::BaseField,
    pub accumulator_y: C::BaseField,
}

impl<C: HonkCurve<TranscriptFieldType>> MSMRow<C> {
    pub fn compute_rows_msms(
        msms: &[Msm<C>],
        total_number_of_muls: u32,
        num_msm_rows: usize,
    ) -> (Vec<Self>, [Vec<usize>; 2]) {
        let num_rows_in_read_counts_table =
            (total_number_of_muls as usize) * (POINT_TABLE_SIZE / 2);
        let mut point_table_read_counts = [
            vec![0; num_rows_in_read_counts_table],
            vec![0; num_rows_in_read_counts_table],
        ];

        let mut update_read_count = |point_idx: usize, slice: i32| {
            let row_index_offset = point_idx * 8;
            let digit_is_negative = slice < 0;
            let relative_row_idx = ((slice + 15) / 2) as usize;
            let column_index = if digit_is_negative { 1 } else { 0 };

            if digit_is_negative {
                point_table_read_counts[column_index][row_index_offset + relative_row_idx] += 1;
            } else {
                point_table_read_counts[column_index][row_index_offset + 15 - relative_row_idx] +=
                    1;
            }
        };

        let mut msm_row_counts = Vec::with_capacity(msms.len() + 1);
        msm_row_counts.push(1);

        let mut pc_values = Vec::with_capacity(msms.len() + 1);
        pc_values.push(total_number_of_muls as usize);

        for msm in msms {
            let num_rows_required = EccvmRowTracker::num_eccvm_msm_rows(msm.len());
            msm_row_counts.push(
                msm_row_counts
                    .last()
                    .expect("msm_row_counts should not be empty")
                    + num_rows_required as usize,
            );
            pc_values.push(pc_values.last().expect("pc_values should not be empty") - msm.len());
        }

        assert_eq!(*pc_values.last().expect("pc_values should not be empty"), 0);

        let mut msm_rows = vec![MSMRow::default(); num_msm_rows];
        msm_rows[0] = MSMRow::default();

        for (msm_idx, msm) in msms.iter().enumerate() {
            for digit_idx in 0..NUM_WNAF_DIGITS_PER_SCALAR {
                let pc = pc_values[msm_idx] as u32;
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
                            update_read_count(
                                (total_number_of_muls as usize - pc as usize) + point_idx,
                                slice,
                            );
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
                                let slice = if msm[point_idx].wnaf_skew { -1 } else { -15 };
                                update_read_count(
                                    (total_number_of_muls as usize - pc as usize) + point_idx,
                                    slice,
                                );
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
        // In what follows, either p1 + p2 = p3, or p1.dbl() = p3
        // We create 1 vector to store the entire point trace. We split into multiple containers using std::span
        // (we want 1 vector object to more efficiently batch normalize points)
        const NUM_POINTS_IN_ADDITION_RELATION: usize = 3;
        let num_points_to_normalize =
            (num_point_adds_and_doubles * NUM_POINTS_IN_ADDITION_RELATION) + num_accumulators;
        let mut p1_trace = vec![C::Affine::zero(); num_point_adds_and_doubles];
        let mut p2_trace = vec![C::Affine::zero(); num_point_adds_and_doubles];
        let mut p3_trace = vec![C::Affine::zero(); num_point_adds_and_doubles];
        // operation_trace records whether an entry in the p1/p2/p3 trace represents a point addition or doubling
        let mut operation_trace = vec![false; num_point_adds_and_doubles];
        // accumulator_trace tracks the value of the ECCVM accumulator for each row
        let mut accumulator_trace = vec![C::Affine::zero(); num_accumulators];

        // we start the accumulator at the offset generator point. This ensures we can support an MSM that produces a
        let offset_generator: C::Affine = offset_generator::<C>();
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
                let pc = pc_values[msm_idx] as u32;
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
                            0
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
                        add_state.slice = if add_state.add { (slice + 15) / 2 } else { 0 };
                        add_state.point = if add_state.add {
                            msm[offset + point_idx].precomputed_table[add_state.slice as usize]
                        } else {
                            C::Affine::default()
                        };

                        let p1 = accumulator;
                        let p2 = add_state.point;
                        accumulator = if add_state.add {
                            let tmp: C = accumulator + add_state.point;
                            tmp.into()
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
                    row.pc = pc;
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
                        add_state.slice = 0;
                        add_state.point = C::Affine::default();
                        add_state.collision_inverse = C::BaseField::zero();

                        p1_trace[trace_index] = accumulator;
                        p2_trace[trace_index] = accumulator;
                        accumulator = (accumulator + accumulator).into();
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
                                if msm[offset + point_idx].wnaf_skew {
                                    7
                                } else {
                                    0
                                }
                            } else {
                                0
                            };

                            add_state.point = if add_state.add {
                                msm[offset + point_idx].precomputed_table[add_state.slice as usize]
                            } else {
                                C::Affine::default()
                            };
                            let add_predicate = if add_state.add {
                                msm[offset + point_idx].wnaf_skew
                            } else {
                                false
                            };
                            let p1 = accumulator;
                            accumulator = if add_predicate {
                                let tmp: C = accumulator + add_state.point;
                                tmp.into()
                            } else {
                                accumulator
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
                        row.pc = pc;
                        accumulator_trace[msm_row_index] = accumulator;
                        msm_row_index += 1;
                    }
                }
            }
        }

        // Normalize the points in the point trace
        let mut points_to_normalize = Vec::with_capacity(num_points_to_normalize);
        points_to_normalize.extend_from_slice(&p1_trace);
        points_to_normalize.extend_from_slice(&p2_trace);
        points_to_normalize.extend_from_slice(&p3_trace);
        points_to_normalize.extend_from_slice(&accumulator_trace);

        points_to_normalize = Utils::batch_normalize::<C>(&points_to_normalize);

        let p1_trace = &points_to_normalize[0..num_point_adds_and_doubles];
        let p2_trace =
            &points_to_normalize[num_point_adds_and_doubles..num_point_adds_and_doubles * 2];
        let accumulator_trace =
            &points_to_normalize[num_point_adds_and_doubles * 3..num_points_to_normalize];

        // inverse_trace is used to compute the value of the `collision_inverse` column in the ECCVM.
        let mut inverse_trace = Vec::with_capacity(num_point_adds_and_doubles);
        for operation_idx in 0..num_point_adds_and_doubles {
            if operation_trace[operation_idx] {
                inverse_trace.push(
                    p1_trace[operation_idx].y().unwrap_or(C::BaseField::zero())
                        + p1_trace[operation_idx].y().unwrap_or(C::BaseField::zero()),
                );
            } else {
                inverse_trace.push(
                    p2_trace[operation_idx].x().unwrap_or(C::BaseField::zero())
                        - p1_trace[operation_idx].x().unwrap_or(C::BaseField::zero()),
                );
            }
        }

        ark_ff::batch_inversion(&mut inverse_trace);

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
                    let normalized_accumulator = &accumulator_trace[accumulator_index];
                    assert!(!normalized_accumulator.is_zero());
                    row.accumulator_x = normalized_accumulator.x().expect("Should be non-zero");
                    row.accumulator_y = normalized_accumulator.y().expect("Should be non-zero");
                    for point_idx in 0..ADDITIONS_PER_ROW {
                        let add_state = &mut row.add_state[point_idx];
                        let inverse = &inverse_trace[trace_index];
                        let p1 = &p1_trace[trace_index];
                        let p2 = &p2_trace[trace_index];
                        add_state.collision_inverse = if add_state.add {
                            *inverse
                        } else {
                            C::BaseField::zero()
                        };
                        add_state.lambda = if add_state.add {
                            (p2.y().expect("Should be non-zero")
                                - p1.y().expect("Should be non-zero"))
                                * inverse
                        } else {
                            C::BaseField::zero()
                        };
                        trace_index += 1;
                    }
                    accumulator_index += 1;
                    msm_row_index += 1;
                }

                if digit_idx < NUM_WNAF_DIGITS_PER_SCALAR - 1 {
                    let row = &mut msm_rows[msm_row_index];
                    let normalized_accumulator = &accumulator_trace[accumulator_index];
                    let acc_x = &if normalized_accumulator.is_zero() {
                        C::BaseField::zero()
                    } else {
                        normalized_accumulator.x().expect("Should be non-zero")
                    };
                    let acc_y = &if normalized_accumulator.is_zero() {
                        C::BaseField::zero()
                    } else {
                        normalized_accumulator.y().expect("Should be non-zero")
                    };
                    row.accumulator_x = *acc_x;
                    row.accumulator_y = *acc_y;
                    for point_idx in 0..ADDITIONS_PER_ROW {
                        let add_state = &mut row.add_state[point_idx];
                        add_state.collision_inverse = C::BaseField::zero();
                        let dx = &p1_trace[trace_index].x().expect("Should be non-zero");
                        let inverse = &inverse_trace[trace_index];
                        add_state.lambda = ((*dx + dx + dx) * dx) * inverse;
                        trace_index += 1;
                    }
                    accumulator_index += 1;
                    msm_row_index += 1;
                } else {
                    for row_idx in 0..num_rows_per_digit {
                        let row = &mut msm_rows[msm_row_index];
                        let normalized_accumulator = &accumulator_trace[accumulator_index];
                        assert!(!normalized_accumulator.is_zero());
                        let offset = row_idx * ADDITIONS_PER_ROW;
                        row.accumulator_x = normalized_accumulator.x().expect("Should be non-zero");
                        row.accumulator_y = normalized_accumulator.y().expect("Should be non-zero");
                        for point_idx in 0..ADDITIONS_PER_ROW {
                            let add_state = &mut row.add_state[point_idx];
                            let add_predicate = if add_state.add {
                                msm[offset + point_idx].wnaf_skew
                            } else {
                                false
                            };

                            let inverse = &inverse_trace[trace_index];
                            let p1 = &p1_trace[trace_index];
                            let p2 = &p2_trace[trace_index];
                            add_state.collision_inverse = if add_predicate {
                                *inverse
                            } else {
                                C::BaseField::zero()
                            };
                            add_state.lambda = if add_predicate {
                                (p2.y().expect("Should be non-zero")
                                    - p1.y().expect("Should be non-zero"))
                                    * inverse
                            } else {
                                C::BaseField::zero()
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
        final_row.pc = *pc_values.last().expect("Should have at least one pc value") as u32;
        final_row.msm_transition = true;
        final_row.accumulator_x = if final_accumulator.is_zero() {
            C::BaseField::zero()
        } else {
            final_accumulator.x().expect("Should be non-zero")
        };
        final_row.accumulator_y = if final_accumulator.is_zero() {
            C::BaseField::zero()
        } else {
            final_accumulator.y().expect("Should be non-zero")
        };
        final_row.msm_size = 0;
        final_row.msm_count = 0;
        final_row.q_add = false;
        final_row.q_double = false;
        final_row.q_skew = false;
        final_row.add_state = [
            AddState::default(),
            AddState::default(),
            AddState::default(),
            AddState::default(),
        ];

        (msm_rows, point_table_read_counts)
    }
}

pub type EccvmOpsTable<P> = EccOpsTable<VMOperation<P>>;

pub type UltraEccOpsTable<P> = EccOpsTable<UltraOp<P>>;

impl<P: CurveGroup> UltraEccOpsTable<P> {
    pub fn ultra_table_size(&self) -> usize {
        self.size() * NUM_ROWS_PER_OP
    }

    pub fn current_ultra_subtable_size(&self) -> usize {
        self.get()[0].len() * NUM_ROWS_PER_OP
    }

    pub fn previous_ultra_table_size(&self) -> usize {
        self.ultra_table_size() - self.current_ultra_subtable_size()
    }

    pub fn construct_table_columns(&self) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
        let poly_size = self.ultra_table_size();
        let subtable_start_idx = 0; // include all subtables
        let subtable_end_idx = self.num_subtables();

        self.construct_column_polynomials_from_subtables(
            poly_size,
            subtable_start_idx,
            subtable_end_idx,
        )
    }

    pub fn construct_previous_table_columns(&self) -> [Polynomial<P::ScalarField>; TABLE_WIDTH] {
        let poly_size = self.previous_ultra_table_size();
        let subtable_start_idx = 1; // exclude the 0th subtable
        let subtable_end_idx = self.num_subtables();

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
            let subtable = &self.get()[subtable_idx];
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
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct EccOpsTable<OpFormat> {
    pub table: Vec<Vec<OpFormat>>,
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
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct VMOperation<P: CurveGroup> {
    pub op_code: EccOpCode,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub base_point: P::Affine,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub z1: BigUint,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub z2: BigUint,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub mul_scalar_full: P::ScalarField,
}

impl<P: CurveGroup> PartialEq for VMOperation<P> {
    fn eq(&self, other: &Self) -> bool {
        self.op_code == other.op_code
            && self.base_point == other.base_point
            && self.z1 == other.z1
            && self.z2 == other.z2
            && self.mul_scalar_full == other.mul_scalar_full
    }
}
#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct UltraOp<P: CurveGroup> {
    pub op_code: EccOpCode,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub x_lo: P::ScalarField,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub x_hi: P::ScalarField,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub y_lo: P::ScalarField,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub y_hi: P::ScalarField,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub z_1: P::ScalarField,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub z_2: P::ScalarField,
    pub return_is_infinity: bool,
}

impl<P: CurveGroup> UltraOp<P> {
    pub fn get_base_point_standard_form(&self) -> (P::BaseField, P::BaseField)
    where
        P::BaseField: PrimeField,
    {
        if self.return_is_infinity {
            return (P::BaseField::zero(), P::BaseField::zero());
        }

        // Adjust this constant if defined elsewhere in the crate.
        let shift_bits = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION;

        let mut x_hi: BigUint = self.x_hi.into();
        let x_lo: BigUint = self.x_lo.into();
        x_hi <<= shift_bits as u32;
        x_hi += x_lo;
        let x: P::BaseField = x_hi.into();

        let mut y_hi: BigUint = self.y_hi.into();
        let y_lo: BigUint = self.y_lo.into();
        y_hi <<= shift_bits as u32;
        y_hi += y_lo;
        let y: P::BaseField = y_hi.into();

        (x, y)
    }
}

#[derive(Default, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct EccOpCode {
    pub add: bool,
    pub mul: bool,
    pub eq: bool,
    pub reset: bool,
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
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct EccvmRowTracker {
    pub cached_num_muls: u32,
    pub cached_active_msm_count: u32,
    pub num_transcript_rows: u32,
    pub num_precompute_table_rows: u32,
    pub num_msm_rows: u32,
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

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct ECCOpQueue<P: CurveGroup> {
    // point_at_infinity: P::Affine,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub accumulator: P::Affine,
    pub eccvm_ops_table: EccvmOpsTable<P>,
    pub ultra_ops_table: UltraEccOpsTable<P>,
    pub eccvm_ops_reconstructed: Vec<VMOperation<P>>,
    pub ultra_ops_reconstructed: Vec<UltraOp<P>>,
    pub eccvm_row_tracker: EccvmRowTracker,
}

impl<P: CurveGroup> ECCOpQueue<P> {
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
    pub fn get_eccvm_ops(&mut self) -> &Vec<VMOperation<P>> {
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
    pub fn set_eccvm_ops_for_fuzzing(&mut self, eccvm_ops_in: Vec<VMOperation<P>>) {
        self.eccvm_ops_reconstructed = eccvm_ops_in;
    }

    pub fn get_accumulator(&self) -> P::Affine {
        self.accumulator
    }
}

impl<P: HonkCurve<TranscriptFieldType>> ECCOpQueue<P> {
    pub fn get_msms(&mut self) -> Vec<Msm<P>> {
        let num_muls = self.get_number_of_muls();

        let compute_precomputed_table =
            |base_point: P::Affine| -> [P::Affine; POINT_TABLE_SIZE + 1] {
                let d2 = base_point * P::ScalarField::from(2);
                let mut table = [P::Affine::zero(); POINT_TABLE_SIZE + 1];
                table[POINT_TABLE_SIZE] = d2.into();
                table[POINT_TABLE_SIZE / 2] = base_point;

                for i in 1..(POINT_TABLE_SIZE / 2) {
                    table[i + POINT_TABLE_SIZE / 2] =
                        (table[i + POINT_TABLE_SIZE / 2 - 1] + d2).into();
                }

                for i in 0..(POINT_TABLE_SIZE / 2) {
                    table[i] = (table[POINT_TABLE_SIZE - 1 - i]).into().neg().into();
                }
                table = Utils::batch_normalize::<P>(&table)
                    .try_into()
                    .expect("Failed to normalize precomputed table");

                let mut result = [P::Affine::default(); POINT_TABLE_SIZE + 1];
                for (i, point) in table.iter().enumerate() {
                    result[i] = *point;
                }
                result
            };

        let compute_wnaf_digits = |mut scalar: BigUint| -> [i32; NUM_WNAF_DIGITS_PER_SCALAR] {
            let mut output = [0; NUM_WNAF_DIGITS_PER_SCALAR];
            let mut previous_slice = 0;

            for i in 0..NUM_WNAF_DIGITS_PER_SCALAR {
                let raw_slice = &scalar & BigUint::from(WNAF_MASK);
                let is_even = (&raw_slice & BigUint::one()) == BigUint::zero();
                let mut wnaf_slice = if let Some(&digit) = raw_slice.to_u32_digits().first() {
                    digit as i32
                } else {
                    0
                };

                if i == 0 && is_even {
                    wnaf_slice += 1;
                } else if is_even {
                    const BORROW_CONSTANT: i32 = 1 << NUM_WNAF_DIGIT_BITS;
                    previous_slice -= BORROW_CONSTANT;
                    wnaf_slice += 1;
                }

                if i > 0 {
                    output[NUM_WNAF_DIGITS_PER_SCALAR - i] = previous_slice;
                }
                previous_slice = wnaf_slice;

                scalar >>= NUM_WNAF_DIGIT_BITS;
            }

            assert!(scalar.is_zero());
            output[0] = previous_slice;

            output
        };

        let mut msm_count = 0;
        let mut active_mul_count = 0;
        let mut msm_opqueue_index = Vec::new();
        let mut msm_mul_index = Vec::new();
        let mut msm_sizes = Vec::new();

        let eccvm_ops = self.get_eccvm_ops();
        for (op_idx, op) in eccvm_ops.iter().enumerate() {
            if op.op_code.mul {
                if (op.z1 != BigUint::zero() || op.z2 != BigUint::zero())
                    && !op.base_point.is_zero()
                {
                    msm_opqueue_index.push(op_idx);
                    msm_mul_index.push((msm_count, active_mul_count));
                    active_mul_count +=
                        (op.z1 != BigUint::zero()) as usize + (op.z2 != BigUint::zero()) as usize;
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

        let mut result: Vec<Msm<P>> = Vec::with_capacity(msm_count);
        for size in &msm_sizes {
            result.push(vec![
                ScalarMul {
                    pc: 0,
                    scalar: BigUint::zero(),
                    base_point: P::Affine::default(),
                    wnaf_digits: [0; NUM_WNAF_DIGITS_PER_SCALAR],
                    wnaf_skew: false,
                    precomputed_table: [P::Affine::default(); POINT_TABLE_SIZE + 1],
                };
                *size
            ]);
        }

        msm_opqueue_index
            .iter()
            .enumerate()
            .for_each(|(i, &op_idx)| {
                let op = &eccvm_ops[op_idx];
                let (msm_index, mut mul_index) = msm_mul_index[i];

                if op.z1 != BigUint::zero() && !op.base_point.is_zero() {
                    result[msm_index][mul_index] = ScalarMul {
                        pc: 0,
                        scalar: op.z1.clone(),
                        base_point: op.base_point,
                        wnaf_digits: compute_wnaf_digits(op.z1.clone()),
                        wnaf_skew: (op.z1.clone() & BigUint::from(1u32)) == BigUint::zero(),
                        precomputed_table: compute_precomputed_table(op.base_point),
                    };
                    mul_index += 1;
                }

                if op.z2 != BigUint::zero() && !op.base_point.is_zero() {
                    let endo_point = P::g1_affine_from_xy(
                        op.base_point.x().expect("BasePoint should not be zero")
                            * P::get_cube_root_of_unity(),
                        -op.base_point.y().expect("BasePoint should not be zero"),
                    );
                    result[msm_index][mul_index] = ScalarMul {
                        pc: 0,
                        scalar: op.z2.clone(),
                        base_point: endo_point,
                        wnaf_digits: compute_wnaf_digits(op.z2.clone()),
                        wnaf_skew: (op.z2.clone() & BigUint::from(1u32)) == BigUint::zero(),
                        precomputed_table: compute_precomputed_table(endo_point),
                    };
                }
            });

        let mut pc = num_muls;
        for msm in &mut result {
            for mul in msm {
                mul.pc = pc;
                pc -= 1;
            }
        }
        assert_eq!(pc, 0);
        result
    }
}

// REFERENCE IMPLEMENTATIONS FOR co_ecc_op_queue.rs

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

impl<P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>> ECCOpQueue<P> {
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
        scalar: P::ScalarField,
    ) -> (P::ScalarField, P::ScalarField) {
        let endo_g1 = BigInt([
            Params::ENDO_G1_LO,
            Params::ENDO_G1_MID,
            Params::ENDO_G1_HI,
            0,
        ]);

        let endo_g2 = BigInt([Params::ENDO_G2_LO, Params::ENDO_G2_MID, 0, 0]);

        let endo_minus_b1 = BigInt([Params::ENDO_MINUS_B1_LO, Params::ENDO_MINUS_B1_MID, 0, 0]);

        let endo_b2 = BigInt([Params::ENDO_B2_LO, Params::ENDO_B2_MID, 0, 0]);

        let scalar_bigint = to_montgomery_form(scalar).into_bigint();

        let c1 = endo_g2.mul_high(&scalar_bigint);
        let c2 = endo_g1.mul_high(&scalar_bigint);

        let q1 = c1.mul(&endo_minus_b1).0;
        let q2 = c2.mul(&endo_b2).0;

        let q1 = from_montgomery_form(P::ScalarField::from_bigint(q1).unwrap());
        let q2 = from_montgomery_form(P::ScalarField::from_bigint(q2).unwrap());

        let t1 = q2 - q1;
        let beta = P::ScalarField::get_root_of_unity(3).unwrap();
        let t2 = t1 * beta + scalar;

        (t2, t1)
    }

    /**
     *
     * @brief Given an ecc operation and its inputs, decompose into ultra format and populate ultra_ops
     *
     * @param op_code
     * @param point
     * @param scalar
     * @return UltraOp
     */
    pub fn construct_and_populate_ultra_ops(
        op_code: EccOpCode,
        point: P::Affine,
        scalar: P::ScalarField,
    ) -> UltraOp<P> {
        let (x, y, return_is_infinity) = (point.x().unwrap(), point.y().unwrap(), point.is_zero());
        let x_256 = x.into_bigint();
        let y_256 = y.into_bigint();

        // Decompose point coordinates (Fq) into hi-lo chunks (Fr)
        const CHUNK_SIZE: u8 = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION as u8;
        let x_256 = x_256.to_bytes_be();
        let y_256 = y_256.to_bytes_be();

        let zero_pad_x = vec![0u8; (2 * CHUNK_SIZE as usize >> 3) - x_256.len()];
        let zero_pad_y = vec![0u8; (2 * CHUNK_SIZE as usize >> 3) - y_256.len()];

        let x_256 = [zero_pad_x, x_256].concat();
        let y_256 = [zero_pad_y, y_256].concat();

        let (x_hi, x_lo) = x_256.split_at(CHUNK_SIZE as usize >> 3);
        let (y_hi, y_lo) = y_256.split_at(CHUNK_SIZE as usize >> 3);

        let (x_lo, x_hi, y_lo, y_hi) = (
            P::ScalarField::from_be_bytes_mod_order(x_lo),
            P::ScalarField::from_be_bytes_mod_order(x_hi),
            P::ScalarField::from_be_bytes_mod_order(y_lo),
            P::ScalarField::from_be_bytes_mod_order(y_hi),
        );

        let converted = from_montgomery_form(scalar);

        let converted_bigint = converted.into_bigint();

        let (z_1, z_2) = if converted_bigint.num_bits() <= 128 {
            (scalar, P::ScalarField::ZERO)
        } else {
            let (z_1, z_2) =
                ECCOpQueue::<P>::split_into_endomorphism_scalars::<Bn254ParamsFr>(converted);
            (to_montgomery_form(z_1), to_montgomery_form(z_2))
        };

        UltraOp {
            op_code,
            x_lo,
            x_hi,
            y_lo,
            y_hi,
            z_1,
            z_2,
            return_is_infinity,
        }
    }
}

fn from_montgomery_form(x: TranscriptFieldType) -> TranscriptFieldType {
    let mont_r: TranscriptFieldType = TranscriptFieldType::MODULUS.montgomery_r().into();
    x * mont_r.inverse().unwrap()
}

fn to_montgomery_form(x: TranscriptFieldType) -> TranscriptFieldType {
    let mont_r: TranscriptFieldType = TranscriptFieldType::MODULUS.montgomery_r().into();
    x * mont_r
}

#[cfg(test)]
mod test {
    use crate::eccvm::ecc_op_queue::Bn254ParamsFr;
    use crate::eccvm::ecc_op_queue::{ECCOpQueue, EccOpCode, UltraOp};
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use mpc_core::gadgets::field_from_hex_string;

    type P = Bn254;
    type Bn254G1 = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;
    type Point = <P as Pairing>::G1Affine;

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

        let point = Point {
            x: field_from_hex_string(
                "0x211561d55817d8e259180a3e684611e49f458da76ade6a1f5a2bad3dd20ed047",
            )
            .unwrap(),
            y: field_from_hex_string(
                "0x1eab68c1f7807f482ffc7dd13fd9a0ce3bf26240230270ac781e2dc5c5460b3f",
            )
            .unwrap(),
            infinity: false,
        };

        let scalar = field_from_hex_string(
            "0x02d9b5973384d81dc3e502de86b99ff96c38b15c4b1c4520d2a3147c7777ce1f",
        )
        .unwrap();

        let ultra_op: UltraOp<_> = ECCOpQueue::<Bn254G1>::construct_and_populate_ultra_ops(
            EccOpCode::default(),
            point,
            scalar,
        );

        let expected_ultra_op = UltraOp {
            op_code: EccOpCode::default(),
            x_lo: field_from_hex_string(
                "0x000000000000000000000000000000e49f458da76ade6a1f5a2bad3dd20ed047",
            )
            .unwrap(),
            x_hi: field_from_hex_string(
                "0x0000000000000000000000000000000000211561d55817d8e259180a3e684611",
            )
            .unwrap(),
            y_lo: field_from_hex_string(
                "0x000000000000000000000000000000ce3bf26240230270ac781e2dc5c5460b3f",
            )
            .unwrap(),
            y_hi: field_from_hex_string(
                "0x00000000000000000000000000000000001eab68c1f7807f482ffc7dd13fd9a0",
            )
            .unwrap(),
            z_1: field_from_hex_string(
                "0x0000000000000000000000000000000018ffbbc11990c665e3edc805f6d1ccf9",
            )
            .unwrap(),
            z_2: field_from_hex_string(
                "0x000000000000000000000000000000004f9333cd430dea1bc75410733863e4f1",
            )
            .unwrap(),
            return_is_infinity: false,
        };

        assert_eq!(ultra_op, expected_ultra_op);
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

        let expected_result = (
            field_from_hex_string(
                "0x1ba2c8d6ff259fa8c79d53093767cd1002d67810d1cb07c131d4fbfac46bf8c9",
            )
            .unwrap(),
            field_from_hex_string(
                "0x0b8ab330373e7c36cab04db25e7f2a1119d7820f8941279a4ec3718c0ebe742c",
            )
            .unwrap(),
        );

        assert_eq!(
            ECCOpQueue::<Bn254G1>::split_into_endomorphism_scalars::<Bn254ParamsFr>(scalar),
            expected_result
        );
    }
}
