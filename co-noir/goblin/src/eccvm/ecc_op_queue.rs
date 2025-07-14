#![expect(unused)]
use crate::eccvm::eccvm_types::batch_normalize;
use crate::eccvm::eccvm_types::batch_normalize_inplace;
use crate::eccvm::eccvm_types::offset_generator;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::PrimeGroup;
use ark_ff::FftField;
use ark_ff::One;
use ark_ff::Zero;
use co_builder::TranscriptFieldType;
use co_builder::prelude::HonkCurve;
use co_builder::prelude::Polynomial;
use num_bigint::BigUint;
use std::array;
use std::ops::Neg;

// TODO FLORIN: Find out which functions in this are actually needed

pub(crate) const NUM_LIMB_BITS_IN_FIELD_SIMULATION: usize = 68;
pub(crate) const NUM_SCALAR_BITS: usize = 128; // The length of scalars handled by the ECCVVM
pub(crate) const NUM_WNAF_DIGIT_BITS: usize = 4; // Scalars are decompose into base 16 in wNAF form
pub(crate) const NUM_WNAF_DIGITS_PER_SCALAR: usize = NUM_SCALAR_BITS / NUM_WNAF_DIGIT_BITS; // 32
pub(crate) const WNAF_MASK: u64 = (1 << NUM_WNAF_DIGIT_BITS) - 1;
pub(crate) const POINT_TABLE_SIZE: usize = 1 << (NUM_WNAF_DIGIT_BITS);
pub(crate) const WNAF_DIGITS_PER_ROW: usize = 4;
pub(crate) const ADDITIONS_PER_ROW: usize = 4;
pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

#[derive(Clone, Default)]
pub(crate) struct ScalarMul<C: CurveGroup> {
    pub(crate) pc: u32,
    pub(crate) scalar: BigUint,
    pub(crate) base_point: C::Affine,
    pub(crate) wnaf_digits: [i32; NUM_WNAF_DIGITS_PER_SCALAR],
    pub(crate) wnaf_skew: bool,
    // size bumped by 1 to record base_point.dbl()
    pub(crate) precomputed_table: [C::Affine; POINT_TABLE_SIZE + 1],
}

pub(crate) type Msm<C> = Vec<ScalarMul<C>>;
#[derive(Default, Clone)]

pub(crate) struct AddState<C: CurveGroup> {
    pub add: bool,
    pub slice: i32,
    pub point: C::Affine,
    pub lambda: C::BaseField,
    pub collision_inverse: C::BaseField,
}
#[derive(Default, Clone)]
pub(crate) struct MSMRow<C: CurveGroup> {
    // Counter over all half-length scalar muls used to compute the required MSMs
    pub(crate) pc: u32,
    // The number of points that will be scaled and summed
    pub(crate) msm_size: u32,
    pub(crate) msm_count: u32,
    pub(crate) msm_round: u32,
    pub(crate) msm_transition: bool,
    pub(crate) q_add: bool,
    pub(crate) q_double: bool,
    pub(crate) q_skew: bool,
    pub(crate) add_state: [AddState<C>; 4],
    pub(crate) accumulator_x: C::BaseField,
    pub(crate) accumulator_y: C::BaseField,
}

impl<C: HonkCurve<TranscriptFieldType>> MSMRow<C> {
    pub(crate) fn compute_rows_msms(
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
            msm_row_counts.push(msm_row_counts.last().unwrap() + num_rows_required as usize);
            pc_values.push(pc_values.last().unwrap() - msm.len());
        }

        assert_eq!(*pc_values.last().unwrap(), 0);

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
        // In what fallows, either p1 + p2 = p3, or p1.dbl() = p3
        // We create 1 vector to store the entire point trace. We split into multiple containers using std::span
        // (we want 1 vector object to more efficiently batch normalize points)
        const NUM_POINTS_IN_ADDITION_RELATION: usize = 3;
        let num_points_to_normalize =
            (num_point_adds_and_doubles * NUM_POINTS_IN_ADDITION_RELATION) + num_accumulators;
        let mut p1_trace = Vec::with_capacity(num_point_adds_and_doubles);
        let mut p2_trace = Vec::with_capacity(num_point_adds_and_doubles);
        let mut p3_trace = Vec::with_capacity(num_point_adds_and_doubles);
        // operation_trace records whether an entry in the p1/p2/p3 trace represents a point addition or doubling
        let mut operation_trace = vec![false; num_point_adds_and_doubles];
        // accumulator_trace tracks the value of the ECCVM accumulator for each row
        let mut accumulator_trace = Vec::with_capacity(num_accumulators);

        // we start the accumulator at the offset generator point. This ensures we can support an MSM that produces a
        let offset_generator: C::Affine = offset_generator::<C>();
        accumulator_trace[0] = offset_generator;

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/973): Reinstate multitreading?
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
                        // let acc_expected = accumulator; // TODO FLORIN: Check if this is needed
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
                            let mut p1 = accumulator;
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

        points_to_normalize = batch_normalize::<C>(&points_to_normalize);

        let p1_trace = &points_to_normalize[0..num_point_adds_and_doubles];
        let p2_trace = &points_to_normalize[num_point_adds_and_doubles..num_point_adds_and_doubles];
        let p3_trace =
            &points_to_normalize[num_point_adds_and_doubles * 2..num_point_adds_and_doubles];
        let accumulator_trace =
            &points_to_normalize[num_point_adds_and_doubles * 3..num_accumulators];

        // inverse_trace is used to compute the value of the `collision_inverse` column in the ECCVM.
        let mut inverse_trace = Vec::with_capacity(num_point_adds_and_doubles);
        for operation_idx in 0..num_point_adds_and_doubles {
            if operation_trace[operation_idx] {
                inverse_trace.push(
                    p1_trace[operation_idx].y().expect("Should be non-zero")
                        + p1_trace[operation_idx].y().expect("Should be non-zero"),
                );
            } else {
                inverse_trace.push(
                    p2_trace[operation_idx].x().expect("Should be non-zero")
                        - p1_trace[operation_idx].x().expect("Should be non-zero"),
                );
            }
        }
        ark_ff::batch_inversion(&mut inverse_trace);

        // complete the computation of the ECCVM execution trace, by adding the affine intermediate point data
        // i.e. row.accumulator_x, row.accumulator_y, row.add_state[0...3].collision_inverse,
        // row.add_state[0...3].lambda
        for msm_idx in 0..msms.len() {
            let msm = &msms[msm_idx];
            let mut trace_index = ((msm_row_counts[msm_idx] - 1) * ADDITIONS_PER_ROW);
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
                for row_idx in 0..num_rows_per_digit {
                    let row = &mut msm_rows[msm_row_index];
                    let normalized_accumulator = &accumulator_trace[accumulator_index];
                    assert!(normalized_accumulator.is_zero());
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

                if (digit_idx < NUM_WNAF_DIGITS_PER_SCALAR - 1) {
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
                        assert!(normalized_accumulator.is_zero());
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
            AddState {
                add: false,
                slice: 0,
                point: C::Affine::default(),
                lambda: C::BaseField::zero(),
                collision_inverse: C::BaseField::zero(),
            },
            AddState {
                add: false,
                slice: 0,
                point: C::Affine::default(),
                lambda: C::BaseField::zero(),
                collision_inverse: C::BaseField::zero(),
            },
            AddState {
                add: false,
                slice: 0,
                point: C::Affine::default(),
                lambda: C::BaseField::zero(),
                collision_inverse: C::BaseField::zero(),
            },
            AddState {
                add: false,
                slice: 0,
                point: C::Affine::default(),
                lambda: C::BaseField::zero(),
                collision_inverse: C::BaseField::zero(),
            },
        ];

        (msm_rows, point_table_read_counts)
    }
}

pub(crate) type EccvmOpsTable<P> = EccOpsTable<VMOperation<P>>;
pub(crate) struct UltraEccOpsTable<P: CurveGroup> {
    table: EccOpsTable<UltraOp<P>>,
}

impl<P: CurveGroup> UltraEccOpsTable<P> {
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
pub struct VMOperation<P: CurveGroup> {
    pub op_code: EccOpCode,
    pub base_point: P::Affine,
    pub z1: BigUint,
    pub z2: BigUint,
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
#[derive(Clone)]
pub(crate) struct UltraOp<P: CurveGroup> {
    pub op_code: EccOpCode,
    pub x_lo: P::ScalarField,
    pub x_hi: P::ScalarField,
    pub y_lo: P::ScalarField,
    pub y_hi: P::ScalarField,
    pub z_1: P::ScalarField,
    pub z_2: P::ScalarField,
    pub return_is_infinity: bool,
}

impl<P: CurveGroup> UltraOp<P> {
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
    pub(crate) add: bool,
    pub(crate) mul: bool,
    pub(crate) eq: bool,
    pub(crate) reset: bool,
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

    pub fn get_precompute_table_row_count_for_single_msm(msm_count: usize) -> u32 {
        let num_precompute_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;
        (msm_count * num_precompute_rows_per_scalar) as u32
    }
}

pub struct ECCOpQueue<P: CurveGroup> {
    point_at_infinity: P::Affine,
    accumulator: P::Affine,
    eccvm_ops_table: EccvmOpsTable<P>,
    ultra_ops_table: UltraEccOpsTable<P>,
    eccvm_ops_reconstructed: Vec<VMOperation<P>>,
    ultra_ops_reconstructed: Vec<UltraOp<P>>,
    eccvm_row_tracker: EccvmRowTracker,
}

impl<P: CurveGroup> ECCOpQueue<P> {
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
                batch_normalize_inplace::<P>(&mut table);

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
                let raw_slice = (&scalar & BigUint::from(WNAF_MASK));
                let is_even = (&raw_slice & BigUint::one()) == BigUint::zero();
                let mut wnaf_slice = raw_slice.to_u32_digits()[0] as i32;

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
        for (i, msm) in result.iter_mut().enumerate() {
            msm.resize(
                msm_sizes[i],
                ScalarMul {
                    pc: 0,
                    scalar: BigUint::zero(),
                    base_point: P::Affine::default(),
                    wnaf_digits: [0; NUM_WNAF_DIGITS_PER_SCALAR],
                    wnaf_skew: false,
                    precomputed_table: [P::Affine::default(); POINT_TABLE_SIZE + 1],
                },
            );
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
                            * P::BaseField::get_root_of_unity(3)
                                .expect("3rd root of unity should exist in the field"),
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
