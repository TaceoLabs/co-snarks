// struct ProverPolynomials {
//     fn new(builder: &CircuitBuilder) -> Self {
//         // compute rows for the three different sections of the ECCVM execution trace
//         let transcript_rows = ECCVMTranscriptBuilder::compute_rows(
//             builder.op_queue.get_eccvm_ops(),
//             builder.get_number_of_muls(),
//         );
//         let msms = builder.get_msms();
//         let point_table_rows = ECCVMPointTablePrecomputationBuilder::compute_rows(
//             CircuitBuilder::get_flattened_scalar_muls(&msms),
//         );
//         let result = ECCVMMSMMBuilder::compute_rows(
//             &msms,
//             builder.get_number_of_muls(),
//             builder.op_queue.get_num_msm_rows(),
//         );
//         let msm_rows = &result.0;
//         let point_table_read_counts = &result.1;

//         let num_rows = std::cmp::max(
//             std::cmp::max(point_table_rows.len(), msm_rows.len()),
//             transcript_rows.len(),
//         ) + NUM_DISABLED_ROWS_IN_SUMCHECK;
//         let log_num_rows = numeric::get_msb64(num_rows) as usize;
//         let mut dyadic_num_rows = 1 << (log_num_rows + if (1 << log_num_rows) == num_rows { 0 } else { 1 });
//         if ECCVM_FIXED_SIZE < dyadic_num_rows {
//             panic!(
//                 "The ECCVM circuit size has exceeded the fixed upper bound! Fixed size: {} actual size: {}",
//                 ECCVM_FIXED_SIZE, dyadic_num_rows
//             );
//         }

//         dyadic_num_rows = ECCVM_FIXED_SIZE;
//         let unmasked_witness_size = dyadic_num_rows - NUM_DISABLED_ROWS_IN_SUMCHECK;

//         for poly in get_to_be_shifted() {
//             *poly = Polynomial::new(dyadic_num_rows - 1, dyadic_num_rows, 1);
//         }
//         // allocate polynomials; define lagrange and lookup read count polynomials
//         for poly in get_all() {
//             if poly.is_empty() {
//                 *poly = Polynomial::new(dyadic_num_rows);
//             }
//         }
//         lagrange_first[0] = 1;
//         lagrange_second[1] = 1;
//         lagrange_last[unmasked_witness_size - 1] = 1;
//         for i in 0..point_table_read_counts[0].len() {
//             lookup_read_counts_0[i + 1] = point_table_read_counts[0][i];
//             lookup_read_counts_1[i + 1] = point_table_read_counts[1][i];
//         }

//         // compute polynomials for transcript columns
//         parallel_for_range(transcript_rows.len(), |start, end| {
//             for i in start..end {
//                 transcript_accumulator_empty.set_if_valid_index(i, transcript_rows[i].accumulator_empty);
//                 transcript_add.set_if_valid_index(i, transcript_rows[i].q_add);
//                 transcript_mul.set_if_valid_index(i, transcript_rows[i].q_mul);
//                 transcript_eq.set_if_valid_index(i, transcript_rows[i].q_eq);
//                 transcript_reset_accumulator.set_if_valid_index(i, transcript_rows[i].q_reset_accumulator);
//                 transcript_msm_transition.set_if_valid_index(i, transcript_rows[i].msm_transition);
//                 transcript_pc.set_if_valid_index(i, transcript_rows[i].pc);
//                 transcript_msm_count.set_if_valid_index(i, transcript_rows[i].msm_count);
//                 transcript_Px.set_if_valid_index(i, transcript_rows[i].base_x);
//                 transcript_Py.set_if_valid_index(i, transcript_rows[i].base_y);
//                 transcript_z1.set_if_valid_index(i, transcript_rows[i].z1);
//                 transcript_z2.set_if_valid_index(i, transcript_rows[i].z2);
//                 transcript_z1zero.set_if_valid_index(i, transcript_rows[i].z1_zero);
//                 transcript_z2zero.set_if_valid_index(i, transcript_rows[i].z2_zero);
//                 transcript_op.set_if_valid_index(i, transcript_rows[i].opcode);
//                 transcript_accumulator_x.set_if_valid_index(i, transcript_rows[i].accumulator_x);
//                 transcript_accumulator_y.set_if_valid_index(i, transcript_rows[i].accumulator_y);
//                 transcript_msm_x.set_if_valid_index(i, transcript_rows[i].msm_output_x);
//                 transcript_msm_y.set_if_valid_index(i, transcript_rows[i].msm_output_y);
//                 transcript_base_infinity.set_if_valid_index(i, transcript_rows[i].base_infinity);
//                 transcript_base_x_inverse.set_if_valid_index(i, transcript_rows[i].base_x_inverse);
//                 transcript_base_y_inverse.set_if_valid_index(i, transcript_rows[i].base_y_inverse);
//                 transcript_add_x_equal.set_if_valid_index(i, transcript_rows[i].transcript_add_x_equal);
//                 transcript_add_y_equal.set_if_valid_index(i, transcript_rows[i].transcript_add_y_equal);
//                 transcript_add_lambda.set_if_valid_index(i, transcript_rows[i].transcript_add_lambda);
//                 transcript_msm_intermediate_x.set_if_valid_index(i, transcript_rows[i].transcript_msm_intermediate_x);
//                 transcript_msm_intermediate_y.set_if_valid_index(i, transcript_rows[i].transcript_msm_intermediate_y);
//                 transcript_msm_infinity.set_if_valid_index(i, transcript_rows[i].transcript_msm_infinity);
//                 transcript_msm_x_inverse.set_if_valid_index(i, transcript_rows[i].transcript_msm_x_inverse);
//                 transcript_msm_count_zero_at_transition.set_if_valid_index(
//                     i,
//                     transcript_rows[i].msm_count_zero_at_transition,
//                 );
//                 transcript_msm_count_at_transition_inverse.set_if_valid_index(
//                     i,
//                     transcript_rows[i].msm_count_at_transition_inverse,
//                 );
//             }
//         });

//         if transcript_rows[transcript_rows.len() - 1].accumulator_empty {
//             for i in transcript_rows.len()..unmasked_witness_size {
//                 transcript_accumulator_empty.set_if_valid_index(i, 1);
//             }
//         }
//         for i in transcript_rows.len()..unmasked_witness_size {
//             transcript_accumulator_x.set_if_valid_index(i, transcript_accumulator_x[i - 1]);
//             transcript_accumulator_y.set_if_valid_index(i, transcript_accumulator_y[i - 1]);
//         }

//         parallel_for_range(point_table_rows.len(), |start, end| {
//             for i in start..end {
//                 precompute_select.set_if_valid_index(i, if i != 0 { 1 } else { 0 });
//                 precompute_pc.set_if_valid_index(i, point_table_rows[i].pc);
//                 precompute_point_transition.set_if_valid_index(i, point_table_rows[i].point_transition as u64);
//                 precompute_round.set_if_valid_index(i, point_table_rows[i].round);
//                 precompute_scalar_sum.set_if_valid_index(i, point_table_rows[i].scalar_sum);
//                 precompute_s1hi.set_if_valid_index(i, point_table_rows[i].s1);
//                 precompute_s1lo.set_if_valid_index(i, point_table_rows[i].s2);
//                 precompute_s2hi.set_if_valid_index(i, point_table_rows[i].s3);
//                 precompute_s2lo.set_if_valid_index(i, point_table_rows[i].s4);
//                 precompute_s3hi.set_if_valid_index(i, point_table_rows[i].s5);
//                 precompute_s3lo.set_if_valid_index(i, point_table_rows[i].s6);
//                 precompute_s4hi.set_if_valid_index(i, point_table_rows[i].s7);
//                 precompute_s4lo.set_if_valid_index(i, point_table_rows[i].s8);
//                 precompute_skew.set_if_valid_index(i, if point_table_rows[i].skew { 7 } else { 0 });
//                 precompute_dx.set_if_valid_index(i, point_table_rows[i].precompute_double.x);
//                 precompute_dy.set_if_valid_index(i, point_table_rows[i].precompute_double.y);
//                 precompute_tx.set_if_valid_index(i, point_table_rows[i].precompute_accumulator.x);
//                 precompute_ty.set_if_valid_index(i, point_table_rows[i].precompute_accumulator.y);
//             }
//         });

//         parallel_for_range(msm_rows.len(), |start, end| {
//             for i in start..end {
//                 msm_transition.set_if_valid_index(i, msm_rows[i].msm_transition as i32);
//                 msm_add.set_if_valid_index(i, msm_rows[i].q_add as i32);
//                 msm_double.set_if_valid_index(i, msm_rows[i].q_double as i32);
//                 msm_skew.set_if_valid_index(i, msm_rows[i].q_skew as i32);
//                 msm_accumulator_x.set_if_valid_index(i, msm_rows[i].accumulator_x);
//                 msm_accumulator_y.set_if_valid_index(i, msm_rows[i].accumulator_y);
//                 msm_pc.set_if_valid_index(i, msm_rows[i].pc);
//                 msm_size_of_msm.set_if_valid_index(i, msm_rows[i].msm_size);
//                 msm_count.set_if_valid_index(i, msm_rows[i].msm_count);
//                 msm_round.set_if_valid_index(i, msm_rows[i].msm_round);
//                 msm_add1.set_if_valid_index(i, msm_rows[i].add_state[0].add as i32);
//                 msm_add2.set_if_valid_index(i, msm_rows[i].add_state[1].add as i32);
//                 msm_add3.set_if_valid_index(i, msm_rows[i].add_state[2].add as i32);
//                 msm_add4.set_if_valid_index(i, msm_rows[i].add_state[3].add as i32);
//                 msm_x1.set_if_valid_index(i, msm_rows[i].add_state[0].point.x);
//                 msm_y1.set_if_valid_index(i, msm_rows[i].add_state[0].point.y);
//                 msm_x2.set_if_valid_index(i, msm_rows[i].add_state[1].point.x);
//                 msm_y2.set_if_valid_index(i, msm_rows[i].add_state[1].point.y);
//                 msm_x3.set_if_valid_index(i, msm_rows[i].add_state[2].point.x);
//                 msm_y3.set_if_valid_index(i, msm_rows[i].add_state[2].point.y);
//                 msm_x4.set_if_valid_index(i, msm_rows[i].add_state[3].point.x);
//                 msm_y4.set_if_valid_index(i, msm_rows[i].add_state[3].point.y);
//                 msm_collision_x1.set_if_valid_index(i, msm_rows[i].add_state[0].collision_inverse);
//                 msm_collision_x2.set_if_valid_index(i, msm_rows[i].add_state[1].collision_inverse);
//                 msm_collision_x3.set_if_valid_index(i, msm_rows[i].add_state[2].collision_inverse);
//                 msm_collision_x4.set_if_valid_index(i, msm_rows[i].add_state[3].collision_inverse);
//                 msm_lambda1.set_if_valid_index(i, msm_rows[i].add_state[0].lambda);
//                 msm_lambda2.set_if_valid_index(i, msm_rows[i].add_state[1].lambda);
//                 msm_lambda3.set_if_valid_index(i, msm_rows[i].add_state[2].lambda);
//                 msm_lambda4.set_if_valid_index(i, msm_rows[i].add_state[3].lambda);
//                 msm_slice1.set_if_valid_index(i, msm_rows[i].add_state[0].slice);
//                 msm_slice2.set_if_valid_index(i, msm_rows[i].add_state[1].slice);
//                 msm_slice3.set_if_valid_index(i, msm_rows[i].add_state[2].slice);
//                 msm_slice4.set_if_valid_index(i, msm_rows[i].add_state[3].slice);
//             }
//         });

//         Self::set_shifted();
//     }
// }
