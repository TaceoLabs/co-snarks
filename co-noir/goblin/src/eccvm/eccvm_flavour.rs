// todo!("implement this function");

//  ProverPolynomials(const CircuitBuilder& builder)
//         {
//             // compute rows for the three different sections of the ECCVM execution trace
//             const auto transcript_rows =
//                 ECCVMTranscriptBuilder::compute_rows(builder.op_queue->get_eccvm_ops(), builder.get_number_of_muls());
//             const std::vector<MSM> msms = builder.get_msms();
//             const auto point_table_rows =
//                 ECCVMPointTablePrecomputationBuilder::compute_rows(CircuitBuilder::get_flattened_scalar_muls(msms));
//             const auto result = ECCVMMSMMBuilder::compute_rows(
//                 msms, builder.get_number_of_muls(), builder.op_queue->get_num_msm_rows());
//             const auto& msm_rows = std::get<0>(result);
//             const auto& point_table_read_counts = std::get<1>(result);

//             const size_t num_rows = std::max({ point_table_rows.size(), msm_rows.size(), transcript_rows.size() }) +
//                                     NUM_DISABLED_ROWS_IN_SUMCHECK;
//             const auto log_num_rows = static_cast<size_t>(numeric::get_msb64(num_rows));
//             size_t dyadic_num_rows = 1UL << (log_num_rows + (1UL << log_num_rows == num_rows ? 0 : 1));
//             if (ECCVM_FIXED_SIZE < dyadic_num_rows) {
//                 throw_or_abort("The ECCVM circuit size has exceeded the fixed upper bound! Fixed size: " +
//                                std::to_string(ECCVM_FIXED_SIZE) + " actual size: " + std::to_string(dyadic_num_rows));
//             }

//             dyadic_num_rows = ECCVM_FIXED_SIZE;
//             size_t unmasked_witness_size = dyadic_num_rows - NUM_DISABLED_ROWS_IN_SUMCHECK;

//             for (auto& poly : get_to_be_shifted()) {
//                 poly = Polynomial{ /*memory size*/ dyadic_num_rows - 1,
//                                    /*largest possible index*/ dyadic_num_rows,
//                                    /* offset */ 1 };
//             }
//             // allocate polynomials; define lagrange and lookup read count polynomials
//             for (auto& poly : get_all()) {
//                 if (poly.is_empty()) {
//                     poly = Polynomial(dyadic_num_rows);
//                 }
//             }
//             lagrange_first.at(0) = 1;
//             lagrange_second.at(1) = 1;
//             lagrange_last.at(unmasked_witness_size - 1) = 1;
//             for (size_t i = 0; i < point_table_read_counts[0].size(); ++i) {
//                 // Explanation of off-by-one offset:
//                 // When computing the WNAF slice for a point at point counter value `pc` and a round index `round`, the
//                 // row number that computes the slice can be derived. This row number is then mapped to the index of
//                 // `lookup_read_counts`. We do this mapping in `ecc_msm_relation`. We are off-by-one because we add an
//                 // empty row at the start of the WNAF columns that is not accounted for (index of lookup_read_counts
//                 // maps to the row in our WNAF columns that computes a slice for a given value of pc and round)
//                 lookup_read_counts_0.at(i + 1) = point_table_read_counts[0][i];
//                 lookup_read_counts_1.at(i + 1) = point_table_read_counts[1][i];
//             }

//             // compute polynomials for transcript columns
//             parallel_for_range(transcript_rows.size(), [&](size_t start, size_t end) {
//                 for (size_t i = start; i < end; i++) {
//                     transcript_accumulator_empty.set_if_valid_index(i, transcript_rows[i].accumulator_empty);
//                     transcript_add.set_if_valid_index(i, transcript_rows[i].q_add);
//                     transcript_mul.set_if_valid_index(i, transcript_rows[i].q_mul);
//                     transcript_eq.set_if_valid_index(i, transcript_rows[i].q_eq);
//                     transcript_reset_accumulator.set_if_valid_index(i, transcript_rows[i].q_reset_accumulator);
//                     transcript_msm_transition.set_if_valid_index(i, transcript_rows[i].msm_transition);
//                     transcript_pc.set_if_valid_index(i, transcript_rows[i].pc);
//                     transcript_msm_count.set_if_valid_index(i, transcript_rows[i].msm_count);
//                     transcript_Px.set_if_valid_index(i, transcript_rows[i].base_x);
//                     transcript_Py.set_if_valid_index(i, transcript_rows[i].base_y);
//                     transcript_z1.set_if_valid_index(i, transcript_rows[i].z1);
//                     transcript_z2.set_if_valid_index(i, transcript_rows[i].z2);
//                     transcript_z1zero.set_if_valid_index(i, transcript_rows[i].z1_zero);
//                     transcript_z2zero.set_if_valid_index(i, transcript_rows[i].z2_zero);
//                     transcript_op.set_if_valid_index(i, transcript_rows[i].opcode);
//                     transcript_accumulator_x.set_if_valid_index(i, transcript_rows[i].accumulator_x);
//                     transcript_accumulator_y.set_if_valid_index(i, transcript_rows[i].accumulator_y);
//                     transcript_msm_x.set_if_valid_index(i, transcript_rows[i].msm_output_x);
//                     transcript_msm_y.set_if_valid_index(i, transcript_rows[i].msm_output_y);
//                     transcript_base_infinity.set_if_valid_index(i, transcript_rows[i].base_infinity);
//                     transcript_base_x_inverse.set_if_valid_index(i, transcript_rows[i].base_x_inverse);
//                     transcript_base_y_inverse.set_if_valid_index(i, transcript_rows[i].base_y_inverse);
//                     transcript_add_x_equal.set_if_valid_index(i, transcript_rows[i].transcript_add_x_equal);
//                     transcript_add_y_equal.set_if_valid_index(i, transcript_rows[i].transcript_add_y_equal);
//                     transcript_add_lambda.set_if_valid_index(i, transcript_rows[i].transcript_add_lambda);
//                     transcript_msm_intermediate_x.set_if_valid_index(i,
//                                                                      transcript_rows[i].transcript_msm_intermediate_x);
//                     transcript_msm_intermediate_y.set_if_valid_index(i,
//                                                                      transcript_rows[i].transcript_msm_intermediate_y);
//                     transcript_msm_infinity.set_if_valid_index(i, transcript_rows[i].transcript_msm_infinity);
//                     transcript_msm_x_inverse.set_if_valid_index(i, transcript_rows[i].transcript_msm_x_inverse);
//                     transcript_msm_count_zero_at_transition.set_if_valid_index(
//                         i, transcript_rows[i].msm_count_zero_at_transition);
//                     transcript_msm_count_at_transition_inverse.set_if_valid_index(
//                         i, transcript_rows[i].msm_count_at_transition_inverse);
//                 }
//             });

//             // TODO(@zac-williamson) if final opcode resets accumulator, all subsequent "is_accumulator_empty" row
//             // values must be 1. Ideally we find a way to tweak this so that empty rows that do nothing have column
//             // values that are all zero (issue #2217)
//             if (transcript_rows[transcript_rows.size() - 1].accumulator_empty) {
//                 for (size_t i = transcript_rows.size(); i < unmasked_witness_size; ++i) {
//                     transcript_accumulator_empty.set_if_valid_index(i, 1);
//                 }
//             }
//             // in addition, unless the accumulator is reset, it contains the value from the previous row so this
//             // must be propagated
//             for (size_t i = transcript_rows.size(); i < unmasked_witness_size; ++i) {
//                 transcript_accumulator_x.set_if_valid_index(i, transcript_accumulator_x[i - 1]);
//                 transcript_accumulator_y.set_if_valid_index(i, transcript_accumulator_y[i - 1]);
//             }

//             parallel_for_range(point_table_rows.size(), [&](size_t start, size_t end) {
//                 for (size_t i = start; i < end; i++) {
//                     // first row is always an empty row (to accommodate shifted polynomials which must have 0 as 1st
//                     // coefficient). All other rows in the point_table_rows represent active wnaf gates (i.e.
//                     // precompute_select = 1)
//                     precompute_select.set_if_valid_index(i, (i != 0) ? 1 : 0);
//                     precompute_pc.set_if_valid_index(i, point_table_rows[i].pc);
//                     precompute_point_transition.set_if_valid_index(
//                         i, static_cast<uint64_t>(point_table_rows[i].point_transition));
//                     precompute_round.set_if_valid_index(i, point_table_rows[i].round);
//                     precompute_scalar_sum.set_if_valid_index(i, point_table_rows[i].scalar_sum);
//                     precompute_s1hi.set_if_valid_index(i, point_table_rows[i].s1);
//                     precompute_s1lo.set_if_valid_index(i, point_table_rows[i].s2);
//                     precompute_s2hi.set_if_valid_index(i, point_table_rows[i].s3);
//                     precompute_s2lo.set_if_valid_index(i, point_table_rows[i].s4);
//                     precompute_s3hi.set_if_valid_index(i, point_table_rows[i].s5);
//                     precompute_s3lo.set_if_valid_index(i, point_table_rows[i].s6);
//                     precompute_s4hi.set_if_valid_index(i, point_table_rows[i].s7);
//                     precompute_s4lo.set_if_valid_index(i, point_table_rows[i].s8);
//                     // If skew is active (i.e. we need to subtract a base point from the msm result),
//                     // write `7` into rows.precompute_skew. `7`, in binary representation, equals `-1` when converted
//                     // into WNAF form
//                     precompute_skew.set_if_valid_index(i, point_table_rows[i].skew ? 7 : 0);
//                     precompute_dx.set_if_valid_index(i, point_table_rows[i].precompute_double.x);
//                     precompute_dy.set_if_valid_index(i, point_table_rows[i].precompute_double.y);
//                     precompute_tx.set_if_valid_index(i, point_table_rows[i].precompute_accumulator.x);
//                     precompute_ty.set_if_valid_index(i, point_table_rows[i].precompute_accumulator.y);
//                 }
//             });

//             // compute polynomials for the msm columns
//             parallel_for_range(msm_rows.size(), [&](size_t start, size_t end) {
//                 for (size_t i = start; i < end; i++) {
//                     msm_transition.set_if_valid_index(i, static_cast<int>(msm_rows[i].msm_transition));
//                     msm_add.set_if_valid_index(i, static_cast<int>(msm_rows[i].q_add));
//                     msm_double.set_if_valid_index(i, static_cast<int>(msm_rows[i].q_double));
//                     msm_skew.set_if_valid_index(i, static_cast<int>(msm_rows[i].q_skew));
//                     msm_accumulator_x.set_if_valid_index(i, msm_rows[i].accumulator_x);
//                     msm_accumulator_y.set_if_valid_index(i, msm_rows[i].accumulator_y);
//                     msm_pc.set_if_valid_index(i, msm_rows[i].pc);
//                     msm_size_of_msm.set_if_valid_index(i, msm_rows[i].msm_size);
//                     msm_count.set_if_valid_index(i, msm_rows[i].msm_count);
//                     msm_round.set_if_valid_index(i, msm_rows[i].msm_round);
//                     msm_add1.set_if_valid_index(i, static_cast<int>(msm_rows[i].add_state[0].add));
//                     msm_add2.set_if_valid_index(i, static_cast<int>(msm_rows[i].add_state[1].add));
//                     msm_add3.set_if_valid_index(i, static_cast<int>(msm_rows[i].add_state[2].add));
//                     msm_add4.set_if_valid_index(i, static_cast<int>(msm_rows[i].add_state[3].add));
//                     msm_x1.set_if_valid_index(i, msm_rows[i].add_state[0].point.x);
//                     msm_y1.set_if_valid_index(i, msm_rows[i].add_state[0].point.y);
//                     msm_x2.set_if_valid_index(i, msm_rows[i].add_state[1].point.x);
//                     msm_y2.set_if_valid_index(i, msm_rows[i].add_state[1].point.y);
//                     msm_x3.set_if_valid_index(i, msm_rows[i].add_state[2].point.x);
//                     msm_y3.set_if_valid_index(i, msm_rows[i].add_state[2].point.y);
//                     msm_x4.set_if_valid_index(i, msm_rows[i].add_state[3].point.x);
//                     msm_y4.set_if_valid_index(i, msm_rows[i].add_state[3].point.y);
//                     msm_collision_x1.set_if_valid_index(i, msm_rows[i].add_state[0].collision_inverse);
//                     msm_collision_x2.set_if_valid_index(i, msm_rows[i].add_state[1].collision_inverse);
//                     msm_collision_x3.set_if_valid_index(i, msm_rows[i].add_state[2].collision_inverse);
//                     msm_collision_x4.set_if_valid_index(i, msm_rows[i].add_state[3].collision_inverse);
//                     msm_lambda1.set_if_valid_index(i, msm_rows[i].add_state[0].lambda);
//                     msm_lambda2.set_if_valid_index(i, msm_rows[i].add_state[1].lambda);
//                     msm_lambda3.set_if_valid_index(i, msm_rows[i].add_state[2].lambda);
//                     msm_lambda4.set_if_valid_index(i, msm_rows[i].add_state[3].lambda);
//                     msm_slice1.set_if_valid_index(i, msm_rows[i].add_state[0].slice);
//                     msm_slice2.set_if_valid_index(i, msm_rows[i].add_state[1].slice);
//                     msm_slice3.set_if_valid_index(i, msm_rows[i].add_state[2].slice);
//                     msm_slice4.set_if_valid_index(i, msm_rows[i].add_state[3].slice);
//                 }
//             });
//             this->set_shifted();
//         }
