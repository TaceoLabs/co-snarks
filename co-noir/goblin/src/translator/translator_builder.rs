use crate::{MICRO_LIMB_BITS, NUM_LAST_LIMB_BITS, NUM_LIMB_BITS, NUM_QUOTIENT_BITS, NUM_Z_BITS};
use crate::{
    NUM_BINARY_LIMBS, NUM_MICRO_LIMBS, NUM_RELATION_WIDE_LIMBS, NUM_Z_LIMBS,
    eccvm::ecc_op_queue::ECCOpQueue, prelude::UltraOp,
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::{TranscriptFieldType, prelude::HonkCurve};
use num_bigint::BigUint;
use std::str::FromStr;

const NUM_WIRES: usize = 81;
const ZERO_IDX: usize = 0;
const ONE_IDX: usize = 1;

struct TranslatorBuilder<P: CurveGroup> {
    pub variables: Vec<P::ScalarField>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub real_variable_index: Vec<u32>,
    pub(crate) real_variable_tags: Vec<u32>,
    batching_challenge_v: P::BaseField,
    evaluation_input_x: P::BaseField,
    wires: [Vec<u32>; NUM_WIRES],
    num_gates: usize,
}
impl<P: HonkCurve<TranscriptFieldType>> TranslatorBuilder<P> {
    pub(crate) const DUMMY_TAG: u32 = 0;
    pub(crate) const REAL_VARIABLE: u32 = u32::MAX - 1;
    pub(crate) const FIRST_VARIABLE_IN_CLASS: u32 = u32::MAX - 2;
    pub(crate) fn add_variable(&mut self, value: P::ScalarField) -> u32 {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        self.real_variable_index.push(idx);
        self.next_var_index.push(Self::REAL_VARIABLE);
        self.prev_var_index.push(Self::FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(Self::DUMMY_TAG);
        idx
    }
    fn feed_ecc_op_queue_into_circuit(
        &mut self,
        batching_challenge_v: P::BaseField,
        evaluation_input_x: P::BaseField,
        ecc_op_queue: &mut ECCOpQueue<P>,
    ) {
        self.evaluation_input_x = evaluation_input_x;
        self.batching_challenge_v = batching_challenge_v;
        let ultra_ops = ecc_op_queue.get_ultra_ops();
        let mut accumulator_trace: Vec<P::BaseField> = Vec::new();
        let current_accumulator = P::BaseField::zero();
        if ultra_ops.is_empty() {
            return;
        }

        // Process the first UltraOp - a no-op - and populate with zeros the beginning of all other wires to ensure all wire
        // polynomials in translator start with 0 (required for shifted polynomials in the proving system). Technically,
        // we'd need only first index to be a zero but, given each "real" UltraOp populates two indices in a polynomial we
        // add two zeros for consistency.
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1360): We'll also have to eventually process random
        // data in the merge protocol (added for zero knowledge)/
        self.populate_wires_from_ultra_op(&ultra_ops[0]);
        for wire in self.wires.iter_mut() {
            // Push two zeros to each wire to ensure the first two indices are zero
            if wire.is_empty() {
                wire.push(ZERO_IDX as u32);
                wire.push(ZERO_IDX as u32);
            }
        }

        self.num_gates += 2;

        // We need to precompute the accumulators at each step, because in the actual circuit we compute the values starting
        // from the later indices. We need to know the previous accumulator to create the gate
        let mut current_accumulator = current_accumulator;
        for i in 1..ultra_ops.len() {
            let ultra_op = &ultra_ops[ultra_ops.len() - i];
            current_accumulator *= evaluation_input_x;
            let (x_256, y_256) = ultra_op.get_base_point_standard_form();
            let z1: BigUint = ultra_op.z_1.into();
            let z2: BigUint = ultra_op.z_2.into();
            let z1: P::BaseField = z1.into();
            let z2: P::BaseField = z2.into();
            current_accumulator += P::BaseField::from(ultra_op.op_code.value())
                + batching_challenge_v
                    * (x_256
                        + batching_challenge_v
                            * (y_256 + batching_challenge_v * (z1 + batching_challenge_v * z2)));
            accumulator_trace.push(current_accumulator);
        }

        // We don't care about the last value since we'll recompute it during witness generation anyway
        accumulator_trace.pop();

        // Generate witness values from all the UltraOps
        for i in 1..ultra_ops.len() {
            let ultra_op = &ultra_ops[i];
            let mut previous_accumulator = P::BaseField::zero();
            // Pop the last value from accumulator trace and use it as previous accumulator
            if let Some(last) = accumulator_trace.pop() {
                previous_accumulator = last;
            }
            // Compute witness values
            let one_accumulation_step = self.generate_witness_values(
                ultra_op,
                previous_accumulator,
                batching_challenge_v,
                evaluation_input_x,
            );

            // And put them into the wires
            self.create_accumulation_gate(one_accumulation_step);
        }
    }

    fn populate_wires_from_ultra_op(&mut self, ultra_op: &UltraOp<P>) {
        let idx = self.add_variable(P::ScalarField::from(ultra_op.op_code.value()));
        self.wires[WireIds::OP.as_usize()].push(idx);
        // Similarly to the ColumnPolynomials in the merge protocol, the op_wire is 0 at every second index
        self.wires[WireIds::OP.as_usize()].push(ZERO_IDX as u32);

        self.insert_pair_into_wire(WireIds::X_LOW_Y_HI, ultra_op.x_lo, ultra_op.y_hi);
        self.insert_pair_into_wire(WireIds::X_HIGH_Z_1, ultra_op.x_hi, ultra_op.z_1);
        self.insert_pair_into_wire(WireIds::Y_LOW_Z_2, ultra_op.y_lo, ultra_op.z_2);
    }
    fn insert_pair_into_wire(
        &mut self,
        wire_index: WireIds,
        first: P::ScalarField,
        second: P::ScalarField,
    ) {
        let first_idx = self.add_variable(first);
        let second_idx = self.add_variable(second);
        let wire = &mut self.wires[wire_index.as_usize()];
        wire.push(first_idx);
        wire.push(second_idx);
    }

    fn generate_witness_values(
        &self,
        ultra_op: &UltraOp<P>,
        previous_accumulator: P::BaseField,
        batching_challenge_v: P::BaseField,
        evaluation_input_x: P::BaseField,
    ) -> AccumulationInput<P> {
        const NUM_LIMB_BITS: usize = 68;
        let shift_1: P::ScalarField = (BigUint::one() << NUM_LIMB_BITS).into();
        let shift_2 = BigUint::one() << (NUM_LIMB_BITS << 1);

        // Precomputed inverse to easily divide by the shift by 2 limbs
        let mut shift_2_inverse: P::ScalarField = shift_2.into();
        shift_2_inverse = shift_2_inverse.inverse().unwrap_or_else(|| {
            panic!(
                "Failed to compute inverse of shift_2, this should not happen in a valid circuit"
            )
        });
        //TODO FLORIN: make this nicer
        let negative_modulus_limbs: [P::ScalarField; 5] = [
            P::ScalarField::from_str("51007615349848998585")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            P::ScalarField::from_str("187243884991886189399")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            P::ScalarField::from_str("292141664167738113703")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            P::ScalarField::from_str("295147053861416594661")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            P::ScalarField::from_str(
                "21888242871839275222246405745257275088400417643534245024707370478506390782651",
            )
            .unwrap_or_else(|_| panic!("invalid field element literal")),
        ];

        // TODO FLORIN: This is kinda wrong
        fn slice_bits(n: &BigUint, start: usize, end: usize) -> BigUint {
            if end <= start {
                return BigUint::zero();
            }
            let width = end - start;
            (n >> start) & ((BigUint::one() << width) - 1u32)
        }

        // Convert BigUint to ScalarField (assumes canonical < modulus)
        fn to_scalar<F: From<u64> + TryFrom<BigUint>>(b: BigUint) -> F {
            // F likely implements From<BigUint> in this codebase; if not, reduce manually.
            // Here we attempt TryFrom, fallback via u64 (only for small slices).
            if let Ok(v) = F::try_from(b.clone()) {
                v
            } else {
                // Fallback (should not trigger for wide limbs in real implementation)
                F::from(b.to_u64_digits().first().copied().unwrap_or(0))
            }
        }

        // All parameters are well-described in the header, this is just for convenience
        const TOP_STANDARD_MICROLIMB_BITS: usize = NUM_LAST_LIMB_BITS % MICRO_LIMB_BITS;
        const TOP_Z_MICROLIMB_BITS: usize = (NUM_Z_BITS % NUM_LIMB_BITS) % MICRO_LIMB_BITS;
        const TOP_QUOTIENT_MICROLIMB_BITS: usize =
            (NUM_QUOTIENT_BITS % NUM_LIMB_BITS) % MICRO_LIMB_BITS;

        /*
         * @brief A small function to transform a uint512_t element into its 4 68-bit limbs in Fr scalars
         *
         * @details Split and integer stored in uint512_T into 4 68-bit chunks (we assume that it is lower than 2²⁷²),
         * convert to Fr
         *
         */
        let uint512_t_to_limbs = |original: &BigUint| -> [P::ScalarField; NUM_BINARY_LIMBS] {
            let mut out = [P::ScalarField::from(0u64); NUM_BINARY_LIMBS];
            for i in 0..NUM_BINARY_LIMBS {
                let lo = slice_bits(original, i * NUM_LIMB_BITS, (i + 1) * NUM_LIMB_BITS);
                out[i] = to_scalar(lo);
            }
            out
        };

        /*
         * @brief A method for splitting wide limbs (P_x_lo, P_y_hi, etc) into two limbs
         *
         */
        let split_wide_limb_into_2_limbs =
            |wide_limb: P::ScalarField| -> [P::ScalarField; NUM_Z_LIMBS] {
                let wide: BigUint = wide_limb.into();
                [
                    to_scalar(slice_bits(&wide, 0, NUM_LIMB_BITS)),
                    to_scalar(slice_bits(&wide, NUM_LIMB_BITS, 2 * NUM_LIMB_BITS)),
                ]
            };
        /*
         * @brief A method to split a full 68-bit limb into 5 14-bit limb and 1 shifted limb for a more secure constraint
         *
         */
        let split_standard_limb_into_micro_limbs =
            |limb: P::ScalarField| -> [P::ScalarField; NUM_MICRO_LIMBS] {
                // static_assert(MICRO_LIMB_BITS == 14);
                let val: BigUint = limb.into();
                let a0 = slice_bits(&val, 0, MICRO_LIMB_BITS);
                let a1 = slice_bits(&val, MICRO_LIMB_BITS, 2 * MICRO_LIMB_BITS);
                let a2 = slice_bits(&val, 2 * MICRO_LIMB_BITS, 3 * MICRO_LIMB_BITS);
                let a3 = slice_bits(&val, 3 * MICRO_LIMB_BITS, 4 * MICRO_LIMB_BITS);
                let a4 = slice_bits(&val, 4 * MICRO_LIMB_BITS, 5 * MICRO_LIMB_BITS);
                let top = {
                    let raw = a4.clone();
                    let shift_amt = MICRO_LIMB_BITS - (NUM_LIMB_BITS % MICRO_LIMB_BITS);
                    if shift_amt == 0 {
                        raw
                    } else {
                        &raw << shift_amt
                    }
                };
                [
                    to_scalar(a0),
                    to_scalar(a1),
                    to_scalar(a2),
                    to_scalar(a3),
                    to_scalar(a4),
                    to_scalar(top),
                ]
            };

        /*
         * @brief A method to split the top 50-bit limb into 4 14-bit limbs and 1 shifted limb for a more secure constraint
         * (plus there is 1 extra space for other constraints)
         *
         */
        let split_top_limb_into_micro_limbs =
            |limb: P::ScalarField, last_limb_bits: usize| -> [P::ScalarField; NUM_MICRO_LIMBS] {
                // static_assert(MICRO_LIMB_BITS == 14);
                let val: BigUint = limb.into();
                let a0 = slice_bits(&val, 0, MICRO_LIMB_BITS);
                let a1 = slice_bits(&val, MICRO_LIMB_BITS, 2 * MICRO_LIMB_BITS);
                let a2 = slice_bits(&val, 2 * MICRO_LIMB_BITS, 3 * MICRO_LIMB_BITS);
                let a3 = slice_bits(&val, 3 * MICRO_LIMB_BITS, 4 * MICRO_LIMB_BITS);
                let a4 = {
                    let raw = slice_bits(&val, 3 * MICRO_LIMB_BITS, 4 * MICRO_LIMB_BITS);
                    let shift_amt = MICRO_LIMB_BITS - (last_limb_bits % MICRO_LIMB_BITS);
                    if shift_amt == 0 {
                        raw
                    } else {
                        &raw << shift_amt
                    }
                };
                [
                    to_scalar(a0),
                    to_scalar(a1),
                    to_scalar(a2),
                    to_scalar(a3),
                    to_scalar(a4),
                    P::ScalarField::from(0u64),
                ]
            };

        /*
         * @brief A method for splitting the top 60-bit z limb into microlimbs (differs from the 68-bit limb by the shift in
         * the last limb)
         *
         */
        let split_top_z_limb_into_micro_limbs =
            |limb: P::ScalarField, last_limb_bits: usize| -> [P::ScalarField; NUM_MICRO_LIMBS] {
                // static_assert(MICRO_LIMB_BITS == 14);
                let val: BigUint = limb.into();
                let a0 = slice_bits(&val, 0, MICRO_LIMB_BITS);
                let a1 = slice_bits(&val, MICRO_LIMB_BITS, 2 * MICRO_LIMB_BITS);
                let a2 = slice_bits(&val, 2 * MICRO_LIMB_BITS, 3 * MICRO_LIMB_BITS);
                let a3 = slice_bits(&val, 3 * MICRO_LIMB_BITS, 4 * MICRO_LIMB_BITS);
                let a4 = slice_bits(&val, 4 * MICRO_LIMB_BITS, 5 * MICRO_LIMB_BITS);
                let a5 = {
                    let raw = slice_bits(&val, 4 * MICRO_LIMB_BITS, 5 * MICRO_LIMB_BITS);
                    let shift_amt = MICRO_LIMB_BITS - (last_limb_bits % MICRO_LIMB_BITS);
                    if shift_amt == 0 {
                        raw
                    } else {
                        &raw << shift_amt
                    }
                };
                [
                    to_scalar(a0),
                    to_scalar(a1),
                    to_scalar(a2),
                    to_scalar(a3),
                    to_scalar(a4),
                    to_scalar(a5),
                ]
            };

        /*
         * @brief Split a 72-bit relation limb into 6 14-bit limbs (we can allow the slack here, since we only need to
         * ensure non-overflow of the modulus)
         *
         */
        let split_relation_limb_into_micro_limbs = |limb: P::ScalarField| -> [P::ScalarField; 6] {
            // static_assert(MICRO_LIMB_BITS == 14);
            let val: BigUint = limb.into();
            let mut out = [P::ScalarField::from(0u64); 6];
            for i in 0..6 {
                let part = slice_bits(&val, i * MICRO_LIMB_BITS, (i + 1) * MICRO_LIMB_BITS);
                out[i] = to_scalar(part);
            }
            out
        };

        // Helper: split base field element into NUM_BINARY_LIMBS limbs of NUM_LIMB_BITS, returned as ScalarField
        let split_fq_into_limbs = |x: P::BaseField| -> [P::ScalarField; NUM_BINARY_LIMBS] {
            let xb: BigUint = x.into();
            let mut out = [P::ScalarField::from(0u64); NUM_BINARY_LIMBS];
            for i in 0..NUM_BINARY_LIMBS {
                let limb = slice_bits(&xb, i * NUM_LIMB_BITS, (i + 1) * NUM_LIMB_BITS);
                out[i] = to_scalar(limb);
            }
            out
        };

        //  x and powers of v are given to us in challenge form, so the verifier has to deal with this :)
        let v_squared = batching_challenge_v * batching_challenge_v;
        let v_cubed = v_squared * batching_challenge_v;
        let v_quarted = v_cubed * batching_challenge_v;

        // Convert the accumulator, powers of v and x into "bigfield" form
        let previous_accumulator_limbs = split_fq_into_limbs(previous_accumulator);
        let v_witnesses = split_fq_into_limbs(batching_challenge_v);
        let v_squared_witnesses = split_fq_into_limbs(v_squared);
        let v_cubed_witnesses = split_fq_into_limbs(v_cubed);
        let v_quarted_witnesses = split_fq_into_limbs(v_quarted);
        let x_witnesses = split_fq_into_limbs(evaluation_input_x);

        // To calculate the quotient, we need to evaluate the expression in integers. So we need uint512_t versions of all
        // elements involved
        let op_code = ultra_op.op_code.value() as u64;
        let uint_previous_accumulator: BigUint = previous_accumulator.into();
        let uint_x: BigUint = evaluation_input_x.into();
        let uint_op = BigUint::from(op_code);
        let num_limb_shift = 2 * NUM_LIMB_BITS;

        let x_lo: BigUint = ultra_op.x_lo.into();
        let x_hi: BigUint = ultra_op.x_hi.into();
        let y_lo: BigUint = ultra_op.y_lo.into();
        let y_hi: BigUint = ultra_op.y_hi.into();
        let z1_b: BigUint = ultra_op.z_1.into();
        let z2_b: BigUint = ultra_op.z_2.into();
        let uint_v: BigUint = batching_challenge_v.into();
        let uint_v_squared: BigUint = v_squared.into();
        let uint_v_cubed: BigUint = v_cubed.into();
        let uint_v_quarted: BigUint = v_quarted.into();

        let limb_shift_big = BigUint::one() << num_limb_shift;
        let uint_p_x = &x_lo + (&x_hi << num_limb_shift);
        let uint_p_y = &y_lo + (&y_hi << num_limb_shift);
        let uint_z1 = z1_b.clone();
        let uint_z2 = z2_b.clone();

        // Construct Fq for op, P.x, P.y, z_1, z_2 for use in witness computation
        let base_op = P::BaseField::from(op_code);
        let base_p_x = {
            // reconstruct as base field
            // x_lo + (x_hi << (2*NUM_LIMB_BITS))
            // Convert back assuming into fits
            // (Simplified assumption: direct BigUint -> BaseField via try_from implemented elsewhere)
            P::BaseField::try_from(uint_p_x.clone()).unwrap()
        };
        let base_p_y = P::BaseField::try_from(uint_p_y.clone()).unwrap();
        let base_z_1 = P::BaseField::try_from(uint_z1.clone()).unwrap();
        let base_z_2 = P::BaseField::try_from(uint_z2.clone()).unwrap();

        // Construct bigfield representations of P.x and P.y
        let [p_x_0, p_x_1] = split_wide_limb_into_2_limbs(ultra_op.x_lo);
        let [p_x_2, p_x_3] = split_wide_limb_into_2_limbs(ultra_op.x_hi);
        let p_x_limbs = [p_x_0, p_x_1, p_x_2, p_x_3];

        let [p_y_0, p_y_1] = split_wide_limb_into_2_limbs(ultra_op.y_lo);
        let [p_y_2, p_y_3] = split_wide_limb_into_2_limbs(ultra_op.y_hi);
        let p_y_limbs = [p_y_0, p_y_1, p_y_2, p_y_3];

        // Construct bigfield representations of ultra_op.z_1 and ultra_op.z_2 only using 2 limbs each
        let z_1_limbs = split_wide_limb_into_2_limbs(ultra_op.z_1);
        let z_2_limbs = split_wide_limb_into_2_limbs(ultra_op.z_2);

        // The formula is `accumulator = accumulator⋅x + (op + v⋅p.x + v²⋅p.y + v³⋅z₁ + v⁴z₂)`. We need to compute the
        // remainder (new accumulator value)

        let remainder: P::BaseField = previous_accumulator * evaluation_input_x
            + base_z_2 * v_quarted
            + base_z_1 * v_cubed
            + base_p_y * v_squared
            + base_p_x * batching_challenge_v
            + base_op;

        // We also need to compute the quotient
        let modulus_big: BigUint = {
            // Assuming existence of modulus retrieval
            P::BaseField::MODULUS.into()
        };

        let uint_remainder: BigUint = remainder.into();

        let quotient_by_modulus = &uint_previous_accumulator * &uint_x
            + &uint_z2 * &uint_v_quarted
            + &uint_z1 * &uint_v_cubed
            + &uint_p_y * &uint_v_squared
            + &uint_p_x * &uint_v
            + &uint_op
            - &uint_remainder;

        let quotient = &quotient_by_modulus / &modulus_big;

        debug_assert!(
            quotient_by_modulus == &quotient * &modulus_big,
            "Quotient reconstruction failed"
        );

        // Compute quotient and remainder bigfield representation
        let remainder_limbs = split_fq_into_limbs(remainder);
        let quotient_limbs = uint512_t_to_limbs(&quotient);

        // We will divide by shift_2 instantly in the relation itself, but first we need to compute the low part (0*0) and
        // the high part (0*1, 1*0) multiplied by a single limb shift
        let low_wide_relation_limb_part_1 = previous_accumulator_limbs[0] * x_witnesses[0]
            + P::ScalarField::from(op_code)
            + v_witnesses[0] * p_x_limbs[0]
            + v_squared_witnesses[0] * p_y_limbs[0]
            + v_cubed_witnesses[0] * z_1_limbs[0]
            + v_quarted_witnesses[0] * z_2_limbs[0]
            + quotient_limbs[0] * negative_modulus_limbs[0]
            - remainder_limbs[0]; // This covers the lowest limb

        let low_wide_relation_limb = low_wide_relation_limb_part_1
            + (previous_accumulator_limbs[1] * x_witnesses[0]
                + previous_accumulator_limbs[0] * x_witnesses[1]
                + v_witnesses[1] * p_x_limbs[0]
                + p_x_limbs[1] * v_witnesses[0]
                + v_squared_witnesses[1] * p_y_limbs[0]
                + v_squared_witnesses[0] * p_y_limbs[1]
                + v_cubed_witnesses[1] * z_1_limbs[0]
                + z_1_limbs[1] * v_cubed_witnesses[0]
                + v_quarted_witnesses[1] * z_2_limbs[0]
                + v_quarted_witnesses[0] * z_2_limbs[1]
                + quotient_limbs[0] * negative_modulus_limbs[1]
                + quotient_limbs[1] * negative_modulus_limbs[0]
                - remainder_limbs[1])
                * shift_1;

        // Low bits have to be zero
        //TODO FLORIN
        // debug_assert!(
        //     slice_bits(&BigUint::from(low_wide_relation_limb), 0, 2 * NUM_LIMB_BITS).is_zero()
        // );

        let low_wide_relation_limb_divided = low_wide_relation_limb * shift_2_inverse;

        // The high relation limb is the accumulation of the low limb divided by 2¹³⁶ and the combination of limbs with
        // indices (0*2,1*1,2*0) with limbs with indices (0*3,1*2,2*1,3*0) multiplied by 2⁶⁸

        let high_wide_relation_limb = low_wide_relation_limb_divided
            + previous_accumulator_limbs[2] * x_witnesses[0]
            + previous_accumulator_limbs[1] * x_witnesses[1]
            + previous_accumulator_limbs[0] * x_witnesses[2]
            + v_witnesses[2] * p_x_limbs[0]
            + v_witnesses[1] * p_x_limbs[1]
            + v_witnesses[0] * p_x_limbs[2]
            + v_squared_witnesses[2] * p_y_limbs[0]
            + v_squared_witnesses[1] * p_y_limbs[1]
            + v_squared_witnesses[0] * p_y_limbs[2]
            + v_cubed_witnesses[2] * z_1_limbs[0]
            + v_cubed_witnesses[1] * z_1_limbs[1]
            + v_quarted_witnesses[2] * z_2_limbs[0]
            + v_quarted_witnesses[1] * z_2_limbs[1]
            + quotient_limbs[2] * negative_modulus_limbs[0]
            + quotient_limbs[1] * negative_modulus_limbs[1]
            + quotient_limbs[0] * negative_modulus_limbs[2]
            - remainder_limbs[2]
            + (previous_accumulator_limbs[3] * x_witnesses[0]
                + previous_accumulator_limbs[2] * x_witnesses[1]
                + previous_accumulator_limbs[1] * x_witnesses[2]
                + previous_accumulator_limbs[0] * x_witnesses[3]
                + v_witnesses[3] * p_x_limbs[0]
                + v_witnesses[2] * p_x_limbs[1]
                + v_witnesses[1] * p_x_limbs[2]
                + v_witnesses[0] * p_x_limbs[3]
                + v_squared_witnesses[3] * p_y_limbs[0]
                + v_squared_witnesses[2] * p_y_limbs[1]
                + v_squared_witnesses[1] * p_y_limbs[2]
                + v_squared_witnesses[0] * p_y_limbs[3]
                + v_cubed_witnesses[3] * z_1_limbs[0]
                + v_cubed_witnesses[2] * z_1_limbs[1]
                + v_quarted_witnesses[3] * z_2_limbs[0]
                + v_quarted_witnesses[2] * z_2_limbs[1]
                + quotient_limbs[3] * negative_modulus_limbs[0]
                + quotient_limbs[2] * negative_modulus_limbs[1]
                + quotient_limbs[1] * negative_modulus_limbs[2]
                + quotient_limbs[0] * negative_modulus_limbs[3]
                - remainder_limbs[3])
                * shift_1;

        // Check that the results lower 136 bits are zero
        //TODO FLORIN
        // debug_assert!(
        //     slice_bits(
        //         &BigUint::from(high_wide_relation_limb),
        //         0,
        //         2 * NUM_LIMB_BITS
        //     )
        //     .is_zero()
        // );

        // Get divided version
        let high_wide_relation_limb_divided = high_wide_relation_limb * shift_2_inverse;

        const LAST_LIMB_INDEX: usize = NUM_BINARY_LIMBS - 1;

        let mut p_x_microlimbs = [[P::ScalarField::from(0u64); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS];
        let mut p_y_microlimbs = [[P::ScalarField::from(0u64); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS];
        let mut z_1_microlimbs = [[P::ScalarField::from(0u64); NUM_MICRO_LIMBS]; NUM_Z_LIMBS];
        let mut z_2_microlimbs = [[P::ScalarField::from(0u64); NUM_MICRO_LIMBS]; NUM_Z_LIMBS];
        let mut current_accumulator_microlimbs =
            [[P::ScalarField::from(0u64); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS];
        let mut quotient_microlimbs =
            [[P::ScalarField::from(0u64); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS];

        // Split P_x into microlimbs for range constraining
        for i in 0..LAST_LIMB_INDEX {
            p_x_microlimbs[i] = split_standard_limb_into_micro_limbs(p_x_limbs[i]);
        }
        p_x_microlimbs[LAST_LIMB_INDEX] = split_top_limb_into_micro_limbs(
            p_x_limbs[LAST_LIMB_INDEX],
            TOP_STANDARD_MICROLIMB_BITS,
        );

        // Split P_y into microlimbs for range constraining
        for i in 0..LAST_LIMB_INDEX {
            p_y_microlimbs[i] = split_standard_limb_into_micro_limbs(p_y_limbs[i]);
        }
        p_y_microlimbs[LAST_LIMB_INDEX] = split_top_limb_into_micro_limbs(
            p_y_limbs[LAST_LIMB_INDEX],
            TOP_STANDARD_MICROLIMB_BITS,
        );

        // Split z scalars into microlimbs for range constraining
        for i in 0..(NUM_Z_LIMBS - 1) {
            z_1_microlimbs[i] = split_standard_limb_into_micro_limbs(z_1_limbs[i]);
            z_2_microlimbs[i] = split_standard_limb_into_micro_limbs(z_2_limbs[i]);
        }
        z_1_microlimbs[NUM_Z_LIMBS - 1] =
            split_top_z_limb_into_micro_limbs(z_1_limbs[NUM_Z_LIMBS - 1], TOP_Z_MICROLIMB_BITS);
        z_2_microlimbs[NUM_Z_LIMBS - 1] =
            split_top_z_limb_into_micro_limbs(z_2_limbs[NUM_Z_LIMBS - 1], TOP_Z_MICROLIMB_BITS);

        // Split current accumulator into microlimbs for range constraining
        for i in 0..LAST_LIMB_INDEX {
            current_accumulator_microlimbs[i] =
                split_standard_limb_into_micro_limbs(remainder_limbs[i]);
        }
        current_accumulator_microlimbs[LAST_LIMB_INDEX] = split_top_limb_into_micro_limbs(
            remainder_limbs[LAST_LIMB_INDEX],
            TOP_STANDARD_MICROLIMB_BITS,
        );

        // Split quotient into microlimbs for range constraining
        for i in 0..LAST_LIMB_INDEX {
            quotient_microlimbs[i] = split_standard_limb_into_micro_limbs(quotient_limbs[i]);
        }
        quotient_microlimbs[LAST_LIMB_INDEX] = split_top_limb_into_micro_limbs(
            quotient_limbs[LAST_LIMB_INDEX],
            TOP_QUOTIENT_MICROLIMB_BITS,
        );

        // Start filling the witness container
        let mut input = AccumulationInput::new(ultra_op.clone(), P::ScalarField::from(0u64));
        input.p_x_limbs = p_x_limbs;
        input.p_x_microlimbs = p_x_microlimbs;
        input.p_y_limbs = p_y_limbs;
        input.p_y_microlimbs = p_y_microlimbs;
        input.z_1_limbs = z_1_limbs;
        input.z_1_microlimbs = z_1_microlimbs;
        input.z_2_limbs = z_2_limbs;
        input.z_2_microlimbs = z_2_microlimbs;
        input.previous_accumulator = previous_accumulator_limbs;
        input.current_accumulator = remainder_limbs;
        input.current_accumulator_microlimbs = current_accumulator_microlimbs;
        input.quotient_binary_limbs = quotient_limbs;
        input.quotient_microlimbs = quotient_microlimbs;
        input.relation_wide_limbs = [
            low_wide_relation_limb_divided,
            high_wide_relation_limb_divided,
        ];
        input.relation_wide_microlimbs = [
            split_relation_limb_into_micro_limbs(low_wide_relation_limb_divided),
            split_relation_limb_into_micro_limbs(high_wide_relation_limb_divided),
        ];

        input
    }

    /**
     * @brief Create a single accumulation gate
     *
     * @param acc_step
     */
    fn create_accumulation_gate(&mut self, acc_step: AccumulationInput<P>) {
        // assert_well_formed_accumulation_input(acc_step);

        self.populate_wires_from_ultra_op(&acc_step.ultra_op);

        // Insert limbs used in bigfield evaluations
        self.insert_pair_into_wire(
            WireIds::P_X_LOW_LIMBS,
            acc_step.p_x_limbs[0],
            acc_step.p_x_limbs[1],
        );
        self.insert_pair_into_wire(
            WireIds::P_X_HIGH_LIMBS,
            acc_step.p_x_limbs[2],
            acc_step.p_x_limbs[3],
        );
        self.insert_pair_into_wire(
            WireIds::P_Y_LOW_LIMBS,
            acc_step.p_y_limbs[0],
            acc_step.p_y_limbs[1],
        );
        self.insert_pair_into_wire(
            WireIds::P_Y_HIGH_LIMBS,
            acc_step.p_y_limbs[2],
            acc_step.p_y_limbs[3],
        );
        self.insert_pair_into_wire(
            WireIds::Z_LOW_LIMBS,
            acc_step.z_1_limbs[0],
            acc_step.z_2_limbs[0],
        );
        self.insert_pair_into_wire(
            WireIds::Z_HIGH_LIMBS,
            acc_step.z_1_limbs[1],
            acc_step.z_2_limbs[1],
        );
        self.insert_pair_into_wire(
            WireIds::QUOTIENT_LOW_BINARY_LIMBS,
            acc_step.quotient_binary_limbs[0],
            acc_step.quotient_binary_limbs[1],
        );
        self.insert_pair_into_wire(
            WireIds::QUOTIENT_HIGH_BINARY_LIMBS,
            acc_step.quotient_binary_limbs[2],
            acc_step.quotient_binary_limbs[3],
        );
        self.insert_pair_into_wire(
            WireIds::RELATION_WIDE_LIMBS,
            acc_step.relation_wide_limbs[0],
            acc_step.relation_wide_limbs[1],
        );

        // We are using some leftover crevices for relation_wide_microlimbs
        let low_relation_microlimbs = acc_step.relation_wide_microlimbs[0];
        let high_relation_microlimbs = acc_step.relation_wide_microlimbs[1];

        // We have 4 wires specifically for the relation microlimbs
        self.insert_pair_into_wire(
            WireIds::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0,
            low_relation_microlimbs[0],
            high_relation_microlimbs[0],
        );
        self.insert_pair_into_wire(
            WireIds::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_1,
            low_relation_microlimbs[1],
            high_relation_microlimbs[1],
        );
        self.insert_pair_into_wire(
            WireIds::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_2,
            low_relation_microlimbs[2],
            high_relation_microlimbs[2],
        );
        self.insert_pair_into_wire(
            WireIds::RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3,
            low_relation_microlimbs[3],
            high_relation_microlimbs[3],
        );

        // Next ones go into top P_x and P_y, current accumulator and quotient unused microlimbs

        // Insert the second highest low relation microlimb into the space left in P_x range constraints highest wire
        let mut top_p_x_microlimbs = acc_step.p_x_microlimbs[NUM_BINARY_LIMBS - 1];
        top_p_x_microlimbs[NUM_MICRO_LIMBS - 1] = low_relation_microlimbs[NUM_MICRO_LIMBS - 2];

        // Insert the second highest high relation microlimb into the space left in P_y range constraints highest wire
        let mut top_p_y_microlimbs = acc_step.p_y_microlimbs[NUM_BINARY_LIMBS - 1];
        top_p_y_microlimbs[NUM_MICRO_LIMBS - 1] = high_relation_microlimbs[NUM_MICRO_LIMBS - 2];

        // The highest low relation microlimb goes into the crevice left in current accumulator microlimbs
        let mut top_current_accumulator_microlimbs =
            acc_step.current_accumulator_microlimbs[NUM_BINARY_LIMBS - 1];
        top_current_accumulator_microlimbs[NUM_MICRO_LIMBS - 1] =
            low_relation_microlimbs[NUM_MICRO_LIMBS - 1];

        // The highest high relation microlimb goes into the quotient crevice
        let mut top_quotient_microlimbs = acc_step.quotient_microlimbs[NUM_BINARY_LIMBS - 1];
        top_quotient_microlimbs[NUM_MICRO_LIMBS - 1] =
            high_relation_microlimbs[NUM_MICRO_LIMBS - 1];

        /*
         * @brief Put several values in sequential wires
         *
         */
        let mut lay_limbs_in_row = |input: &[P::ScalarField], starting_wire: WireIds| {
            let mut wire_index = starting_wire.as_usize();
            for &element in input.iter() {
                let var_idx = self.add_variable(element);
                self.wires[wire_index].push(var_idx);
                wire_index += 1;
            }
        };

        // Now put all microlimbs into appropriate wires
        lay_limbs_in_row(
            &acc_step.p_x_microlimbs[0],
            WireIds::P_X_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.p_x_microlimbs[1],
            WireIds::P_X_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.p_x_microlimbs[2],
            WireIds::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &top_p_x_microlimbs,
            WireIds::P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.p_y_microlimbs[0],
            WireIds::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.p_y_microlimbs[1],
            WireIds::P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.p_y_microlimbs[2],
            WireIds::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &top_p_y_microlimbs,
            WireIds::P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.z_1_microlimbs[0],
            WireIds::Z_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.z_2_microlimbs[0],
            WireIds::Z_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.z_1_microlimbs[1],
            WireIds::Z_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.z_2_microlimbs[1],
            WireIds::Z_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.current_accumulator,
            WireIds::ACCUMULATORS_BINARY_LIMBS_0,
        );
        lay_limbs_in_row(
            &acc_step.previous_accumulator,
            WireIds::ACCUMULATORS_BINARY_LIMBS_0,
        );
        lay_limbs_in_row(
            &acc_step.current_accumulator_microlimbs[0],
            WireIds::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.current_accumulator_microlimbs[1],
            WireIds::ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.current_accumulator_microlimbs[2],
            WireIds::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &top_current_accumulator_microlimbs,
            WireIds::ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        lay_limbs_in_row(
            &acc_step.quotient_microlimbs[0],
            WireIds::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_0,
        );
        lay_limbs_in_row(
            &acc_step.quotient_microlimbs[1],
            WireIds::QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_0,
        );
        lay_limbs_in_row(
            &acc_step.quotient_microlimbs[2],
            WireIds::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_0,
        );
        lay_limbs_in_row(
            &top_quotient_microlimbs,
            WireIds::QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_0,
        );

        self.num_gates += 2;

        // Check that all the wires are filled equally
        // TODO FLORIN DO WE WANT TO DO THIS?
        // for (i, wire) in self.wires.iter().enumerate() {
        //     debug_assert!(
        //         wire.len() == self.num_gates,
        //         "wire {i} len {} != {}",
        //         wire.len(),
        //         self.num_gates
        //     );
        // }
    }
}

#[allow(non_camel_case_types)]
#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WireIds {
    OP, // The first 4 wires contain the standard values from the EccQueue wire
    X_LOW_Y_HI,
    X_HIGH_Z_1,
    Y_LOW_Z_2,
    P_X_LOW_LIMBS,               // P.xₗₒ split into 2 68 bit limbs
    P_X_HIGH_LIMBS,              // P.xₕᵢ split into a 68 and a 50 bit limb
    P_Y_LOW_LIMBS,               // P.yₗₒ split into 2 68 bit limbs
    P_Y_HIGH_LIMBS,              // P.yₕᵢ split into a 68 and a 50 bit limb
    Z_LOW_LIMBS,                 // Low limbs of z_1 and z_2 (68 bits each)
    Z_HIGH_LIMBS,                // High Limbs of z_1 and z_2 (60 bits each)
    ACCUMULATORS_BINARY_LIMBS_0, // Contain 68-bit limbs of current and previous accumulator (previous at higher
    // indices because of the nuances of KZG commitment).
    ACCUMULATORS_BINARY_LIMBS_1,
    ACCUMULATORS_BINARY_LIMBS_2,
    ACCUMULATORS_BINARY_LIMBS_3, // Highest limb is 50 bits (254 mod 68)    P_X_LOW_LIMBS_RANGE_CONSTRAINT_0, // Low
    // limbs split further into smaller chunks for range constraints
    QUOTIENT_LOW_BINARY_LIMBS, // Quotient limbs
    QUOTIENT_HIGH_BINARY_LIMBS,
    RELATION_WIDE_LIMBS, // Limbs for checking the correctness of  mod 2²⁷² relations.
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_0, // Low limbs split further into smaller chunks for range constraints
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_1,
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_2,
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_3,
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_4,
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_TAIL,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0, // High limbs split into chunks for range constraints
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_1,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_2,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_3,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_4,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0, // Low limbs split into chunks for range constraints
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_1,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_2,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_3,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_4,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_TAIL,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0, // High limbs split into chunks for range constraints
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_1,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_2,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_3,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_4,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_0, // Range constraints for low limbs of z_1 and z_2
    Z_LOW_LIMBS_RANGE_CONSTRAINT_1,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_2,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_3,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_4,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_TAIL,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_0, // Range constraints for high limbs of z_1 and z_2
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_1,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_2,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_3,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_4,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL,

    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0, // Range constraints for the current accumulator limbs (no need to
    // redo previous accumulator)
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_1,
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_2,
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_3,
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_4,
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_TAIL,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_1,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_2,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_3,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_4,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL,

    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_0, // Range constraints for quotient
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_1,
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_2,
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_3,
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_4,
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_TAIL,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_0,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_1,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_2,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_3,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_4,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_TAIL,
    RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0,
    RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_1,
    RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_2,
    RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3,

    TOTAL_COUNT,
}

impl WireIds {
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Debug)]
struct AccumulationInput<P: HonkCurve<TranscriptFieldType>> {
    // Members necessary for the gate creation
    ultra_op: UltraOp<P>,

    p_x_limbs: [P::ScalarField; NUM_BINARY_LIMBS],
    p_x_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    p_y_limbs: [P::ScalarField; NUM_BINARY_LIMBS],
    p_y_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    z_1_limbs: [P::ScalarField; NUM_Z_LIMBS],
    z_1_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
    z_2_limbs: [P::ScalarField; NUM_Z_LIMBS],
    z_2_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],

    previous_accumulator: [P::ScalarField; NUM_BINARY_LIMBS],
    current_accumulator: [P::ScalarField; NUM_BINARY_LIMBS],
    current_accumulator_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    quotient_binary_limbs: [P::ScalarField; NUM_BINARY_LIMBS],
    quotient_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    relation_wide_limbs: [P::ScalarField; NUM_RELATION_WIDE_LIMBS],
    relation_wide_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; 2],
}

impl<P: HonkCurve<TranscriptFieldType>> AccumulationInput<P> {
    fn new(ultra_op: UltraOp<P>, zero: P::ScalarField) -> Self {
        Self {
            ultra_op,
            p_x_limbs: [zero; NUM_BINARY_LIMBS],
            p_x_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            p_y_limbs: [zero; NUM_BINARY_LIMBS],
            p_y_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            z_1_limbs: [zero; NUM_Z_LIMBS],
            z_1_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
            z_2_limbs: [zero; NUM_Z_LIMBS],
            z_2_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
            previous_accumulator: [zero; NUM_BINARY_LIMBS],
            current_accumulator: [zero; NUM_BINARY_LIMBS],
            current_accumulator_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            quotient_binary_limbs: [zero; NUM_BINARY_LIMBS],
            quotient_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            relation_wide_limbs: [zero; NUM_RELATION_WIDE_LIMBS],
            relation_wide_microlimbs: [[zero; NUM_MICRO_LIMBS]; 2],
        }
    }
}
