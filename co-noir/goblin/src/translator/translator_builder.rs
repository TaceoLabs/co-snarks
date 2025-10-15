use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::eccvm::ecc_op_queue::{ECCOpQueue, UltraOp};
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::prelude::Polynomials;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::polynomials::polynomial::Polynomial;
use co_noir_common::utils::Utils;
use co_noir_common::{
    MICRO_LIMB_BITS, NUM_BINARY_LIMBS, NUM_LAST_LIMB_BITS, NUM_MICRO_LIMBS, NUM_QUOTIENT_BITS,
    NUM_RELATION_WIDE_LIMBS, NUM_Z_BITS, NUM_Z_LIMBS,
};
use num_bigint::BigUint;
use std::str::FromStr;

const NUM_WIRES: usize = 81;
const ZERO_IDX: usize = 0;

pub struct TranslatorBuilder<P: CurveGroup> {
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
impl<P: HonkCurve<TranscriptFieldType>> Default for TranslatorBuilder<P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: HonkCurve<TranscriptFieldType>> TranslatorBuilder<P> {
    pub(crate) const DUMMY_TAG: u32 = 0;
    pub(crate) const REAL_VARIABLE: u32 = u32::MAX - 1;
    pub(crate) const FIRST_VARIABLE_IN_CLASS: u32 = u32::MAX - 2;
    pub fn new() -> Self {
        Self {
            variables: Vec::new(),
            next_var_index: Vec::new(),
            prev_var_index: Vec::new(),
            real_variable_index: Vec::new(),
            real_variable_tags: Vec::new(),
            batching_challenge_v: P::BaseField::zero(),
            evaluation_input_x: P::BaseField::zero(),
            wires: std::array::from_fn(|_| Vec::new()),
            num_gates: 0,
        }
    }
    pub(crate) fn add_variable(&mut self, value: P::ScalarField) -> u32 {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        self.real_variable_index.push(idx);
        self.next_var_index.push(Self::REAL_VARIABLE);
        self.prev_var_index.push(Self::FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(Self::DUMMY_TAG);
        idx
    }
    pub fn feed_ecc_op_queue_into_circuit(
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
        for ultra_op in ultra_ops.iter().skip(1).rev() {
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
        // Generate witness values from all the UltraOps
        for ultra_op in ultra_ops.iter().skip(1) {
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
                &negative_modulus_limbs,
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
        negative_modulus_limbs: &[P::ScalarField; 5],
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
            for (i, limb) in out.iter_mut().enumerate() {
                *limb = P::ScalarField::from(Utils::slice_u256(
                    original,
                    (i * NUM_LIMB_BITS) as u64,
                    ((i + 1) * NUM_LIMB_BITS) as u64,
                ));
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
                    P::ScalarField::from(Utils::slice_u256(&wide, 0, NUM_LIMB_BITS as u64)),
                    P::ScalarField::from(Utils::slice_u256(
                        &wide,
                        NUM_LIMB_BITS as u64,
                        2 * NUM_LIMB_BITS as u64,
                    )),
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
                let a0 = Utils::slice_u256(&val, 0, MICRO_LIMB_BITS as u64);
                let a1 =
                    Utils::slice_u256(&val, MICRO_LIMB_BITS as u64, 2 * MICRO_LIMB_BITS as u64);
                let a2 =
                    Utils::slice_u256(&val, 2 * MICRO_LIMB_BITS as u64, 3 * MICRO_LIMB_BITS as u64);
                let a3 =
                    Utils::slice_u256(&val, 3 * MICRO_LIMB_BITS as u64, 4 * MICRO_LIMB_BITS as u64);
                let a4 =
                    Utils::slice_u256(&val, 4 * MICRO_LIMB_BITS as u64, 5 * MICRO_LIMB_BITS as u64);
                let top = a4.clone() << (MICRO_LIMB_BITS - (NUM_LIMB_BITS % MICRO_LIMB_BITS));
                [
                    P::ScalarField::from(a0),
                    P::ScalarField::from(a1),
                    P::ScalarField::from(a2),
                    P::ScalarField::from(a3),
                    P::ScalarField::from(a4),
                    P::ScalarField::from(top),
                ]
            };

        /*
         * @brief A method to split the top 50-bit limb into 4 14-bit limbs and 1 shifted limb for a more secure constraint
         * (plus there is 1 extra space for other constraints)
         *
         */
        let split_top_limb_into_micro_limbs = |limb: P::ScalarField,
                                               last_limb_bits: usize|
         -> [P::ScalarField; NUM_MICRO_LIMBS] {
            // static_assert(MICRO_LIMB_BITS == 14);
            let val: BigUint = limb.into();
            let a0 = Utils::slice_u256(&val, 0, MICRO_LIMB_BITS as u64);
            let a1 = Utils::slice_u256(&val, MICRO_LIMB_BITS as u64, 2 * MICRO_LIMB_BITS as u64);
            let a2 =
                Utils::slice_u256(&val, 2 * MICRO_LIMB_BITS as u64, 3 * MICRO_LIMB_BITS as u64);
            let a3 =
                Utils::slice_u256(&val, 3 * MICRO_LIMB_BITS as u64, 4 * MICRO_LIMB_BITS as u64);
            let a4 =
                Utils::slice_u256(&val, 3 * MICRO_LIMB_BITS as u64, 4 * MICRO_LIMB_BITS as u64)
                    << (MICRO_LIMB_BITS - (last_limb_bits % MICRO_LIMB_BITS));

            [
                P::ScalarField::from(a0),
                P::ScalarField::from(a1),
                P::ScalarField::from(a2),
                P::ScalarField::from(a3),
                P::ScalarField::from(a4),
                P::ScalarField::from(0u64),
            ]
        };

        /*
         * @brief A method for splitting the top 60-bit z limb into microlimbs (differs from the 68-bit limb by the shift in
         * the last limb)
         *
         */
        let split_top_z_limb_into_micro_limbs = |limb: P::ScalarField,
                                                 last_limb_bits: usize|
         -> [P::ScalarField; NUM_MICRO_LIMBS] {
            // static_assert(MICRO_LIMB_BITS == 14);
            let val: BigUint = limb.into();
            let a0 = Utils::slice_u256(&val, 0, MICRO_LIMB_BITS as u64);
            let a1 = Utils::slice_u256(&val, MICRO_LIMB_BITS as u64, 2 * MICRO_LIMB_BITS as u64);
            let a2 =
                Utils::slice_u256(&val, 2 * MICRO_LIMB_BITS as u64, 3 * MICRO_LIMB_BITS as u64);
            let a3 =
                Utils::slice_u256(&val, 3 * MICRO_LIMB_BITS as u64, 4 * MICRO_LIMB_BITS as u64);
            let a4 =
                Utils::slice_u256(&val, 4 * MICRO_LIMB_BITS as u64, 5 * MICRO_LIMB_BITS as u64);
            let a5 =
                Utils::slice_u256(&val, 4 * MICRO_LIMB_BITS as u64, 5 * MICRO_LIMB_BITS as u64)
                    << (MICRO_LIMB_BITS - (last_limb_bits % MICRO_LIMB_BITS));

            [
                P::ScalarField::from(a0),
                P::ScalarField::from(a1),
                P::ScalarField::from(a2),
                P::ScalarField::from(a3),
                P::ScalarField::from(a4),
                P::ScalarField::from(a5),
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
            for (i, slot) in out.iter_mut().enumerate() {
                let part = Utils::slice_u256(
                    &val,
                    (i * MICRO_LIMB_BITS) as u64,
                    ((i + 1) * MICRO_LIMB_BITS) as u64,
                );
                *slot = P::ScalarField::from(part);
            }
            out
        };

        // Helper: split base field element into NUM_BINARY_LIMBS limbs of NUM_LIMB_BITS, returned as ScalarField
        let split_fq_into_limbs = |x: P::BaseField| -> [P::ScalarField; NUM_BINARY_LIMBS] {
            let xb: BigUint = x.into();
            let mut out = [P::ScalarField::from(0u64); NUM_BINARY_LIMBS];

            for (i, limb) in out.iter_mut().enumerate() {
                let slice = Utils::slice_u256(
                    &xb,
                    (i * NUM_LIMB_BITS) as u64,
                    ((i + 1) * NUM_LIMB_BITS) as u64,
                );
                *limb = P::ScalarField::from(slice);
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

        let uint_p_x = &x_lo + (&x_hi << num_limb_shift);
        let uint_p_y = &y_lo + (&y_hi << num_limb_shift);
        let uint_z1 = z1_b.clone();
        let uint_z2 = z2_b.clone();

        // Construct Fq for op, P.x, P.y, z_1, z_2 for use in witness computation
        let base_op = P::BaseField::from(op_code);
        let base_p_x = P::BaseField::from(uint_p_x.clone());
        let base_p_y = P::BaseField::from(uint_p_y.clone());
        let base_z_1 = P::BaseField::from(uint_z1.clone());
        let base_z_2 = P::BaseField::from(uint_z2.clone());

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
        let modulus_big: BigUint = P::BaseField::MODULUS.into();

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
        debug_assert!(
            Utils::slice_u256(&low_wide_relation_limb.into(), 0, 2 * NUM_LIMB_BITS as u64)
                .is_zero()
        );

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
        debug_assert!(
            Utils::slice_u256(&high_wide_relation_limb.into(), 0, 2 * NUM_LIMB_BITS as u64)
                .is_zero()
        );

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
        let mut input = AccumulationInput::new(ultra_op.clone());
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
        for (i, wire) in self.wires.iter().enumerate() {
            debug_assert!(
                wire.len() == self.num_gates,
                "wire {i} len {} != {}",
                wire.len(),
                self.num_gates
            );
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(usize)]
#[derive(Clone, Copy, Debug)]
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
    pub const fn as_usize(&self) -> usize {
        *self as usize
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
    fn new(ultra_op: UltraOp<P>) -> Self {
        let zero = P::ScalarField::zero();
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

pub fn construct_pk_from_builder<C: HonkCurve<TranscriptFieldType>>(
    circuit: TranslatorBuilder<C>,
) -> Polynomials<C::ScalarField, TranslatorFlavour> {
    let mini_circuit_dyadic_size = TranslatorFlavour::MINI_CIRCUIT_SIZE;
    // The actual circuit size is several times bigger than the trace in the circuit, because we use interleaving
    // to bring the degree of relations down, while extending the length.

    let dyadic_circuit_size = mini_circuit_dyadic_size * TranslatorFlavour::INTERLEAVING_GROUP_SIZE;
    // Check that the Translator Circuit does not exceed the fixed upper bound, the current value amounts to
    // a number of EccOps sufficient for 10 rounds of folding (so 20 circuits)
    if circuit.num_gates > TranslatorFlavour::MINI_CIRCUIT_SIZE {
        panic!(
            "The Translator circuit size has exceeded the fixed upper bound ({} > {})",
            circuit.num_gates,
            TranslatorFlavour::MINI_CIRCUIT_SIZE
        );
    }

    let circuit_size = 1 << TranslatorFlavour::CONST_TRANSLATOR_LOG_N;
    let mut polys = Polynomials::<C::ScalarField, TranslatorFlavour>::new(circuit_size);
    for poly in polys.witness.to_be_shifted_mut() {
        poly.resize(mini_circuit_dyadic_size, C::ScalarField::zero());
    }
    for poly in polys.witness.get_ordered_range_constraints_mut() {
        poly.resize(circuit_size, C::ScalarField::zero());
    }
    polys
        .precomputed
        .lagrange_first_mut()
        .resize(1, C::ScalarField::zero());
    polys
        .precomputed
        .lagrange_result_row_mut()
        .resize(3, C::ScalarField::zero());
    polys
        .precomputed
        .lagrange_even_in_minicircuit_mut()
        .resize(mini_circuit_dyadic_size, C::ScalarField::zero());
    polys
        .precomputed
        .lagrange_odd_in_minicircuit_mut()
        .resize(mini_circuit_dyadic_size, C::ScalarField::zero());

    // Populate the wire polynomials from the wire vectors in the circuit
    for (wire_poly, wire_indices) in polys
        .witness
        .get_wires_mut()
        .iter_mut()
        .zip(circuit.wires.iter())
    {
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1383)
        for i in 0..circuit.num_gates {
            let var_idx = wire_indices[i] as usize;
            let value = circuit.variables[var_idx];
            wire_poly[i] = value;
        }
    }

    // First and last lagrange polynomials (in the full circuit size)
    polys.precomputed.lagrange_first_mut()[0] = C::ScalarField::one();
    polys.precomputed.lagrange_real_last_mut()[dyadic_circuit_size - 1] = C::ScalarField::one();
    polys.precomputed.lagrange_last_mut()[dyadic_circuit_size - 1] = C::ScalarField::one();

    // Construct polynomials with odd and even indices set to 1 up to the minicircuit margin + lagrange
    // polynomials at second and second to last indices in the minicircuit
    {
        for i in (2..mini_circuit_dyadic_size).step_by(2) {
            polys.precomputed.lagrange_even_in_minicircuit_mut()[i] = C::ScalarField::one();
            polys.precomputed.lagrange_odd_in_minicircuit_mut()[i + 1] = C::ScalarField::one();
        }
        polys.precomputed.lagrange_result_row_mut()[2] = C::ScalarField::one();
        polys.precomputed.lagrange_last_in_minicircuit_mut()[mini_circuit_dyadic_size - 1] =
            C::ScalarField::one();
    }
    // Construct the extra range constraint numerator which contains all the additional values in the ordered range
    // constraints not present in the interleaved polynomials
    // NB this will always have a fixed size unless we change the allowed range
    {
        let extra_range_constraint_numerator = polys
            .precomputed
            .ordered_extra_range_constraints_numerator_mut();

        const MAX_VALUE: u32 = (1u32 << MICRO_LIMB_BITS) - 1;

        // Calculate how many elements there are in the sequence MAX_VALUE, MAX_VALUE - 3,...,0
        let sort_step = TranslatorFlavour::SORT_STEP as u32;
        let sorted_elements_count =
            (MAX_VALUE / sort_step) as usize + 1 + if MAX_VALUE % sort_step == 0 { 0 } else { 1 };

        // Check that we can fit every element in the polynomial
        debug_assert!(
            (TranslatorFlavour::NUM_INTERLEAVED_WIRES + 1) * sorted_elements_count
                < extra_range_constraint_numerator.len()
        );

        let mut sorted_elements = vec![0usize; sorted_elements_count];

        // Calculate the sequence in integers
        sorted_elements[0] = MAX_VALUE as usize;
        for (i, elem) in sorted_elements.iter_mut().enumerate().skip(1) {
            *elem = (sorted_elements_count - 1 - i) * TranslatorFlavour::SORT_STEP;
        }

        // AZTEC TODO(#756): can be parallelized further. This will use at most 5 threads
        // Fill polynomials with a sequence, where each element is repeated NUM_INTERLEAVED_WIRES+1 times
        let interleaved_span = TranslatorFlavour::NUM_INTERLEAVED_WIRES + 1;
        for shift in 0..interleaved_span {
            for i in 0..sorted_elements_count {
                extra_range_constraint_numerator[shift + i * interleaved_span] =
                    C::ScalarField::from(sorted_elements[i] as u64);
            }
        }

        // Construct the polynomials resulted from interleaving the small polynomials in each group
        {
            // The vector of groups of polynomials to be interleaved
            let interleaved = polys.witness.get_groups_to_be_interleaved().to_owned();
            // Resulting interleaved polynomials
            let mut targets = [
                Polynomial::<C::ScalarField>::new_zero(circuit_size),
                Polynomial::<C::ScalarField>::new_zero(circuit_size),
                Polynomial::<C::ScalarField>::new_zero(circuit_size),
                Polynomial::<C::ScalarField>::new_zero(circuit_size),
            ];

            let num_polys_in_group = interleaved[0].len();
            debug_assert!(num_polys_in_group == TranslatorFlavour::INTERLEAVING_GROUP_SIZE);

            // Targets have to be full-sized proving_key->polynomials. We can compute the mini circuit size from them by
            // dividing by the number of polynomials in the group
            let mini_circuit_size = targets[0].len() / num_polys_in_group;
            debug_assert!(mini_circuit_size * num_polys_in_group == targets[0].len());

            for index in 0..(interleaved.len() * num_polys_in_group) {
                // Get the index of the interleaved polynomial
                let i = index / interleaved[0].len();
                // Get the index of the original polynomial
                let j = index % interleaved[0].len();
                let group = &interleaved[i];

                // Copy into appropriate position in the interleaved polynomial
                // We offset by start_index() as the first 0 is not physically represented for shiftable values
                for k in 1..group[j].len() {
                    // We have an offset here
                    targets[i][k * num_polys_in_group + j] = group[j][k];
                }
            }

            for (src, des) in targets.iter().zip(
                polys
                    .witness
                    .get_interleaved_range_constraints_mut()
                    .iter_mut(),
            ) {
                *des = src.to_owned();
            }
        }
        // Construct the ordered polynomials, containing the values of the interleaved polynomials + enough values to
        // bridge the range from 0 to 3 (3 is the maximum allowed range defined by the range constraint).
        {
            // Get constants
            let sort_step = TranslatorFlavour::SORT_STEP;
            let num_interleaved_wires = TranslatorFlavour::NUM_INTERLEAVED_WIRES;

            let mini_num_disabled_rows_in_sumcheck = 0usize;
            let full_num_disabled_rows_in_sumcheck = 0usize;
            let real_circuit_size = dyadic_circuit_size - full_num_disabled_rows_in_sumcheck;

            // The value we have to end polynomials with, 2¹⁴ - 1
            let max_value: u32 = (1u32 << MICRO_LIMB_BITS) - 1;

            // Number of elements needed to go from 0 to MAX_VALUE with our step
            let sorted_elements_count = (max_value as usize / sort_step)
                + 1
                + if (max_value as usize) % sort_step == 0 {
                    0
                } else {
                    1
                };

            // Check if we can construct these polynomials
            debug_assert!((num_interleaved_wires + 1) * sorted_elements_count < real_circuit_size);

            // First use integers (easier to sort)
            let mut sorted_elements = vec![0usize; sorted_elements_count];

            // Fill with necessary steps
            sorted_elements[0] = max_value as usize;
            for (i, elem) in sorted_elements.iter_mut().enumerate().skip(1) {
                *elem = (sorted_elements_count - 1 - i) * sort_step;
            }

            let mut extra_denominator_uint = vec![0usize; real_circuit_size];

            // Given the polynomials in group_i, transfer their elements, sorted in non-descending order, into the corresponding
            // ordered_range_constraint_i up to the given capacity and the remaining elements to the last range constraint.
            // Sorting is done by converting the elements to uint for efficiency.
            for i in 0..num_interleaved_wires {
                let group = polys.witness.get_groups_to_be_interleaved()[i];
                let mut ordered_vectors_uint = vec![0u32; real_circuit_size];

                // Calculate how much space there is for values from the group polynomials given we also need to append the
                // additional steps
                let free_space_before_runway = real_circuit_size - sorted_elements_count;

                // Calculate the starting index of this group's overflowing elements in the extra denominator polynomial
                let mut extra_denominator_offset = i * sorted_elements_count;

                // Go through each polynomial in the interleaved group
                for (j, group_el) in group
                    .iter()
                    .enumerate()
                    .take(TranslatorFlavour::INTERLEAVING_GROUP_SIZE)
                {
                    // Calculate the offset in the target vector
                    let current_offset =
                        j * (mini_circuit_dyadic_size - mini_num_disabled_rows_in_sumcheck);

                    let start = 0usize;
                    let end = group_el.len() - mini_num_disabled_rows_in_sumcheck;

                    // For each element in the polynomial
                    for k in start..end {
                        let val_big = group_el[k].into_bigint();
                        let limb0 = val_big.as_ref()[0] as u32;

                        // Put it it the target polynomial
                        if (current_offset + k) < free_space_before_runway {
                            ordered_vectors_uint[current_offset + k] = limb0;

                        // Or in the extra one if there is no space left
                        } else {
                            extra_denominator_uint[extra_denominator_offset] = limb0 as usize;
                            extra_denominator_offset += 1;
                        }
                    }
                }
                // Advance the iterator past the last written element in the range constraint polynomial and complete it with
                // sorted steps
                for (dst, src) in ordered_vectors_uint
                    [free_space_before_runway..free_space_before_runway + sorted_elements_count]
                    .iter_mut()
                    .zip(sorted_elements.iter())
                {
                    *dst = *src as u32;
                }

                // Sort the polynomial in nondescending order. We sort using the size_t vector for 2 reasons:
                // 1. It is faster to sort size_t
                // 2. Comparison operators for finite fields are operating on internal form, so we'd have to convert them
                // from Montgomery
                ordered_vectors_uint.sort_unstable();
                debug_assert!(ordered_vectors_uint.len() == real_circuit_size);
                // Copy the values into the actual polynomial
                for (idx, v) in ordered_vectors_uint.iter().enumerate() {
                    polys.witness.get_ordered_range_constraints_mut()[i][idx] =
                        C::ScalarField::from(*v as u64);
                }
            }

            // Construct the first 4 polynomials

            // Advance the iterator into the extra range constraint past the last written element
            let extra_offset = num_interleaved_wires * sorted_elements_count;

            // Add steps to the extra denominator polynomial to fill it
            for (dst, src) in extra_denominator_uint
                [extra_offset..extra_offset + sorted_elements_count]
                .iter_mut()
                .zip(sorted_elements.iter())
            {
                *dst = *src;
            }

            debug_assert!(extra_denominator_uint.len() == real_circuit_size);
            // Sort it

            extra_denominator_uint.sort_unstable();
            debug_assert!(extra_denominator_uint.len() == real_circuit_size);

            // Copy the values into the actual polynomial
            let poly4 = polys.witness.ordered_range_constraints_4_mut();
            for (i, v) in extra_denominator_uint.iter().enumerate() {
                poly4[i] = C::ScalarField::from(*v as u64);
            }
        }
    }

    polys
}
