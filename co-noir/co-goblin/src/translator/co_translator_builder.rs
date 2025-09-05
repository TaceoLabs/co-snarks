use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::eccvm::NUM_LIMB_BITS_IN_FIELD_SIMULATION;
use co_builder::eccvm::co_ecc_op_queue::CoECCOpQueue;
use co_builder::eccvm::co_ecc_op_queue::CoUltraOp;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::polynomials::polynomial::Polynomial;
use co_noir_common::utils::Utils;
use co_noir_common::{
    MICRO_LIMB_BITS, NUM_BINARY_LIMBS, NUM_LAST_LIMB_BITS, NUM_MICRO_LIMBS, NUM_QUOTIENT_BITS,
    NUM_RELATION_WIDE_LIMBS, NUM_Z_BITS, NUM_Z_LIMBS,
};
use co_ultrahonk::types::Polynomials;
use goblin::prelude::WireIds;
use itertools::Itertools;
use num_bigint::BigUint;
use std::str::FromStr;

const NUM_WIRES: usize = 81;
const ZERO_IDX: usize = 0;

pub struct CoTranslatorBuilder<C: CurveGroup, T: NoirWitnessExtensionProtocol<C::ScalarField>>
where
    C::BaseField: PrimeField,
{
    pub variables: Vec<T::AcvmType>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub real_variable_index: Vec<u32>,
    pub(crate) real_variable_tags: Vec<u32>,
    batching_challenge_v: C::BaseField,
    evaluation_input_x: C::BaseField,
    wires: [Vec<u32>; NUM_WIRES],
    num_gates: usize,
}
impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>> Default
    for CoTranslatorBuilder<C, T>
{
    fn default() -> Self {
        Self::new()
    }
}
impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
    CoTranslatorBuilder<C, T>
{
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
            batching_challenge_v: C::BaseField::zero(),
            evaluation_input_x: C::BaseField::zero(),
            wires: std::array::from_fn(|_| Vec::new()),
            num_gates: 0,
        }
    }
    pub(crate) fn add_variable(&mut self, value: T::AcvmType) -> u32 {
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
        batching_challenge_v: C::BaseField,
        evaluation_input_x: C::BaseField,
        ecc_op_queue: &mut CoECCOpQueue<T, C>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        const NUM_LIMB_BITS: usize = 68;
        self.evaluation_input_x = evaluation_input_x;
        self.batching_challenge_v = batching_challenge_v;
        let ultra_ops = ecc_op_queue.get_ultra_ops();
        let mut accumulator_trace: Vec<T::OtherAcvmType<C>> =
            Vec::with_capacity(ultra_ops.len() - 1);
        let mut current_accumulator = T::OtherAcvmType::<C>::default();
        if ultra_ops.is_empty() {
            return Ok(());
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

        let mut batch_convert = Vec::with_capacity(ultra_ops.len() * 7);
        for ultra_op in ultra_ops.iter().skip(1).rev() {
            batch_convert.push(ultra_op.x_hi);
            batch_convert.push(ultra_op.x_lo);
            batch_convert.push(ultra_op.y_hi);
            batch_convert.push(ultra_op.y_lo);
            batch_convert.push(ultra_op.z_1);
            batch_convert.push(ultra_op.z_2);
            batch_convert.push(ultra_op.return_is_infinity);
        }
        // Adjust this constant if defined elsewhere in the crate.
        let shift_bits = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION;
        let shift: C::BaseField = (BigUint::one() << shift_bits).into();
        let converted = driver.convert_fields_back::<C>(&batch_convert)?;
        for (i, ultra_op) in ultra_ops.iter().skip(1).rev().enumerate() {
            T::mul_assign_with_public_other(&mut current_accumulator, evaluation_input_x);
            let x_hi = converted[i * 7];
            let x_lo = converted[i * 7 + 1];
            let y_hi = converted[i * 7 + 2];
            let y_lo = converted[i * 7 + 3];
            let z_1 = converted[i * 7 + 4];
            let z_2 = converted[i * 7 + 5];
            let is_infinity = converted[i * 7 + 6];
            let (x_256, y_256) = {
                let mut x_256 = x_hi;
                T::mul_assign_with_public_other(&mut x_256, shift);
                driver.add_assign_other(&mut x_256, x_lo);

                let mut y_256 = y_hi;
                T::mul_assign_with_public_other(&mut y_256, shift);
                driver.add_assign_other(&mut y_256, y_lo);

                (x_256, y_256)
            };
            let negated = driver.sub_other(C::BaseField::one().into(), is_infinity);

            //TACEO TODO: Batch this
            let [x_256, y_256] = driver
                .mul_many_other(&[x_256, y_256], &[negated, negated])?
                .try_into()
                .expect("We should have two values");

            let mut tmp = z_2;
            T::mul_assign_with_public_other(&mut tmp, batching_challenge_v);
            driver.add_assign_other(&mut tmp, z_1);
            T::mul_assign_with_public_other(&mut tmp, batching_challenge_v);
            driver.add_assign_other(&mut tmp, y_256);
            T::mul_assign_with_public_other(&mut tmp, batching_challenge_v);
            driver.add_assign_other(&mut tmp, x_256);
            T::mul_assign_with_public_other(&mut tmp, batching_challenge_v);
            let op_code_value: C::BaseField = C::BaseField::from(ultra_op.op_code.value());
            driver.add_assign_with_public_other(op_code_value, &mut tmp);
            driver.add_assign_other(&mut current_accumulator, tmp);
            accumulator_trace.push(current_accumulator);
        }

        let mut converted_ultra_ops = converted.chunks_exact(6).collect_vec();
        converted_ultra_ops.reverse();
        // We don't care about the last value since we'll recompute it during witness generation anyway
        accumulator_trace.pop();

        let negative_modulus_limbs: [C::ScalarField; 5] = [
            C::ScalarField::from_str("51007615349848998585")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            C::ScalarField::from_str("187243884991886189399")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            C::ScalarField::from_str("292141664167738113703")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            C::ScalarField::from_str("295147053861416594661")
                .unwrap_or_else(|_| panic!("invalid field element literal")),
            C::ScalarField::from_str(
                "21888242871839275222246405745257275088400417643534245024707370478506390782651",
            )
            .unwrap_or_else(|_| panic!("invalid field element literal")),
        ];
        let mut split_wide_limb_into_2_limbs_many = Vec::with_capacity(6 * (ultra_ops.len() - 1));
        for ultra_op in ultra_ops.iter().skip(1) {
            split_wide_limb_into_2_limbs_many.push(ultra_op.x_lo);
            split_wide_limb_into_2_limbs_many.push(ultra_op.x_hi);
            split_wide_limb_into_2_limbs_many.push(ultra_op.y_lo);
            split_wide_limb_into_2_limbs_many.push(ultra_op.y_hi);
            split_wide_limb_into_2_limbs_many.push(ultra_op.z_1);
            split_wide_limb_into_2_limbs_many.push(ultra_op.z_2);
        }
        let split_wide_limb_into_2_limbs_res = if split_wide_limb_into_2_limbs_many
            .iter()
            .any(|v| T::is_shared(v))
        {
            let inp: Vec<_> = split_wide_limb_into_2_limbs_many
                .iter()
                .map(|y| driver.get_as_shared(y))
                .collect();
            driver
                .decompose_arithmetic_many(&inp, 2 * NUM_LIMB_BITS, NUM_LIMB_BITS)?
                .into_iter()
                .map(|arr| arr.into_iter().map(T::AcvmType::from).collect_vec())
                .collect()
        } else {
            let mut res = Vec::with_capacity(split_wide_limb_into_2_limbs_many.len() * 2);
            for val in split_wide_limb_into_2_limbs_many.iter() {
                let val: BigUint = T::get_public(val)
                    .expect("We checked that it is public")
                    .into();
                let lo = Utils::slice_u256(&val, 0, NUM_LIMB_BITS as u64);
                let hi = Utils::slice_u256(&val, NUM_LIMB_BITS as u64, 2 * NUM_LIMB_BITS as u64);
                res.push(vec![
                    T::AcvmType::from(C::ScalarField::from(lo)),
                    T::AcvmType::from(C::ScalarField::from(hi)),
                ]);
            }
            res
        };
        let split_wide_limb_into_2_limbs_res = split_wide_limb_into_2_limbs_res
            .chunks_exact(6)
            .collect_vec();

        let mut accumulator_trace_res = if accumulator_trace.iter().any(|v| T::is_shared_other(v)) {
            let inp: Vec<_> = accumulator_trace
                .iter()
                .map(|y| driver.get_as_shared_other(y))
                .collect();
            driver.decompose_arithmetic_other_to_acvm_many(
                &inp,
                C::BaseField::MODULUS_BIT_SIZE as usize,
                NUM_LIMB_BITS,
            )?
        } else {
            let mut accumulator_trace_res =
                Vec::with_capacity(accumulator_trace.len() * NUM_BINARY_LIMBS);
            for x in accumulator_trace.iter() {
                let val: BigUint = T::get_public_other(x)
                    .expect("We checked that it is public")
                    .into();
                let mut out = [T::AcvmType::default(); NUM_BINARY_LIMBS];
                for (i, slot) in out.iter_mut().enumerate() {
                    let part = Utils::slice_u256(
                        &val,
                        (i * NUM_LIMB_BITS) as u64,
                        ((i + 1) * NUM_LIMB_BITS) as u64,
                    );
                    *slot = T::AcvmType::from(C::ScalarField::from(part));
                }
                accumulator_trace_res.push(out.to_vec());
            }
            accumulator_trace_res
        };

        // Generate witness values from all the UltraOps
        for (i, ultra_op) in ultra_ops.iter().skip(1).enumerate() {
            let mut previous_accumulator = T::OtherAcvmType::default();
            let mut previous_accumulator_limbs = [T::AcvmType::default(); NUM_BINARY_LIMBS];
            // Pop the last value from accumulator trace and use it as previous accumulator
            if let Some(last) = accumulator_trace.pop() {
                previous_accumulator = last;
                previous_accumulator_limbs = accumulator_trace_res
                    .pop()
                    .expect("We should have the limbs for the accumulator")
                    .try_into()
                    .expect("We should have the correct number of limbs");
            }
            // Compute witness values
            let one_accumulation_step = self.generate_witness_values(
                ultra_op,
                previous_accumulator,
                batching_challenge_v,
                evaluation_input_x,
                &negative_modulus_limbs,
                split_wide_limb_into_2_limbs_res[i],
                &previous_accumulator_limbs,
                converted_ultra_ops[i],
                driver,
            )?;

            // And put them into the wires
            self.create_accumulation_gate(one_accumulation_step);
        }
        Ok(())
    }

    fn populate_wires_from_ultra_op(&mut self, ultra_op: &CoUltraOp<T, C>) {
        let idx = self.add_variable(T::AcvmType::from(C::ScalarField::from(
            ultra_op.op_code.value(),
        )));
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
        first: T::AcvmType,
        second: T::AcvmType,
    ) {
        let first_idx = self.add_variable(first);
        let second_idx = self.add_variable(second);
        let wire = &mut self.wires[wire_index.as_usize()];
        wire.push(first_idx);
        wire.push(second_idx);
    }

    #[expect(clippy::too_many_arguments)]
    fn generate_witness_values(
        &self,
        ultra_op: &CoUltraOp<T, C>,
        previous_accumulator: T::OtherAcvmType<C>,
        batching_challenge_v: C::BaseField,
        evaluation_input_x: C::BaseField,
        negative_modulus_limbs: &[C::ScalarField; 5],
        split_wide_limb_into_2_limbs_res: &[Vec<T::AcvmType>],
        previous_accumulator_limbs: &[T::AcvmType; NUM_BINARY_LIMBS],
        converted_ultra_ops: &[T::OtherAcvmType<C>],
        driver: &mut T,
    ) -> eyre::Result<CoAccumulationInput<T, C>> {
        const NUM_LIMB_BITS: usize = 68;
        let shift_1: C::ScalarField = (BigUint::one() << NUM_LIMB_BITS).into();
        let shift_2 = BigUint::one() << (NUM_LIMB_BITS << 1);

        // Precomputed inverse to easily divide by the shift by 2 limbs
        let mut shift_2_inverse: C::ScalarField = shift_2.into();
        shift_2_inverse = shift_2_inverse.inverse().expect(
            "Failed to compute inverse of shift_2, this should not happen in a valid circuit",
        );

        // All parameters are well-described in the header, this is just for convenience
        const TOP_STANDARD_MICROLIMB_BITS: usize = NUM_LAST_LIMB_BITS % MICRO_LIMB_BITS;
        const TOP_Z_MICROLIMB_BITS: usize = (NUM_Z_BITS % NUM_LIMB_BITS) % MICRO_LIMB_BITS;
        const TOP_QUOTIENT_MICROLIMB_BITS: usize =
            (NUM_QUOTIENT_BITS % NUM_LIMB_BITS) % MICRO_LIMB_BITS;

        /*
         * @brief A method to split a full 68-bit limb into 5 14-bit limb and 1 shifted limb for a more secure constraint
         *
         */
        // TACEO TODO: this calculates these values: p_x_limbs[i] p_y_limbs[i] z_1_limbs[i] z_2_limbs[i] remainder_limbs[i] quotient_limbs[i] and can be batched
        let split_standard_limb_into_micro_limbs = |limb: T::AcvmType,
                                                    driver: &mut T|
         -> eyre::Result<
            [T::AcvmType; NUM_MICRO_LIMBS],
        > {
            if T::is_shared(&limb) {
                let result = driver.decompose_arithmetic(
                    T::get_shared(&limb).expect("We checked that it is shared"),
                    68,
                    MICRO_LIMB_BITS,
                )?;
                {
                    debug_assert!(result.len() >= NUM_MICRO_LIMBS);
                    let mut arr = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                    for (i, item) in result.into_iter().take(NUM_MICRO_LIMBS).enumerate() {
                        arr[i] = T::AcvmType::from(item);
                    }
                    arr[NUM_MICRO_LIMBS - 1] = driver.mul_with_public(
                        C::ScalarField::from(
                            1u64 << (MICRO_LIMB_BITS - (NUM_LIMB_BITS % MICRO_LIMB_BITS)),
                        ),
                        arr[NUM_MICRO_LIMBS - 2],
                    );
                    Ok(arr)
                }
            } else {
                let val: BigUint = T::get_public(&limb)
                    .expect("We checked that it is public")
                    .into();
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
                Ok([
                    T::AcvmType::from(C::ScalarField::from(a0)),
                    T::AcvmType::from(C::ScalarField::from(a1)),
                    T::AcvmType::from(C::ScalarField::from(a2)),
                    T::AcvmType::from(C::ScalarField::from(a3)),
                    T::AcvmType::from(C::ScalarField::from(a4)),
                    T::AcvmType::from(C::ScalarField::from(top)),
                ])
            }
        };

        /*
         * @brief A method to split the top 50-bit limb into 4 14-bit limbs and 1 shifted limb for a more secure constraint
         * (plus there is 1 extra space for other constraints)
         *
         */
        // TACEO TODO: this calculates these values: p_x_limbs[LAST_LIMB_INDEX] p_y_limbs[LAST_LIMB_INDEX] remainder_limbs[LAST_LIMB_INDEX] quotient_limbs[LAST_LIMB_INDEX] and can be batched
        let split_top_limb_into_micro_limbs =
            |limb: T::AcvmType,
             last_limb_bits: usize,
             driver: &mut T|
             -> eyre::Result<[T::AcvmType; NUM_MICRO_LIMBS]> {
                if T::is_shared(&limb) {
                    let result = driver.decompose_arithmetic(
                        T::get_shared(&limb).expect("We checked that it is shared"),
                        50,
                        MICRO_LIMB_BITS,
                    )?;
                    {
                        debug_assert!(result.len() >= NUM_MICRO_LIMBS - 1);
                        let mut arr = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                        for (i, item) in result.into_iter().take(NUM_MICRO_LIMBS - 1).enumerate() {
                            arr[i] = T::AcvmType::from(item);
                        }
                        arr[NUM_MICRO_LIMBS - 2] = driver.mul_with_public(
                            C::ScalarField::from(
                                1u64 << (MICRO_LIMB_BITS - (last_limb_bits % MICRO_LIMB_BITS)),
                            ),
                            arr[NUM_MICRO_LIMBS - 3],
                        );
                        Ok(arr)
                    }
                } else {
                    let val: BigUint = T::get_public(&limb)
                        .expect("We checked that it is public")
                        .into();
                    let a0 = Utils::slice_u256(&val, 0, MICRO_LIMB_BITS as u64);
                    let a1 =
                        Utils::slice_u256(&val, MICRO_LIMB_BITS as u64, 2 * MICRO_LIMB_BITS as u64);
                    let a2 = Utils::slice_u256(
                        &val,
                        2 * MICRO_LIMB_BITS as u64,
                        3 * MICRO_LIMB_BITS as u64,
                    );
                    let a3 = Utils::slice_u256(
                        &val,
                        3 * MICRO_LIMB_BITS as u64,
                        4 * MICRO_LIMB_BITS as u64,
                    );
                    let a4 = a3.clone() << (MICRO_LIMB_BITS - (last_limb_bits % MICRO_LIMB_BITS));
                    Ok([
                        T::AcvmType::from(C::ScalarField::from(a0)),
                        T::AcvmType::from(C::ScalarField::from(a1)),
                        T::AcvmType::from(C::ScalarField::from(a2)),
                        T::AcvmType::from(C::ScalarField::from(a3)),
                        T::AcvmType::from(C::ScalarField::from(a4)),
                        T::AcvmType::default(),
                    ])
                }
            };

        /*
         * @brief A method for splitting the top 60-bit z limb into microlimbs (differs from the 68-bit limb by the shift in
         * the last limb)
         *
         */
        // TACEO TODO: this calculates these values: z_1_limbs = split_wide_limb_into_2_limbs(ultra_op.z_1, driver)?; z_2_limbs = split_wide_limb_into_2_limbs(ultra_op.z_2, driver)?; and can be batched ouside the loop
        let split_top_z_limb_into_micro_limbs = |limb: T::AcvmType,
                                                 last_limb_bits: usize,
                                                 driver: &mut T|
         -> eyre::Result<
            [T::AcvmType; NUM_MICRO_LIMBS],
        > {
            if T::is_shared(&limb) {
                let result = driver.decompose_arithmetic(
                    T::get_shared(&limb).expect("We checked that it is shared"),
                    60,
                    MICRO_LIMB_BITS,
                )?;
                {
                    debug_assert!(result.len() >= NUM_MICRO_LIMBS);
                    let mut arr = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                    for (i, item) in result.into_iter().take(NUM_MICRO_LIMBS - 1).enumerate() {
                        arr[i] = T::AcvmType::from(item);
                    }
                    arr[NUM_MICRO_LIMBS - 1] = driver.mul_with_public(
                        C::ScalarField::from(
                            1u64 << (MICRO_LIMB_BITS - (last_limb_bits % MICRO_LIMB_BITS)),
                        ),
                        arr[NUM_MICRO_LIMBS - 2],
                    );
                    Ok(arr)
                }
            } else {
                let val: BigUint = T::get_public(&limb)
                    .expect("We checked that it is public")
                    .into();
                let a0 = Utils::slice_u256(&val, 0, MICRO_LIMB_BITS as u64);
                let a1 =
                    Utils::slice_u256(&val, MICRO_LIMB_BITS as u64, 2 * MICRO_LIMB_BITS as u64);
                let a2 =
                    Utils::slice_u256(&val, 2 * MICRO_LIMB_BITS as u64, 3 * MICRO_LIMB_BITS as u64);
                let a3 =
                    Utils::slice_u256(&val, 3 * MICRO_LIMB_BITS as u64, 4 * MICRO_LIMB_BITS as u64);
                let a4 =
                    Utils::slice_u256(&val, 4 * MICRO_LIMB_BITS as u64, 5 * MICRO_LIMB_BITS as u64);
                let a5 =
                    Utils::slice_u256(&val, 4 * MICRO_LIMB_BITS as u64, 5 * MICRO_LIMB_BITS as u64)
                        << (MICRO_LIMB_BITS - (last_limb_bits % MICRO_LIMB_BITS));
                Ok([
                    T::AcvmType::from(C::ScalarField::from(a0)),
                    T::AcvmType::from(C::ScalarField::from(a1)),
                    T::AcvmType::from(C::ScalarField::from(a2)),
                    T::AcvmType::from(C::ScalarField::from(a3)),
                    T::AcvmType::from(C::ScalarField::from(a4)),
                    T::AcvmType::from(C::ScalarField::from(a5)),
                ])
            }
        };

        /*
         * @brief Split a 72-bit relation limb into 6 14-bit limbs (we can allow the slack here, since we only need to
         * ensure non-overflow of the modulus)
         *
         */
        // TACEO TODO: this calculates these values:low_wide_relation_limb_divided high_wide_relation_limb_divided and can be batched
        let split_relation_limb_into_micro_limbs =
            |limbs: (T::AcvmType, T::AcvmType),
             driver: &mut T|
             -> eyre::Result<[[T::AcvmType; NUM_MICRO_LIMBS]; 2]> {
                if T::is_shared(&limbs.0) && T::is_shared(&limbs.1) {
                    let result = driver.decompose_arithmetic_many(
                        &[
                            T::get_shared(&limbs.0).expect("We checked that it is shared"),
                            T::get_shared(&limbs.1).expect("We checked that it is shared"),
                        ],
                        72,
                        MICRO_LIMB_BITS,
                    )?;
                    {
                        debug_assert_eq!(result.len(), 2);
                        debug_assert!(result[0].len() >= NUM_MICRO_LIMBS);
                        debug_assert!(result[1].len() >= NUM_MICRO_LIMBS);

                        let mut arr1 = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                        let mut arr2 = [T::AcvmType::default(); NUM_MICRO_LIMBS];

                        for (i, item) in result[0].iter().take(NUM_MICRO_LIMBS).enumerate() {
                            arr1[i] = T::AcvmType::from(item.to_owned());
                        }

                        for (i, item) in result[1].iter().take(NUM_MICRO_LIMBS).enumerate() {
                            arr2[i] = T::AcvmType::from(item.to_owned());
                        }

                        Ok([arr1, arr2])
                    }
                } else if T::is_shared(&limbs.0) && !T::is_shared(&limbs.1) {
                    let result = driver.decompose_arithmetic(
                        T::get_shared(&limbs.0).expect("We checked that it is shared"),
                        72,
                        MICRO_LIMB_BITS,
                    )?;
                    {
                        debug_assert!(result.len() >= NUM_MICRO_LIMBS);
                        let mut arr1 = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                        for (i, item) in result.into_iter().take(NUM_MICRO_LIMBS).enumerate() {
                            arr1[i] = T::AcvmType::from(item);
                        }
                        let val: BigUint = T::get_public(&limbs.1)
                            .expect("We checked that it is public")
                            .into();
                        let mut arr2 = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                        for (i, slot) in arr2.iter_mut().enumerate() {
                            let part = Utils::slice_u256(
                                &val,
                                (i * MICRO_LIMB_BITS) as u64,
                                ((i + 1) * MICRO_LIMB_BITS) as u64,
                            );
                            *slot = T::AcvmType::from(C::ScalarField::from(part));
                        }
                        Ok([arr1, arr2])
                    }
                } else if !T::is_shared(&limbs.0) && T::is_shared(&limbs.1) {
                    let result = driver.decompose_arithmetic(
                        T::get_shared(&limbs.1).expect("We checked that it is shared"),
                        72,
                        MICRO_LIMB_BITS,
                    )?;
                    {
                        debug_assert!(result.len() >= NUM_MICRO_LIMBS);
                        let mut arr2 = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                        for (i, item) in result.into_iter().take(NUM_MICRO_LIMBS).enumerate() {
                            arr2[i] = T::AcvmType::from(item);
                        }
                        let val: BigUint = T::get_public(&limbs.0)
                            .expect("We checked that it is public")
                            .into();
                        let mut arr1 = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                        for (i, slot) in arr1.iter_mut().enumerate() {
                            let part = Utils::slice_u256(
                                &val,
                                (i * MICRO_LIMB_BITS) as u64,
                                ((i + 1) * MICRO_LIMB_BITS) as u64,
                            );
                            *slot = T::AcvmType::from(C::ScalarField::from(part));
                        }
                        Ok([arr1, arr2])
                    }
                } else {
                    let val: BigUint = T::get_public(&limbs.0)
                        .expect("We checked that it is public")
                        .into();
                    let mut arr1 = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                    for (i, slot) in arr1.iter_mut().enumerate() {
                        let part = Utils::slice_u256(
                            &val,
                            (i * MICRO_LIMB_BITS) as u64,
                            ((i + 1) * MICRO_LIMB_BITS) as u64,
                        );
                        *slot = T::AcvmType::from(C::ScalarField::from(part));
                    }
                    let val: BigUint = T::get_public(&limbs.1)
                        .expect("We checked that it is public")
                        .into();
                    let mut arr2 = [T::AcvmType::default(); NUM_MICRO_LIMBS];
                    for (i, slot) in arr2.iter_mut().enumerate() {
                        let part = Utils::slice_u256(
                            &val,
                            (i * MICRO_LIMB_BITS) as u64,
                            ((i + 1) * MICRO_LIMB_BITS) as u64,
                        );
                        *slot = T::AcvmType::from(C::ScalarField::from(part));
                    }
                    Ok([arr1, arr2])
                }
            };

        // Helper: split base field element into NUM_BINARY_LIMBS limbs of NUM_LIMB_BITS, returned as ScalarField
        let split_fq_into_limbs_public = |x: C::BaseField| -> [C::ScalarField; NUM_BINARY_LIMBS] {
            let xb: BigUint = x.into();
            let mut out = [C::ScalarField::from(0u64); NUM_BINARY_LIMBS];

            for (i, limb) in out.iter_mut().enumerate() {
                let slice = Utils::slice_u256(
                    &xb,
                    (i * NUM_LIMB_BITS) as u64,
                    ((i + 1) * NUM_LIMB_BITS) as u64,
                );
                *limb = C::ScalarField::from(slice);
            }
            out
        };

        //  x and powers of v are given to us in challenge form, so the verifier has to deal with this :)
        let v_squared = batching_challenge_v * batching_challenge_v;
        let v_cubed = v_squared * batching_challenge_v;
        let v_quarted = v_cubed * batching_challenge_v;

        // Convert the accumulator, powers of v and x into "bigfield" form
        // let previous_accumulator_limbs = split_fq_into_limbs_shared(previous_accumulator, driver)?;
        let v_witnesses = split_fq_into_limbs_public(batching_challenge_v);
        let v_squared_witnesses = split_fq_into_limbs_public(v_squared);
        let v_cubed_witnesses = split_fq_into_limbs_public(v_cubed);
        let v_quarted_witnesses = split_fq_into_limbs_public(v_quarted);
        let x_witnesses = split_fq_into_limbs_public(evaluation_input_x);

        // To calculate the quotient, we need to evaluate the expression in integers. So we need uint512_t versions of all
        // elements involved
        let op_code = ultra_op.op_code.value() as u64;
        let num_limb_shift = 2 * NUM_LIMB_BITS;

        let x_lo = ultra_op.x_lo;
        let x_hi = ultra_op.x_hi;
        let y_lo = ultra_op.y_lo;
        let y_hi = ultra_op.y_hi;
        let z_1 = ultra_op.z_1;
        let z_2 = ultra_op.z_2;

        // Compute quotient and remainder bigfield representation
        // TACEO TODO: Batch this outside the loop
        let (quotient_limbs, remainder_limbs) = driver.compute_remainder_limbs_and_quotient_limbs(
            &[x_lo, x_hi, y_lo, y_hi, z_1, z_2],
            converted_ultra_ops,
            evaluation_input_x,
            batching_challenge_v,
            previous_accumulator,
            op_code,
            num_limb_shift,
            NUM_BINARY_LIMBS,
        )?;

        // Construct bigfield representations of P.x and P.y
        let [p_x_0, p_x_1] = split_wide_limb_into_2_limbs_res[0]
            .clone()
            .try_into()
            .expect("Should have two elements");
        let [p_x_2, p_x_3] = split_wide_limb_into_2_limbs_res[1]
            .clone()
            .try_into()
            .expect("Should have two elements");
        let p_x_limbs = [p_x_0, p_x_1, p_x_2, p_x_3];

        let [p_y_0, p_y_1] = split_wide_limb_into_2_limbs_res[2]
            .clone()
            .try_into()
            .expect("Should have two elements");
        let [p_y_2, p_y_3] = split_wide_limb_into_2_limbs_res[3]
            .clone()
            .try_into()
            .expect("Should have two elements");
        let p_y_limbs = [p_y_0, p_y_1, p_y_2, p_y_3];

        // Construct bigfield representations of ultra_op.z_1 and ultra_op.z_2 only using 2 limbs each
        let z_1_limbs = split_wide_limb_into_2_limbs_res[4].clone(); //split_wide_limb_into_2_limbs(ultra_op.z_1, driver)?;
        let z_2_limbs = split_wide_limb_into_2_limbs_res[5].clone(); // split_wide_limb_into_2_limbs(ultra_op.z_2, driver)?;

        // We will divide by shift_2 instantly in the relation itself, but first we need to compute the low part (0*0) and
        // the high part (0*1, 1*0) multiplied by a single limb shift
        let mut low_wide_relation_limb_part_1 = T::AcvmType::from(C::ScalarField::from(op_code));
        let summand1 = driver.mul_with_public(x_witnesses[0], previous_accumulator_limbs[0]);
        let summand2 = driver.mul_with_public(v_witnesses[0], p_x_limbs[0]);
        let summand3 = driver.mul_with_public(v_squared_witnesses[0], p_y_limbs[0]);
        let summand4 = driver.mul_with_public(v_cubed_witnesses[0], z_1_limbs[0]);
        let summand5 = driver.mul_with_public(v_quarted_witnesses[0], z_2_limbs[0]);
        let summand6 = driver.mul_with_public(negative_modulus_limbs[0], quotient_limbs[0]);
        driver.add_assign(&mut low_wide_relation_limb_part_1, summand1);
        driver.add_assign(&mut low_wide_relation_limb_part_1, summand2);
        driver.add_assign(&mut low_wide_relation_limb_part_1, summand3);
        driver.add_assign(&mut low_wide_relation_limb_part_1, summand4);
        driver.add_assign(&mut low_wide_relation_limb_part_1, summand5);
        driver.add_assign(&mut low_wide_relation_limb_part_1, summand6);
        low_wide_relation_limb_part_1 =
            driver.sub(low_wide_relation_limb_part_1, remainder_limbs[0]);
        // This covers the lowest limb

        let mut low_wide_relation_limb = low_wide_relation_limb_part_1;
        let mut summand1 = driver.mul_with_public(x_witnesses[0], previous_accumulator_limbs[1]);
        let summand2 = driver.mul_with_public(x_witnesses[1], previous_accumulator_limbs[0]);
        let summand3 = driver.mul_with_public(v_witnesses[1], p_x_limbs[0]);
        let summand4 = driver.mul_with_public(v_witnesses[0], p_x_limbs[1]);
        let summand5 = driver.mul_with_public(v_squared_witnesses[1], p_y_limbs[0]);
        let summand6 = driver.mul_with_public(v_squared_witnesses[0], p_y_limbs[1]);
        let summand7 = driver.mul_with_public(v_cubed_witnesses[1], z_1_limbs[0]);
        let summand8 = driver.mul_with_public(v_cubed_witnesses[0], z_1_limbs[1]);
        let summand9 = driver.mul_with_public(v_quarted_witnesses[1], z_2_limbs[0]);
        let summand10 = driver.mul_with_public(v_quarted_witnesses[0], z_2_limbs[1]);
        let summand11 = driver.mul_with_public(negative_modulus_limbs[1], quotient_limbs[0]);
        let summand12 = driver.mul_with_public(negative_modulus_limbs[0], quotient_limbs[1]);

        driver.add_assign(&mut summand1, summand2);
        driver.add_assign(&mut summand1, summand3);
        driver.add_assign(&mut summand1, summand4);
        driver.add_assign(&mut summand1, summand5);
        driver.add_assign(&mut summand1, summand6);
        driver.add_assign(&mut summand1, summand7);
        driver.add_assign(&mut summand1, summand8);
        driver.add_assign(&mut summand1, summand9);
        driver.add_assign(&mut summand1, summand10);
        driver.add_assign(&mut summand1, summand11);
        driver.add_assign(&mut summand1, summand12);
        summand1 = driver.sub(summand1, remainder_limbs[1]);
        summand1 = driver.mul_with_public(shift_1, summand1);
        driver.add_assign(&mut low_wide_relation_limb, summand1);

        // Low bits have to be zero

        let low_wide_relation_limb_divided =
            driver.mul_with_public(shift_2_inverse, low_wide_relation_limb);

        // The high relation limb is the accumulation of the low limb divided by 2¹³⁶ and the combination of limbs with
        // indices (0*2,1*1,2*0) with limbs with indices (0*3,1*2,2*1,3*0) multiplied by 2⁶⁸

        let mut high_wide_relation_limb = low_wide_relation_limb_divided;
        let summand1 = driver.mul_with_public(x_witnesses[0], previous_accumulator_limbs[2]);
        let summand2 = driver.mul_with_public(x_witnesses[1], previous_accumulator_limbs[1]);
        let summand3 = driver.mul_with_public(x_witnesses[2], previous_accumulator_limbs[0]);
        let summand4 = driver.mul_with_public(v_witnesses[2], p_x_limbs[0]);
        let summand5 = driver.mul_with_public(v_witnesses[1], p_x_limbs[1]);
        let summand6 = driver.mul_with_public(v_witnesses[0], p_x_limbs[2]);
        let summand7 = driver.mul_with_public(v_squared_witnesses[2], p_y_limbs[0]);
        let summand8 = driver.mul_with_public(v_squared_witnesses[1], p_y_limbs[1]);
        let summand9 = driver.mul_with_public(v_squared_witnesses[0], p_y_limbs[2]);
        let summand10 = driver.mul_with_public(v_cubed_witnesses[2], z_1_limbs[0]);
        let summand11 = driver.mul_with_public(v_cubed_witnesses[1], z_1_limbs[1]);
        let summand12 = driver.mul_with_public(v_quarted_witnesses[2], z_2_limbs[0]);
        let summand13 = driver.mul_with_public(v_quarted_witnesses[1], z_2_limbs[1]);
        let summand14 = driver.mul_with_public(negative_modulus_limbs[0], quotient_limbs[2]);
        let summand15 = driver.mul_with_public(negative_modulus_limbs[1], quotient_limbs[1]);
        let summand16 = driver.mul_with_public(negative_modulus_limbs[2], quotient_limbs[0]);
        driver.add_assign(&mut high_wide_relation_limb, summand1);
        driver.add_assign(&mut high_wide_relation_limb, summand2);
        driver.add_assign(&mut high_wide_relation_limb, summand3);
        driver.add_assign(&mut high_wide_relation_limb, summand4);
        driver.add_assign(&mut high_wide_relation_limb, summand5);
        driver.add_assign(&mut high_wide_relation_limb, summand6);
        driver.add_assign(&mut high_wide_relation_limb, summand7);
        driver.add_assign(&mut high_wide_relation_limb, summand8);
        driver.add_assign(&mut high_wide_relation_limb, summand9);
        driver.add_assign(&mut high_wide_relation_limb, summand10);
        driver.add_assign(&mut high_wide_relation_limb, summand11);
        driver.add_assign(&mut high_wide_relation_limb, summand12);
        driver.add_assign(&mut high_wide_relation_limb, summand13);
        driver.add_assign(&mut high_wide_relation_limb, summand14);
        driver.add_assign(&mut high_wide_relation_limb, summand15);
        driver.add_assign(&mut high_wide_relation_limb, summand16);
        high_wide_relation_limb = driver.sub(high_wide_relation_limb, remainder_limbs[2]);
        let mut second_part = driver.mul_with_public(x_witnesses[0], previous_accumulator_limbs[3]);

        let summand1 = driver.mul_with_public(x_witnesses[1], previous_accumulator_limbs[2]);
        let summand2 = driver.mul_with_public(x_witnesses[2], previous_accumulator_limbs[1]);
        let summand3 = driver.mul_with_public(x_witnesses[3], previous_accumulator_limbs[0]);
        let summand4 = driver.mul_with_public(v_witnesses[3], p_x_limbs[0]);
        let summand5 = driver.mul_with_public(v_witnesses[2], p_x_limbs[1]);
        let summand6 = driver.mul_with_public(v_witnesses[1], p_x_limbs[2]);
        let summand7 = driver.mul_with_public(v_witnesses[0], p_x_limbs[3]);
        let summand8 = driver.mul_with_public(v_squared_witnesses[3], p_y_limbs[0]);
        let summand9 = driver.mul_with_public(v_squared_witnesses[2], p_y_limbs[1]);
        let summand10 = driver.mul_with_public(v_squared_witnesses[1], p_y_limbs[2]);
        let summand11 = driver.mul_with_public(v_squared_witnesses[0], p_y_limbs[3]);
        let summand12 = driver.mul_with_public(v_cubed_witnesses[3], z_1_limbs[0]);
        let summand13 = driver.mul_with_public(v_cubed_witnesses[2], z_1_limbs[1]);
        let summand14 = driver.mul_with_public(v_quarted_witnesses[3], z_2_limbs[0]);
        let summand15 = driver.mul_with_public(v_quarted_witnesses[2], z_2_limbs[1]);
        let summand16 = driver.mul_with_public(negative_modulus_limbs[0], quotient_limbs[3]);
        let summand17 = driver.mul_with_public(negative_modulus_limbs[1], quotient_limbs[2]);
        let summand18 = driver.mul_with_public(negative_modulus_limbs[2], quotient_limbs[1]);
        let summand19 = driver.mul_with_public(negative_modulus_limbs[3], quotient_limbs[0]);
        driver.add_assign(&mut second_part, summand1);
        driver.add_assign(&mut second_part, summand2);
        driver.add_assign(&mut second_part, summand3);
        driver.add_assign(&mut second_part, summand4);
        driver.add_assign(&mut second_part, summand5);
        driver.add_assign(&mut second_part, summand6);
        driver.add_assign(&mut second_part, summand7);
        driver.add_assign(&mut second_part, summand8);
        driver.add_assign(&mut second_part, summand9);
        driver.add_assign(&mut second_part, summand10);
        driver.add_assign(&mut second_part, summand11);
        driver.add_assign(&mut second_part, summand12);
        driver.add_assign(&mut second_part, summand13);
        driver.add_assign(&mut second_part, summand14);
        driver.add_assign(&mut second_part, summand15);
        driver.add_assign(&mut second_part, summand16);
        driver.add_assign(&mut second_part, summand17);
        driver.add_assign(&mut second_part, summand18);
        driver.add_assign(&mut second_part, summand19);
        second_part = driver.sub(second_part, remainder_limbs[3]);
        second_part = driver.mul_with_public(shift_1, second_part);
        driver.add_assign(&mut high_wide_relation_limb, second_part);

        // We dont do this assert
        // Check that the results lower 136 bits are zero
        // debug_assert!(
        //     Utils::slice_u256(&high_wide_relation_limb.into(), 0, 2 * NUM_LIMB_BITS as u64)
        //         .is_zero()
        // );

        // Get divided version
        let high_wide_relation_limb_divided =
            driver.mul_with_public(shift_2_inverse, high_wide_relation_limb);

        const LAST_LIMB_INDEX: usize = NUM_BINARY_LIMBS - 1;

        let mut p_x_microlimbs = [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS];
        let mut p_y_microlimbs = [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS];
        let mut z_1_microlimbs = [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_Z_LIMBS];
        let mut z_2_microlimbs = [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_Z_LIMBS];
        let mut current_accumulator_microlimbs =
            [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS];
        let mut quotient_microlimbs = [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS];

        // Split P_x into microlimbs for range constraining
        for i in 0..LAST_LIMB_INDEX {
            p_x_microlimbs[i] = split_standard_limb_into_micro_limbs(p_x_limbs[i], driver)?;
        }
        p_x_microlimbs[LAST_LIMB_INDEX] = split_top_limb_into_micro_limbs(
            p_x_limbs[LAST_LIMB_INDEX],
            TOP_STANDARD_MICROLIMB_BITS,
            driver,
        )?;

        // Split P_y into microlimbs for range constraining
        for i in 0..LAST_LIMB_INDEX {
            p_y_microlimbs[i] = split_standard_limb_into_micro_limbs(p_y_limbs[i], driver)?;
        }
        p_y_microlimbs[LAST_LIMB_INDEX] = split_top_limb_into_micro_limbs(
            p_y_limbs[LAST_LIMB_INDEX],
            TOP_STANDARD_MICROLIMB_BITS,
            driver,
        )?;

        // Split z scalars into microlimbs for range constraining
        z_1_microlimbs[0] = split_standard_limb_into_micro_limbs(z_1_limbs[0], driver)?;
        z_2_microlimbs[0] = split_standard_limb_into_micro_limbs(z_2_limbs[0], driver)?;

        z_1_microlimbs[NUM_Z_LIMBS - 1] = split_top_z_limb_into_micro_limbs(
            z_1_limbs[NUM_Z_LIMBS - 1],
            TOP_Z_MICROLIMB_BITS,
            driver,
        )?;
        z_2_microlimbs[NUM_Z_LIMBS - 1] = split_top_z_limb_into_micro_limbs(
            z_2_limbs[NUM_Z_LIMBS - 1],
            TOP_Z_MICROLIMB_BITS,
            driver,
        )?;

        // Split current accumulator into microlimbs for range constraining
        for i in 0..LAST_LIMB_INDEX {
            current_accumulator_microlimbs[i] =
                split_standard_limb_into_micro_limbs(remainder_limbs[i], driver)?;
        }
        current_accumulator_microlimbs[LAST_LIMB_INDEX] = split_top_limb_into_micro_limbs(
            remainder_limbs[LAST_LIMB_INDEX],
            TOP_STANDARD_MICROLIMB_BITS,
            driver,
        )?;

        // Split quotient into microlimbs for range constraining
        for i in 0..LAST_LIMB_INDEX {
            quotient_microlimbs[i] =
                split_standard_limb_into_micro_limbs(quotient_limbs[i], driver)?;
        }
        quotient_microlimbs[LAST_LIMB_INDEX] = split_top_limb_into_micro_limbs(
            quotient_limbs[LAST_LIMB_INDEX],
            TOP_QUOTIENT_MICROLIMB_BITS,
            driver,
        )?;

        // Start filling the witness container
        let mut input = CoAccumulationInput::new(ultra_op.clone());
        input.p_x_limbs = p_x_limbs;
        input.p_x_microlimbs = p_x_microlimbs;
        input.p_y_limbs = p_y_limbs;
        input.p_y_microlimbs = p_y_microlimbs;
        input.z_1_limbs = z_1_limbs.try_into().expect("Should have two elements");
        input.z_1_microlimbs = z_1_microlimbs;
        input.z_2_limbs = z_2_limbs.try_into().expect("Should have two elements");
        input.z_2_microlimbs = z_2_microlimbs;
        input.previous_accumulator = *previous_accumulator_limbs;
        input.current_accumulator = remainder_limbs.try_into().expect("Should have 4 limbs");
        input.current_accumulator_microlimbs = current_accumulator_microlimbs;
        input.quotient_binary_limbs = quotient_limbs.try_into().expect("Should have 4 limbs");
        input.quotient_microlimbs = quotient_microlimbs;
        input.relation_wide_limbs = [
            low_wide_relation_limb_divided,
            high_wide_relation_limb_divided,
        ];
        input.relation_wide_microlimbs = split_relation_limb_into_micro_limbs(
            (
                low_wide_relation_limb_divided,
                high_wide_relation_limb_divided,
            ),
            driver,
        )?;

        Ok(input)
    }

    /**
     * @brief Create a single accumulation gate
     *
     * @param acc_step
     */
    fn create_accumulation_gate(&mut self, acc_step: CoAccumulationInput<T, C>) {
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
        let mut lay_limbs_in_row = |input: &[T::AcvmType], starting_wire: WireIds| {
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

#[derive(Clone)]
struct CoAccumulationInput<
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
    C: HonkCurve<TranscriptFieldType>,
> {
    // Members necessary for the gate creation
    ultra_op: CoUltraOp<T, C>,

    p_x_limbs: [T::AcvmType; NUM_BINARY_LIMBS],
    p_x_microlimbs: [[T::AcvmType; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    p_y_limbs: [T::AcvmType; NUM_BINARY_LIMBS],
    p_y_microlimbs: [[T::AcvmType; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    z_1_limbs: [T::AcvmType; NUM_Z_LIMBS],
    z_1_microlimbs: [[T::AcvmType; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
    z_2_limbs: [T::AcvmType; NUM_Z_LIMBS],
    z_2_microlimbs: [[T::AcvmType; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],

    previous_accumulator: [T::AcvmType; NUM_BINARY_LIMBS],
    current_accumulator: [T::AcvmType; NUM_BINARY_LIMBS],
    current_accumulator_microlimbs: [[T::AcvmType; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    quotient_binary_limbs: [T::AcvmType; NUM_BINARY_LIMBS],
    quotient_microlimbs: [[T::AcvmType; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    relation_wide_limbs: [T::AcvmType; NUM_RELATION_WIDE_LIMBS],
    relation_wide_microlimbs: [[T::AcvmType; NUM_MICRO_LIMBS]; 2],
}

impl<T: NoirWitnessExtensionProtocol<C::ScalarField>, C: HonkCurve<TranscriptFieldType>>
    CoAccumulationInput<T, C>
{
    fn new(ultra_op: CoUltraOp<T, C>) -> Self {
        Self {
            ultra_op,
            p_x_limbs: [T::AcvmType::default(); NUM_BINARY_LIMBS],
            p_x_microlimbs: [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            p_y_limbs: [T::AcvmType::default(); NUM_BINARY_LIMBS],
            p_y_microlimbs: [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            z_1_limbs: [T::AcvmType::default(); NUM_Z_LIMBS],
            z_1_microlimbs: [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
            z_2_limbs: [T::AcvmType::default(); NUM_Z_LIMBS],
            z_2_microlimbs: [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
            previous_accumulator: [T::AcvmType::default(); NUM_BINARY_LIMBS],
            current_accumulator: [T::AcvmType::default(); NUM_BINARY_LIMBS],
            current_accumulator_microlimbs: [[T::AcvmType::default(); NUM_MICRO_LIMBS];
                NUM_BINARY_LIMBS],
            quotient_binary_limbs: [T::AcvmType::default(); NUM_BINARY_LIMBS],
            quotient_microlimbs: [[T::AcvmType::default(); NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            relation_wide_limbs: [T::AcvmType::default(); NUM_RELATION_WIDE_LIMBS],
            relation_wide_microlimbs: [[T::AcvmType::default(); NUM_MICRO_LIMBS]; 2],
        }
    }
}

pub fn construct_pk_from_builder<
    C: HonkCurve<TranscriptFieldType>,
    U: NoirUltraHonkProver<C>,
    T: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = U::ArithmeticShare>,
>(
    circuit: CoTranslatorBuilder<C, T>,
    driver: &mut T,
) -> eyre::Result<Polynomials<U::ArithmeticShare, C::ScalarField, TranslatorFlavour>> {
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
    let mut polys =
        Polynomials::<U::ArithmeticShare, C::ScalarField, TranslatorFlavour>::new(circuit_size);
    for poly in polys.witness.to_be_shifted_mut() {
        poly.resize(mini_circuit_dyadic_size, U::ArithmeticShare::default());
    }
    for poly in polys.witness.get_ordered_range_constraints_mut() {
        poly.resize(circuit_size, U::ArithmeticShare::default());
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
            wire_poly[i] = driver.get_as_shared(&value);
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
                Polynomial::<U::ArithmeticShare>::new_default(circuit_size),
                Polynomial::<U::ArithmeticShare>::new_default(circuit_size),
                Polynomial::<U::ArithmeticShare>::new_default(circuit_size),
                Polynomial::<U::ArithmeticShare>::new_default(circuit_size),
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

            let mut extra_denominator_uint = vec![U::ArithmeticShare::default(); real_circuit_size];

            // Given the polynomials in group_i, transfer their elements, sorted in non-descending order, into the corresponding
            // ordered_range_constraint_i up to the given capacity and the remaining elements to the last range constraint.
            // Sorting is done by converting the elements to uint for efficiency.
            let mut batch_convert = Vec::with_capacity(
                mini_circuit_dyadic_size
                    * TranslatorFlavour::INTERLEAVING_GROUP_SIZE
                    * num_interleaved_wires,
            );
            for i in 0..num_interleaved_wires {
                let group = polys.witness.get_groups_to_be_interleaved()[i];
                for group_el in group
                    .iter()
                    .take(TranslatorFlavour::INTERLEAVING_GROUP_SIZE)
                {
                    let start = 0usize;
                    let end = group_el.len() - mini_num_disabled_rows_in_sumcheck;
                    for k in start..end {
                        let lo = group_el[k];
                        batch_convert.push(lo);
                    }
                }
            }
            // TACEO TODO: In the test case these values are always small enough to fit into u32, maybe this can be assumed in all cases? Then this conversion could be avoided
            let batch_converted_to_u32 = driver.get_lowest_32_bits_many(&batch_convert)?;
            let mut counter = 0;
            for i in 0..num_interleaved_wires {
                let group = polys.witness.get_groups_to_be_interleaved()[i];
                let mut ordered_vectors_uint =
                    vec![U::ArithmeticShare::default(); real_circuit_size];

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
                        let lo = batch_converted_to_u32[counter];
                        counter += 1;

                        // Put it it the target polynomial
                        if (current_offset + k) < free_space_before_runway {
                            ordered_vectors_uint[current_offset + k] = lo;

                        // Or in the extra one if there is no space left
                        } else {
                            extra_denominator_uint[extra_denominator_offset] = lo;
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
                    *dst =
                        driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(*src as u32)));
                }

                // Sort the polynomial in nondescending order. We sort using the size_t vector for 2 reasons:
                // 1. It is faster to sort size_t
                // 2. Comparison operators for finite fields are operating on internal form, so we'd have to convert them
                // from Montgomery
                let ordered_vectors_uint = driver.sort(
                    &ordered_vectors_uint
                        .iter()
                        .map(|x| T::AcvmType::from(*x))
                        .collect_vec(),
                    32,
                )?;
                // ordered_vectors_uint.sort_unstable();
                debug_assert!(ordered_vectors_uint.len() == real_circuit_size);
                // Copy the values into the actual polynomial
                for (idx, v) in ordered_vectors_uint.iter().enumerate() {
                    polys.witness.get_ordered_range_constraints_mut()[i][idx] = *v;
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
                *dst = driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(*src as u32)));
            }

            debug_assert!(extra_denominator_uint.len() == real_circuit_size);
            // Sort it
            let extra_denominator_uint = driver.sort(
                &extra_denominator_uint
                    .iter()
                    .map(|x| T::AcvmType::from(*x))
                    .collect_vec(),
                32,
            )?;
            debug_assert!(extra_denominator_uint.len() == real_circuit_size);

            // Copy the values into the actual polynomial
            let poly4 = polys.witness.ordered_range_constraints_4_mut();
            for (i, v) in extra_denominator_uint.iter().enumerate() {
                poly4[i] = *v;
            }
        }
    }

    Ok(polys)
}
