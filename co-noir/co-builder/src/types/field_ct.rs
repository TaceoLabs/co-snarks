use super::types::{AddQuad, EccDblGate, MulQuad};
use crate::types::generators;
use crate::types::plookup::{ColumnIdx, Plookup};
use crate::types::types::{AddTriple, EccAddGate, PolyTriple};
use crate::ultra_builder::GenericUltraCircuitBuilder;
use ark_ec::{AffineRepr, CurveConfig, CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_ff::{One, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType};
use itertools::{Itertools, izip};
use num_bigint::BigUint;
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct FieldCT<F: PrimeField> {
    pub(crate) additive_constant: F,
    pub(crate) multiplicative_constant: F,
    pub(crate) witness_index: u32,
}

impl<F: PrimeField> FieldCT<F> {
    pub(crate) const IS_CONSTANT: u32 = u32::MAX;

    pub fn from_witness_index(witness_index: u32) -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::one(),
            witness_index,
        }
    }

    pub fn from_witness<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: T::AcvmType,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> Self {
        let witness = WitnessCT::from_acvm_type(input, builder);
        Self::from(witness)
    }

    pub fn get_value<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> T::AcvmType {
        if !self.is_constant() {
            let variable = builder.get_variable(self.witness_index as usize);
            let mut res = driver.mul_with_public(self.multiplicative_constant, variable);
            driver.add_assign_with_public(self.additive_constant, &mut res);
            res
        } else {
            assert!(self.multiplicative_constant == F::one());
            T::AcvmType::from(self.additive_constant)
        }
    }

    pub(crate) fn get_witness_index<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> u32 {
        self.normalize(builder, driver).witness_index
    }

    /**
     * @brief Constrain that this field is equal to the given field.
     *
     * @warning: After calling this method, both field values *will* be equal, regardless of whether the constraint
     * succeeds or fails. This can lead to confusion when debugging. If you want to log the inputs, do so before
     * calling this method.
     */
    pub fn assert_equal<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        if self.is_constant() && other.is_constant() {
            let left =
                T::get_public(&self.get_value(builder, driver)).expect("Constant should be public");
            let right = T::get_public(&other.get_value(builder, driver))
                .expect("Constant should be public");
            builder.assert_if_has_witness(left == right);
        }
        if self.is_constant() {
            let left =
                T::get_public(&self.get_value(builder, driver)).expect("Constant should be public");
            builder.assert_equal_constant(other.witness_index as usize, left);
        } else if other.is_constant() {
            let right = T::get_public(&other.get_value(builder, driver))
                .expect("Constant should be public");
            builder.assert_equal_constant(self.witness_index as usize, right);
        } else if self.is_normalized() || other.is_normalized() {
            builder.assert_equal(self.witness_index as usize, other.witness_index as usize);
        } else {
            // Instead of creating 2 gates for normalizing both witnesses and applying a copy constraint, we use a
            // single `add` gate constraining a - b = 0
            builder.create_add_gate(&AddTriple {
                a: self.witness_index,
                b: other.witness_index,
                c: builder.zero_idx,
                a_scaling: self.multiplicative_constant,
                b_scaling: -other.multiplicative_constant,
                c_scaling: P::ScalarField::zero(),
                const_scaling: self.additive_constant - other.additive_constant,
            });
        }
    }

    pub fn is_constant(&self) -> bool {
        self.witness_index == Self::IS_CONSTANT
    }

    pub(crate) fn to_bool_ct<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> BoolCT<P::ScalarField, T> {
        // If `this` is a constant field_t element, the resulting bool is also constant.
        // In this case, `additive_constant` uniquely determines the value of `this`.
        // After ensuring that `additive_constant` \in {0, 1}, we set the `.witness_bool` field of `result` to match the
        // value of `additive_constant`.
        if self.is_constant() {
            return BoolCT {
                witness_bool: self.additive_constant.into(), // == F::one(),
                witness_inverted: false,
                witness_index: Self::IS_CONSTANT,
            };
        }

        let add_constant_check = self.additive_constant.is_zero();
        let mul_constant_check = self.multiplicative_constant == F::one();
        let inverted_check =
            (self.additive_constant == F::one()) && (self.multiplicative_constant == -F::one());
        let mut result_inverted = false;
        // Process the elements of the form
        //      a = a.v * 1 + 0 and a = a.v * (-1) + 1
        // They do not need to be normalized if `a.v` is constrained to be boolean. In the first case, we have
        //      a == a.v,
        // and in the second case
        //      a == ¬(a.v).
        // The distinction between the cases is tracked by the .witness_inverted field of bool_t.
        let mut witness_idx = self.witness_index;
        if (add_constant_check && mul_constant_check) || inverted_check {
            result_inverted = inverted_check;
        } else {
            // In general, the witness has to be normalized.
            witness_idx = self.get_normalized_witness_index(builder, driver);
        }
        // Get the normalized value of the witness
        let witness = builder.get_variable(witness_idx as usize);
        if let Some(witness) = T::get_public(&witness) {
            assert!(witness == F::zero() || witness == F::one());
        }
        builder.create_bool_gate(witness_idx);
        BoolCT {
            witness_bool: witness, // == F::one(),
            witness_inverted: result_inverted,
            witness_index: witness_idx,
        }
    }

    pub(crate) fn normalize<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        if self.is_normalized() {
            return self.to_owned();
        }

        // Value of this = this.v * this.mul + this.add; // where this.v = context->variables[this.witness_index]
        // Normalised result = result.v * 1 + 0;         // where result.v = this.v * this.mul + this.add
        // We need a new gate to enforce that the `result` was correctly calculated from `this`.

        let mut result = FieldCT::default();
        let value = builder.get_variable(self.witness_index as usize);
        let mut out = driver.mul_with_public(self.multiplicative_constant, value);
        driver.add_assign_with_public(self.additive_constant, &mut out);

        result.witness_index = builder.add_variable(out);
        result.additive_constant = F::zero();
        result.multiplicative_constant = F::one();
        // Aim of new gate: this.v * this.mul + this.add == result.v
        // <=>                           this.v * [this.mul] +                  result.v * [ -1] + [this.add] == 0
        // <=> this.v * this.v * [ 0 ] + this.v * [this.mul] + this.v * [ 0 ] + result.v * [ -1] + [this.add] == 0
        // <=> this.v * this.v * [q_m] + this.v * [   q_l  ] + this.v * [q_r] + result.v * [q_o] + [   q_c  ] == 0

        builder.create_add_gate(&AddTriple {
            a: self.witness_index,
            b: builder.zero_idx,
            c: result.witness_index,
            a_scaling: self.multiplicative_constant,
            b_scaling: P::ScalarField::zero(),
            c_scaling: -P::ScalarField::one(),
            const_scaling: self.additive_constant,
        });
        result
    }

    pub(crate) fn get_normalized_witness_index<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> u32 {
        self.normalize(builder, driver).witness_index
    }

    pub fn multiply<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut result = Self::default();

        if self.is_constant() && other.is_constant() {
            // Both inputs are constant - don't add a gate.
            // The value of a constant is tracked in `.additive_constant`.
            result.additive_constant = self.additive_constant * other.additive_constant;
        } else if !self.is_constant() && other.is_constant() {
            // One input is constant: don't add a gate, but update scaling factors.

            // /**
            //  * Let:
            //  *   a := this;
            //  *   b := other;
            //  *   a.v := ctx->variables[this.witness_index];
            //  *   b.v := ctx->variables[other.witness_index];
            //  *   .mul = .multiplicative_constant
            //  *   .add = .additive_constant
            //  */
            // /**
            //  * Value of this   = a.v * a.mul + a.add;
            //  * Value of other  = b.add
            //  * Value of result = a * b = a.v * [a.mul * b.add] + [a.add * b.add]
            //  *                             ^   ^result.mul       ^result.add
            //  *                             ^result.v
            //  */
            result.additive_constant = self.additive_constant * other.additive_constant;
            result.multiplicative_constant = self.multiplicative_constant * other.additive_constant;
            result.witness_index = self.witness_index;
        } else if self.is_constant() && !other.is_constant() {
            // One input is constant: don't add a gate, but update scaling factors.

            // /**
            //  * Value of this   = a.add;
            //  * Value of other  = b.v * b.mul + b.add
            //  * Value of result = a * b = b.v * [a.add * b.mul] + [a.add * b.add]
            //  *                             ^   ^result.mul       ^result.add
            //  *                             ^result.v
            //  */
            result.additive_constant = self.additive_constant * other.additive_constant;
            result.multiplicative_constant = other.multiplicative_constant * self.additive_constant;
            result.witness_index = other.witness_index;
        } else {
            // Both inputs map to circuit varaibles: create a `*` constraint.

            // /**
            //  * Value of this   = a.v * a.mul + a.add;
            //  * Value of other  = b.v * b.mul + b.add;
            //  * Value of result = a * b
            //  *            = [a.v * b.v] * [a.mul * b.mul] + a.v * [a.mul * b.add] + b.v * [a.add * b.mul] + [a.ac * b.add]
            //  *            = [a.v * b.v] * [     q_m     ] + a.v * [     q_l     ] + b.v * [     q_r     ] + [    q_c     ]
            //  *            ^               ^Notice the add/mul_constants form selectors when a gate is created.
            //  *            |                Only the witnesses (pointed-to by the witness_indexes) form the wires in/out of
            //  *            |                the gate.
            //  *            ^This entire value is pushed to ctx->variables as a new witness. The
            //  *             implied additive & multiplicative constants of the new witness are 0 & 1 resp.
            //  * Left wire value: a.v
            //  * Right wire value: b.v
            //  * Output wire value: result.v (with q_o = -1)
            //  */
            let q_c = self.additive_constant * other.additive_constant;
            let q_r = self.additive_constant * other.multiplicative_constant;
            let q_l = self.multiplicative_constant * other.additive_constant;
            let q_m = self.multiplicative_constant * other.multiplicative_constant;

            let left = builder.get_variable(self.witness_index as usize);
            let right = builder.get_variable(other.witness_index as usize);

            let out = driver.mul(left.to_owned(), right.to_owned())?;
            let mut out = driver.mul_with_public(q_m, out);

            let t0 = driver.mul_with_public(q_l, left);
            driver.add_assign(&mut out, t0);

            let t0 = driver.mul_with_public(q_r, right);
            driver.add_assign(&mut out, t0);
            driver.add_assign_with_public(q_c, &mut out);

            result.witness_index = builder.add_variable(out);
            builder.create_poly_gate(&PolyTriple {
                a: self.witness_index,
                b: other.witness_index,
                c: result.witness_index,
                q_m,
                q_l,
                q_r,
                q_o: -P::ScalarField::one(),
                q_c,
            });
        }
        Ok(result)
    }

    pub fn multiply_many<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        lhs: &[Self],
        rhs: &[Self],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Vec<Self>> {
        let (constant_operand, variable_operands): (Vec<_>, Vec<_>) = lhs
            .iter()
            .zip(rhs.iter())
            .enumerate()
            .partition(|(_, (l, r))| l.is_constant() || r.is_constant());

        let constant_operand = constant_operand
            .into_iter()
            .map(|(i, (l, r))| l.multiply(r, builder, driver).map(|res| (i, res)))
            .collect::<eyre::Result<Vec<_>>>()?;

        // Both inputs map to circuit varaibles: create a `*` constraint.

        // /**
        //  * Value of this   = a.v * a.mul + a.add;
        //  * Value of other  = b.v * b.mul + b.add;
        //  * Value of result = a * b
        //  *            = [a.v * b.v] * [a.mul * b.mul] + a.v * [a.mul * b.add] + b.v * [a.add * b.mul] + [a.ac * b.add]
        //  *            = [a.v * b.v] * [     q_m     ] + a.v * [     q_l     ] + b.v * [     q_r     ] + [    q_c     ]
        //  *            ^               ^Notice the add/mul_constants form selectors when a gate is created.
        //  *            |                Only the witnesses (pointed-to by the witness_indexes) form the wires in/out of
        //  *            |                the gate.
        //  *            ^This entire value is pushed to ctx->variables as a new witness. The
        //  *             implied additive & multiplicative constants of the new witness are 0 & 1 resp.
        //  * Left wire value: a.v
        //  * Right wire value: b.v
        //  * Output wire value: result.v (with q_o = -1)
        //  */
        let variables = variable_operands
            .iter()
            .map(|(_, (l, r))| {
                (
                    builder.get_variable(l.witness_index as usize),
                    builder.get_variable(r.witness_index as usize),
                )
            })
            .collect::<Vec<_>>();

        let (left_vals, right_vals) = variables
            .clone()
            .into_iter()
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let point_wise_products = driver.mul_many(&left_vals, &right_vals)?;

        let variable_operands = izip!(variable_operands, variables, point_wise_products)
            .map(|((i, (l, r)), (l_var, r_var), p)| {
                let mut result = FieldCT::default();

                let q_c = l.additive_constant * r.additive_constant;
                let q_r = l.additive_constant * r.multiplicative_constant;
                let q_l = l.multiplicative_constant * r.additive_constant;
                let q_m = l.multiplicative_constant * r.multiplicative_constant;

                let mut out = driver.mul_with_public(q_m, p);

                let t0 = driver.mul_with_public(q_l, l_var);
                driver.add_assign(&mut out, t0);

                let t0 = driver.mul_with_public(q_r, r_var);
                driver.add_assign(&mut out, t0);
                driver.add_assign_with_public(q_c, &mut out);

                result.witness_index = builder.add_variable(out);
                builder.create_poly_gate(&PolyTriple {
                    a: l.witness_index,
                    b: r.witness_index,
                    c: result.witness_index,
                    q_m,
                    q_l,
                    q_r,
                    q_o: -P::ScalarField::one(),
                    q_c,
                });

                (i, result)
            })
            .collect::<Vec<(usize, FieldCT<F>)>>();

        let result = constant_operand
            .into_iter()
            .chain(variable_operands)
            .sorted_by_key(|(i, _)| *i)
            .map(|(_, res)| res)
            .collect::<Vec<_>>();

        Ok(result)
    }

    pub fn mul_assign<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        *self = self.multiply(other, builder, driver)?;
        Ok(())
    }

    pub fn divide<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        other.assert_is_not_zero(builder, driver)?;
        self.divide_no_zero_check(other, builder, driver)
    }

    fn divide_no_zero_check<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut result = Self::default();

        let mut additive_multiplier = F::one();

        if self.is_constant() && other.is_constant() {
            // both inputs are constant - don't add a gate
            if !other.additive_constant.is_zero() {
                additive_multiplier = other
                    .additive_constant
                    .inverse()
                    .expect("Non-zero constant");
            }
            result.additive_constant = self.additive_constant * additive_multiplier;
        } else if !self.is_constant() && other.is_constant() {
            // one input is constant - don't add a gate, but update scaling factors
            if !other.additive_constant.is_zero() {
                additive_multiplier = other
                    .additive_constant
                    .inverse()
                    .expect("Non-zero constant");
            }
            result.additive_constant = self.additive_constant * additive_multiplier;
            result.multiplicative_constant = self.multiplicative_constant * additive_multiplier;
            result.witness_index = self.witness_index;
        } else if self.is_constant() && !other.is_constant() {
            let val = self.get_value(builder, driver);
            let val = T::get_public(&val).expect("Already checked it is public");
            // numerator 0?
            if val.is_zero() {
                result.additive_constant = F::zero();
                result.multiplicative_constant = F::one();
                result.witness_index = Self::IS_CONSTANT;
            } else {
                let q_m = other.multiplicative_constant;
                let q_l = other.additive_constant;
                let q_c = -val;
                let other_val = other.get_value(builder, driver);
                let inverse = driver.invert(other_val)?;
                let out_value = driver.mul_with_public(val, inverse);
                result.witness_index = builder.add_variable(out_value);
                builder.create_poly_gate(&PolyTriple {
                    a: result.witness_index,
                    b: other.witness_index,
                    c: result.witness_index,
                    q_m,
                    q_l,
                    q_r: F::zero(),
                    q_o: F::zero(),
                    q_c,
                });
            }
        } else {
            // AZTEC TODO SHOULD WE CARE ABOUT IF THE DIVISOR IS ZERO?
            let left = builder.get_variable(self.witness_index as usize);
            let right = builder.get_variable(other.witness_index as usize);

            // even if LHS is constant, if divisor is not constant we need a gate to compute the inverse
            // bb::fr witness_multiplier = other.witness.invert();
            // m1.x1 + a1 / (m2.x2 + a2) = x3
            let mut t0 = driver.mul_with_public(self.multiplicative_constant, left);
            driver.add_assign_with_public(self.additive_constant, &mut t0);
            let mut t1 = driver.mul_with_public(other.multiplicative_constant, right);
            driver.add_assign_with_public(other.additive_constant, &mut t1);

            // if t1 == 0 ? 0 : t1^-1
            let t1 = Self::zero_or_inverse::<P, T>(t1, driver)?;
            let out = driver.mul(t0, t1)?;
            result.witness_index = builder.add_variable(out);

            // m2.x2.x3 + a2.x3 = m1.x1 + a1
            // m2.x2.x3 + a2.x3 - m1.x1 - a1 = 0
            // left = x3
            // right = x2
            // out = x1
            // qm = m2
            // ql = a2
            // qr = 0
            // qo = -m1
            // qc = -a1
            let q_m = other.multiplicative_constant;
            let q_l = other.additive_constant;
            let q_r = F::zero();
            let q_o = -self.multiplicative_constant;
            let q_c = -self.additive_constant;

            builder.create_poly_gate(&PolyTriple {
                a: result.witness_index,
                b: other.witness_index,
                c: self.witness_index,
                q_m,
                q_l,
                q_r,
                q_o,
                q_c,
            });
        }

        Ok(result)
    }

    /**
     * @brief raise a field_t to a power of an exponent (field_t). Note that the exponent must not exceed 32 bits and is
     * implicitly range constrained.
     *
     * @returns this ** (exponent)
     */
    pub fn pow<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        exponent: &FieldCT<P::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut exponent_value = exponent.get_value(builder, driver);
        let exponent_constant = exponent.is_constant();

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/446): optimize by allowing smaller exponent
        // TACEO TODO: Also optimize this for the mpc case
        let mut exponent_bits = vec![BoolCT::default(); 32];
        for i in 0..32 {
            let value_bit = driver
                .integer_bitwise_and(exponent_value.clone(), P::ScalarField::ONE.into(), 32)
                .unwrap();
            let bit =
                BoolCT::from_witness_ct(WitnessCT::from_acvm_type(value_bit, builder), builder);
            exponent_bits[31 - i] = bit;
            exponent_value = driver.right_shift(exponent_value, 1)?;
        }

        if !exponent_constant {
            let mut exponent_accumulator = FieldCT::from(F::zero());
            for bit in &exponent_bits {
                exponent_accumulator.add_assign(&exponent_accumulator.clone(), builder, driver);
                exponent_accumulator.add_assign(&bit.to_field_ct(driver), builder, driver);
            }
            exponent.assert_equal(&exponent_accumulator, builder, driver);
        }

        let mut accumulator = FieldCT::from(F::one());
        let mul_coefficient = self.sub(&FieldCT::from(F::one()), builder, driver);
        for bit in exponent_bits.iter().take(32) {
            accumulator
                .mul_assign(&accumulator.clone(), builder, driver)
                .unwrap();
            let bit = bit.to_field_ct(driver);
            let rhs = mul_coefficient
                .madd(&bit, &FieldCT::from(F::one()), builder, driver)
                .unwrap();
            accumulator.mul_assign(&rhs, builder, driver)?;
        }

        // TACEO TODO: Origin Tags
        Ok(accumulator.normalize(builder, driver))
    }

    pub fn add<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let mut result = Self::default();

        if self.witness_index == other.witness_index && !self.is_constant() {
            result.additive_constant = self.additive_constant + other.additive_constant;
            result.multiplicative_constant =
                self.multiplicative_constant + other.multiplicative_constant;
            result.witness_index = self.witness_index;
        } else if self.is_constant() && other.is_constant() {
            // both inputs are constant - don't add a gate
            result.additive_constant = self.additive_constant + other.additive_constant;
        } else if !self.is_constant() && other.is_constant() {
            // one input is constant - don't add a gate, but update scaling factors
            result.additive_constant = self.additive_constant + other.additive_constant;
            result.multiplicative_constant = self.multiplicative_constant;
            result.witness_index = self.witness_index;
        } else if self.is_constant() && !other.is_constant() {
            result.additive_constant = self.additive_constant + other.additive_constant;
            result.multiplicative_constant = other.multiplicative_constant;
            result.witness_index = other.witness_index;
        } else {
            let left = builder.get_variable(self.witness_index as usize);
            let right = builder.get_variable(other.witness_index as usize);
            let mut out = driver.mul_with_public(self.multiplicative_constant, left);
            let t0 = driver.mul_with_public(other.multiplicative_constant, right);
            driver.add_assign(&mut out, t0);
            driver.add_assign_with_public(self.additive_constant, &mut out);
            driver.add_assign_with_public(other.additive_constant, &mut out);

            result.witness_index = builder.add_variable(out);
            builder.create_add_gate(&AddTriple {
                a: self.witness_index,
                b: other.witness_index,
                c: result.witness_index,
                a_scaling: self.multiplicative_constant,
                b_scaling: other.multiplicative_constant,
                c_scaling: -P::ScalarField::one(),
                const_scaling: (self.additive_constant + other.additive_constant),
            });
        }
        result
    }

    pub(crate) fn add_assign<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        *self = self.add(other, builder, driver);
    }

    pub fn neg(&self) -> Self {
        let mut result = self.to_owned();
        result.neg_inplace();
        result
    }

    pub(crate) fn neg_inplace(&mut self) {
        self.additive_constant = -self.additive_constant;
        if !self.is_constant() {
            self.multiplicative_constant = -self.multiplicative_constant;
        }
    }

    pub fn sub<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let mut rhs = other.to_owned();

        rhs.additive_constant = -rhs.additive_constant;
        if !rhs.is_constant() {
            rhs.multiplicative_constant = -rhs.multiplicative_constant;
        }

        self.add(&rhs, builder, driver)
    }

    // this * to_mul + to_add
    pub fn madd<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        to_mul: &Self,
        to_add: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if to_mul.is_constant() && to_add.is_constant() && self.is_constant() {
            let mut mul = self.multiply(to_mul, builder, driver)?;
            mul.add_assign(to_add, builder, driver);
            return Ok(mul);
        }

        // Let:
        //    a = this;
        //    b = to_mul;
        //    c = to_add;
        //    a.v = ctx->variables[this.witness_index];
        //    b.v = ctx->variables[to_mul.witness_index];
        //    c.v = ctx->variables[to_add.witness_index];
        //    .mul = .multiplicative_constant;
        //    .add = .additive_constant.
        //
        // result = a * b + c
        //   = (a.v * a.mul + a.add) * (b.v * b.mul + b.add) + (c.v * c.mul + c.add)
        //   = a.v * b.v * [a.mul * b.mul] + a.v * [a.mul * b.add] + b.v * [b.mul + a.add] + c.v * [c.mul] +
        //     [a.add * b.add + c.add]
        //   = a.v * b.v * [     q_m     ] + a.v * [     q_1     ] + b.v * [     q_2     ] + c.v * [ q_3 ] + [ q_c ]

        let q_m = self.multiplicative_constant * to_mul.multiplicative_constant;
        let q_1 = self.multiplicative_constant * to_mul.additive_constant;
        let q_2 = to_mul.multiplicative_constant * self.additive_constant;
        let q_3 = to_add.multiplicative_constant;
        let q_c = self.additive_constant * to_mul.additive_constant + to_add.additive_constant;

        // Note: the value of a constant field_t is wholly tracked by the field_t's `additive_constant` member, which is
        // accounted for in the above-calculated selectors (`q_`'s). Therefore no witness (`variables[witness_index]`)
        // exists for constants, and so the field_t's corresponding wire value is set to `0` in the gate equation.

        let a = if self.is_constant() {
            T::public_zero()
        } else {
            builder.get_variable(self.witness_index as usize)
        };
        let b = if to_mul.is_constant() {
            T::public_zero()
        } else {
            builder.get_variable(to_mul.witness_index as usize)
        };
        let c = if to_add.is_constant() {
            T::public_zero()
        } else {
            builder.get_variable(to_add.witness_index as usize)
        };

        let mult_tmp = driver.mul(a.to_owned(), b.to_owned())?;
        let a_tmp = driver.mul_with_public(q_1, a);
        let b_tmp = driver.mul_with_public(q_2, b);
        let c_tmp = driver.mul_with_public(q_3, c);

        let mut out = driver.mul_with_public(q_m, mult_tmp);
        driver.add_assign(&mut out, a_tmp);
        driver.add_assign(&mut out, b_tmp);
        driver.add_assign(&mut out, c_tmp);
        driver.add_assign_with_public(q_c, &mut out);

        let result = Self::from_witness_index(builder.add_variable(out));

        builder.create_big_mul_gate(&MulQuad {
            a: if self.is_constant() {
                builder.zero_idx
            } else {
                self.witness_index
            },
            b: if to_mul.is_constant() {
                builder.zero_idx
            } else {
                to_mul.witness_index
            },
            c: if to_add.is_constant() {
                builder.zero_idx
            } else {
                to_add.witness_index
            },
            d: result.witness_index,
            mul_scaling: q_m,
            a_scaling: q_1,
            b_scaling: q_2,
            c_scaling: q_3,
            d_scaling: -F::one(),
            const_scaling: q_c,
        });

        Ok(result)
    }

    /**
     * @brief Splits the field element into (lo, hi), where:
     * - lo contains bits [0, lsb_index)
     * - hi contains bits [lsb_index, num_bits)
     */
    pub(crate) fn split_at<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        lsb_index: u8,
        num_bits: Option<u8>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<[Self; 2]> {
        const GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH: u8 = 252;
        let num_bits = num_bits.unwrap_or(GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH);

        assert!(lsb_index < num_bits);
        assert!(num_bits <= GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH);

        assert!(lsb_index < num_bits);
        assert!(num_bits <= GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH);

        let value = self.get_value(builder, driver);

        // Handle edge case when lsb_index == 0
        if lsb_index == 0 {
            if self.is_constant() {
                let hi_val = T::get_public(&value).expect("Constants are public");
                return Ok([FieldCT::default(), FieldCT::from(hi_val)]);
            } else {
                self.create_range_constraint(num_bits as usize, builder, driver)?;
                return Ok([FieldCT::default(), self.clone()]);
            }
        }

        let (hi, lo) = if T::is_shared(&value) {
            let value = T::get_shared(&value).expect("Already checked it is shared");
            // TACEO TODO: We are returning one more value than needed here
            let [lo, hi, _] =
                driver.slice(value, num_bits, lsb_index, F::MODULUS_BIT_SIZE as usize)?;
            (T::AcvmType::from(hi), T::AcvmType::from(lo))
        } else {
            let value: BigUint = T::get_public(&value)
                .expect("Already checked it is public")
                .into();

            let lo_mask = (BigUint::one() << lsb_index) - BigUint::one();
            let lo = &value & lo_mask;
            let hi = &value >> lsb_index;

            let hi_ = T::AcvmType::from(F::from(hi));
            let lo_ = T::AcvmType::from(F::from(lo));
            (hi_, lo_)
        };

        if self.is_constant() {
            // If `*this` is constant, we can return the split values directly
            let lo_val = T::get_public(&lo).expect("Constants are public");
            let hi_val = T::get_public(&hi).expect("Constants are public");

            let reconstructed = lo_val + (hi_val * F::from(BigUint::one() << lsb_index));
            let original = T::get_public(&value).expect("Constants are public");
            assert_eq!(reconstructed, original);

            return Ok([FieldCT::from(lo_val), FieldCT::from(hi_val)]);
        }

        let lo_wit = Self::from_witness(lo, builder);
        let hi_wit = Self::from_witness(hi, builder);

        // Ensure that `lo_wit` is in the range [0, 2^lsb_index - 1]
        lo_wit.create_range_constraint(lsb_index as usize, builder, driver)?;

        // Ensure that `hi_wit` is in the range [0, 2^(num_bits - lsb_index) - 1]
        hi_wit.create_range_constraint(num_bits as usize - lsb_index as usize, builder, driver)?;

        // Check that *this = lo_wit + hi_wit * 2^{lsb_index}
        let shift_factor = FieldCT::from(F::from(BigUint::one() << lsb_index));
        let hi_shifted = hi_wit.multiply(&shift_factor, builder, driver)?;
        let reconstructed = lo_wit.add(&hi_shifted, builder, driver);
        self.assert_equal(&reconstructed, builder, driver);

        Ok([lo_wit, hi_wit])
    }

    pub(crate) fn create_range_constraint<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        if num_bits == 0 {
            self.assert_is_zero(builder);
        } else if self.is_constant() {
            let val: BigUint = T::get_public(&self.get_value(builder, driver))
                .expect("Constants are public")
                .into();
            assert!((val.bits() as usize) < num_bits);
        } else {
            let index = self.get_witness_index(builder, driver);
            // We have plookup
            builder.decompose_into_default_range(
                driver,
                index,
                num_bits as u64,
                None,
                GenericUltraCircuitBuilder::<P, T>::DEFAULT_PLOOKUP_RANGE_BITNUM as u64,
            )?;
        }
        Ok(())
    }

    fn assert_is_zero<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) {
        if self.is_constant() {
            builder.assert_if_has_witness(self.additive_constant.is_zero());
            return;
        }

        let var = builder.get_variable(self.witness_index as usize);
        if !T::is_shared(&var) {
            // Sanity check
            let value = T::get_public(&var).expect("Already checked it is public");
            builder.assert_if_has_witness(
                (value * self.multiplicative_constant + self.additive_constant).is_zero(),
            )
        } else {
            // We set the share to a public value since we are asserting it is zero.
            let val = -self.additive_constant / self.multiplicative_constant;
            builder.update_variable(self.witness_index as usize, val.into());
        }

        builder.create_poly_gate(&PolyTriple {
            a: self.witness_index,
            b: builder.zero_idx,
            c: builder.zero_idx,
            q_m: P::ScalarField::zero(),
            q_l: self.multiplicative_constant,
            q_r: P::ScalarField::zero(),
            q_o: P::ScalarField::zero(),
            q_c: self.additive_constant,
        });
    }

    // if val == 0 ? 0 : val^-1
    fn zero_or_inverse<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        val: T::AcvmType,
        driver: &mut T,
    ) -> eyre::Result<T::AcvmType> {
        let is_zero = driver.equal(&val, &F::zero().into())?;
        let to_invert = driver.cmux(is_zero.to_owned(), F::one().into(), val)?;
        let inverse = driver.invert(to_invert)?;
        driver.cmux(is_zero, F::zero().into(), inverse)
    }

    // if val == 0 ? 1 : val^-1
    fn one_or_inverse_and_is_zero<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        val: T::AcvmType,
        driver: &mut T,
    ) -> eyre::Result<(T::AcvmType, T::AcvmType)> {
        let is_zero = driver.equal(&val, &F::zero().into())?;
        let to_invert = driver.cmux(is_zero.to_owned(), F::one().into(), val)?;
        let inverse = driver.invert(to_invert)?;
        Ok((inverse, is_zero))
    }

    pub(crate) fn assert_is_not_zero<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        if self.is_constant() {
            assert!(!self.additive_constant.is_zero());
            return Ok(());
        }

        let var = self.get_value(builder, driver);
        if !T::is_shared(&var) {
            // Sanity check
            let value = T::get_public(&var).expect("Already checked it is public");
            builder.assert_if_has_witness(!value.is_zero())
        }

        // if val == 0 ? 0 : val^-1
        let inverse = Self::zero_or_inverse::<P, T>(var, driver)?;

        let inverse = FieldCT::from_witness(inverse, builder);

        // Aim of new gate: `this` has an inverse (hence is not zero).
        // I.e.:
        //     (this.v * this.mul + this.add) * inverse.v == 1;
        // <=> this.v * inverse.v * [this.mul] + this.v * [ 0 ] + inverse.v * [this.add] + 0 * [ 0 ] + [ -1] == 0
        // <=> this.v * inverse.v * [   q_m  ] + this.v * [q_l] + inverse.v * [   q_r  ] + 0 * [q_o] + [q_c] == 0

        // (a * mul_const + add_const) * b - 1 = 0
        builder.create_poly_gate(&PolyTriple {
            a: self.witness_index,             // input value
            b: inverse.witness_index,          // inverse
            c: builder.zero_idx,               // no output
            q_m: self.multiplicative_constant, // a * b * mul_const
            q_l: P::ScalarField::zero(),       // a * 0
            q_r: self.additive_constant,       // b * mul_const
            q_o: P::ScalarField::zero(),       // c * 0
            q_c: -P::ScalarField::one(),       // -1
        });
        Ok(())
    }

    // if predicate == true then return lhs, else return rhs
    fn conditional_assign_internal<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        predicate: &BoolCT<P::ScalarField, T>,
        lhs: &Self,
        rhs: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if predicate.is_constant() {
            let val = T::get_public(&predicate.get_value(driver)).expect("Constants are public");
            if val.is_zero() {
                return Ok(rhs.to_owned());
            } else {
                return Ok(lhs.to_owned());
            }
        }
        // if lhs and rhs are the same witness, just return it!
        if lhs.witness_index == rhs.witness_index
            && (lhs.additive_constant == rhs.additive_constant)
            && (lhs.multiplicative_constant == rhs.multiplicative_constant)
        {
            return Ok(lhs.to_owned());
        }

        let diff = lhs.sub(rhs, builder, driver);
        diff.madd(&predicate.to_field_ct(driver), rhs, builder, driver)
    }

    pub(crate) fn conditional_assign<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        predicate: &BoolCT<P, T>,
        lhs: &Self,
        rhs: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        Ok(
            Self::conditional_assign_internal(predicate, lhs, rhs, builder, driver)?
                .normalize(builder, driver),
        )
    }

    pub(crate) fn evaluate_linear_identity<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        a: &FieldCT<F>,
        b: &FieldCT<F>,
        c: &FieldCT<F>,
        d: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        if a.is_constant() && b.is_constant() && c.is_constant() && d.is_constant() {
            let val_a = T::get_public(&a.get_value(builder, driver)).expect("Constants are public");
            let val_b = T::get_public(&b.get_value(builder, driver)).expect("Constants are public");
            let val_c = T::get_public(&c.get_value(builder, driver)).expect("Constants are public");
            let val_d = T::get_public(&d.get_value(builder, driver)).expect("Constants are public");
            assert!(val_a + val_b + val_c + val_d == F::zero());
            return;
        }

        // Validate that a + b + c + d = 0
        let q_1 = a.multiplicative_constant;
        let q_2 = b.multiplicative_constant;
        let q_3 = c.multiplicative_constant;
        let q_4 = d.multiplicative_constant;
        let q_c =
            a.additive_constant + b.additive_constant + c.additive_constant + d.additive_constant;

        builder.create_big_add_gate(
            &AddQuad {
                a: if a.is_constant() {
                    builder.zero_idx
                } else {
                    a.witness_index
                },
                b: if b.is_constant() {
                    builder.zero_idx
                } else {
                    b.witness_index
                },
                c: if c.is_constant() {
                    builder.zero_idx
                } else {
                    c.witness_index
                },
                d: if d.is_constant() {
                    builder.zero_idx
                } else {
                    d.witness_index
                },
                a_scaling: q_1,
                b_scaling: q_2,
                c_scaling: q_3,
                d_scaling: q_4,
                const_scaling: q_c,
            },
            false,
        );
    }

    pub(crate) fn evaluate_polynomial_identity<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        a: &Self,
        b: &Self,
        c: &Self,
        d: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        if a.is_constant() && b.is_constant() && c.is_constant() && d.is_constant() {
            let val_a = T::get_public(&a.get_value(builder, driver)).expect("Constants are public");
            let val_b = T::get_public(&b.get_value(builder, driver)).expect("Constants are public");
            let val_c = T::get_public(&c.get_value(builder, driver)).expect("Constants are public");
            let val_d = T::get_public(&d.get_value(builder, driver)).expect("Constants are public");
            let result = val_a * val_b + val_c + val_d;
            builder.assert_if_has_witness(result.is_zero());
            return;
        }

        // validate that a * b + c + d = 0
        let q_m = a.multiplicative_constant * b.multiplicative_constant;
        let q_1 = a.multiplicative_constant * b.additive_constant;
        let q_2 = b.multiplicative_constant * a.additive_constant;
        let q_3 = c.multiplicative_constant;
        let q_4 = d.multiplicative_constant;
        let q_c =
            a.additive_constant * b.additive_constant + c.additive_constant + d.additive_constant;

        builder.create_big_mul_gate(&MulQuad {
            a: if a.is_constant() {
                builder.zero_idx
            } else {
                a.witness_index
            },
            b: if b.is_constant() {
                builder.zero_idx
            } else {
                b.witness_index
            },
            c: if c.is_constant() {
                builder.zero_idx
            } else {
                c.witness_index
            },
            d: if d.is_constant() {
                builder.zero_idx
            } else {
                d.witness_index
            },
            mul_scaling: q_m,
            a_scaling: q_1,
            b_scaling: q_2,
            c_scaling: q_3,
            d_scaling: q_4,
            const_scaling: q_c,
        });
    }

    fn equals<P: CurveGroup<ScalarField = F>, T: NoirWitnessExtensionProtocol<F>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BoolCT<P::ScalarField, T>> {
        let sub = self.sub(other, builder, driver);
        sub.is_zero(builder, driver)
    }

    pub fn add_two<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        add_a: &Self,
        add_b: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let has_const_summand = self.is_constant() || add_a.is_constant() || add_b.is_constant();

        if has_const_summand {
            // If at least one of the summands is constant, the summation is efficiently handled by `+` operator
            return self.add(add_a, builder, driver).add(add_b, builder, driver);
        }

        // Let  d := a + (b+c), where
        //      a := *this;
        //      b := add_b;
        //      c := add_c;
        // define selector values by
        //      mul_scaling   :=  0
        //      a_scaling     :=  a_mul;
        //      b_scaling     :=  b_mul;
        //      c_scaling     :=  c_mul;
        //      d_scaling     :=  -1;
        //      const_scaling := a_add + b_add + c_add;
        // Create a `big_mul_gate` to constrain
        //  	a * b * mul_scaling + a * a_scaling + b * b_scaling + c * c_scaling + d * d_scaling + const_scaling = 0

        let a_scaling = self.multiplicative_constant;
        let b_scaling = add_a.multiplicative_constant;
        let c_scaling = add_b.multiplicative_constant;
        let const_scaling =
            self.additive_constant + add_a.additive_constant + add_b.additive_constant;

        let a = if self.is_constant() {
            T::public_zero()
        } else {
            builder.get_variable(self.witness_index as usize)
        };
        let b = if add_a.is_constant() {
            T::public_zero()
        } else {
            builder.get_variable(add_a.witness_index as usize)
        };
        let c = if add_b.is_constant() {
            T::public_zero()
        } else {
            builder.get_variable(add_b.witness_index as usize)
        };

        let mut out = driver.mul_with_public(a_scaling, a);
        let t0 = driver.mul_with_public(b_scaling, b);
        let t1 = driver.mul_with_public(c_scaling, c);
        driver.add_assign(&mut out, t0);
        driver.add_assign(&mut out, t1);
        driver.add_assign_with_public(const_scaling, &mut out);

        let index = builder.add_variable(out);
        let result = Self::from_witness_index(index);

        builder.create_big_mul_gate(&MulQuad {
            a: if self.is_constant() {
                builder.zero_idx
            } else {
                self.witness_index
            },
            b: if add_a.is_constant() {
                builder.zero_idx
            } else {
                add_a.witness_index
            },
            c: if add_b.is_constant() {
                builder.zero_idx
            } else {
                add_b.witness_index
            },
            d: result.witness_index,
            mul_scaling: F::zero(),
            a_scaling,
            b_scaling,
            c_scaling,
            d_scaling: -F::one(),
            const_scaling,
        });

        result
    }

    /*
     * @brief Validate whether a field_t element is zero.
     *
     * @details
     * Let     a   := (*this).normalize()
     *         is_zero := (a == 0)
     *
     * To check whether `a = 0`, we use the fact that, if `a != 0`, it has a modular inverse `I`, such that
     *         a * I =  1.
     *
     * We reduce the check to the following algebraic constraints
     * 1)      a * I - 1 + is_zero   = 0
     * 2)      -is_zero * I + is_zero = 0
     *
     * If the value of `is_zero` is `false`, the first equation reduces to
     *         a * I = 1
     * then `I` must be the modular inverse of `a`, therefore `a != 0`. This explains the first constraint.
     *
     * If `is_zero = true`, then either `a` or `I` is zero (or both). To ensure that
     *         a = 0 && I != 0
     * we use the second constraint, it validates that
     *         (is_zero.v = true) ==>  (I = 1)
     * This way, if `a * I = 0`, we know that a = 0.
     *
     * @warning  If you want to ENFORCE that a field_t object is zero, use `assert_is_zero`
     */
    pub fn is_zero<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BoolCT<P::ScalarField, T>> {
        if self.is_constant() {
            let val = self.get_value(builder, driver);
            let is_zero = T::get_public(&val).expect("Constants are public").is_zero();
            return Ok(BoolCT::from(is_zero));
        }

        let native_value = self.get_value(builder, driver);

        // This can be done out of circuit, as `is_zero = true` implies `I = 1`.
        let (is_zero, inverse) = if T::is_shared(&native_value) {
            let (inverse_val, is_zero) =
                Self::one_or_inverse_and_is_zero::<P, T>(native_value.to_owned(), driver)?;
            let is_zero_witness = WitnessCT::from_acvm_type(is_zero.to_owned(), builder);
            (
                BoolCT::from_witness_ct(is_zero_witness, builder),
                inverse_val,
            )
        } else {
            let val = T::get_public(&native_value).expect("Constants are public");
            let is_zero = val.is_zero();
            let inverse_val = if is_zero {
                F::one().into()
            } else {
                val.inverse().expect("non-zero").into()
            };
            let is_zero_witness =
                WitnessCT::from_acvm_type(F::from(is_zero as u64).into(), builder);
            (
                BoolCT::from_witness_ct(is_zero_witness, builder),
                inverse_val,
            )
        };
        let inverse = FieldCT::<F>::from(WitnessCT::from_acvm_type(inverse.to_owned(), builder));

        // Note that `evaluate_polynomial_identity(a, b, c, d)` checks that `a * b + c + d = 0`, so we are using it for the
        // constraints 1) and 2) above.
        // More precisely, to check that `a * I - 1 + is_zero   = 0`, it creates a `big_mul_gate` given by the equation:
        //      a.v * I.v * mul_scaling + a.v * a_scaling + I.v * b_scaling + is_zero.v * c_scaling + (-1) * d_scaling +
        //      const_scaling = 0
        // where
        //      muk_scaling := a.mul * I.mul;
        //      a_scaling := a.mul * I.add;
        //      b_scaling := I.mul * a.add;
        //      c_scaling := 1;
        //      d_scaling := 0;
        //      const_scaling := a.add * I.add + is_zero.add - 1;
        Self::evaluate_polynomial_identity(
            self,
            &inverse,
            &is_zero.to_field_ct(driver),
            &FieldCT::from(-F::one()),
            builder,
            driver,
        );

        // To check that `-is_zero * I + is_zero = 0`, create a `big_mul_gate` given by the equation:
        //      is_zero.v * (-I).v * mul_scaling + is_zero.v * a_scaling + (-I).v * b_scaling + is_zero.v * c_scaling + 0 *
        //      d_scaling + const_scaling = 0
        // where
        //      mul_scaling := is_zero.mul * (-I).mul;
        //      a_scaling := is_zero.mul * (-I).add;
        //      b_scaling := (-I).mul * is_zero.add;
        //      c_scaling := is_zero.mul;
        //      d_scaling := 0;
        //      const_scaling := is_zero.add * (-I).add + is_zero.add;
        Self::evaluate_polynomial_identity(
            &is_zero.to_field_ct(driver),
            &inverse.neg(),
            &is_zero.to_field_ct(driver),
            &FieldCT::default(),
            builder,
            driver,
        );

        Ok(is_zero)
    }

    /**
     * Create a witness from a constant. This way the value of the witness is fixed and public (public, because the
     * value becomes hard-coded as an element of the q_c selector vector).
     */
    pub fn convert_constant_to_fixed_witness<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        assert!(self.is_constant());
        let value = self.get_value(builder, driver);
        let witness = WitnessCT::from_acvm_type(value, builder);
        *self = FieldCT::from(witness);
        builder.fix_witness(
            self.witness_index,
            T::get_public(&self.get_value(builder, driver))
                .expect("Fixed witness should be public"),
        );
    }

    pub(crate) fn is_normalized(&self) -> bool {
        self.is_constant()
            || ((self.multiplicative_constant.is_one()) && (self.additive_constant.is_zero()))
    }

    /**
     * @brief Efficiently compute the sum of vector entries. Using `big_add_gate` we reduce the number of gates needed
     * to compute from `input.size()` to `input_size.size() / 3`.
     *
     * Note that if the size of the input vector is not a multiple of 3, the final gate will be padded with zero_idx wires
     */
    pub fn accumulate<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: &[FieldCT<F>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<F>> {
        if input.is_empty() {
            return Ok(FieldCT::from(F::zero()));
        }

        if input.len() == 1 {
            return Ok(input[0].normalize(builder, driver));
        }

        let mut accumulator = Vec::new();
        let mut constant_term = FieldCT::from(F::zero());

        // Remove constant terms from input field elements
        for element in input {
            if element.is_constant() {
                constant_term = constant_term.add(element, builder, driver);
            } else {
                accumulator.push(element.clone());
            }
        }
        if accumulator.is_empty() {
            return Ok(constant_term);
        }
        // Add the accumulated constant term to the first witness. It does not create any gates - only the additive
        // constant of `accumulator[0]` is updated.
        accumulator[0] = accumulator[0].add(&constant_term, builder, driver);

        // Step 2: compute output value
        let num_elements = accumulator.len();
        let mut output = T::AcvmType::default();
        for acc in &accumulator {
            let val = acc.get_value(builder, driver);
            driver.add_assign(&mut output, val);
        }

        // Pad the accumulator with zeroes so that its size is a multiple of 3.
        let num_padding_wires = if (num_elements % 3) == 0 {
            0
        } else {
            3 - (num_elements % 3)
        };
        for _ in 0..num_padding_wires {
            accumulator.push(FieldCT::from_witness_index(builder.zero_idx));
        }
        let num_elements = accumulator.len();
        let num_gates = num_elements / 3;
        // Last gate is handled separetely
        let last_gate_idx = num_gates - 1;

        let total = FieldCT::from_witness(output, builder);
        let mut accumulating_total = total.clone();

        // Let
        //      a_i := accumulator[3*i];
        //      b_i := accumulator[3*i+1];
        //      c_i := accumulator[3*i+2];
        //      d_0 := total;
        //      d_i := total - \sum_(j <  3*i) accumulator[j];
        // which leads us to equations
        //      d_{i+1} = d_{i} - a_i - b_i - c_i for i = 0, ..., last_idx - 1;
        //      0       = d_{i} - a_i - b_i - c_i for i = last_gate_idx,
        // that are turned into constraints below.

        for i in 0..last_gate_idx {
            // For i < last_gate_idx, we create a `big_add_gate` constraint
            //      a_i.v * a_scaling + b_i.v * b_scaling + c_i.v * c_scaling + d_i.v * d_scaling + const_scaling +
            //      w_4_omega = 0
            // where
            //      a_scaling       :=  a_i.mul
            //      b_scaling       :=  b_i.mul
            //      c_scaling       :=  c_i.mul
            //      d_scaling       := -1
            //      const_scaling   :=  a_i.add + b_i.add + c_i.add
            //      w_4_omega :=  d_{i+1}
            builder.create_big_add_gate(
                &AddQuad {
                    a: accumulator[3 * i].witness_index,
                    b: accumulator[3 * i + 1].witness_index,
                    c: accumulator[3 * i + 2].witness_index,
                    d: accumulating_total.witness_index,
                    a_scaling: accumulator[3 * i].multiplicative_constant,
                    b_scaling: accumulator[3 * i + 1].multiplicative_constant,
                    c_scaling: accumulator[3 * i + 2].multiplicative_constant,
                    d_scaling: -F::one(),
                    const_scaling: accumulator[3 * i].additive_constant
                        + accumulator[3 * i + 1].additive_constant
                        + accumulator[3 * i + 2].additive_constant,
                },
                true, // use_next_gate_w_4 = true
            );

            let new_total_val = {
                let acc_total = accumulating_total.get_value(builder, driver);
                let a_val = accumulator[3 * i].get_value(builder, driver);
                let b_val = accumulator[3 * i + 1].get_value(builder, driver);
                let c_val = accumulator[3 * i + 2].get_value(builder, driver);

                let mut new_total = driver.sub(acc_total, a_val);
                new_total = driver.sub(new_total, b_val);
                driver.sub(new_total, c_val)
            };
            accumulating_total = FieldCT::from_witness(new_total_val, builder);
        }

        // For i = last_gate_idx, we create a `big_add_gate` constraining
        //      a_i.v * a_scaling + b_i.v * b_scaling + c_i.v * c_scaling + d_i.v * d_scaling + const_scaling = 0
        builder.create_big_add_gate(
            &AddQuad {
                a: accumulator[3 * last_gate_idx].witness_index,
                b: accumulator[3 * last_gate_idx + 1].witness_index,
                c: accumulator[3 * last_gate_idx + 2].witness_index,
                d: accumulating_total.witness_index,
                a_scaling: accumulator[3 * last_gate_idx].multiplicative_constant,
                b_scaling: accumulator[3 * last_gate_idx + 1].multiplicative_constant,
                c_scaling: accumulator[3 * last_gate_idx + 2].multiplicative_constant,
                d_scaling: -F::one(),
                const_scaling: accumulator[3 * last_gate_idx].additive_constant
                    + accumulator[3 * last_gate_idx + 1].additive_constant
                    + accumulator[3 * last_gate_idx + 2].additive_constant,
            },
            false, // use_next_gate_w_4 = false
        );
        Ok(total.normalize(builder, driver))
    }
}

impl<F: PrimeField> From<F> for FieldCT<F> {
    fn from(value: F) -> Self {
        Self {
            additive_constant: value,
            multiplicative_constant: F::one(),
            witness_index: Self::IS_CONSTANT,
        }
    }
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> From<WitnessCT<F, T>> for FieldCT<F> {
    fn from(value: WitnessCT<F, T>) -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::one(),
            witness_index: value.witness_index,
        }
    }
}

impl<F: PrimeField> Default for FieldCT<F> {
    fn default() -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::one(),
            witness_index: Self::IS_CONSTANT,
        }
    }
}

pub struct WitnessCT<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> {
    pub(crate) witness: T::AcvmType,
    pub(crate) witness_index: u32,
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> WitnessCT<F, T> {
    #[expect(dead_code)]
    const IS_CONSTANT: u32 = FieldCT::<F>::IS_CONSTANT;

    pub fn from_acvm_type<P: CurveGroup<ScalarField = F>>(
        value: T::AcvmType,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> Self {
        let witness_index = builder.add_variable(value.to_owned());
        Self {
            witness: value,
            witness_index,
        }
    }
}

pub struct BoolCT<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> {
    pub(crate) witness_bool: T::AcvmType,
    pub(crate) witness_inverted: bool,
    pub(crate) witness_index: u32,
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> Debug for BoolCT<F, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoolCT")
            .field("witness_bool", &self.witness_bool)
            .field("witness_inverted", &self.witness_inverted)
            .field("witness_index", &self.witness_index)
            .finish()
    }
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> Default for BoolCT<F, T> {
    fn default() -> Self {
        Self {
            witness_bool: T::public_zero(),
            witness_inverted: false,
            witness_index: FieldCT::<F>::IS_CONSTANT,
        }
    }
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> Clone for BoolCT<F, T> {
    fn clone(&self) -> Self {
        Self {
            witness_bool: self.witness_bool.to_owned(),
            witness_inverted: self.witness_inverted,
            witness_index: self.witness_index,
        }
    }
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> From<bool> for BoolCT<F, T> {
    fn from(val: bool) -> Self {
        Self {
            witness_bool: F::from(val as u64).into(),
            witness_inverted: false,
            witness_index: FieldCT::<F>::IS_CONSTANT,
        }
    }
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> BoolCT<F, T> {

     pub(crate) fn get_witness_index<P: CurveGroup<ScalarField = F>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> u32 {
        self.normalize(builder, driver).witness_index
    }
    pub(crate) fn is_constant(&self) -> bool {
        self.witness_index == FieldCT::<F>::IS_CONSTANT
    }

    // It is assumed here that the value of the WitnessCT is boolean (secret-shared)
    pub fn from_witness_ct<P: CurveGroup<ScalarField = F>>(
        witness: WitnessCT<F, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> Self {
        builder.create_bool_gate(witness.witness_index);
        Self {
            witness_bool: witness.witness,
            witness_inverted: false,
            witness_index: witness.witness_index,
        }
    }

    pub fn get_value(&self, driver: &mut T) -> T::AcvmType {
        let mut result = self.witness_bool.to_owned();

        if self.witness_inverted {
            driver.negate_inplace(&mut result);
            driver.add_assign_with_public(F::one(), &mut result);
        }
        result
    }

    pub fn to_field_ct(&self, driver: &mut T) -> FieldCT<F> {
        if self.is_constant() {
            let value = T::get_public(&self.get_value(driver)).expect("Constants are public");
            let additive_constant = if self.witness_inverted {
                F::one() - value
            } else {
                value
            };
            let multiplicative_constant = F::one();
            FieldCT {
                additive_constant,
                multiplicative_constant,
                witness_index: FieldCT::<F>::IS_CONSTANT,
            }
        } else if self.witness_inverted {
            FieldCT {
                additive_constant: F::one(),
                multiplicative_constant: -F::one(),
                witness_index: self.witness_index,
            }
        } else {
            FieldCT {
                additive_constant: F::zero(),
                multiplicative_constant: F::one(),
                witness_index: self.witness_index,
            }
        }
    }

    fn conditional_assign<P: CurveGroup<ScalarField = F>>(
        predicate: &Self,
        lhs: &Self,
        rhs: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if predicate.is_constant() {
            let value = predicate.get_value(driver);
            let value = T::get_public(&value).expect("Constants are public");
            if value.is_zero() {
                return Ok(rhs.normalize(builder, driver).to_owned());
            } else {
                return Ok(lhs.normalize(builder, driver).to_owned());
            }
        }

        let same = lhs.witness_index == rhs.witness_index;

        let witness_same =
            same && !lhs.is_constant() && (lhs.witness_inverted == rhs.witness_inverted);

        let const_same = same && lhs.is_constant() && (lhs.witness_bool == rhs.witness_bool); // Both lhs and rhs are constants so we can just compare

        if witness_same || const_same {
            return Ok(lhs.normalize(builder, driver).to_owned());
        }

        // TACEO TODO: is this the correct order?
        let l = predicate.and(lhs, builder, driver)?;
        let r = predicate.not().and(rhs, builder, driver)?;
        Ok((l.or(&r, builder, driver)?).normalize(builder, driver))
    }

    fn assert_equal<P: CurveGroup<ScalarField = F>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        if self.is_constant() && other.is_constant() {
            assert_eq!(self.get_value(driver), other.get_value(driver)); // Both are public so we can just compare
        } else if self.is_constant() {
            // if rhs is inverted, flip the value of the lhs constant
            let value = T::get_public(&self.get_value(driver)).expect("Constants are public");
            let value = if other.witness_inverted {
                P::ScalarField::one() - value
            } else {
                value
            };
            builder.assert_equal_constant(other.witness_index as usize, value);
        } else if other.is_constant() {
            // if lhs is inverted, flip the value of the rhs constant
            let value = T::get_public(&other.get_value(driver)).expect("Constants are public");
            let value = if self.witness_inverted {
                P::ScalarField::one() - value
            } else {
                value
            };
            builder.assert_equal_constant(self.witness_index as usize, value);
        } else {
            let mut left = self.to_owned();
            let mut right = other.to_owned();
            // we need to normalize iff lhs or rhs has an inverted witness (but not both)
            if self.witness_inverted ^ other.witness_inverted {
                left = left.normalize(builder, driver);
                right = right.normalize(builder, driver);
            }
            builder.assert_equal(left.witness_index as usize, right.witness_index as usize);
        }
    }

    fn and<P: CurveGroup<ScalarField = F>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut result = BoolCT::default();

        let left = self.get_value(driver);
        let right = other.get_value(driver);

        if !self.is_constant() && !other.is_constant() {
            let value = driver.mul(left, right)?;
            result.witness_bool = value.to_owned();
            result.witness_index = builder.add_variable(value);

            // result.witness_inverted = false;

            //      /**
            //  * A bool can be represented by a witness value `w` and an 'inverted' flag `i`
            //  *
            //  * A bool's value is defined via the equation:
            //  *      w + i - 2.i.w
            //  *
            //  * | w | i | w + i - 2.i.w |
            //  * | - | - | ------------- |
            //  * | 0 | 0 |       0       |
            //  * | 0 | 1 |       1       |
            //  * | 1 | 0 |       1       |
            //  * | 1 | 1 |       0       |
            //  *
            //  * For two bools (w_a, i_a), (w_b, i_b), the & operation is expressed as:
            //  *
            //  *   (w_a + i_a - 2.i_a.w_a).(w_b + i_b - 2.i_b.w_b)
            //  *
            //  * This can be rearranged to:
            //  *
            //  *      w_a.w_b.(1 - 2.i_b - 2.i_a + 4.i_a.i_b)     -> q_m coefficient
            //  *    + w_a.(i_b.(1 - 2.i_a))                       -> q_1 coefficient
            //  *    + w_b.(i_a.(1 - 2.i_b))                       -> q_2 coefficient
            //  *    + i_a.i_b                                     -> q_c coefficient
            //  *
            //  **/
            let i_a = self.witness_inverted as i32;
            let i_b = other.witness_inverted as i32;

            let qm = 1 - 2 * i_b - 2 * i_a + 4 * i_a * i_b;
            let qm = if qm < 0 {
                -P::ScalarField::from(-qm)
            } else {
                P::ScalarField::from(qm)
            };
            let q1 = i_b * (1 - 2 * i_a);
            let q1 = if q1 < 0 {
                -P::ScalarField::from(-q1)
            } else {
                P::ScalarField::from(q1)
            };
            let q2 = i_a * (1 - 2 * i_b);
            let q2 = if q2 < 0 {
                -P::ScalarField::from(-q2)
            } else {
                P::ScalarField::from(q2)
            };
            let q3 = -P::ScalarField::one();
            let qc = P::ScalarField::from(i_a * i_b);
            builder.create_poly_gate(&PolyTriple {
                a: self.witness_index,
                b: other.witness_index,
                c: result.witness_index,
                q_m: qm,
                q_l: q1,
                q_r: q2,
                q_o: q3,
                q_c: qc,
            });
        } else if !self.is_constant() && other.is_constant() {
            let right = T::get_public(&right).expect("Constants are public");
            if right.is_one() {
                result = self.to_owned();
            }
            // else {
            //     result.witness_bool = false;
            //     result.witness_inverted = false;
            //     result.witness_index = IS_CONSTANT;
            // }
        } else if self.is_constant() && !other.is_constant() {
            let left = T::get_public(&left).expect("Constants are public");
            if left.is_one() {
                result = other.to_owned();
            }
            // else {
            //     result.witness_bool = false;
            //     result.witness_inverted = false;
            //     result.witness_index = IS_CONSTANT;
            // }
        } else {
            let val1 = T::get_public(&left).expect("Constants are public");
            let val2 = T::get_public(&right).expect("Constants are public");
            let value = T::AcvmType::from(val1 * val2);
            result.witness_bool = value;
            // result.witness_index = IS_CONSTANT;
            // result.witness_inverted = false;
        }

        Ok(result)
    }

    fn or<P: CurveGroup<ScalarField = F>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut result = BoolCT::default();

        let left = self.get_value(driver);
        let right = other.get_value(driver);

        // Or = a + b - a*b
        let mul = driver.mul(left.to_owned(), right.to_owned())?;
        let add = driver.add(left.to_owned(), right.to_owned());
        let value = driver.sub(add, mul);

        result.witness_bool = value.to_owned();
        // result.witness_inverted = false;

        if !self.is_constant() && !other.is_constant() {
            result.witness_index = builder.add_variable(value);
            // Let
            //      a := lhs = *this;
            //      b := rhs = other;
            // The result is given by
            //      a + b - a * b =  [-(1 - 2*i_a) * (1 - 2*i_b)] * w_a w_b +
            //                        [(1 - 2 * i_a) * (1 - i_b)] * w_a
            //                        [(1 - 2 * i_b) * (1 - i_a)] * w_b
            //                            [i_a + i_b - i_a * i_b] * 1
            let rhs_inverted = other.witness_inverted as i32;
            let lhs_inverted = self.witness_inverted as i32;

            let q_m = P::ScalarField::from(-(1 - 2 * rhs_inverted) * (1 - 2 * lhs_inverted));
            let q_l = P::ScalarField::from((1 - 2 * lhs_inverted) * (1 - rhs_inverted));
            let q_r = P::ScalarField::from((1 - lhs_inverted) * (1 - 2 * rhs_inverted));
            let q_o = -P::ScalarField::one();
            let q_c =
                P::ScalarField::from(rhs_inverted + lhs_inverted - rhs_inverted * lhs_inverted);

            // Let r := a | b;
            // Constrain
            //      q_m * w_a * w_b + q_l * w_a + q_r * w_b + q_o * r + q_c = 0
            builder.create_poly_gate(&PolyTriple {
                a: self.witness_index,
                b: other.witness_index,
                c: result.witness_index,
                q_m,
                q_l,
                q_r,
                q_o,
                q_c,
            });
        } else if !self.is_constant() && other.is_constant() {
            assert!(!other.witness_inverted);
            // If we are computing a | b and b is a constant `true`, the result is a constant `true` that does not
            // depend on `a`.
            result = if T::get_public(&other.witness_bool)
                .expect("Constants are public")
                .is_zero()
            {
                self.to_owned()
            } else {
                other.to_owned()
            };
        } else if self.is_constant() && !other.is_constant() {
            assert!(!self.witness_inverted);
            // If we are computing a | b and `a` is a constant `true`, the result is a constant `true` that does not
            // depend on `b`.
            result = if T::get_public(&self.witness_bool)
                .expect("Constants are public")
                .is_zero()
            {
                other.to_owned()
            } else {
                self.to_owned()
            };
        }

        Ok(result)
    }

    fn not(&self) -> Self {
        let mut result = self.to_owned();
        if result.is_constant() {
            result.witness_bool = (F::one()
                - T::get_public(&result.witness_bool).expect("Constants are public"))
            .into();

            return result;
        }
        result.witness_inverted = !result.witness_inverted;
        result
    }

    fn equals<P: CurveGroup<ScalarField = F>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if other.is_constant() && self.is_constant() {
            let self_value = T::get_public(&self.get_value(driver)).expect("Constants are public");
            let other_value =
                T::get_public(&other.get_value(driver)).expect("Constants are public");
            let result = BoolCT::from(self_value == other_value);
            Ok(result)
        } else if !self.is_constant() && other.is_constant() {
            let other_value =
                T::get_public(&other.get_value(driver)).expect("Constants are public");
            if other_value.is_one() {
                Ok(self.to_owned())
            } else {
                Ok(self.not())
            }
        } else if self.is_constant() && !other.is_constant() {
            let self_value = T::get_public(&self.get_value(driver)).expect("Constants are public");
            if self_value.is_one() {
                Ok(other.to_owned())
            } else {
                Ok(other.not())
            }
        } else {
            let mut result = BoolCT::default();
            let self_value = self.get_value(driver);
            let other_value = other.get_value(driver);
            let value = driver.equal(&self_value, &other_value)?;
            result.witness_bool = value.to_owned();
            result.witness_index = builder.add_variable(value);
            // norm a, norm b or both inv: 1 - a - b + 2ab
            // inv a or inv b = a + b - 2ab
            let multiplicative_coefficient;
            let left_coefficient;
            let right_coefficient;
            let constant_coefficient;
            if (self.witness_inverted && other.witness_inverted)
                || (!self.witness_inverted && !other.witness_inverted)
            {
                multiplicative_coefficient = P::ScalarField::from(2);
                left_coefficient = -P::ScalarField::one();
                right_coefficient = -P::ScalarField::one();
                constant_coefficient = P::ScalarField::one();
            } else {
                multiplicative_coefficient = -P::ScalarField::from(2);
                left_coefficient = P::ScalarField::one();
                right_coefficient = P::ScalarField::one();
                constant_coefficient = P::ScalarField::zero();
            }
            builder.create_poly_gate(&PolyTriple {
                a: self.witness_index,
                b: other.witness_index,
                c: result.witness_index,
                q_m: multiplicative_coefficient,
                q_l: left_coefficient,
                q_r: right_coefficient,
                q_o: -P::ScalarField::one(),
                q_c: constant_coefficient,
            });

            Ok(result)
        }
    }

    pub(crate) fn normalize<P: CurveGroup<ScalarField = F>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        if self.is_constant() {
            assert!(!self.witness_inverted);
            return self.to_owned();
        }

        if !self.witness_inverted {
            return self.to_owned();
        }

        let value = self.get_value(driver);
        let new_witness = builder.add_variable(value.to_owned());
        let new_value = value;

        let (q_l, q_c) = if self.witness_inverted {
            (-P::ScalarField::one(), P::ScalarField::one())
        } else {
            (P::ScalarField::one(), P::ScalarField::zero())
        };
        let q_o = -P::ScalarField::one();
        let q_m = P::ScalarField::zero();
        let q_r = P::ScalarField::zero();
        builder.create_poly_gate(&PolyTriple {
            a: self.witness_index,
            b: self.witness_index,
            c: new_witness,
            q_m,
            q_l,
            q_r,
            q_o,
            q_c,
        });

        Self {
            witness_bool: new_value,
            witness_inverted: false,
            witness_index: new_witness,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CycleGroupCT<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) x: FieldCT<P::ScalarField>,
    pub(crate) y: FieldCT<P::ScalarField>,
    pub(crate) is_infinity: BoolCT<P::ScalarField, T>,
    pub(crate) is_standard: bool,
    pub(crate) is_constant: bool,
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> Clone for CycleGroupCT<P, T> {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            is_infinity: self.is_infinity.clone(),
            is_standard: self.is_standard,
            is_constant: self.is_constant,
        }
    }
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> CycleGroupCT<P, T> {
    const ULTRA_NUM_TABLE_BITS: usize = 4;
    const TABLE_BITS: usize = Self::ULTRA_NUM_TABLE_BITS;

    pub(crate) fn new(
        x: FieldCT<P::ScalarField>,
        y: FieldCT<P::ScalarField>,
        is_infinity: BoolCT<P::ScalarField, T>,
        driver: &mut T,
    ) -> Self {
        let is_standard = is_infinity.is_constant();
        let is_constant = x.is_constant() && y.is_constant() && is_standard;

        if is_standard
            && !T::get_public(&is_infinity.get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            return Self::default();
        }

        Self {
            x,
            y,
            is_infinity,
            is_standard,
            is_constant,
        }
    }

    pub(crate) fn new_from_parts(x: P::ScalarField, y: P::ScalarField, is_infinity: bool) -> Self {
        if is_infinity {
            return Self::default();
        }
        let x = FieldCT::from(x);
        let y = FieldCT::from(y);
        let is_infinity = BoolCT::from(false);

        // TACEO TODO: We should assert a valid point here

        Self {
            x,
            y,
            is_infinity,
            is_standard: true,
            is_constant: true,
        }
    }

    pub(crate) fn standardize(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        assert!(
            self.is_constant()
                == (self.x.is_constant() && self.y.is_constant() && self.is_infinity.is_constant())
        );
        if self.is_infinity.is_constant()
            && !T::get_public(&self.is_infinity.get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            assert!(self.is_constant && self.is_standard);
        }

        if self.is_standard {
            return Ok(());
        }

        self.is_standard = true;
        let zero = FieldCT::default();
        self.x = FieldCT::conditional_assign(&self.is_infinity, &zero, &self.x, builder, driver)?;
        self.y = FieldCT::conditional_assign(&self.is_infinity, &zero, &self.y, builder, driver)?;

        Ok(())
    }

    pub(crate) fn get_standard_form(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut result = self.clone();
        result.standardize(builder, driver)?;
        Ok(result)
    }

    pub(crate) fn is_point_at_infinity(&self) -> &BoolCT<P::ScalarField, T> {
        &self.is_infinity
    }

    #[expect(dead_code)]
    pub(crate) fn set_point_at_infinity(
        &mut self,
        is_infinity: BoolCT<P::ScalarField, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        assert!(
            self.is_constant()
                == (self.x.is_constant() && self.y.is_constant() && self.is_infinity.is_constant())
        );

        self.is_standard = true;

        if is_infinity.is_constant() && self.is_infinity.is_constant() {
            // Check that it's not possible to enter the case when
            // The point is already infinity, but `is_infinity` = false
            let self_val =
                T::get_public(&self.is_infinity.get_value(driver)).expect("Constants are public");
            let other_val =
                T::get_public(&is_infinity.get_value(driver)).expect("Constants are public");
            assert!(self_val == other_val || !self_val.is_zero());

            if !other_val.is_zero() {
                self.x = FieldCT::default();
                self.y = FieldCT::default();
                self.is_infinity = BoolCT::from(true);
                self.is_constant = true;
                return Ok(());
            }
        }

        if is_infinity.is_constant() && !self.is_infinity.is_constant() {
            let other_val =
                T::get_public(&is_infinity.get_value(driver)).expect("Constants are public");
            if other_val.is_zero() {
                self.is_infinity
                    .assert_equal(&BoolCT::from(false), builder, driver);
                self.is_infinity = BoolCT::from(false);
            } else {
                self.x = FieldCT::default();
                self.y = FieldCT::default();
                self.is_infinity = BoolCT::from(true);
                self.is_constant = true;
                return Ok(());
            }
            return Ok(());
        }

        if self.is_infinity.is_constant()
            && !T::get_public(&self.is_infinity.get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            // I can't imagine this case happening, but still
            is_infinity.assert_equal(&BoolCT::from(true), builder, driver);

            self.x = FieldCT::default();
            self.y = FieldCT::default();
            self.is_constant = true;
            return Ok(());
        }

        let zero = FieldCT::default();
        self.x = FieldCT::conditional_assign(&is_infinity, &zero, &self.x, builder, driver)?;
        self.y = FieldCT::conditional_assign(&is_infinity, &zero, &self.y, builder, driver)?;

        // We won't bump into the case where we end up with non constant coordinates
        assert!(!self.x.is_constant() && !self.y.is_constant());
        self.is_constant = false;

        // We have to check this to avoid the situation, where we change the infinity
        let equal = self.is_infinity.equals(&is_infinity, builder, driver)?;
        let set_allowed = equal.or(&is_infinity, builder, driver)?;

        set_allowed.assert_equal(&BoolCT::from(true), builder, driver);
        self.is_infinity = is_infinity;

        Ok(())
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.is_constant
    }
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> Default
    for CycleGroupCT<P, T>
{
    fn default() -> Self {
        Self {
            x: FieldCT::default(),
            y: FieldCT::default(),
            is_infinity: BoolCT::from(true),
            is_constant: true,
            is_standard: true,
        }
    }
}

impl<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>>
    CycleGroupCT<P, T>
{
    const OFFSET_GENERATOR_DOMAIN_SEPARATOR: &[u8] = "cycle_group_offset_generator".as_bytes();

    pub(crate) fn new_with_assert(
        x: FieldCT<P::ScalarField>,
        y: FieldCT<P::ScalarField>,
        is_infinity: BoolCT<P, T>,
        assert_on_curve: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let is_standard = is_infinity.is_constant();
        let is_constant = x.is_constant() && y.is_constant() && is_standard;

        if is_standard
            && !T::get_public(&is_infinity.get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            return Ok(Self::default());
        }

        let res = Self {
            x,
            y,
            is_infinity,
            is_standard,
            is_constant,
        };

        if assert_on_curve {
            res.validate_on_curve(builder, driver)?;
        }
        Ok(res)
    }

    /// Validates that the point is on the curve (short Weierstrass: y^2 = x^3 + b, with a = 0).
    pub(crate) fn validate_on_curve(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        // This class is for short Weierstrass curves only!
        // static_assert(Group::curve_a == 0); // In Rust, we assume curve_a == 0

        let xx = self.x.multiply(&self.x, builder, driver)?;
        let xxx = xx.multiply(&self.x, builder, driver)?;
        let curve_b = FieldCT::from(P::get_curve_b());
        let rhs = xxx.add(&curve_b, builder, driver);
        let mut res = self.y.madd(&self.y, &rhs.neg(), builder, driver)?;

        // If this is the point at infinity, then res is changed to 0, otherwise it remains unchanged
        let is_not_infinity = self.is_point_at_infinity().not();
        res = res.multiply(&is_not_infinity.to_field_ct(driver), builder, driver)?;

        res.assert_is_zero(builder);

        Ok(())
    }

    fn from_group_element(value: P::CycleGroup) -> Self {
        match value.into_affine().xy() {
            Some((x, y)) => Self {
                x: FieldCT::from(x),
                y: FieldCT::from(y),
                is_infinity: BoolCT::from(false),
                is_constant: true,
                is_standard: true,
            },
            None => Self {
                x: FieldCT::default(),
                y: FieldCT::default(),
                is_infinity: BoolCT::from(true),
                is_constant: true,
                is_standard: true,
            },
        }
    }

    fn from_constant_witness(
        inp: P::CycleGroup,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let mut result = Self::default();

        // Point at infinity's coordinates break our arithmetic
        // Since we are not using these coordinates anyway
        // We can set them both to be zero
        if inp.is_zero() {
            result.x = FieldCT::default();
            result.y = FieldCT::default();
            result.is_constant = true;
        } else {
            let (x, y) = inp.into_affine().xy().expect("Non-zero");
            result.x = FieldCT::from_witness(x.into(), builder);
            result.y = FieldCT::from_witness(y.into(), builder);
            result.x.assert_equal(&FieldCT::from(x), builder, driver);
            result.y.assert_equal(&FieldCT::from(y), builder, driver);
            result.is_constant = false;
        }

        // point at infinity is circuit constant
        result.is_infinity = BoolCT::from(inp.is_zero());
        result.is_standard = true;
        result
    }

    fn get_value(
        &self,
        builder: &GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<T::AcvmPoint<P::CycleGroup>> {
        let x = self.x.get_value(builder, driver);
        let y = self.y.get_value(builder, driver);
        let is_infinity = self.is_infinity.get_value(driver);

        driver.field_shares_to_pointshare::<P::CycleGroup>(x, y, is_infinity)
    }

    pub(crate) fn batch_mul(
        base_points: Vec<Self>,
        scalars: Vec<CycleScalarCT<P::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        debug_assert_eq!(base_points.len(), scalars.len());

        let mut variable_base_scalars = Vec::new();
        let mut variable_base_points = Vec::new();
        let mut fixed_base_scalars = Vec::new();
        let mut fixed_base_points = Vec::new();

        let num_bits = scalars[0].num_bits();
        for scalar in scalars.iter() {
            assert_eq!(
                num_bits,
                scalar.num_bits(),
                "All scalars must have the same bit length"
            );
        }

        let num_bits_not_full_field_size = num_bits != CycleScalarCT::<P::ScalarField>::NUM_BITS;

        // When calling `_variable_base_batch_mul_internal`, we can unconditionally add iff all of the input points
        // are fixed-base points
        // (i.e. we are ULTRA Builder and we are doing fixed-base mul over points not present in our plookup tables)
        let mut can_unconditional_add = true;
        let mut has_non_constant_component = false;

        let mut constant_acc = P::CycleGroup::zero();
        for (point, scalar) in base_points.iter().zip(scalars.iter()) {
            let scalar_constant = scalar.is_constant();
            let point_constant = point.is_constant();

            if scalar_constant && point_constant {
                let scalar_val = scalar.get_constant_value(builder, driver);
                let point_val = point.get_value(builder, driver)?;

                let point_val = T::get_public_point(&point_val).expect("Constants are public");
                constant_acc += point_val * scalar_val;
            } else if !scalar_constant && point_constant {
                let point_val = point.get_value(builder, driver)?;
                let point_val = T::get_public_point(&point_val).expect("Constants are public");
                if point_val.is_zero() {
                    // oi mate, why are you creating a circuit that multiplies a known point at infinity?
                    continue;
                }
                // We are a UltraCircuit
                if !num_bits_not_full_field_size
                    && Plookup::lookup_table_exists_for_point::<P>(point_val.into())
                {
                    fixed_base_scalars.push(scalar.to_owned());
                    fixed_base_points.push(point_val);
                } else {
                    // womp womp. We have lookup tables at home. ROM tables.
                    variable_base_scalars.push(scalar.to_owned());
                    variable_base_points.push(point.to_owned());
                }
                has_non_constant_component = true;
            } else {
                variable_base_scalars.push(scalar.to_owned());
                variable_base_points.push(point.to_owned());
                can_unconditional_add = false;
                has_non_constant_component = true;
                // variable base
            }
        }

        // If all inputs are constant, return the computed constant component and call it a day.
        if !has_non_constant_component {
            let result = CycleGroupCT::from_group_element(constant_acc);
            return Ok(result);
        }

        // add the constant component into our offset accumulator
        // (we'll subtract `offset_accumulator` from the MSM output i.e. we negate here to counter the future negation)
        let mut offset_accumulator = -constant_acc;
        let has_variable_points = !variable_base_points.is_empty();
        let has_fixed_points = !fixed_base_points.is_empty();

        let mut result = CycleGroupCT::default();

        if has_fixed_points {
            let (fixed_accumulator, offset_generator_delta) = Self::fixed_base_batch_mul_internal(
                &fixed_base_scalars,
                &fixed_base_points,
                builder,
                driver,
            )?;
            offset_accumulator += offset_generator_delta;
            result = fixed_accumulator;
        }

        if has_variable_points {
            // Compute all required offset generators.
            let num_offset_generators = variable_base_points.len() + 1;
            let offset_generators = generators::derive_generators::<P::CycleGroup>(
                Self::OFFSET_GENERATOR_DOMAIN_SEPARATOR,
                num_offset_generators,
                0,
            );

            let (variable_accumulator, offset_generator_delta) =
                Self::variable_base_batch_mul_internal(
                    &variable_base_scalars,
                    &variable_base_points,
                    &offset_generators,
                    can_unconditional_add,
                    builder,
                    driver,
                )?;
            offset_accumulator += offset_generator_delta;
            if has_fixed_points {
                result = if can_unconditional_add {
                    result.unconditional_add(&variable_accumulator, None, builder, driver)?
                } else {
                    result.checked_unconditional_add(
                        &variable_accumulator,
                        None,
                        builder,
                        driver,
                    )?
                };
            } else {
                result = variable_accumulator;
            }
        }

        // Update `result` to remove the offset generator terms, and add in any constant terms from `constant_acc`.
        // We have two potential modes here:
        // 1. All inputs are fixed-base and we constant_acc is not the point at infinity
        // 2. Everything else.
        // Case 1 is a special case, as we *know* we cannot hit incomplete addition edge cases,
        // under the assumption that all input points are linearly independent of one another.
        // Because constant_acc is not the point at infnity we know that at least 1 input scalar was not zero,
        // i.e. the output will not be the point at infinity. We also know under case 1, we won't trigger the
        // doubling formula either, as every point is lienarly independent of every other point (including offset
        // generators).
        if !constant_acc.is_zero() && can_unconditional_add {
            result = result.unconditional_add(
                &CycleGroupCT::from_group_element(-offset_accumulator),
                None,
                builder,
                driver,
            )?;
        } else {
            // For case 2, we must use a full subtraction operation that handles all possible edge cases, as the output
            // point may be the point at infinity.
            // TODO(@zac-williamson) We can probably optimize this a bit actually. We might hit the point at infinity,
            // but an honest prover won't trigger the doubling edge case.
            // (doubling edge case implies input points are also the offset generator points,
            // which we can assume an honest Prover will not do if we make this case produce unsatisfiable constraints)
            // We could do the following:
            // 1. If x-coords match, assert y-coords do not match
            // 2. If x-coords match, return point at infinity, else return result - offset_accumulator.
            // This would be slightly cheaper than operator- as we do not have to evaluate the double edge case.
            result = result.sub(
                &CycleGroupCT::from_group_element(offset_accumulator),
                builder,
                driver,
            )?;
        }

        Ok(result)
    }

    fn fixed_base_batch_mul_internal(
        scalars: &[CycleScalarCT<P::ScalarField>],
        base_points: &[P::CycleGroup],
        // offset_generators: &[<P::CycleGroup as CurveGroup>::Affine],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(CycleGroupCT<P, T>, P::CycleGroup)> {
        debug_assert_eq!(scalars.len(), base_points.len());

        let num_points = base_points.len();
        let mut plookup_table_ids = Vec::with_capacity(num_points * 2);
        let mut plookup_base_points = Vec::with_capacity(num_points * 2);
        let mut plookup_scalars = Vec::with_capacity(num_points * 2);

        for (scalar, point) in scalars.iter().zip(base_points.iter()) {
            let table_id = Plookup::get_lookup_table_ids_for_point::<P>(point.to_owned().into())
                .expect("This function is only called when these exist");
            plookup_table_ids.push(table_id.0);
            plookup_table_ids.push(table_id.1);
            plookup_base_points.push(point.to_owned());
            let point2 = *point
                * <<P::CycleGroup as CurveGroup>::Config as CurveConfig>::ScalarField::from(
                    BigUint::one() << CycleScalarCT::<P::ScalarField>::LO_BITS,
                );
            plookup_base_points.push(point2);
            plookup_scalars.push(scalar.lo.to_owned());
            plookup_scalars.push(scalar.hi.to_owned());
        }

        let mut lookup_points = Vec::new();
        let mut offset_generator_accumulator = P::CycleGroup::zero();
        let zero_ct = FieldCT::default();
        for (id, scalar) in plookup_table_ids.into_iter().zip(plookup_scalars) {
            let lookup_data = Plookup::get_lookup_accumulators_ct(
                builder,
                driver,
                id.to_owned(),
                &scalar,
                &zero_ct,
                false,
            )?;
            for j in 0..lookup_data[ColumnIdx::C2].len() {
                let x = lookup_data[ColumnIdx::C2][j].to_owned();
                let y = lookup_data[ColumnIdx::C3][j].to_owned();
                lookup_points.push(CycleGroupCT::new(x, y, BoolCT::from(false), driver));
            }

            let offset_1 =
                Plookup::get_generator_offset_for_table_id::<P>(id).expect("Must have a value");
            offset_generator_accumulator += offset_1;
        }

        // /**
        //  * Compute the witness values of the batch_mul algorithm natively, as Element types with a Z-coordinate.
        //  * We then batch-convert to AffineElement types, and feed these points as "hints" into the cycle_group methods.
        //  * This avoids the need to compute modular inversions for every group operation, which dramatically reduces witness
        //  * generation times
        //  */
        let mut operation_transcript = Vec::with_capacity(lookup_points.len() - 1);
        let mut accumulator = lookup_points[0].get_value(builder, driver)?;
        for point in lookup_points.iter().skip(1) {
            let point = point.get_value(builder, driver)?;
            accumulator = driver.add_points(accumulator, point);
            operation_transcript.push(accumulator.to_owned());
        }

        // BB batch normalizes all
        let operation_hints = operation_transcript;

        let mut accumulator = lookup_points[0].to_owned();
        // Perform all point additions sequentially. The Ultra ecc_addition relation costs 1 gate iff additions are chained
        // and output point of previous addition = input point of current addition.
        // If this condition is not met, the addition relation costs 2 gates. So it's good to do these sequentially!
        for (point, hint) in lookup_points.into_iter().skip(1).zip(operation_hints) {
            accumulator = accumulator.unconditional_add(&point, Some(hint), builder, driver)?;
        }
        // /**
        //  * offset_generator_accumulator represents the sum of all the offset generator terms present in `accumulator`.
        //  * We don't subtract off yet, as we may be able to combine `offset_generator_accumulator` with other constant terms
        //  * in `batch_mul` before performing the subtraction.
        //  */
        Ok((accumulator, offset_generator_accumulator))
    }

    fn variable_base_batch_mul_internal(
        scalars: &[CycleScalarCT<P::ScalarField>],
        base_points: &[CycleGroupCT<P, T>],
        offset_generators: &[<P::CycleGroup as CurveGroup>::Affine],
        unconditional_add: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(CycleGroupCT<P, T>, P::CycleGroup)> {
        debug_assert_eq!(scalars.len(), base_points.len());

        let num_bits = scalars[0].num_bits();
        for s in scalars.iter() {
            assert_eq!(
                s.num_bits(),
                num_bits,
                "Scalars of different bit-lengths not supported!"
            );
        }

        let num_rounds = num_bits.div_ceil(Self::TABLE_BITS);
        let num_points = scalars.len();
        let table_size = (1 << Self::TABLE_BITS) as usize;

        let mut scalar_slices = Vec::with_capacity(num_points);

        for scalar in scalars.iter() {
            scalar_slices.push(StrausScalarSlice::new(
                scalar,
                Self::TABLE_BITS,
                builder,
                driver,
            )?);
        }
        // /**
        //  * Compute the witness values of the batch_mul algorithm natively, as Element types with a Z-coordinate.
        //  * We then batch-convert to AffineElement types, and feed these points as "hints" into the cycle_group methods.
        //  * This avoids the need to compute modular inversions for every group operation, which dramatically reduces witness
        //  * generation times
        //  */
        let mut operation_transcript =
            Vec::with_capacity(Self::TABLE_BITS + num_rounds * num_points);
        let mut offset_generator_accumulator: P::CycleGroup =
            offset_generators[0].to_owned().into();

        // Construct native straus lookup table for each point
        let mut native_straus_tables = Vec::with_capacity(num_points);
        for i in 0..num_points {
            let table_transcript = StrausLookupTable::<P, T>::compute_native_table(
                base_points[i].get_value(builder, driver)?,
                offset_generators[i + 1].to_owned(),
                Self::TABLE_BITS,
                driver,
            )?;
            // Skip the first element (offset generator), push the rest into operation_transcript
            for hint in table_transcript.iter().skip(1) {
                operation_transcript.push(hint.to_owned());
            }
            native_straus_tables.push(table_transcript);
        }

        // We translate the Point LUTs to field luts
        // TACEO TODO this whole process could be batched
        let mut native_straus_tables_x = Vec::with_capacity(native_straus_tables.len());
        let mut native_straus_tables_y = Vec::with_capacity(native_straus_tables.len());
        let mut native_straus_tables_i = Vec::with_capacity(native_straus_tables.len());
        for native_straus_table in native_straus_tables.into_iter() {
            let mut x_table = Vec::with_capacity(native_straus_table.len());
            let mut y_table = Vec::with_capacity(native_straus_table.len());
            let mut i_table = Vec::with_capacity(native_straus_table.len());
            for val in native_straus_table.into_iter() {
                let (x, y, i) = driver.pointshare_to_field_shares(val)?;
                x_table.push(x);
                y_table.push(y);
                i_table.push(i);
            }
            native_straus_tables_x.push(driver.init_lut_by_acvm_type(x_table));
            native_straus_tables_y.push(driver.init_lut_by_acvm_type(y_table));
            native_straus_tables_i.push(driver.init_lut_by_acvm_type(i_table));
        }

        // Perform the Straus algorithm natively to generate the witness values (hints) for all intermediate points
        let accumulator: P::CycleGroup = offset_generators[0].to_owned().into();
        let mut accumulator = T::AcvmPoint::from(accumulator);
        for i in 0..num_rounds {
            if i != 0 {
                for _ in 0..Self::TABLE_BITS {
                    // offset_generator_accumulator is a regular Element, so dbl() won't add constraints
                    accumulator = driver.add_points(accumulator.to_owned(), accumulator);
                    operation_transcript.push(accumulator.to_owned());
                    offset_generator_accumulator += offset_generator_accumulator;
                }
            }

            for (
                scalar_sclice,
                native_straus_table_x,
                native_straus_table_y,
                native_straus_table_i,
                offset_generator,
            ) in izip!(
                scalar_slices.iter(),
                native_straus_tables_x.iter(),
                native_straus_tables_y.iter(),
                native_straus_tables_i.iter(),
                offset_generators.iter().skip(1)
            ) {
                let index = scalar_sclice.slices_native[num_rounds - i - 1].to_owned();

                // TACEO TODO batch the reads
                let x = driver.read_lut_by_acvm_type(index.to_owned(), native_straus_table_x)?;
                let y = driver.read_lut_by_acvm_type(index.to_owned(), native_straus_table_y)?;
                let i = driver.read_lut_by_acvm_type(index, native_straus_table_i)?;
                let point = driver.field_shares_to_pointshare::<P::CycleGroup>(x, y, i)?;
                accumulator = driver.add_points(accumulator, point);
                operation_transcript.push(accumulator.to_owned());
                offset_generator_accumulator += offset_generator;
            }
        }

        // BB batch normalizes operation_transcript here
        let operation_hints = operation_transcript;

        let mut point_tables = Vec::with_capacity(num_points);
        let hints_per_table = table_size - 1;
        for (i, (point, offset_generator)) in
            izip!(base_points.iter(), offset_generators.iter().skip(1)).enumerate()
        {
            // Get the slice of hints for this table
            let table_hints =
                operation_hints[i * hints_per_table..(i + 1) * hints_per_table].to_vec();
            let lookup_table = StrausLookupTable::new(
                point,
                CycleGroupCT::from_group_element(offset_generator.to_owned().into()),
                Self::TABLE_BITS,
                Some(table_hints),
                builder,
                driver,
            )?;
            point_tables.push(lookup_table);
        }

        // let hint_ptr = &operation_hints[num_points * hints_per_table];
        let mut hint_ctr = num_points * hints_per_table;
        let mut accumulator =
            CycleGroupCT::from_group_element(offset_generators[0].to_owned().into());

        // populate the set of points we are going to add into our accumulator, *before* we do any ECC operations
        // this way we are able to fuse mutliple ecc add / ecc double operations and reduce total gate count.
        // (ecc add/ecc double gates normally cost 2 UltraPlonk gates. However if we chain add->add, add->double,
        // double->add, double->double, they only cost one)
        let mut points_to_add = Vec::with_capacity(num_rounds * num_points);
        for i in 0..num_rounds {
            for (scalar_slice, point_table) in scalar_slices.iter().zip(point_tables.iter()) {
                let scalar_slice = scalar_slice.read(num_rounds - i - 1);
                // if we are doing a batch mul over scalars of different bit-lengths, we may not have any scalar bits for a
                // given round and a given scalar
                if let Some(scalar_slice) = scalar_slice {
                    let point = point_table.read(scalar_slice, builder, driver);
                    points_to_add.push(point?);
                }
            }
        }

        let mut x_coordinate_checks = Vec::with_capacity(if !unconditional_add {
            num_points * num_rounds
        } else {
            0
        });
        let mut point_counter = 0;
        for i in 0..num_rounds {
            if i != 0 {
                for _ in 0..Self::TABLE_BITS {
                    let hint_ptr = &operation_hints[hint_ctr];
                    accumulator = accumulator.dbl(Some(hint_ptr.to_owned()), builder, driver)?;
                    hint_ctr += 1;
                }
            }

            for scalar_slice in scalar_slices.iter().take(num_points) {
                let scalar_slice_ = scalar_slice.read(num_rounds - i - 1);
                // if we are doing a batch mul over scalars of different bit-lengths, we may not have a bit slice
                // for a given round and a given scalar
                if let Some(scalar_slice_) = scalar_slice_ {
                    if let Some(public) = T::get_public(&scalar_slice_.get_value(builder, driver)) {
                        builder.assert_if_has_witness(
                            public
                                == T::get_public(&scalar_slice.slices_native[num_rounds - i - 1])
                                    .expect("Should also be public"),
                        );
                    }

                    // const auto& point = points_to_add[point_counter++];
                    let point = &points_to_add[point_counter];
                    point_counter += 1;
                    if !unconditional_add {
                        x_coordinate_checks.push((accumulator.x.clone(), point.x.clone()));
                    }
                    let hint_ptr = &operation_hints[hint_ctr];
                    accumulator = accumulator.unconditional_add(
                        point,
                        Some(hint_ptr.to_owned()),
                        builder,
                        driver,
                    )?;
                    hint_ctr += 1;
                }
            }
        }

        // validate that none of the x-coordinate differences are zero
        // we batch the x-coordinate checks together
        // because `assert_is_not_zero` witness generation needs a modular inversion (expensive)
        let mut coordinate_check_product = FieldCT::from(P::ScalarField::one());
        for (x1, x2) in x_coordinate_checks {
            let x_diff = x2.sub(&x1, builder, driver);
            coordinate_check_product.mul_assign(&x_diff, builder, driver)?;
        }
        coordinate_check_product.assert_is_not_zero(builder, driver)?;

        Ok((accumulator, offset_generator_accumulator))
    }

    // Evaluates a doubling. Uses Ultra double gate
    fn dbl(
        &self,
        hint: Option<T::AcvmPoint<P::CycleGroup>>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        // If this is a constant point at infinity, return early
        if self.is_point_at_infinity().is_constant()
            && !T::get_public(&self.is_point_at_infinity().get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            return Ok(self.to_owned());
        }

        // To support the point at infinity, we conditionally modify y to be 1 to avoid division by zero in the
        // doubling formula
        let modified_y = FieldCT::conditional_assign(
            self.is_point_at_infinity(),
            &FieldCT::from(P::ScalarField::one()),
            &self.y,
            builder,
            driver,
        )?;

        let result;

        if let Some(hint) = hint {
            let (x3, y3, _) = driver.pointshare_to_field_shares(hint)?;
            if self.is_constant() {
                let x3 = T::get_public(&x3).expect("Constants are public");
                let y3 = T::get_public(&y3).expect("Constants are public");
                result = CycleGroupCT::new(
                    FieldCT::from(x3),
                    FieldCT::from(y3),
                    self.is_point_at_infinity().to_owned(),
                    driver,
                );
                return Ok(result);
            }

            let x = FieldCT::from_witness(x3, builder);
            let y = FieldCT::from_witness(y3, builder);
            result = CycleGroupCT::new(x, y, self.is_point_at_infinity().to_owned(), driver);
        } else {
            let x1 = self.x.get_value(builder, driver);
            let y1 = modified_y.get_value(builder, driver);

            // N.B. the formula to derive the witness value for x3 mirrors the formula in elliptic_relation.hpp
            // Specifically, we derive x^4 via the Short Weierstrass curve formula `y^2 = x^3 + b`
            // i.e. x^4 = x * (y^2 - b)
            // We must follow this pattern exactly to support the edge-case where the input is the point at infinity.
            let y_pow_2 = driver.mul(y1.to_owned(), y1.to_owned())?;
            let sub = driver.sub(y_pow_2.to_owned(), P::get_curve_b().into());
            let x_pow_4 = driver.mul(x1.to_owned(), sub)?;
            let tmp1 = driver.mul_with_public(P::ScalarField::from(9), x_pow_4);
            let tmp2 = driver.mul_with_public(P::ScalarField::from(4), y_pow_2);
            let inv = driver.invert(tmp2)?;
            let lambda_squared = driver.mul(tmp1, inv)?;
            let y2_2 = driver.add(y1.to_owned(), y1.to_owned());
            let y2_2_inv = driver.invert(y2_2)?;
            let x_square = driver.mul(x1.to_owned(), x1.to_owned())?;
            let x_square_3 = driver.mul_with_public(P::ScalarField::from(3), x_square);
            let lambda = driver.mul(x_square_3, y2_2_inv)?;
            let x3 = driver.sub(lambda_squared, x1.to_owned());
            let x3 = driver.sub(x3, x1.to_owned());
            let diff = driver.sub(x1, x3.to_owned());
            let y3 = driver.mul(lambda, diff)?;
            let y3 = driver.sub(y3, y1);

            if self.is_constant() {
                let x3 = T::get_public(&x3).expect("Constants are public");
                let y3 = T::get_public(&y3).expect("Constants are public");
                let inf_value = self.is_point_at_infinity().get_value(driver);
                let inf_value = T::get_public(&inf_value).expect("Constants are public");
                let result = CycleGroupCT::new_from_parts(x3, y3, inf_value.is_one());
                return Ok(result);
            }
            result = CycleGroupCT::new(
                FieldCT::from_witness(x3, builder),
                FieldCT::from_witness(y3, builder),
                self.is_point_at_infinity().to_owned(),
                driver,
            );
        }
        let ecc_dbl_gate = EccDblGate {
            x1: self.x.get_witness_index(builder, driver),
            y1: modified_y.get_witness_index(builder, driver),
            x3: result.x.get_witness_index(builder, driver),
            y3: result.y.get_witness_index(builder, driver),
        };
        builder.create_ecc_dbl_gate(&ecc_dbl_gate);

        Ok(result)
    }

    fn checked_unconditional_add(
        &self,
        other: &Self,
        hint: Option<T::AcvmPoint<P::CycleGroup>>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let x_delta = self.x.sub(&other.x, builder, driver);
        if x_delta.is_constant() {
            assert!(
                !T::get_public(&x_delta.get_value(builder, driver))
                    .expect("Constants are public")
                    .is_zero()
            );
        } else {
            x_delta.assert_is_not_zero(builder, driver)?;
        }
        self.unconditional_add(other, hint, builder, driver)
    }

    fn unconditional_add(
        &self,
        other: &Self,
        hint: Option<T::AcvmPoint<P::CycleGroup>>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let lhs_constant = self.is_constant();
        let rhs_constant = other.is_constant();
        if lhs_constant && !rhs_constant {
            let value = self.get_value(builder, driver)?;
            let value = T::get_public_point(&value).expect("Constants are public");
            let lhs = CycleGroupCT::from_constant_witness(value, builder, driver);
            return lhs.unconditional_add(other, hint, builder, driver);
        }
        if !lhs_constant && rhs_constant {
            let value = other.get_value(builder, driver)?;
            let value = T::get_public_point(&value).expect("Constants are public");
            let rhs = CycleGroupCT::from_constant_witness(value, builder, driver);
            return self.unconditional_add(&rhs, hint, builder, driver);
        }

        let result;

        if let Some(hint) = hint {
            let (x3, y3, _) = driver.pointshare_to_field_shares(hint)?;
            if lhs_constant && rhs_constant {
                let x3 = T::get_public(&x3).expect("Constants are public");
                let y3 = T::get_public(&y3).expect("Constants are public");
                return Ok(CycleGroupCT::new_from_parts(x3, y3, false));
            }
            let x = FieldCT::from_witness(x3, builder);
            let y = FieldCT::from_witness(y3, builder);
            result = CycleGroupCT::new(x, y, BoolCT::from(false), driver);
        } else {
            let p1 = self.get_value(builder, driver)?;
            let p2 = other.get_value(builder, driver)?;
            let p3 = driver.add_points(p1, p2);

            if lhs_constant && rhs_constant {
                let p3 = T::get_public_point(&p3).expect("Constants are public");
                let result = CycleGroupCT::from_group_element(p3);
                return Ok(result);
            }
            let (x, y, _) = driver.pointshare_to_field_shares(p3)?;
            let r_x = FieldCT::from_witness(x, builder);
            let r_y = FieldCT::from_witness(y, builder);
            result = CycleGroupCT::new(r_x, r_y, BoolCT::from(false), driver);
        }

        let add_gate = EccAddGate {
            x1: self.x.get_witness_index(builder, driver),
            y1: self.y.get_witness_index(builder, driver),
            x2: other.x.get_witness_index(builder, driver),
            y2: other.y.get_witness_index(builder, driver),
            x3: result.x.get_witness_index(builder, driver),
            y3: result.y.get_witness_index(builder, driver),
            sign_coefficient: P::ScalarField::one(),
        };
        builder.create_ecc_add_gate(&add_gate);

        Ok(result)
    }

    pub(crate) fn add(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if self.is_infinity.is_constant()
            && !T::get_public(&self.is_infinity.get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            return Ok(other.to_owned());
        }

        if other.is_infinity.is_constant()
            && !T::get_public(&other.is_infinity.get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            return Ok(self.to_owned());
        }

        let x_coordinates_match = self.x.equals(&other.x, builder, driver)?;
        let y_coordinates_match = self.y.equals(&other.y, builder, driver)?;

        let x1 = &self.x;
        let y1 = &self.y;
        let x2 = &other.x;
        let y2 = &other.y;
        // if x_coordinates match, lambda triggers a divide by zero error.
        // Adding in `x_coordinates_match` ensures that lambda will always be well-formed
        let x_diff = x2.add_two(
            &x1.neg(),
            &x_coordinates_match.to_field_ct(driver),
            builder,
            driver,
        );

        // Computes lambda = (y2-y1)/x_diff, using the fact that x_diff is never 0

        let lambda = if (y1.is_constant() && y2.is_constant()) || x_diff.is_constant() {
            (y2.sub(y1, builder, driver)).divide_no_zero_check(&x_diff, builder, driver)?
        } else {
            let y2_ = y2.get_value(builder, driver);
            let y1_ = y1.get_value(builder, driver);
            let sub = driver.sub(y2_, y1_);
            let x_diff_value = x_diff.get_value(builder, driver);
            let invert = driver.invert(x_diff_value)?;
            let lambda = driver.mul(sub, invert)?;
            let lambda = FieldCT::from_witness(lambda, builder);
            FieldCT::evaluate_polynomial_identity(&x_diff, &lambda, &y2.neg(), y1, builder, driver);
            lambda
        };

        let add_result_x =
            lambda.madd(&lambda, &x2.add(x1, builder, driver).neg(), builder, driver)?;
        let add_result_y = lambda.madd(
            &x1.sub(&add_result_x, builder, driver),
            &y1.neg(),
            builder,
            driver,
        )?;

        let dbl_result = self.dbl(None, builder, driver)?;

        // dbl if x_match, y_match
        // infinity if x_match, !y_match
        let double_predicate = x_coordinates_match.and(&y_coordinates_match, builder, driver)?;
        let mut result_x = FieldCT::conditional_assign(
            &double_predicate,
            &dbl_result.x,
            &add_result_x,
            builder,
            driver,
        )?;
        let mut result_y = FieldCT::conditional_assign(
            &double_predicate,
            &dbl_result.y,
            &add_result_y,
            builder,
            driver,
        )?;

        // if lhs infinity, return rhs
        let lhs_infinity = self.is_point_at_infinity();
        result_x = FieldCT::conditional_assign(lhs_infinity, &other.x, &result_x, builder, driver)?;
        result_y = FieldCT::conditional_assign(lhs_infinity, &other.y, &result_y, builder, driver)?;

        // if rhs infinity, return lhs
        let rhs_infinity = other.is_point_at_infinity();
        result_x = FieldCT::conditional_assign(rhs_infinity, &self.x, &result_x, builder, driver)?;
        result_y = FieldCT::conditional_assign(rhs_infinity, &self.y, &result_y, builder, driver)?;

        // is result point at infinity?
        // yes = infinity_predicate && !lhs_infinity && !rhs_infinity
        // yes = lhs_infinity && rhs_infinity
        let infinity_predicate =
            x_coordinates_match.and(&y_coordinates_match.not(), builder, driver)?;
        let result_is_infinity = infinity_predicate.and(
            &lhs_infinity
                .not()
                .and(&rhs_infinity.not(), builder, driver)?,
            builder,
            driver,
        )?;
        let both_infinity = lhs_infinity.and(rhs_infinity, builder, driver)?;
        let result_is_infinity = result_is_infinity.or(&both_infinity, builder, driver)?;

        let result = CycleGroupCT::new(result_x, result_y, result_is_infinity, driver);

        Ok(result)
    }

    fn sub(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        if other.is_infinity.is_constant()
            && !T::get_public(&other.is_infinity.get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            return Ok(self.to_owned());
        }

        if self.is_infinity.is_constant()
            && !T::get_public(&self.is_infinity.get_value(driver))
                .expect("Constants are public")
                .is_zero()
        {
            return other.neg(builder, driver);
        }

        let x_coordinates_match = self.x.equals(&other.x, builder, driver)?;
        let y_coordinates_match = self.y.equals(&other.y, builder, driver)?;

        let x1 = &self.x;
        let y1 = &self.y;
        let x2 = &other.x;
        let y2 = &other.y;
        let x_diff = x2.add_two(
            &x1.neg(),
            &x_coordinates_match.to_field_ct(driver),
            builder,
            driver,
        );
        // Computes lambda = (-y2-y1)/x_diff, using the fact that x_diff is never 0

        let lambda = if (y1.is_constant() && y2.is_constant()) || x_diff.is_constant() {
            (y2.neg().sub(y1, builder, driver)).divide_no_zero_check(&x_diff, builder, driver)?
        } else {
            let y2_ = y2.neg().get_value(builder, driver);
            let y1_ = y1.get_value(builder, driver);
            let sub = driver.sub(y2_, y1_);
            let x_diff_value = x_diff.get_value(builder, driver);
            let invert = driver.invert(x_diff_value)?;
            let lambda = driver.mul(sub, invert)?;
            let lambda = FieldCT::from_witness(lambda, builder);
            FieldCT::evaluate_polynomial_identity(&x_diff, &lambda, y2, y1, builder, driver);
            lambda
        };

        let x3 = lambda.madd(&lambda, &x2.add(x1, builder, driver).neg(), builder, driver)?;
        let y3 = lambda.madd(&x1.sub(&x3, builder, driver), &y1.neg(), builder, driver)?;
        let add_result = CycleGroupCT::new(x3, y3, x_coordinates_match.to_owned(), driver);

        let dbl_result = self.dbl(None, builder, driver)?;

        // dbl if x_match, !y_match
        // infinity if x_match, y_match
        let double_predicate = x_coordinates_match
            .and(&y_coordinates_match.not(), builder, driver)?
            .normalize(builder, driver);
        let mut result_x = FieldCT::conditional_assign(
            &double_predicate,
            &dbl_result.x,
            &add_result.x,
            builder,
            driver,
        )?;
        let mut result_y = FieldCT::conditional_assign(
            &double_predicate,
            &dbl_result.y,
            &add_result.y,
            builder,
            driver,
        )?;

        let lhs_infinity = self.is_point_at_infinity();
        let rhs_infinity = other.is_point_at_infinity();
        // if lhs infinity, return -rhs
        result_x = FieldCT::conditional_assign(lhs_infinity, &other.x, &result_x, builder, driver)?;
        result_y =
            FieldCT::conditional_assign(lhs_infinity, &other.y.neg(), &result_y, builder, driver)?;

        // if rhs infinity, return lhs
        result_x = FieldCT::conditional_assign(rhs_infinity, &self.x, &result_x, builder, driver)?;
        result_y = FieldCT::conditional_assign(rhs_infinity, &self.y, &result_y, builder, driver)?;

        // is result point at infinity?
        // yes = infinity_predicate && !lhs_infinity && !rhs_infinity
        // yes = lhs_infinity && rhs_infinity
        // n.b. can likely optimize this
        let infinity_predicate = x_coordinates_match
            .and(&y_coordinates_match, builder, driver)?
            .normalize(builder, driver);
        let result_is_infinity = infinity_predicate.and(
            &lhs_infinity
                .not()
                .and(&rhs_infinity.not(), builder, driver)?,
            builder,
            driver,
        )?;
        let both_infinity = lhs_infinity.and(rhs_infinity, builder, driver)?;
        let result_is_infinity = result_is_infinity.or(&both_infinity, builder, driver)?;

        let result = CycleGroupCT::new(result_x, result_y, result_is_infinity, driver);
        Ok(result)
    }

    fn neg(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut result = self.to_owned();
        result.y = self.y.neg().normalize(builder, driver);
        Ok(result)
    }

    fn conditional_assign(
        predicate: &BoolCT<P::ScalarField, T>,
        lhs: &Self,
        rhs: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let mut x = FieldCT::conditional_assign(predicate, &lhs.x, &rhs.x, builder, driver)?;
        let y = FieldCT::conditional_assign(predicate, &lhs.y, &rhs.y, builder, driver)?;
        let is_infinity = BoolCT::conditional_assign(
            predicate,
            lhs.is_point_at_infinity(),
            rhs.is_point_at_infinity(),
            builder,
            driver,
        )?;

        let mut is_standard = lhs.is_standard && rhs.is_standard;
        if predicate.is_constant() {
            let value = T::get_public(&predicate.get_value(driver))
                .expect("Constants are public")
                .is_zero();
            is_standard = if value {
                rhs.is_standard
            } else {
                lhs.is_standard
            };
        }

        // Rare case when we bump into two constants, s.t. lhs = -rhs
        if x.is_constant() && !y.is_constant() {
            x = FieldCT::from_witness_index(builder.put_constant_variable(
                T::get_public(&x.get_value(builder, driver)).expect("Constants are public"),
            ));
        }

        let mut result = CycleGroupCT::new(x, y, is_infinity, driver);
        result.is_standard = is_standard;

        Ok(result)
    }

    pub(crate) fn assert_equal(
        &mut self,
        other: &mut Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        self.standardize(builder, driver)?;
        other.standardize(builder, driver)?;
        self.x.assert_equal(&other.x, builder, driver);
        self.y.assert_equal(&other.y, builder, driver);
        self.is_infinity
            .assert_equal(&other.is_infinity, builder, driver);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CycleScalarCT<F: PrimeField> {
    pub(crate) lo: FieldCT<F>,
    pub(crate) hi: FieldCT<F>,
}

impl<F: PrimeField> CycleScalarCT<F> {
    const NUM_BITS: usize = F::MODULUS_BIT_SIZE as usize;
    const SKIP_PRIMALITY_TEST: bool = false;
    const USE_BN254_SCALAR_FIELD_FOR_PRIMALITY_TEST: bool = false;
    const MAX_BITS_PER_ENDOMORPHISM_SCALAR: usize = 128;
    pub(crate) const LO_BITS: usize = Self::MAX_BITS_PER_ENDOMORPHISM_SCALAR;
    pub(crate) const HI_BITS: usize = Self::NUM_BITS - Self::LO_BITS;

    pub(crate) fn new<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        lo: FieldCT<F>,
        hi: FieldCT<F>,
        skip_validation: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let res = Self { lo, hi };
        // Unless explicitly skipped, validate the scalar is in the Grumpkin scalar field
        if !skip_validation {
            res.validate_scalar_is_in_field(builder, driver)?;
        }
        Ok(res)
    }

    #[expect(unused)] // This will be used in the fieldct transcript
    pub(crate) fn from_field_ct<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        inp: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let value = inp.get_value(builder, driver);
        let msb = Self::NUM_BITS as u8;
        let lsb = Self::LO_BITS as u8;
        let total_bitsize = F::MODULUS_BIT_SIZE as usize;
        let shift: BigUint = BigUint::one() << Self::LO_BITS;
        let shift_ct = FieldCT::from(F::from(shift.clone()));
        let (hi_v, lo_v) = if T::is_shared(&value) {
            let value = T::get_shared(&value).expect("Already checked it is shared");
            let [lo, _, hi] = driver.slice(value, msb - 1, lsb, total_bitsize)?;
            (T::AcvmType::from(hi), T::AcvmType::from(lo))
        } else {
            let value: BigUint = T::get_public(&value)
                .expect("Already checked it is public")
                .into();

            let lo = &value & (&shift - BigUint::one());
            let hi = value >> Self::LO_BITS;

            (
                T::AcvmType::from(F::from(hi)),
                T::AcvmType::from(F::from(lo)),
            )
        };

        if inp.is_constant() {
            Ok(Self {
                lo: FieldCT::from(T::get_public(&lo_v).expect("Constants are public")),
                hi: FieldCT::from(T::get_public(&hi_v).expect("Constants are public")),
            })
        } else {
            let result = Self {
                lo: FieldCT::from_witness(lo_v, builder),
                hi: FieldCT::from_witness(hi_v, builder),
            };
            let mul = result.hi.multiply(&shift_ct, builder, driver)?;
            let recomposed = result.lo.add(&mul, builder, driver);
            inp.assert_equal(&recomposed, builder, driver);
            result.validate_scalar_is_in_field(builder, driver)?;
            Ok(result)
        }
    }

    fn is_constant(&self) -> bool {
        self.lo.is_constant() && self.hi.is_constant()
    }

    const fn skip_primality_test(&self) -> bool {
        Self::SKIP_PRIMALITY_TEST
    }

    const fn use_bn254_scalar_field_for_primality_test(&self) -> bool {
        Self::USE_BN254_SCALAR_FIELD_FOR_PRIMALITY_TEST
    }

    const fn num_bits(&self) -> usize {
        Self::NUM_BITS
    }

    fn get_constant_value<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> <<P::CycleGroup as CurveGroup>::Config as CurveConfig>::ScalarField {
        let lo = self.lo.get_value(builder, driver);
        let hi = self.hi.get_value(builder, driver);
        let mut lo: BigUint = T::get_public(&lo).expect("Constants are public").into();
        let hi: BigUint = T::get_public(&hi).expect("Constants are public").into();
        lo += hi << Self::LO_BITS;
        lo.into()
    }

    fn slice(inp: BigUint) -> (BigUint, BigUint) {
        // Hardcoded for these value
        debug_assert_eq!(Self::LO_BITS, 128);
        debug_assert!(Self::HI_BITS < 128);
        let digits = inp.to_u64_digits();
        let mut lo = BigUint::zero();
        let mut hi = BigUint::zero();
        for digit in digits.iter().take(2).rev() {
            lo <<= 64;
            lo += *digit;
        }
        for digit in digits.iter().skip(2).take(2).rev() {
            hi <<= 64;
            hi += *digit;
        }
        debug_assert!(hi.bits() as usize <= Self::HI_BITS);
        (lo, hi)
    }

    fn validate_scalar_is_in_field<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        if self.is_constant() || self.skip_primality_test() {
            return Ok(());
        }
        // if !self.is_constant() && !self.skip_primality_test() {
        let cycle_group_modulus = if self.use_bn254_scalar_field_for_primality_test() {
            BigUint::from(ark_bn254::Fr::MODULUS)
        } else {
            // In BB this is Grumpkin::ScalarField::MODULUS, so we can use P::BaseField::MODULUS
            P::BaseField::MODULUS.into()
        };
        let (r_lo, r_hi) = Self::slice(cycle_group_modulus);

        let lo_value = self.lo.get_value(builder, driver);
        let borrow = if self.lo.is_constant() {
            let lo_value: BigUint = T::get_public(&lo_value)
                .expect("Constants are public")
                .into();
            let need_borrow = lo_value > r_lo;
            FieldCT::from(P::ScalarField::from(need_borrow as u64))
        } else {
            let need_borrow = if T::is_shared(&lo_value) {
                driver.gt(lo_value, F::from(r_lo.to_owned()).into())?
            } else {
                let lo_value: BigUint = T::get_public(&lo_value)
                    .expect("Already checked it is public")
                    .into();
                let need_borrow = lo_value > r_lo;
                P::ScalarField::from(need_borrow as u64).into()
            };
            FieldCT::from_witness(need_borrow, builder)
        };

        // directly call `create_new_range_constraint` to avoid creating an arithmetic gate
        if !self.lo.is_constant() {
            // We have a ultra builder
            let index = borrow.get_witness_index(builder, driver);
            builder.create_new_range_constraint(index, 1);
        }

        // Hi range check = r_hi - y_hi - borrow
        // Lo range check = r_lo - y_lo + borrow * 2^{126}
        let borrow_scaled = borrow.multiply(
            &FieldCT::from(P::ScalarField::from(BigUint::one() << Self::LO_BITS)),
            builder,
            driver,
        )?;
        let hi_diff = self
            .hi
            .neg()
            .add(&FieldCT::from(P::ScalarField::from(r_hi)), builder, driver)
            .sub(&borrow, builder, driver);
        let lo_diff = self
            .lo
            .neg()
            .add(&FieldCT::from(P::ScalarField::from(r_lo)), builder, driver)
            .add(&borrow_scaled, builder, driver);

        hi_diff.create_range_constraint(Self::HI_BITS, builder, driver)?;
        lo_diff.create_range_constraint(Self::LO_BITS, builder, driver)?;

        Ok(())
    }
}

#[derive(Debug)]
struct StrausScalarSlice<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    table_bits: usize,
    slices: Vec<FieldCT<P::ScalarField>>,
    slices_native: Vec<T::AcvmType>,
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> Clone
    for StrausScalarSlice<P, T>
{
    fn clone(&self) -> Self {
        Self {
            table_bits: self.table_bits,
            slices: self.slices.clone(),
            slices_native: self.slices_native.clone(),
        }
    }
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> StrausScalarSlice<P, T> {
    fn new(
        scalar: &CycleScalarCT<P::ScalarField>,
        table_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let lo_bits = if scalar.num_bits() > CycleScalarCT::<P::ScalarField>::LO_BITS {
            CycleScalarCT::<P::ScalarField>::LO_BITS
        } else {
            scalar.num_bits()
        };
        let hi_bits = if scalar.num_bits() > CycleScalarCT::<P::ScalarField>::LO_BITS {
            scalar.num_bits() - CycleScalarCT::<P::ScalarField>::LO_BITS
        } else {
            0
        };

        let hi_slices =
            Self::compute_scalar_slices(&scalar.hi, hi_bits, table_bits, builder, driver)?;
        let lo_slices =
            Self::compute_scalar_slices(&scalar.lo, lo_bits, table_bits, builder, driver)?;

        let mut slices = lo_slices.0;
        slices.extend(hi_slices.0);

        let mut slices_native = lo_slices.1;
        slices_native.extend(hi_slices.1);

        Ok(Self {
            table_bits,
            slices,
            slices_native,
        })
    }

    // convert an input cycle_scalar object into a vector of slices, each containing `table_bits` bits.
    // this also performs an implicit range check on the input slices
    #[expect(clippy::type_complexity)]
    fn compute_scalar_slices(
        scalar: &FieldCT<P::ScalarField>,
        num_bits: usize,
        table_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<(Vec<FieldCT<P::ScalarField>>, Vec<T::AcvmType>)> {
        // we record the scalar slices both as field_t circuit elements and u64 values
        // (u64 values are used to index arrays and we don't want to repeatedly cast a stdlib value to a numeric
        // primitive as this gets expensive when repeated enough times)
        let table_size = (1 << table_bits) as usize;
        let mut result = Vec::with_capacity(table_size);
        let mut result_native = Vec::with_capacity(table_size);

        if num_bits == 0 {
            return Ok((result, result_native));
        }

        if scalar.is_constant() {
            let num_slices = num_bits.div_ceil(table_bits);
            let table_mask = table_size as u64 - 1;
            let value = scalar.get_value(builder, driver);
            let value = T::get_public(&value).expect("Constants are public");
            let mut raw_value: BigUint = value.into();
            for _ in 0..num_slices {
                let slice_v = raw_value.iter_u64_digits().next().unwrap_or_default() & table_mask;
                result.push(FieldCT::from(P::ScalarField::from(slice_v)));
                result_native.push(P::ScalarField::from(slice_v).into());
                raw_value >>= table_bits;
            }
            return Ok((result, result_native));
        }

        let index = scalar.get_witness_index(builder, driver);
        let slice_indices = builder.decompose_into_default_range(
            driver,
            index,
            num_bits as u64,
            None,
            table_bits as u64,
        )?;

        for idx in slice_indices {
            let slice = FieldCT::from_witness_index(idx);
            result_native.push(slice.get_value(builder, driver));
            result.push(slice);
        }
        Ok((result, result_native))
    }

    fn read(&self, index: usize) -> Option<FieldCT<P::ScalarField>> {
        if index >= self.slices.len() {
            return None;
        }
        Some(self.slices[index].to_owned())
    }
}

struct StrausLookupTable<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    #[expect(dead_code)]
    table_bits: usize,
    #[expect(dead_code)] // Is in ROM, so technically not needed anymore
    point_table: Vec<CycleGroupCT<P, T>>,
    rom_id: usize,
}

impl<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>>
    StrausLookupTable<P, T>
{
    fn new(
        base_point: &CycleGroupCT<P, T>,
        offset_generator: CycleGroupCT<P, T>,
        table_bits: usize,
        hints: Option<Vec<T::AcvmPoint<P::CycleGroup>>>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let table_size = (1 << table_bits) as usize;
        let mut point_table = Vec::with_capacity(table_size);
        point_table.push(offset_generator.to_owned());

        // We want to support the case where input points are points at infinity.
        // If base point is at infinity, we want every point in the table to just be `generator_point`.
        // We achieve this via the following:
        // 1: We create a "work_point" that is base_point if not at infinity, otherwise is just 1
        // 2: When computing the point table, we use "work_point" in additions instead of the "base_point" (to prevent
        //    x-coordinate collisions in honest case) 3: When assigning to the point table, we conditionally assign either
        //    the output of the point addition (if not at infinity) or the generator point (if at infinity)
        // Note: if `base_point.is_point_at_infinity()` is constant, these conditional assigns produce zero gate overhead

        let fallback_point = CycleGroupCT::<P, T>::from_group_element(P::CycleGroup::generator());
        let modded_x = FieldCT::conditional_assign(
            base_point.is_point_at_infinity(),
            &fallback_point.x,
            &base_point.x,
            builder,
            driver,
        )?;
        let modded_y = FieldCT::conditional_assign(
            base_point.is_point_at_infinity(),
            &fallback_point.y,
            &base_point.y,
            builder,
            driver,
        )?;
        let mut modded_base_point =
            CycleGroupCT::new(modded_x, modded_y, BoolCT::from(false), driver);

        // if the input point is constant, it is cheaper to fix the point as a witness and then derive the table, than it is
        // to derive the table and fix its witnesses to be constant! (due to group additions = 1 gate, and fixing x/y coords
        // to be constant = 2 gates)

        let mut else_branch = true;

        if modded_base_point.is_constant() {
            let value = base_point.is_point_at_infinity().get_value(driver);
            let value = T::get_public(&value).expect("Constants are public");
            let is_infinity = value.is_one();
            if !is_infinity {
                else_branch = false;
                let value = modded_base_point.get_value(builder, driver)?;
                let value = T::get_public_point(&value).expect("Constants are public");
                modded_base_point = CycleGroupCT::from_constant_witness(value, builder, driver);

                let value = offset_generator.get_value(builder, driver)?;
                let value = T::get_public_point(&value).expect("Constants are public");
                point_table[0] = CycleGroupCT::from_constant_witness(value, builder, driver);
                for i in 1..table_size {
                    let hint = hints.as_ref().map(|hints| hints[i - 1].to_owned());
                    point_table.push(point_table[i - 1].unconditional_add(
                        &modded_base_point,
                        hint,
                        builder,
                        driver,
                    )?);
                }
            }
        }
        if else_branch {
            let mut x_coordinate_checks = Vec::with_capacity(table_size - 1);
            // ensure all of the ecc add gates are lined up so that we can pay 1 gate per add and not 2
            for i in 1..table_size {
                let hint = hints.as_ref().map(|hints| hints[i - 1].to_owned());
                x_coordinate_checks.push((
                    point_table[i - 1].x.to_owned(),
                    modded_base_point.x.to_owned(),
                ));
                point_table.push(point_table[i - 1].unconditional_add(
                    &modded_base_point,
                    hint,
                    builder,
                    driver,
                )?);
            }

            // batch the x-coordinate checks together
            // because `assert_is_not_zero` witness generation needs a modular inversion (expensive)
            let mut coordinate_check_product = FieldCT::from(P::ScalarField::one());
            for (x1, x2) in x_coordinate_checks {
                let x_diff = x2.sub(&x1, builder, driver);
                coordinate_check_product.mul_assign(&x_diff, builder, driver)?;
            }
            coordinate_check_product.assert_is_not_zero(builder, driver)?;

            for point in point_table.iter_mut().skip(1) {
                *point = CycleGroupCT::conditional_assign(
                    base_point.is_point_at_infinity(),
                    &offset_generator,
                    point,
                    builder,
                    driver,
                )?;
            }
        }

        // We are Ultra, so we use ROM
        let rom_id = builder.create_rom_array(table_size);
        for (i, point) in point_table.iter_mut().enumerate() {
            if point.is_constant() {
                let element = point.get_value(builder, driver)?;
                let element = T::get_public_point(&element).expect("Constants are public");
                *point = CycleGroupCT::from_constant_witness(element, builder, driver);
            }
            let coordinate_indices = [
                point.x.get_witness_index(builder, driver),
                point.y.get_witness_index(builder, driver),
            ];
            builder.set_rom_element_pair(rom_id, i, coordinate_indices);
        }

        Ok(Self {
            table_bits,
            point_table,
            rom_id,
        })
    }

    fn compute_native_table(
        base_point: T::AcvmPoint<P::CycleGroup>,
        offset_generator: <P::CycleGroup as CurveGroup>::Affine,
        table_bits: usize,
        driver: &mut T,
    ) -> eyre::Result<Vec<T::AcvmPoint<P::CycleGroup>>> {
        let tables_size = (1 << table_bits) as usize;

        // let base_point = if base_point == 0 {::CycleGroup::generator() else base_point;
        let base_point = driver.set_point_to_value_if_zero(
            base_point,
            T::AcvmPoint::from(P::CycleGroup::generator()),
        )?;

        let mut hints = Vec::with_capacity(tables_size);
        hints.push(T::AcvmPoint::from(offset_generator.into()));
        for i in 1..tables_size {
            hints.push(driver.add_points(hints[i - 1].to_owned(), base_point.to_owned()));
        }
        Ok(hints)
    }

    fn read(
        &self,
        mut index: FieldCT<P::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<CycleGroupCT<P, T>> {
        // We are Ultra, so we use ROM

        if index.is_constant() {
            let index_val = index.get_value(builder, driver);
            let index_val_pub = T::get_public(&index_val).expect("Constants are public");
            index = FieldCT::from_witness(index_val, builder);
            index.assert_equal(&FieldCT::from(index_val_pub), builder, driver);
        }
        let index = index.get_witness_index(builder, driver);
        let output_indices = builder.read_rom_array_pair(self.rom_id, index, driver)?;
        let x = FieldCT::from_witness_index(output_indices[0]);
        let y = FieldCT::from_witness_index(output_indices[1]);
        Ok(CycleGroupCT::new(x, y, BoolCT::from(false), driver))
    }
}

pub(crate) struct ByteArray<F: PrimeField> {
    pub(crate) values: Vec<FieldCT<F>>,
}

impl<F: PrimeField> ByteArray<F> {
    pub(crate) fn default_with_length(length: usize) -> Self {
        Self {
            values: vec![FieldCT::default(); length],
        }
    }

    pub(crate) fn write(&mut self, other: &Self) {
        self.values.extend_from_slice(&other.values);
    }

    pub(crate) fn write_at(&mut self, other: &Self, index: usize) {
        assert!(index + other.values.len() <= self.values.len());
        for (i, value) in other.values.iter().enumerate() {
            self.values[i + index] = value.clone();
        }
    }

    pub(crate) fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub(crate) fn set_byte(&mut self, index: usize, byte_val: FieldCT<F>) {
        assert!(index < self.values.len());
        self.values[index] = byte_val;
    }

    pub(crate) fn get_byte(&self, index: usize) -> FieldCT<F> {
        assert!(index < self.values.len());
        self.values[index].clone()
    }

    pub(crate) fn from_field_ct<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: &FieldCT<F>,
        num_bytes: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let max_num_bytes = 32;
        let midpoint = max_num_bytes / 2;
        let one = BigUint::one();

        assert!(num_bytes < max_num_bytes);
        let mut values = Vec::with_capacity(num_bytes);
        let value = input.get_value(builder, driver);

        let is_shared = T::is_shared(&value);
        let decomposed = if is_shared {
            let value = T::get_shared(&value).expect("Already checked it is shared");

            driver
                .decompose_arithmetic(value, num_bytes * 8, 8)?
                .into_iter()
                .rev()
                .map(T::AcvmType::from)
                .collect::<Vec<_>>()
        } else {
            let value: BigUint = T::get_public(&value)
                .expect("Already checked it is public")
                .into();
            let mut bytes = value.to_bytes_be();
            bytes.resize(num_bytes, 0);
            bytes
                .into_iter()
                .map(|byte| F::from(byte).into())
                .collect::<Vec<_>>()
        };

        // To optimize the computation of the reconstructed_hi  and reconstructed_lo, we use the `field_t::accumulate`
        // method.
        let mut accumulator_lo = Vec::with_capacity(midpoint);
        let mut accumulator_hi = Vec::with_capacity(midpoint);

        for (i, byte_val) in decomposed.iter().enumerate() {
            let bit_start = (num_bytes - i - 1) * 8;
            let scaling_factor = FieldCT::from(F::from(one.clone() << bit_start));

            // Ensure that current `byte_array` element is a witness iff input is a witness and that it is range
            // constrained.
            let byte = if input.is_constant() {
                let byte = FieldCT::from(T::get_public(byte_val).expect("Constants are public"));
                byte.create_range_constraint(8, builder, driver)?;
                byte
            } else {
                let byte_witness = FieldCT::from_witness(byte_val.clone(), builder);
                byte_witness.create_range_constraint(8, builder, driver)?;
                byte_witness
            };
            values.push(byte.clone());

            if i < midpoint {
                accumulator_hi.push(scaling_factor.multiply(&byte, builder, driver)?);
            } else {
                accumulator_lo.push(scaling_factor.multiply(&byte, builder, driver)?);
            }
        }

        // Reconstruct the high and low limbs of input from the byte decomposition
        let reconstructed_lo = FieldCT::accumulate(&accumulator_lo, builder, driver)?;
        let reconstructed_hi = FieldCT::accumulate(&accumulator_hi, builder, driver)?;
        let reconstructed = reconstructed_hi.add(&reconstructed_lo, builder, driver);

        // Ensure that the reconstruction succeeded
        input.assert_equal(&reconstructed, builder, driver);

        // Handle the case when the decomposition is not unique
        if num_bytes == 32 {
            // For a modulus `r`, split `r - 1` into limbs
            let modulus_minus_one: BigUint = F::MODULUS.into() - BigUint::one();
            let s_lo: BigUint = &modulus_minus_one & ((BigUint::one() << 128) - BigUint::one());
            let s_hi = FieldCT::from(F::from(&modulus_minus_one >> 128));
            let shift: BigUint = BigUint::one() << 128;

            // Ensure that `(r - 1).lo + 2 ^ 128 - reconstructed_lo` is a 129 bit integer by slicing it into a 128- and 1-
            // bit chunks.
            let diff_lo = reconstructed_lo
                .neg()
                .add(&FieldCT::from(F::from(s_lo.clone())), builder, driver)
                .add(&FieldCT::from(F::from(shift.clone())), builder, driver);
            let diff_lo_value = diff_lo.get_value(builder, driver);

            // Extract the "borrow" bit
            let [diff_lo_lo_value, diff_lo_hi_value] = if T::is_shared(&diff_lo_value) {
                let slice_result = driver.slice(
                    T::get_shared(&diff_lo_value).expect("we checked it is shared"),
                    127,
                    0,
                    F::MODULUS_BIT_SIZE as usize,
                )?;
                [
                    T::AcvmType::from(slice_result[0].clone()),
                    T::AcvmType::from(slice_result[1].clone()),
                ]
            } else {
                let diff_lo_value: BigUint = T::get_public(&diff_lo_value)
                    .expect("Already checked it is public")
                    .into();
                let lo = T::AcvmType::from(F::from(&diff_lo_value & (&shift - BigUint::one())));
                let hi = T::AcvmType::from(F::from(&diff_lo_value >> 128));
                [lo, hi]
            };
            let diff_lo_hi = if input.is_constant() {
                FieldCT::from(T::get_public(&diff_lo_hi_value).expect("Constants are public"))
            } else {
                FieldCT::from_witness(diff_lo_hi_value, builder)
            };
            diff_lo_hi.create_range_constraint(1, builder, driver)?;

            // // Extract first 128 bits of `diff_lo`
            let diff_lo_lo = if input.is_constant() {
                FieldCT::from(T::get_public(&diff_lo_lo_value).expect("Constants are public"))
            } else {
                FieldCT::from_witness(diff_lo_lo_value, builder)
            };
            diff_lo_lo.create_range_constraint(128, builder, driver)?;

            // Both chunks were computed out-of-circuit - need to constrain. The range constraints above ensure that
            // they are not overlapping.
            let shift_ct = FieldCT::from(F::from(shift));
            let mul = diff_lo_hi.multiply(&shift_ct, builder, driver)?;
            let add = diff_lo_lo.add(&mul, builder, driver);
            diff_lo.assert_equal(&add, builder, driver);

            let overlap = diff_lo_hi
                .neg()
                .add(&FieldCT::from(F::from(1u64)), builder, driver);
            // Ensure that (r - 1).hi  - reconstructed_hi/shift - overlap is positive.
            let div = reconstructed_hi.neg().divide(&shift_ct, builder, driver)?;
            let diff_hi = div.add_two(&s_hi, &overlap.neg(), builder, driver);
            diff_hi.create_range_constraint(128, builder, driver)?;
        }
        Ok(Self { values })
    }

    /**
     * @brief Slice `length` bytes from the byte array, starting at `offset`. Does not add any constraints
     **/
    pub(crate) fn slice(&self, offset: usize, length: usize) -> Self {
        assert!(offset < self.values.len());
        assert!(length <= self.values.len() - offset);
        let start = offset;
        let end = offset + length;
        Self {
            values: self.values[start..end].to_vec(),
        }
    }

    pub(crate) fn slice_from_offset(&self, offset: usize) -> Self {
        assert!(offset < self.values.len());
        Self {
            values: self.values[offset..].to_vec(),
        }
    }

    /**
     * @brief Convert a byte array into a field element.
     *
     * @details The byte array is represented as a big integer, that is then converted into a field element.
     * The transformation is only injective if the byte array is < 32 bytes.
     * Larger byte arrays can still be cast to a single field element, but the value will wrap around the circuit
     *modulus
     **/
    pub(crate) fn to_field_ct<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<F>> {
        let bytes = self.values.len();
        assert!(bytes < 32);

        let mut scaled_values = Vec::with_capacity(bytes);

        for (i, value) in self.values.iter().enumerate() {
            let shift_amount = 8 * (bytes - i - 1);
            let scaling_factor = FieldCT::from(F::from(BigUint::one() << shift_amount));
            scaled_values.push(value.multiply(&scaling_factor, builder, driver)?);
        }

        FieldCT::accumulate(&scaled_values, builder, driver)
    }

    /// Reverse the bytes in the byte array
    pub(crate) fn reverse_in_place(&mut self) {
        self.values.reverse();
    }

    pub(crate) fn reverse(&self) -> Self {
        let mut values = self.values.clone();
        values.reverse();
        Self { values }
    }
}
