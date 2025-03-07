use std::num;

use super::types::{EccDblGate, MulQuad};
use crate::builder::GenericUltraCircuitBuilder;
use crate::prelude::HonkCurve;
use crate::types::generators;
use crate::types::plookup::{ColumnIdx, Plookup};
use crate::types::types::{AddTriple, EccAddGate, PolyTriple};
use crate::TranscriptFieldType;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveConfig, CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_ff::{One, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use itertools::izip;
use num_bigint::BigUint;
use serde::de::value;

#[derive(Clone, Debug)]
pub(crate) struct FieldCT<F: PrimeField> {
    pub(crate) additive_constant: F,
    pub(crate) multiplicative_constant: F,
    pub(crate) witness_index: u32,
}

impl<F: PrimeField> FieldCT<F> {
    pub(crate) const IS_CONSTANT: u32 = u32::MAX;

    pub(crate) fn zero() -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::zero(),
            witness_index: Self::IS_CONSTANT,
        }
    }

    pub(crate) fn zero_with_additive(additive: F) -> Self {
        Self {
            additive_constant: additive,
            multiplicative_constant: F::zero(),
            witness_index: Self::IS_CONSTANT,
        }
    }

    pub(crate) fn from_witness_index(witness_index: u32) -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::one(),
            witness_index,
        }
    }

    pub(crate) fn from_witness<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: T::AcvmType,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> Self {
        let witness = WitnessCT::from_acvm_type(input, builder);
        Self::from(witness)
    }

    pub(crate) fn get_value<
        P: Pairing<ScalarField = F>,
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
            T::AcvmType::from(self.additive_constant)
        }
    }

    pub(crate) fn get_witness_index(&self) -> u32 {
        self.witness_index
    }

    /**
     * @brief Constrain that this field is equal to the given field.
     *
     * @warning: After calling this method, both field values *will* be equal, regardless of whether the constraint
     * succeeds or fails. This can lead to confusion when debugging. If you want to log the inputs, do so before
     * calling this method.
     */
    pub(crate) fn assert_equal<
        P: Pairing<ScalarField = F>,
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
        } else if self.is_constant() {
            let right = other.normalize(builder, driver);
            let left =
                T::get_public(&self.get_value(builder, driver)).expect("Constant should be public");
            builder.assert_equal_constant(right.witness_index as usize, left);
        } else if other.is_constant() {
            let left = self.normalize(builder, driver);
            let right = T::get_public(&other.get_value(builder, driver))
                .expect("Constant should be public");
            builder.assert_equal_constant(left.witness_index as usize, right);
        } else {
            let left = self.normalize(builder, driver);
            let right = other.normalize(builder, driver);
            builder.assert_equal(left.witness_index as usize, right.witness_index as usize);
        }
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.witness_index == Self::IS_CONSTANT
    }

    pub(crate) fn to_bool_ct<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> BoolCT<P, T> {
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

        if (!add_constant_check || !mul_constant_check) && !inverted_check {
            let normalized_element = self.normalize(builder, driver);
            let witness = builder.get_variable(normalized_element.get_witness_index() as usize);
            if let Some(witness) = T::get_public(&witness) {
                assert!(witness == F::zero() || witness == F::one());
            }
            builder.create_bool_gate(normalized_element.get_witness_index());
            return BoolCT {
                witness_bool: witness, // == F::one(),
                witness_inverted: false,
                witness_index: normalized_element.get_witness_index(),
            };
        }

        let witness = builder.get_variable(self.witness_index as usize);
        if let Some(witness) = T::get_public(&witness) {
            assert!(witness == F::zero() || witness == F::one());
        }
        builder.create_bool_gate(self.witness_index);
        BoolCT {
            witness_bool: witness, // == F::one(),
            witness_inverted: false,
            witness_index: self.witness_index,
        }
    }

    pub(crate) fn normalize<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        if self.is_constant()
            || ((self.multiplicative_constant == F::one()) && (self.additive_constant == F::zero()))
        {
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
            b: self.witness_index,
            c: result.witness_index,
            a_scaling: self.multiplicative_constant,
            b_scaling: P::ScalarField::zero(),
            c_scaling: -P::ScalarField::one(),
            const_scaling: self.additive_constant,
        });
        result
    }

    pub(crate) fn get_normalized_witness_index<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> u32 {
        self.normalize(builder, driver).witness_index
    }

    pub(crate) fn multiply<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
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

    pub(crate) fn mul_assign<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        *self = self.multiply(other, builder, driver)?;
        Ok(())
    }

    pub(crate) fn divide<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
        other.assert_is_not_zero(builder, driver)?;
        self.divide_no_zero_check(other, builder, driver)
    }

    fn divide_no_zero_check<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
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

    pub(crate) fn add<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let mut result = Self::default();

        if self.witness_index == other.witness_index {
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
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        *self = self.add(other, builder, driver);
    }

    pub(crate) fn neg(&self) -> Self {
        let mut result = self.to_owned();
        result.additive_constant = -result.additive_constant;
        result.multiplicative_constant = -result.multiplicative_constant;
        result
    }

    pub(crate) fn sub<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let rhs = other.neg();
        self.add(&rhs, builder, driver)
    }

    // this * to_mul + to_add
    pub(crate) fn madd<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        to_mul: &Self,
        to_add: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
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

        let mut out = mult_tmp;
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

    // Slices a `field_ct` at given indices (msb, lsb) both included in the slice,
    // returns three parts: [low, slice, high].
    pub(crate) fn slice<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        msb: u8,
        lsb: u8,
        total_bitsize: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<[Self; 3]> {
        const GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH: usize = 252;

        assert!(msb >= lsb);
        assert!((msb as usize) < GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH);

        let msb_plus_one = msb as u32 + 1;

        let value = self.get_value(builder, driver);
        let (hi, lo, slice) = if T::is_shared(&value) {
            let value = T::get_shared(&value).expect("Already checked it is shared");
            let [lo, slice, hi] = driver.slice(value, msb, lsb, total_bitsize)?;
            (
                T::AcvmType::from(hi),
                T::AcvmType::from(lo),
                T::AcvmType::from(slice),
            )
        } else {
            let value: BigUint = T::get_public(&value)
                .expect("Already checked it is public")
                .into();

            let hi_mask = (BigUint::one() << (total_bitsize - msb as usize)) - BigUint::one();
            let hi = (&value >> msb_plus_one) & hi_mask;

            let lo_mask = (BigUint::one() << lsb) - BigUint::one();
            let lo = &value & lo_mask;

            let slice_mask = (BigUint::one() << ((msb - lsb) as u32 + 1)) - BigUint::one();
            let slice = (value >> lsb) & slice_mask;

            let hi_ = T::AcvmType::from(F::from(hi));
            let lo_ = T::AcvmType::from(F::from(lo));
            let slice_ = T::AcvmType::from(F::from(slice));
            (hi_, lo_, slice_)
        };

        let hi_wit = Self::from_witness(hi, builder);
        let lo_wit = Self::from_witness(lo, builder);
        let slice_wit = Self::from_witness(slice, builder);

        hi_wit.create_range_constraint(
            GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH - msb as usize,
            builder,
            driver,
        )?;
        lo_wit.create_range_constraint(lsb as usize, builder, driver)?;
        slice_wit.create_range_constraint(msb_plus_one as usize - lsb as usize, builder, driver)?;

        let tmp_hi = hi_wit.multiply(
            &FieldCT::from(F::from(BigUint::one() << msb_plus_one)),
            builder,
            driver,
        )?;
        let mut other = tmp_hi.add(&lo_wit, builder, driver);
        let tmp_slice = slice_wit.multiply(
            &FieldCT::from(F::from(BigUint::one() << lsb)),
            builder,
            driver,
        )?;
        other.add_assign(&tmp_slice, builder, driver);
        self.assert_equal(&other, builder, driver);

        Ok([lo_wit, slice_wit, hi_wit])
    }

    fn create_range_constraint<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        if num_bits == 0 {
            self.assert_is_zero(builder);
        } else if self.is_constant() {
            let val: BigUint = T::get_public(&self.get_value(builder, driver))
                .expect("Constants are public")
                .into();
            assert!((val.bits() as usize) < num_bits);
        } else {
            let index = self.normalize(builder, driver).get_witness_index();
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
        P: Pairing<ScalarField = F>,
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
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        val: T::AcvmType,
        driver: &mut T,
    ) -> std::io::Result<T::AcvmType> {
        let is_zero = driver.equal(&val, &F::zero().into())?;
        let to_invert = driver.cmux(is_zero.to_owned(), F::one().into(), val)?;
        let inverse = driver.invert(to_invert)?;
        driver.cmux(is_zero, F::zero().into(), inverse)
    }

    fn assert_is_not_zero<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
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
    fn conditional_assign<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        predicate: &BoolCT<P, T>,
        lhs: &Self,
        rhs: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
        if predicate.is_constant() {
            let val = T::get_public(&predicate.get_value(driver)).expect("Constants are public");
            if val.is_zero() {
                return Ok(rhs.to_owned());
            } else {
                return Ok(lhs.to_owned());
            }
        }
        // if lhs and rhs are the same witness, just return it!
        if lhs.get_witness_index() == rhs.get_witness_index()
            && (lhs.additive_constant == rhs.additive_constant)
            && (lhs.multiplicative_constant == rhs.multiplicative_constant)
        {
            return Ok(lhs.to_owned());
        }

        let diff = lhs.sub(rhs, builder, driver);
        diff.madd(&predicate.to_field_ct(driver), rhs, builder, driver)
    }

    fn evaluate_polynomial_identity<
        P: Pairing<ScalarField = F>,
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

    fn equals<P: Pairing<ScalarField = F>, T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<BoolCT<P, T>> {
        let fa = self.get_value(builder, driver);
        let fb = other.get_value(builder, driver);

        if self.is_constant() && other.is_constant() {
            let val1 = T::get_public(&fa).expect("Constants are public");
            let val2 = T::get_public(&fb).expect("Constants are public");
            return Ok(BoolCT::from(val1 == val2));
        }

        let is_equal = driver.equal(&fa, &fb)?;
        let fd = driver.sub(fa, fb);
        let to_invert = driver.cmux(is_equal.to_owned(), F::one().into(), fd)?;
        let fc = driver.invert(to_invert)?;

        let result_witness = WitnessCT::from_acvm_type(is_equal.to_owned(), builder);
        let result = BoolCT {
            witness_bool: is_equal,
            witness_inverted: false,
            witness_index: result_witness.witness_index,
        };

        let x = FieldCT::from_witness(fc, builder);
        let diff = self.sub(other, builder, driver);
        // these constraints ensure that result is a boolean
        let result_ct = result.to_field_ct(driver);
        let zero_ct = FieldCT::from(F::zero());
        Self::evaluate_polynomial_identity(
            &diff,
            &x,
            &result_ct,
            &FieldCT::from(F::one()).neg(),
            builder,
            driver,
        );
        Self::evaluate_polynomial_identity(&diff, &result_ct, &zero_ct, &zero_ct, builder, driver);

        Ok(result)
    }

    fn add_two<P: Pairing<ScalarField = F>, T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        add_a: &Self,
        add_b: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        if add_a.is_constant() && add_b.is_constant() && self.is_constant() {
            return self
                .add(add_a, builder, driver)
                .add(add_b, builder, driver)
                .normalize(builder, driver);
        }

        let q_1 = self.multiplicative_constant;
        let q_2 = add_a.multiplicative_constant;
        let q_3 = add_b.multiplicative_constant;
        let q_c = self.additive_constant + add_a.additive_constant + add_b.additive_constant;

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

        let mut out = driver.mul_with_public(q_1, a);
        let t0 = driver.mul_with_public(q_2, b);
        let t1 = driver.mul_with_public(q_3, c);
        driver.add_assign(&mut out, t0);
        driver.add_assign(&mut out, t1);
        driver.add_assign_with_public(q_c, &mut out);

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
            a_scaling: q_1,
            b_scaling: q_2,
            c_scaling: q_3,
            d_scaling: -F::one(),
            const_scaling: q_c,
        });

        result
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

impl<
        F: PrimeField,
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    > From<WitnessCT<P, T>> for FieldCT<F>
{
    fn from(value: WitnessCT<P, T>) -> Self {
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

#[expect(dead_code)]
pub(crate) struct WitnessCT<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) witness: T::AcvmType,
    pub(crate) witness_index: u32,
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> WitnessCT<P, T> {
    #[expect(dead_code)]
    const IS_CONSTANT: u32 = FieldCT::<P::ScalarField>::IS_CONSTANT;

    pub(crate) fn from_acvm_type(
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

#[derive(Debug)]
pub(crate) struct BoolCT<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) witness_bool: T::AcvmType,
    pub(crate) witness_inverted: bool,
    pub(crate) witness_index: u32,
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> Default for BoolCT<P, T> {
    fn default() -> Self {
        Self {
            witness_bool: T::public_zero(),
            witness_inverted: false,
            witness_index: FieldCT::<P::ScalarField>::IS_CONSTANT,
        }
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> Clone for BoolCT<P, T> {
    fn clone(&self) -> Self {
        Self {
            witness_bool: self.witness_bool.to_owned(),
            witness_inverted: self.witness_inverted,
            witness_index: self.witness_index,
        }
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> From<bool> for BoolCT<P, T> {
    fn from(val: bool) -> Self {
        Self {
            witness_bool: P::ScalarField::from(val as u64).into(),
            witness_inverted: false,
            witness_index: FieldCT::<P::ScalarField>::IS_CONSTANT,
        }
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> BoolCT<P, T> {
    pub(crate) fn is_constant(&self) -> bool {
        self.witness_index == FieldCT::<P::ScalarField>::IS_CONSTANT
    }

    pub(crate) fn get_value(&self, driver: &mut T) -> T::AcvmType {
        let mut result = self.witness_bool.to_owned();

        if self.witness_inverted {
            driver.negate_inplace(&mut result);
            driver.add_assign_with_public(P::ScalarField::one(), &mut result);
        }
        result
    }

    fn to_field_ct(&self, driver: &mut T) -> FieldCT<P::ScalarField> {
        if self.is_constant() {
            let value = T::get_public(&self.get_value(driver)).expect("Constants are public");
            let additive_constant = if self.witness_inverted {
                P::ScalarField::one() - value
            } else {
                value
            };
            let multiplicative_constant = P::ScalarField::one();
            FieldCT {
                additive_constant,
                multiplicative_constant,
                witness_index: FieldCT::<P::ScalarField>::IS_CONSTANT,
            }
        } else if self.witness_inverted {
            FieldCT {
                additive_constant: P::ScalarField::one(),
                multiplicative_constant: -P::ScalarField::one(),
                witness_index: self.witness_index,
            }
        } else {
            FieldCT {
                additive_constant: P::ScalarField::zero(),
                multiplicative_constant: P::ScalarField::one(),
                witness_index: self.witness_index,
            }
        }
    }

    fn and(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
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

    fn or(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
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
            // result = A + B - AB, where A,B are the "real" values of the variables. But according to whether
            // witness_inverted flag is true, we need to invert the input. Hence, we look at four cases, and compute the
            // relevent coefficients of the selector q_1,q_2,q_m,q_c in each case
            let multiplicative_coefficient;
            let left_coefficient;
            let right_coefficient;
            let constant_coefficient;
            // a inverted: (1-a) + b - (1-a)b = 1-a+ab
            // ==> q_1=-1,q_2=0,q_m=1,q_c=1
            if self.witness_inverted && !other.witness_inverted {
                multiplicative_coefficient = P::ScalarField::one();
                left_coefficient = -P::ScalarField::one();
                right_coefficient = P::ScalarField::zero();
                constant_coefficient = P::ScalarField::one();
            }
            // b inverted: a + (1-b) - a(1-b) = 1-b+ab
            // ==> q_1=0,q_2=-1,q_m=1,q_c=1
            else if !self.witness_inverted && other.witness_inverted {
                multiplicative_coefficient = P::ScalarField::one();
                left_coefficient = P::ScalarField::zero();
                right_coefficient = -P::ScalarField::one();
                constant_coefficient = P::ScalarField::one();
            }
            // Both inverted: (1 - a) + (1 - b) - (1 - a)(1 - b) = 2 - a - b - (1 -a -b +ab) = 1 - ab
            // ==> q_m=-1,q_1=0,q_2=0,q_c=1
            else if self.witness_inverted && other.witness_inverted {
                multiplicative_coefficient = -P::ScalarField::one();
                left_coefficient = P::ScalarField::zero();
                right_coefficient = P::ScalarField::zero();
                constant_coefficient = P::ScalarField::one();
            }
            // No inversions: a + b - ab ==> q_m=-1,q_1=1,q_2=1,q_c=0
            else {
                multiplicative_coefficient = -P::ScalarField::one();
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
        } else if !self.is_constant() && other.is_constant() {
            let right = T::get_public(&right).expect("Constants are public");
            if right.is_zero() {
                result = self.to_owned();
            } else {
                result.witness_bool = P::ScalarField::one().into();
                // result.witness_inverted = false;
                // result.witness_index = IS_CONSTANT;
            }
        } else if self.is_constant() && !other.is_constant() {
            let left = T::get_public(&left).expect("Constants are public");
            if left.is_zero() {
                result = other.to_owned();
            } else {
                result.witness_bool = P::ScalarField::one().into();
                // result.witness_inverted = false;
                // result.witness_index = IS_CONSTANT;
            }
        } else {
            // result.witness_index = IS_CONSTANT;
            // result.witness_inverted = false;
        }

        Ok(result)
    }

    fn not(&self) -> Self {
        let mut result = self.to_owned();
        result.witness_inverted = !result.witness_inverted;
        result
    }

    fn normalize(&self, builder: &mut GenericUltraCircuitBuilder<P, T>, driver: &mut T) -> Self {
        if self.is_constant() || !self.witness_inverted {
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
pub(crate) struct CycleGroupCT<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) x: FieldCT<P::ScalarField>,
    pub(crate) y: FieldCT<P::ScalarField>,
    pub(crate) is_infinity: BoolCT<P, T>,
    pub(crate) is_constant: bool,
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> Clone for CycleGroupCT<P, T> {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            is_infinity: self.is_infinity.clone(),
            is_constant: self.is_constant,
        }
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> CycleGroupCT<P, T> {
    const ULTRA_NUM_TABLE_BITS: usize = 4;
    const TABLE_BITS: usize = Self::ULTRA_NUM_TABLE_BITS;

    pub(crate) fn new(
        x: FieldCT<P::ScalarField>,
        y: FieldCT<P::ScalarField>,
        is_infinity: BoolCT<P, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let x_ = x.normalize(builder, driver);
        let y_ = y.normalize(builder, driver);
        let is_constant = x.is_constant() && y.is_constant() && is_infinity.is_constant();

        Self {
            x: x_,
            y: y_,
            is_infinity,
            is_constant,
        }
    }

    pub(crate) fn get_standard_form(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
        let zero = FieldCT::zero();
        Ok(Self::new(
            FieldCT::conditional_assign(&self.is_infinity, &zero, &self.x, builder, driver)?,
            FieldCT::conditional_assign(&self.is_infinity, &zero, &self.y, builder, driver)?,
            self.is_infinity.to_owned(),
            builder,
            driver,
        ))
    }

    pub(crate) fn is_point_at_infinity(&self) -> &BoolCT<P, T> {
        &self.is_infinity
    }

    pub(crate) fn set_point_at_infinity(&mut self, is_infinity: BoolCT<P, T>) {
        self.is_infinity = is_infinity;
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.is_constant
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> Default for CycleGroupCT<P, T> {
    fn default() -> Self {
        Self {
            x: FieldCT::zero(),
            y: FieldCT::zero(),
            is_infinity: BoolCT::from(true),
            is_constant: true,
        }
    }
}

impl<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>>
    CycleGroupCT<P, T>
{
    const OFFSET_GENERATOR_DOMAIN_SEPARATOR: &[u8] = "cycle_group_offset_generator".as_bytes();

    fn from_group_element(value: P::CycleGroup) -> Self {
        match value.into_affine().xy() {
            Some((x, y)) => Self {
                x: FieldCT::from(x),
                y: FieldCT::from(y),
                is_infinity: BoolCT::from(false),
                is_constant: true,
            },
            None => Self {
                x: FieldCT::zero(),
                y: FieldCT::zero(),
                is_infinity: BoolCT::from(true),
                is_constant: true,
            },
        }
    }

    fn from_constant_witness(
        inp: P::CycleGroup,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let (x, y) = inp.into_affine().xy().unwrap_or_default();
        let result = Self {
            x: FieldCT::from_witness(x.into(), builder),
            y: FieldCT::from_witness(y.into(), builder),
            is_infinity: BoolCT::from(inp.is_zero()),
            is_constant: false,
        };

        result.x.assert_equal(&FieldCT::from(x), builder, driver);
        result.y.assert_equal(&FieldCT::from(y), builder, driver);
        result
    }

    fn get_value(
        &self,
        builder: &GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<T::AcvmPoint<P::CycleGroup>> {
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
    ) -> std::io::Result<Self> {
        debug_assert_eq!(base_points.len(), scalars.len());

        let mut variable_base_scalars = Vec::new();
        let mut variable_base_points = Vec::new();
        let mut fixed_base_scalars = Vec::new();
        let mut fixed_base_points = Vec::new();

        let mut num_bits = 0;
        for scalar in scalars.iter() {
            num_bits = std::cmp::max(num_bits, scalar.num_bits());

            // Note: is this the best place to put `validate_is_in_field`? Should it not be part of the constructor?
            // Note note: validate_scalar_is_in_field does not apply range checks to the hi/lo slices, this is performed
            // implicitly via the scalar mul algorithm
            scalar.validate_scalar_is_in_field(builder, driver)?;
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

        // Compute all required offset generators.
        let num_offset_generators = variable_base_points.len()
            + fixed_base_points.len()
            + has_variable_points as usize
            + has_fixed_points as usize;
        let offset_generators = generators::derive_generators::<P::CycleGroup>(
            Self::OFFSET_GENERATOR_DOMAIN_SEPARATOR,
            num_offset_generators,
            0,
        );

        let mut result = CycleGroupCT::default();

        if has_fixed_points {
            let (fixed_accumulator, offset_generator_delta) = Self::fixed_base_batch_mul_internal(
                &fixed_base_scalars,
                &fixed_base_points,
                // &offset_generators,
                builder,
                driver,
            )?;
            offset_accumulator += offset_generator_delta;
            result = fixed_accumulator;
        }

        if has_variable_points {
            let offset_generators_for_variable_base_batch_mul = &offset_generators
                [fixed_base_points.len()..offset_generators.len() - fixed_base_points.len()];

            let (variable_accumulator, offset_generator_delta) =
                Self::variable_base_batch_mul_internal(
                    &variable_base_scalars,
                    &variable_base_points,
                    offset_generators_for_variable_base_batch_mul,
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
    ) -> std::io::Result<(CycleGroupCT<P, T>, P::CycleGroup)> {
        debug_assert_eq!(scalars.len(), base_points.len());

        let num_points = base_points.len();
        let mut plookup_table_ids = Vec::with_capacity(num_points * 2);
        let mut plookup_base_points = Vec::with_capacity(num_points * 2);
        let mut plookup_scalars = Vec::with_capacity(num_points * 2);

        for (scalar, point) in scalars.iter().zip(base_points.iter()) {
            // Merge all tags of scalars (we don't have to account for CircuitSimulator in cycle_group yet, because it breaks)
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
        let zero_ct = FieldCT::zero();
        for (id, scalar) in plookup_table_ids.into_iter().zip(plookup_scalars) {
            let lookup_data = Plookup::get_lookup_accumulators_ct(
                builder,
                driver,
                id.to_owned(),
                scalar,
                zero_ct.to_owned(),
                false,
            )?;
            for j in 0..lookup_data[ColumnIdx::C2].len() {
                let x = lookup_data[ColumnIdx::C2][j].to_owned();
                let y = lookup_data[ColumnIdx::C3][j].to_owned();
                lookup_points.push(CycleGroupCT::new(
                    x,
                    y,
                    BoolCT::from(false),
                    builder,
                    driver,
                ));
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
    ) -> std::io::Result<(CycleGroupCT<P, T>, P::CycleGroup)> {
        debug_assert_eq!(scalars.len(), base_points.len());

        let mut num_bits = 0;
        for scalar in scalars.iter() {
            num_bits = std::cmp::max(num_bits, scalar.num_bits());
        }

        let num_rounds = num_bits.div_ceil(Self::TABLE_BITS);
        let num_points = base_points.len();
        let table_size = (1 << Self::TABLE_BITS) as usize;

        let mut scalar_slices = Vec::with_capacity(2 * num_points);

        // /**
        //  * Compute the witness values of the batch_mul algorithm natively, as Element types with a Z-coordinate.
        //  * We then batch-convert to AffineElement types, and feed these points as "hints" into the cycle_group methods.
        //  * This avoids the need to compute modular inversions for every group operation, which dramatically reduces witness
        //  * generation times
        //  */
        let mut operation_transcript =
            Vec::with_capacity(Self::TABLE_BITS + num_rounds * num_points);
        let mut native_straus_tables = Vec::with_capacity(num_points);
        let mut offset_generator_accumulator: P::CycleGroup =
            offset_generators[0].to_owned().into();
        for (point, offset_generator) in base_points.iter().zip(offset_generators.iter().skip(1)) {
            let mut native_straus_table = Vec::with_capacity(table_size);
            native_straus_table.push(T::AcvmPoint::from(offset_generator.to_owned().into()));
            for j in 1..table_size {
                let val = point.get_value(builder, driver)?;
                let val = driver.add_points(val, native_straus_table[j - 1].to_owned());
                native_straus_table.push(val);
            }
            native_straus_tables.push(native_straus_table);
        }
        for (scalar, point, offset_generator) in
            izip!(scalars.iter(), base_points.iter(), offset_generators.iter())
        {
            scalar_slices.push(StrausScalarSlice::new(
                scalar,
                Self::TABLE_BITS,
                builder,
                driver,
            )?);

            let table_transcript = StrausLookupTable::<P, T>::compute_straus_lookup_table_hints(
                point.get_value(builder, driver)?,
                offset_generator.to_owned(),
                Self::TABLE_BITS,
                driver,
            );
            for hint in table_transcript.into_iter().skip(1) {
                operation_transcript.push(hint);
            }
        }

        let mut accumulator: P::CycleGroup = offset_generators[0].to_owned().into();
        for i in 0..num_rounds {
            if i != 0 {
                for _ in 0..Self::TABLE_BITS {
                    // offset_generator_accumulator is a regular Element, so dbl() won't add constraints
                    accumulator += accumulator;
                    operation_transcript.push(T::AcvmPoint::from(accumulator));
                    offset_generator_accumulator += offset_generator_accumulator;
                }
            }

            for j in 0..num_points {
                todo!("Implement variable_base_batch_mul_internal")
            }
        }

        // BB batch normalizes operation_transcript here
        let operation_hints = operation_transcript;

        let mut point_tables = Vec::with_capacity(num_points);
        let hints_per_table = table_size - 1;
        for (i, (point, offset_generator)) in izip!(
            // scalars.iter(),
            base_points.iter(),
            offset_generators.iter().skip(1)
        )
        .enumerate()
        {
            // scalar_slices.push(StrausScalarSlice::new(scalar, Self::TABLE_BITS));
            scalar_slices.push(scalar_slices[i].to_owned()); // Already computed this
            point_tables.push(StrausLookupTable::<P, T>::new(
                point,
                offset_generator,
                Self::TABLE_BITS,
            ));
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
                    let point = point_table.read(scalar_slice);
                    points_to_add.push(point.expect("Must have a value"));
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
                    accumulator.dbl(Some(hint_ptr.to_owned()), builder, driver)?;
                    hint_ctr += 1;
                }
            }

            for scalar_slice in scalar_slices.iter() {
                let scalar_slice_ = scalar_slice.read(num_rounds - i - 1);
                // if we are doing a batch mul over scalars of different bit-lengths, we may not have a bit slice
                // for a given round and a given scalar
                if let Some(scalar_slice_) = scalar_slice_ {
                    // if let Some(public) = T::get_public(&scalar_slice_.get_value(builder, driver)) {
                    //     builder.assert_if_has_witness(
                    //         public
                    //             == P::ScalarField::from(
                    //                 scalar_slice.slices_native[num_rounds - i - 1],
                    //             ),
                    //     );
                    // }
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
        let mut coordinate_check_product = FieldCT::zero_with_additive(P::ScalarField::one());
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
    ) -> std::io::Result<Self> {
        // ensure we use a value of y that is not zero. (only happens if point at infinity)
        // this costs 0 gates if `is_infinity` is a circuit constant
        let modified_y = FieldCT::conditional_assign(
            self.is_point_at_infinity(),
            &FieldCT::zero_with_additive(P::ScalarField::one()),
            &self.y,
            builder,
            driver,
        )?
        .normalize(builder, driver);

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
                    builder,
                    driver,
                );
                return Ok(result);
            }

            let x = FieldCT::from_witness(x3, builder);
            let y = FieldCT::from_witness(y3, builder);
            result = CycleGroupCT::new(
                x,
                y,
                self.is_point_at_infinity().to_owned(),
                builder,
                driver,
            );
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
                let result = CycleGroupCT::new(
                    FieldCT::from(x3),
                    FieldCT::from(y3),
                    BoolCT::from(inf_value.is_one()),
                    builder,
                    driver,
                );
                return Ok(result);
            }
            result = CycleGroupCT::new(
                FieldCT::from_witness(x3, builder),
                FieldCT::from_witness(y3, builder),
                self.is_point_at_infinity().to_owned(),
                builder,
                driver,
            );
        }

        let y = modified_y.normalize(builder, driver);

        builder.create_ecc_dbl_gate(&EccDblGate {
            x1: self.x.get_witness_index(),
            y1: y.get_witness_index(),
            x3: result.x.get_witness_index(),
            y3: result.y.get_witness_index(),
        });

        Ok(result)
    }

    fn checked_unconditional_add(
        &self,
        other: &Self,
        hint: Option<T::AcvmPoint<P::CycleGroup>>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
        let x_delta = self.x.sub(&other.x, builder, driver);
        x_delta.assert_is_not_zero(builder, driver)?;
        self.unconditional_add(other, hint, builder, driver)
    }

    fn unconditional_add(
        &self,
        other: &Self,
        hint: Option<T::AcvmPoint<P::CycleGroup>>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
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
                return Ok(CycleGroupCT::new(
                    FieldCT::from(x3),
                    FieldCT::from(y3),
                    BoolCT::from(false),
                    builder,
                    driver,
                ));
            }
            let x = FieldCT::from_witness(x3, builder);
            let y = FieldCT::from_witness(y3, builder);
            result = CycleGroupCT::new(x, y, BoolCT::from(false), builder, driver);
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
            result = CycleGroupCT::new(r_x, r_y, BoolCT::from(false), builder, driver);
        }

        let add_gate = EccAddGate {
            x1: self.x.get_witness_index(),
            y1: self.y.get_witness_index(),
            x2: other.x.get_witness_index(),
            y2: other.y.get_witness_index(),
            x3: result.x.get_witness_index(),
            y3: result.y.get_witness_index(),
            sign_coefficient: P::ScalarField::one(),
        };
        builder.create_ecc_add_gate(&add_gate);

        Ok(result)
    }

    #[expect(clippy::field_reassign_with_default)]
    fn sub(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
        let x_coordinates_match = self.x.equals(&other.x, builder, driver)?;
        let y_coordinates_match = self.y.equals(&other.y, builder, driver)?;
        let double_predicate = x_coordinates_match
            .and(&y_coordinates_match.not(), builder, driver)?
            .normalize(builder, driver);
        let infinity_predicate = x_coordinates_match
            .and(&y_coordinates_match, builder, driver)?
            .normalize(builder, driver);

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
        let lambda = y2
            .neg()
            .sub(y1, builder, driver)
            .divide(&x_diff, builder, driver)?;
        let x3 = lambda.madd(&lambda, &x2.add(x1, builder, driver).neg(), builder, driver)?;
        let y3 = lambda.madd(&x1.sub(&x3, builder, driver), &y1.neg(), builder, driver)?;
        let add_result = CycleGroupCT::new(x3, y3, infinity_predicate.to_owned(), builder, driver);

        let dbl_result = self.dbl(None, builder, driver)?;

        // dbl if x_match, !y_match
        // infinity if x_match, y_match
        let mut result = CycleGroupCT::default();
        result.x = FieldCT::conditional_assign(
            &double_predicate,
            &dbl_result.x,
            &add_result.x,
            builder,
            driver,
        )?;
        result.y = FieldCT::conditional_assign(
            &double_predicate,
            &dbl_result.y,
            &add_result.y,
            builder,
            driver,
        )?;

        let lhs_infinity = self.is_point_at_infinity();
        let rhs_infinity = other.is_point_at_infinity();
        // if lhs infinity, return -rhs
        result.x = FieldCT::conditional_assign(lhs_infinity, &other.x, &result.x, builder, driver)?;
        result.y = FieldCT::conditional_assign(
            lhs_infinity,
            &other.y.neg().normalize(builder, driver),
            &result.y,
            builder,
            driver,
        )?;

        // if rhs infinity, return lhs
        result.x = FieldCT::conditional_assign(rhs_infinity, &self.x, &result.x, builder, driver)?;
        result.y = FieldCT::conditional_assign(rhs_infinity, &self.y, &result.y, builder, driver)?;

        // is result point at infinity?
        // yes = infinity_predicate && !lhs_infinity && !rhs_infinity
        // yes = lhs_infinity && rhs_infinity
        // n.b. can likely optimize this
        let result_is_infinity = infinity_predicate.and(
            &lhs_infinity
                .not()
                .and(&rhs_infinity.not(), builder, driver)?,
            builder,
            driver,
        )?;
        let both_infinity = lhs_infinity.and(rhs_infinity, builder, driver)?;
        let result_is_infinity = result_is_infinity.or(&both_infinity, builder, driver)?;
        result.set_point_at_infinity(result_is_infinity);
        Ok(result)
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
    const LO_BITS: usize = Self::MAX_BITS_PER_ENDOMORPHISM_SCALAR;
    const HI_BITS: usize = Self::NUM_BITS - Self::LO_BITS;

    pub(crate) fn new(lo: FieldCT<F>, hi: FieldCT<F>) -> Self {
        Self { lo, hi }
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
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        if self.is_constant() || self.skip_primality_test() {
            return Ok(());
        }
        // if !self.is_constant() && !self.skip_primality_test() {
        let cycle_group_modulus = if self.use_bn254_scalar_field_for_primality_test() {
            BigUint::from(ark_bn254::Fr::MODULUS)
        } else {
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
            builder.create_new_range_constraint(borrow.get_witness_index(), 1);
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

#[derive(Clone, Debug)]
struct StrausScalarSlice<F: PrimeField> {
    table_bits: usize,
    slices: Vec<FieldCT<F>>,
    // slices_native: Vec<u64>,
    // Note: We ignore the native values for now
}

impl<F: PrimeField> StrausScalarSlice<F> {
    fn new<P: Pairing<ScalarField = F>, T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        scalar: &CycleScalarCT<F>,
        table_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
        // Note: We ignore the native values for now
        let lo_bits = if scalar.num_bits() > CycleScalarCT::<F>::LO_BITS {
            CycleScalarCT::<F>::LO_BITS
        } else {
            scalar.num_bits()
        };
        let hi_bits = if scalar.num_bits() > CycleScalarCT::<F>::LO_BITS {
            scalar.num_bits() - CycleScalarCT::<F>::LO_BITS
        } else {
            0
        };

        let hi_slices = Self::slice_scalar(&scalar.hi, hi_bits, table_bits, builder, driver)?;
        let lo_slices = Self::slice_scalar(&scalar.lo, lo_bits, table_bits, builder, driver)?;

        let mut slices = lo_slices;
        slices.extend(hi_slices);

        // let mut slices_native = lo_slices.1;
        // slices_native.extend(hi_slices.1);

        Ok(Self {
            table_bits,
            slices,
            // slices_native,
        })
    }

    // convert an input cycle_scalar object into a vector of slices, each containing `table_bits` bits.
    // this also performs an implicit range check on the input slices
    fn slice_scalar<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        scalar: &FieldCT<F>,
        num_bits: usize,
        table_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Vec<FieldCT<F>>> {
        // Note: We ignore the native values for now

        // we record the scalar slices both as field_t circuit elements and u64 values
        // (u64 values are used to index arrays and we don't want to repeatedly cast a stdlib value to a numeric
        // primitive as this gets expensive when repeated enough times)
        let table_size = (1 << table_bits) as usize;
        let mut result = Vec::with_capacity(table_size);
        // let mut result_native = Vec::with_capacity(table_size);

        if num_bits == 0 {
            return Ok(result);
        }

        if scalar.is_constant() {
            let num_slices = num_bits.div_ceil(table_bits);
            let table_mask = table_size as u64 - 1;
            let value = scalar.get_value(builder, driver);
            let value = T::get_public(&value).expect("Constants are public");
            let mut raw_value: BigUint = value.into();
            for _ in 0..num_slices {
                let slice_v = raw_value.iter_u64_digits().next().unwrap_or_default() & table_mask;
                result.push(FieldCT::zero_with_additive(P::ScalarField::from(slice_v)));
                raw_value >>= table_bits;
            }
            return Ok(result);
        }

        let scalar_ = scalar.normalize(builder, driver);
        let slice_indices = builder.decompose_into_default_range(
            driver,
            scalar_.get_witness_index(),
            num_bits as u64,
            None,
            table_bits as u64,
        )?;

        for slice in slice_indices {
            result.push(FieldCT::from_witness_index(slice));
        }

        Ok(result)
    }

    fn read(&self, index: usize) -> Option<FieldCT<F>> {
        todo!("Implement StrausScalarSlice::read")
    }
}

struct StrausLookupTable<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    table_bits: usize,
    point_table: Vec<CycleGroupCT<P, T>>,
    rom_id: usize,
}

impl<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>>
    StrausLookupTable<P, T>
{
    fn new(
        base_point: &CycleGroupCT<P, T>,
        offset_generator: &<P::CycleGroup as CurveGroup>::Affine,
        table_bits: usize,
    ) -> Self {
        todo!("Implement StrausLookupTable::new")
    }

    fn compute_straus_lookup_table_hints(
        base_point: T::AcvmPoint<P::CycleGroup>,
        offset_generator: <P::CycleGroup as CurveGroup>::Affine,
        table_bits: usize,
        driver: &mut T,
    ) -> Vec<T::AcvmPoint<P::CycleGroup>> {
        let tables_size = (1 << table_bits) as usize;
        let base = if let Some(base_point) = T::get_public_point(&base_point) {
            if base_point.is_zero() {
                T::AcvmPoint::from(P::CycleGroup::generator())
            } else {
                T::AcvmPoint::from(base_point)
            }
        } else {
            todo!("Check zero here!");
            base_point
        };

        let mut hints = Vec::with_capacity(tables_size);
        hints.push(T::AcvmPoint::from(offset_generator.into()));
        for i in 1..tables_size {
            hints.push(driver.add_points(hints[i - 1].to_owned(), base.to_owned()));
        }
        hints
    }

    fn read(&self, index: FieldCT<P::ScalarField>) -> Option<CycleGroupCT<P, T>> {
        todo!("Implement StrausLookupTable::read")
    }
}
