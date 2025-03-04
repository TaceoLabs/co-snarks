use super::types::MulQuad;
use crate::builder::GenericUltraCircuitBuilder;
use crate::prelude::HonkCurve;
use crate::types::types::{AddTriple, PolyTriple};
use crate::TranscriptFieldType;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::PrimeField;
use ark_ff::{One, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;

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
            assert_eq!(left, right);
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
            assert!(self.additive_constant.is_zero());
            return;
        }

        let var = builder.get_variable(self.witness_index as usize);
        if !T::is_shared(&var) {
            // Sanity check
            let value = T::get_public(&var).expect("Already checked it is public");
            assert!((value * self.multiplicative_constant + self.additive_constant).is_zero())
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

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> Clone for BoolCT<P, T> {
    fn clone(&self) -> Self {
        Self {
            witness_bool: self.witness_bool.to_owned(),
            witness_inverted: self.witness_inverted,
            witness_index: self.witness_index,
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
}

pub(crate) struct CycleGroupCT<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) x: FieldCT<P::ScalarField>,
    pub(crate) y: FieldCT<P::ScalarField>,
    pub(crate) is_infinity: BoolCT<P, T>,
    pub(crate) is_constant: bool,
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> CycleGroupCT<P, T> {
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

    pub(crate) fn is_constant(&self) -> bool {
        self.is_constant
    }
}

impl<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>>
    CycleGroupCT<P, T>
{
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
                // && plookup::fixed_base::table::lookup_table_exists_for_point(point_val)
                {
                    todo!("plookup stuff");
                    fixed_base_scalars.push(scalar);
                    fixed_base_points.push(point_val);
                } else {
                    // womp womp. We have lookup tables at home. ROM tables.
                    variable_base_scalars.push(scalar);
                    variable_base_points.push(point);
                }
                has_non_constant_component = true;
            } else {
                variable_base_scalars.push(scalar);
                variable_base_points.push(point);
                can_unconditional_add = false;
                has_non_constant_component = true;
                // variable base
            }
        }

        todo!("Implement batch_mul")
    }
}

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
        for digit in digits.iter().take(2) {
            lo <<= 64;
            lo += *digit;
        }
        for digit in digits.iter().skip(2).take(2) {
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
            F::MODULUS.into()
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
