use crate::builder::GenericUltraCircuitBuilder;
use crate::types::types::{AddTriple, PolyTriple};
use crate::utils::Utils;
use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;

use super::types::MulQuad;

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

    pub(crate) fn sub<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        self.add(
            &FieldCT {
                additive_constant: other.additive_constant.neg(),
                multiplicative_constant: other.multiplicative_constant.neg(),
                witness_index: other.witness_index,
            },
            builder,
            driver,
        )
    }

    pub(crate) fn negate_inplace(&mut self) {
        self.additive_constant.neg_in_place();
        self.multiplicative_constant.neg_in_place();
    }
    pub(crate) fn negate(&self) -> Self {
        FieldCT {
            additive_constant: self.additive_constant.neg(),
            multiplicative_constant: self.multiplicative_constant.neg(),
            witness_index: self.witness_index,
        }
    }

    pub(crate) fn add_two<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        add_a: &Self,
        add_b: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        if self.is_constant() && add_a.is_constant() && add_b.is_constant() {
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

    pub(crate) fn create_range_constraint<
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

pub(crate) struct ByteArray<F: PrimeField> {
    pub(crate) values: Vec<FieldCT<F>>,
}

impl<F: PrimeField> ByteArray<F> {
    pub(crate) fn default_with_length(length: usize) -> Self {
        Self {
            values: vec![FieldCT::zero(); length],
        }
    }

    pub(crate) fn write(&mut self, other: &Self) {
        self.values.extend_from_slice(&other.values);
    }

    pub(crate) fn new() -> Self {
        Self { values: Vec::new() }
    }
    pub(crate) fn from_field_ct<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: &FieldCT<F>,
        num_bytes: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
        assert!(num_bytes <= 32);
        let value = input.get_value(builder, driver);
        let mut values = Vec::with_capacity(num_bytes);
        if input.is_constant() {
            for i in 0..num_bytes {
                let byte_val = Utils::slice_u256(
                    T::get_public(&value)
                        .expect("Already checked it is public")
                        .into(),
                    (num_bytes - i - 1) as u64 * 8,
                    (num_bytes - i) as u64 * 8,
                );
                values.push(FieldCT::from(F::from(byte_val)));
            }
        } else {
            let byte_shift = F::from(256u64);
            let mut validator: FieldCT<F> = FieldCT::zero();
            let mut shifted_high_limb = FieldCT::zero(); // will be set to 2^128v_hi if `i` reaches 15.
            for i in 0..num_bytes {
                let byte = if T::is_shared(&value) {
                    let byte_val = driver.slice_once(
                        T::get_shared(&value).expect("Already checked it is shared"),
                        (num_bytes - i) as u8 * 8 - 1,
                        (num_bytes - i - 1) as u8 * 8,
                        254,
                    )?;
                    FieldCT::from_witness(byte_val.into(), builder)
                } else {
                    let byte_val = Utils::slice_u256(
                        T::get_public(&value)
                            .expect("Already checked it is public")
                            .into(),
                        (num_bytes - i - 1) as u64 * 8,
                        (num_bytes - i) as u64 * 8,
                    );
                    FieldCT::from_witness(F::from(byte_val).into(), builder)
                };
                byte.create_range_constraint(8, builder, driver)?;
                let scaling_factor_value = byte_shift.pow([(num_bytes - 1 - i) as u64]);
                let scaling_factor = FieldCT::from(scaling_factor_value);
                // AZTEC TODO: Addition could be optimized
                let mul = scaling_factor.multiply(&byte, builder, driver)?;
                validator = validator.add(&mul, builder, driver);
                values.push(byte);
                if i == 15 {
                    shifted_high_limb = validator.clone();
                }
            }
            validator.assert_equal(input, builder, driver);

            // constrain validator to be < r
            if num_bytes == 32 {
                let modulus_minus_one: BigUint = (-F::one()).into(); //fr::modulus - 1;
                let s_lo: F = Utils::slice_u256(modulus_minus_one.clone(), 0, 128).into();
                let s_hi: F = Utils::slice_u256(modulus_minus_one, 128, 256).into();
                let shift = F::from(BigUint::one() << 128);
                validator.negate_inplace();
                let y_lo = validator.add(&FieldCT::from(s_lo + shift), builder, driver);

                // we have plookup
                // carve out the 2 high bits from (y_lo + shifted_high_limb) and instantiate as y_overlap
                let y_lo_value = y_lo.get_value(builder, driver);
                let shifted_high_limb_val = shifted_high_limb.get_value(builder, driver);
                let y_lo_value = T::add(driver, y_lo_value, shifted_high_limb_val);
                let y_overlap_value = T::right_shift(driver, y_lo_value, 128)?;
                let mut y_overlap = FieldCT::from_witness(y_overlap_value, builder);
                y_overlap.create_range_constraint(2, builder, driver)?;
                let y_overlap_mul = y_overlap.multiply(
                    &FieldCT::from(F::from(BigUint::one() << 128)),
                    builder,
                    driver,
                )?;
                let y_remainder =
                    y_lo.add_two(&shifted_high_limb, &y_overlap_mul.negate(), builder, driver);
                y_remainder.create_range_constraint(128, builder, driver)?;
                let y_overlap_neg = y_overlap.negate();
                y_overlap = y_overlap_neg.add(&FieldCT::from(F::one()), builder, driver);

                // define input_hi = shifted_high_limb/shift. We know input_hi is max 128 bits, and we're checking
                // s_hi - (input_hi + borrow) is non-negative

                let mul = shifted_high_limb.multiply(
                    &FieldCT::from(shift.inverse().expect("non-zero")),
                    builder,
                    driver,
                )?;
                let mut y_hi = mul.add(&FieldCT::from(s_hi), builder, driver);
                y_hi = y_hi.sub(&y_overlap, builder, driver);
                y_hi.create_range_constraint(128, builder, driver)?;
            }
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
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<FieldCT<F>> {
        let bytes = self.values.len();
        let shift = F::from(256u64);
        let mut result = FieldCT::zero();
        for (i, value) in self.values.iter().enumerate() {
            let scaling_factor_value = shift.pow([(bytes - 1 - i) as u64]);
            let scaling_factor = FieldCT::from(scaling_factor_value);
            let mul = scaling_factor.multiply(value, builder, driver)?;
            result = result.add(&mul, builder, driver);
        }
        Ok(result.normalize(builder, driver))
    }

    /// Reverse the bytes in the byte array
    pub(crate) fn reverse(&mut self) {
        self.values.reverse();
    }
}
