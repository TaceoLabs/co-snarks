use crate::builder::GenericUltraCircuitBuilder;
use crate::types::types::{AddTriple, PolyTriple};
use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_ff::PrimeField;
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
