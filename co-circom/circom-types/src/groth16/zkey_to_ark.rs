use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};

/// A helper to enable [ConstraintMatrices] to be able to be serialized using [ark-serialize].
pub struct ConstraintMatricesWrapper<F: PrimeField>(pub ConstraintMatrices<F>);

impl<F: PrimeField> CanonicalSerialize for ConstraintMatricesWrapper<F> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.a.serialize_with_mode(&mut writer, compress)?;
        self.0.b.serialize_with_mode(&mut writer, compress)?;
        self.0.c.serialize_with_mode(&mut writer, compress)?;
        self.0
            .a_num_non_zero
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .b_num_non_zero
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .c_num_non_zero
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .num_instance_variables
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .num_witness_variables
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .num_constraints
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.0.a.serialized_size(compress)
            + self.0.b.serialized_size(compress)
            + self.0.c.serialized_size(compress)
            + self.0.a_num_non_zero.serialized_size(compress)
            + self.0.b_num_non_zero.serialized_size(compress)
            + self.0.c_num_non_zero.serialized_size(compress)
            + self.0.num_instance_variables.serialized_size(compress)
            + self.0.num_witness_variables.serialized_size(compress)
            + self.0.num_constraints.serialized_size(compress)
    }
}

impl<F: PrimeField> Valid for ConstraintMatricesWrapper<F> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.0.a.check()?;
        self.0.b.check()?;
        self.0.c.check()?;
        self.0.a_num_non_zero.check()?;
        self.0.b_num_non_zero.check()?;
        self.0.c_num_non_zero.check()?;
        self.0.num_instance_variables.check()?;
        self.0.num_witness_variables.check()?;
        self.0.num_constraints.check()?;
        Ok(())
    }
}

impl<F: PrimeField> CanonicalDeserialize for ConstraintMatricesWrapper<F> {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let a = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let b = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let c = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let a_num_non_zero =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let b_num_non_zero =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let c_num_non_zero =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let num_instance_variables =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let num_witness_variables =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let num_constraints =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;

        Ok(ConstraintMatricesWrapper(ConstraintMatrices {
            a,
            b,
            c,
            a_num_non_zero,
            b_num_non_zero,
            c_num_non_zero,
            num_instance_variables,
            num_witness_variables,
            num_constraints,
        }))
    }
}
