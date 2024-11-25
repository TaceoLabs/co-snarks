use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde::ser::SerializeStruct;

macro_rules! into_u64 {
    ($x: expr) => {
        u64::try_from($x).expect("usize fits into u64")
    };
}

pub fn matrices_se<S, F>(matrices: &ConstraintMatrices<F>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    F: PrimeField,
{
    let mut state = s.serialize_struct("matrices", 9)?;
    state.serialize_field("num_instance_variables", &matrices.num_instance_variables)?;
    state.serialize_field("num_witness_variables", &matrices.num_witness_variables)?;
    state.serialize_field("num_constraints", &matrices.num_constraints)?;
    state.serialize_field("a_num_non_zero", &matrices.a_num_non_zero)?;
    state.serialize_field("b_num_non_zero", &matrices.b_num_non_zero)?;
    state.serialize_field("c_num_non_zero", &matrices.c_num_non_zero)?;
    println!("a len: {}", matrices.a.len());
    println!("a[0] len: {}", matrices.a[0].len());
    todo!()
}

/// Serialize an object with ark serialization, to be used with serde.
/// `#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]`
pub fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

/// Deserialize an object with ark deserialization, to be used with serde. This
/// version does not perform any sanity checks after deserialization (e.g. check
/// whether a point is on a curve or not).
/// `#[serde(serialize_with = "ark_se", deserialize_with = "unchecked_ark_de")]`
pub fn unchecked_ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::No);
    a.map_err(serde::de::Error::custom)
}
