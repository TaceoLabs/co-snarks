use std::{marker::PhantomData, str::FromStr};

use ark_ff::PrimeField;
use serde::ser::SerializeSeq;
use serde::{de, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct JsonPublicInput<F: PrimeField + FromStr> {
    pub values: Vec<F>,
}

struct FrSeqVisitor<F: PrimeField + FromStr> {
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField + FromStr> FrSeqVisitor<F> {
    fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

impl<'de, F: PrimeField + FromStr> de::Visitor<'de> for FrSeqVisitor<F> {
    type Value = Vec<F>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of elements on a PrimeField as string with radix 10")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(s) = seq.next_element::<String>()? {
            values.push(F::from_str(&s).map_err(|_| de::Error::custom("invalid field element"))?);
        }
        Ok(values)
    }
}

impl<'de, F: PrimeField + FromStr> de::Deserialize<'de> for JsonPublicInput<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(Self {
            values: deserializer.deserialize_seq(FrSeqVisitor::<F>::new())?,
        })
    }
}

impl<F: PrimeField + FromStr> Serialize for JsonPublicInput<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.values.len()))?;
        for fr in self.values.iter() {
            seq.serialize_element(&fr.to_string())?;
        }
        seq.end()
    }
}

#[cfg(test)]
mod tests {

    use super::JsonPublicInput;
    use std::str::FromStr;

    #[test]
    fn can_serde_public_input_bn254() {
        let is_public_input_str = "[\"1\",\"2\",\"3\"]";
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>(is_public_input_str).unwrap();
        let should_values = vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("2").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
        ];
        assert_eq!(public_input.values, should_values);
        let ser_proof = serde_json::to_string(&public_input).unwrap();
        assert_eq!(ser_proof, is_public_input_str);
        let der_proof = serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>(&ser_proof).unwrap();
        assert_eq!(der_proof, public_input);
    }

    #[test]
    fn can_serde_public_input_bls12_381() {
        let is_public_input_str = "[\"1\",\"2\",\"3\"]";
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bls12_381::Fr>>(is_public_input_str)
                .unwrap();
        let should_values = vec![
            ark_bls12_381::Fr::from_str("1").unwrap(),
            ark_bls12_381::Fr::from_str("2").unwrap(),
            ark_bls12_381::Fr::from_str("3").unwrap(),
        ];
        assert_eq!(public_input.values, should_values);
        let ser_public_input = serde_json::to_string(&public_input).unwrap();
        assert_eq!(ser_public_input, is_public_input_str);
        let der_public_input =
            serde_json::from_str::<JsonPublicInput<ark_bls12_381::Fr>>(&ser_public_input).unwrap();
        assert_eq!(der_public_input, public_input);
    }
}
