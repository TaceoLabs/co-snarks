use std::{marker::PhantomData, str::FromStr};

use ark_ff::PrimeField;
use serde::{de, Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonPublicInput<F: PrimeField + FromStr> {
    #[serde(deserialize_with = "deserialize_public_input::<_, F>")]
    pub values: Vec<F>,
}

fn deserialize_public_input<'de, D, F: PrimeField + FromStr>(
    deserializer: D,
) -> Result<Vec<F>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Test::<F>::new())
}

struct Test<F: PrimeField + FromStr> {
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField + FromStr> Test<F> {
    fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

impl<'de, F: PrimeField + FromStr> de::Visitor<'de> for Test<F> {
    type Value = Vec<F>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 3 strings, representing a projective point on G1")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(s) = seq.next_element::<String>()? {
            values.push(F::from_str(&s).map_err(|_| de::Error::custom("".to_owned()))?);
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::JsonPublicInput;

    #[test]
    fn test() {
        let public_input =
            serde_json::from_str::<JsonPublicInput<ark_bn254::Fr>>("[\"1\",\"2\",\"3\",\"4\"]")
                .unwrap();
        println!("{public_input:?}");
    }
}
