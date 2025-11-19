pub mod test_utils {
    use std::collections::BTreeMap;

    use acir::native_types::{WitnessMap, WitnessStack};
    use ark_ff::PrimeField;
    use co_acvm::Rep3AcvmType;
    use co_circom_types::{Input, SharedWitness};
    use eyre::{Context as _, ContextCompat as _};
    use itertools::izip;
    use mpc_core::protocols::rep3;
    use num_bigint::BigUint;
    use num_traits::Num as _;

    pub fn combine_field_elements_for_vm(
        a: SharedWitness<ark_bn254::Fr, rep3::arithmetic::FieldShare<ark_bn254::Fr>>,
        b: SharedWitness<ark_bn254::Fr, rep3::arithmetic::FieldShare<ark_bn254::Fr>>,
        c: SharedWitness<ark_bn254::Fr, rep3::arithmetic::FieldShare<ark_bn254::Fr>>,
    ) -> Vec<ark_bn254::Fr> {
        let mut res = Vec::with_capacity(a.public_inputs.len() + a.witness.len());
        for (a, b, c) in izip!(a.public_inputs, b.public_inputs, c.public_inputs) {
            assert_eq!(a, b);
            assert_eq!(b, c);
            res.push(a);
        }
        res.extend(rep3::combine_field_elements(
            &a.witness, &b.witness, &c.witness,
        ));
        res
    }

    pub fn combine_field_elements_for_acvm<F: PrimeField>(
        mut a: WitnessStack<Rep3AcvmType<F>>,
        mut b: WitnessStack<Rep3AcvmType<F>>,
        mut c: WitnessStack<Rep3AcvmType<F>>,
    ) -> WitnessStack<F> {
        let mut res = WitnessStack::default();
        assert_eq!(a.length(), b.length());
        assert_eq!(b.length(), c.length());
        while let Some(stack_item_a) = a.pop() {
            let stack_item_b = b.pop().unwrap();
            let stack_item_c = c.pop().unwrap();
            assert_eq!(stack_item_a.index, stack_item_b.index);
            assert_eq!(stack_item_b.index, stack_item_c.index);
            let mut witness_map = WitnessMap::default();
            for ((witness_a, share_a), (witness_b, share_b), (witness_c, share_c)) in itertools::izip!(
                stack_item_a.witness.into_iter(),
                stack_item_b.witness.into_iter(),
                stack_item_c.witness.into_iter()
            ) {
                assert_eq!(witness_a, witness_b);
                assert_eq!(witness_b, witness_c);
                let reconstructed = match (share_a, share_b, share_c) {
                    (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b), Rep3AcvmType::Public(c)) => {
                        if a == b && b == c {
                            a
                        } else {
                            panic!("must be all public")
                        }
                    }
                    (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b), Rep3AcvmType::Shared(c)) => {
                        mpc_core::protocols::rep3::combine_field_element(a, b, c)
                    }
                    _ => unimplemented!(),
                };
                witness_map.insert(witness_a, reconstructed);
            }
            res.push(stack_item_a.index, witness_map);
        }
        res
    }

    pub fn split_input_plain<F: PrimeField>(input: Input) -> eyre::Result<BTreeMap<String, F>> {
        let mut split_input = BTreeMap::new();
        for (name, val) in input {
            let parsed_vals = if val.is_array() {
                parse_array::<F>(&val)?
                    .into_iter()
                    .enumerate()
                    .filter_map(|(idx, field)| field.map(|field| (format!("{name}[{idx}]"), field)))
                    .collect::<BTreeMap<_, _>>()
            } else if val.is_boolean() {
                BTreeMap::from([(name.clone(), parse_boolean::<F>(&val)?)])
            } else {
                BTreeMap::from([(name.clone(), parse_field::<F>(&val)?)])
            };

            for (k, v) in parsed_vals.into_iter() {
                split_input.insert(k.clone(), v);
            }
        }
        Ok(split_input)
    }

    fn parse_field<F>(val: &serde_json::Value) -> eyre::Result<F>
    where
        F: std::str::FromStr + PrimeField,
    {
        let s = val.as_str().ok_or_else(|| {
            eyre::eyre!(
                "expected input to be a field element string, got \"{}\"",
                val
            )
        })?;
        let (is_negative, stripped) = if let Some(stripped) = s.strip_prefix('-') {
            (true, stripped)
        } else {
            (false, s)
        };
        let positive_value = if let Some(stripped) = stripped.strip_prefix("0x") {
            let mut big_int = BigUint::from_str_radix(stripped, 16)
                .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
                .context("while parsing field element")?;
            let modulus = BigUint::try_from(F::MODULUS).expect("can convert mod to biguint");
            if big_int >= modulus {
                tracing::warn!("val {} >= mod", big_int);
                // snarkjs also does this
                big_int %= modulus;
            }
            let big_int: F::BigInt = big_int
                .try_into()
                .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
                .context("while parsing field element")?;
            F::from(big_int)
        } else {
            stripped
                .parse::<F>()
                .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
                .context("while parsing field element")?
        };
        if is_negative {
            Ok(-positive_value)
        } else {
            Ok(positive_value)
        }
    }

    fn parse_array<F: PrimeField>(val: &serde_json::Value) -> eyre::Result<Vec<Option<F>>> {
        let json_arr = val.as_array().expect("is an array");
        let mut field_elements = vec![];
        for ele in json_arr {
            if ele.is_array() {
                field_elements.extend(parse_array::<F>(ele)?);
            } else if ele.is_boolean() {
                field_elements.push(Some(parse_boolean(ele)?));
            } else if ele.as_str().is_some_and(|e| e == "?") {
                field_elements.push(None);
            } else {
                field_elements.push(Some(parse_field(ele)?));
            }
        }
        Ok(field_elements)
    }

    fn parse_boolean<F: PrimeField>(val: &serde_json::Value) -> eyre::Result<F> {
        let bool = val
            .as_bool()
            .with_context(|| format!("expected input to be a bool, got {val}"))?;
        if bool {
            Ok(F::ONE)
        } else {
            Ok(F::ZERO)
        }
    }
}
