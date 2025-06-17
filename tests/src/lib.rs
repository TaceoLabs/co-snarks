pub mod test_utils {
    use std::{array, collections::BTreeMap, thread::JoinHandle};

    use acir::{
        acir_field::GenericFieldElement,
        native_types::{WitnessMap, WitnessStack},
    };
    use ark_ff::PrimeField;
    use co_acvm::{
        solver::{partial_abi::PublicMarker, Rep3CoSolver},
        Rep3AcvmType,
    };
    use co_circom_types::SharedWitness;
    use co_noir::Pairing;
    use itertools::izip;
    use mpc_core::protocols::rep3;
    use noirc_abi::Abi;
    use num_bigint::BigUint;
    use num_traits::Num as _;
    use rand::{CryptoRng, Rng};
    use rayon::ThreadPoolBuilder;

    pub fn spawn_pool<T: Send + 'static>(op: impl FnOnce() -> T + Send + 'static) -> JoinHandle<T> {
        std::thread::spawn(|| {
            let pool = ThreadPoolBuilder::new()
                .num_threads(4)
                .use_current_thread()
                .build()
                .unwrap();
            pool.install(op)
        })
    }

    pub fn share_input_rep3<P: Pairing, R: Rng + CryptoRng>(
        initial_witness: BTreeMap<String, PublicMarker<GenericFieldElement<P::ScalarField>>>,
        rng: &mut R,
    ) -> [BTreeMap<String, Rep3AcvmType<P::ScalarField>>; 3] {
        let mut witnesses = array::from_fn(|_| BTreeMap::default());
        for (witness, v) in initial_witness.into_iter() {
            match v {
                PublicMarker::Public(v) => {
                    for w in witnesses.iter_mut() {
                        w.insert(witness.to_owned(), Rep3AcvmType::Public(v.into_repr()));
                    }
                }
                PublicMarker::Private(v) => {
                    let shares = rep3::share_field_element(v.into_repr(), rng);
                    for (w, share) in witnesses.iter_mut().zip(shares) {
                        w.insert(witness.clone(), Rep3AcvmType::Shared(share));
                    }
                }
            }
        }

        witnesses
    }

    pub fn translate_witness_share_rep3(
        witness: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>,
        abi: &Abi,
    ) -> WitnessMap<Rep3AcvmType<ark_bn254::Fr>> {
        Rep3CoSolver::<ark_bn254::Fr, ()>::witness_map_from_string_map(witness, abi).unwrap()
    }

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

    pub fn parse_field<F>(val: &serde_json::Value) -> eyre::Result<F>
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
                .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))?;
            let modulus = BigUint::try_from(F::MODULUS).expect("can convert mod to biguint");
            if big_int >= modulus {
                // snarkjs also does this
                big_int %= modulus;
            }
            let big_int: F::BigInt = big_int
                .try_into()
                .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))?;
            F::from(big_int)
        } else {
            stripped
                .parse::<F>()
                .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))?
        };
        if is_negative {
            Ok(-positive_value)
        } else {
            Ok(positive_value)
        }
    }

    pub fn parse_array<F: PrimeField>(val: &serde_json::Value) -> eyre::Result<Vec<F>> {
        let json_arr = val.as_array().expect("is an array");
        let mut field_elements = vec![];
        for ele in json_arr {
            if ele.is_array() {
                field_elements.extend(parse_array::<F>(ele)?);
            } else if ele.is_boolean() {
                panic!()
            } else {
                field_elements.push(parse_field(ele)?);
            }
        }
        Ok(field_elements)
    }
}
