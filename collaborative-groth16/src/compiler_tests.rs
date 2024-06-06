#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use circom_mpc_compiler::CompilerBuilder;
    use circom_types::groth16::witness::Witness;
    use std::{
        fs::{self, File},
        str::FromStr,
    };

    pub struct TestInputs {
        circuit_path: String,
        input: Vec<ark_bn254::Fr>,
        witness: Witness<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>,
    }

    pub fn from_test_name(fn_name: &str, number: usize) -> TestInputs {
        let circuit_path = format!("../test_vectors/circuits/test-circuits/{}.circom", fn_name);
        let input_file = File::open(format!(
            "../test_vectors/circuits/test-circuits/witness_outputs/{}/input{}.json",
            fn_name, number
        ))
        .unwrap();
        let json_str: serde_json::Value = serde_json::from_reader(input_file).unwrap();
        let input = json_str
            .get("in")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|s| ark_bn254::Fr::from_str(s.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();

        let witness = File::open(format!(
            "../test_vectors/circuits/test-circuits/witness_outputs/{}/witness{}.wtns",
            fn_name, number
        ))
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();

        TestInputs {
            circuit_path,
            input,
            witness: should_witness,
        }
    }

    #[test]
    fn multiplier16() {
        let inp: TestInputs = from_test_name("multiplier16", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    #[test]
    fn control_flow() {
        let inp: TestInputs = from_test_name("control_flow", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    #[test]
    fn functions() {
        let inp: TestInputs = from_test_name("functions", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }
    #[test]
    fn binsum_test() {
        let inp: TestInputs = from_test_name("binsum_test", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    #[test]
    fn mimc() {
        let inp: TestInputs = from_test_name("mimc_hasher", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    #[test]
    fn pedersen() {
        let inp: TestInputs = from_test_name("pedersen_hasher", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    #[test]
    fn poseidon_1() {
        let inp: TestInputs = from_test_name("poseidon_hasher1", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    #[test]
    fn poseidon2() {
        let inp: TestInputs = from_test_name("poseidon_hasher2", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    #[test]
    fn poseidon16() {
        let inp: TestInputs = from_test_name("poseidon_hasher16", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    #[test]
    fn eddsa_verify() {
        let inp: TestInputs = from_test_name("eddsa_verify", 0);
        let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(inp.input)
            .unwrap();
        assert_eq!(is_witness, inp.witness.values);
    }

    //new ones:
    #[test]
    fn aliascheck_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/aliascheck_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("aliascheck_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn babyadd_tester() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/babyadd_tester/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("babyadd_tester", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn babycheck_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/babycheck_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("babycheck_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn babypbk_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/babypbk_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("babypbk_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn binsub_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/binsub_test/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("binsub_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn constants_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/constants_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("constants_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn eddsa_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/eddsa_test/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("eddsa_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn eddsamimc_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/eddsamimc_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("eddsamimc_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn eddsaposeidon_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/eddsaposeidon_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("eddsaposeidon_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn edwards2montgomery() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/edwards2montgomery/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("edwards2montgomery", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn escalarmul_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/escalarmul_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("escalarmul_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn escalarmul_test_min() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/escalarmul_test_min/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("escalarmul_test_min", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn escalarmulany_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/escalarmulany_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("escalarmulany_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn escalarmulfix_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/escalarmulfix_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("escalarmulfix_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn escalarmulw4table_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/escalarmulw4table_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("escalarmulw4table_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn escalarmulw4table_test3() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/escalarmulw4table_test3/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("escalarmulw4table_test3", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn greatereqthan() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("greatereqthan", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn greaterthan() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/greaterthan/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("greaterthan", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn isequal() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/isequal/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("isequal", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn iszero() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/iszero/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("iszero", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn lesseqthan() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/lesseqthan/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("lesseqthan", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn lessthan() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/lessthan/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("lessthan", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn mimc_sponge_hash_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/mimc_sponge_hash_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("mimc_sponge_hash_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn mimc_sponge_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/mimc_sponge_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("mimc_sponge_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn mimc_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/mimc_test/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("mimc_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn montgomery2edwards() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/montgomery2edwards/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("montgomery2edwards", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn montgomeryadd() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/montgomeryadd/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("montgomeryadd", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn montgomerydouble() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/montgomerydouble/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("montgomerydouble", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn mux1_1() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/mux1_1/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("mux1_1", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn mux2_1() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/mux2_1/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("mux2_1", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn mux3_1() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/mux3_1/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("mux3_1", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn mux4_1() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("mux4_1", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn pedersen2_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/pedersen2_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("pedersen2_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn pedersen_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/pedersen_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("pedersen_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn pointbits_loopback() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/pointbits_loopback/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("pointbits_loopback", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn poseidon3_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/poseidon3_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("poseidon3_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn poseidon6_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/poseidon6_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("poseidon6_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn poseidonex_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/poseidonex_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("poseidonex_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn sha256_2_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/sha256_2_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("sha256_2_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn sha256_test448() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/sha256_test448/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("sha256_test448", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }
    #[test]
    fn sha256_test512() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/sha256_test512/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("sha256_test512", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn sign_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/sign_test/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("sign_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn smtprocessor10_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/smtprocessor10_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("smtprocessor10_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn smtverifier10_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/smtverifier10_test/witness{}.wtns", i
                )).is_err() {
                    break
                }
            let inp: TestInputs = from_test_name("smtverifier10_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }

    #[test]
    fn sum_test() {
        let mut i = 0;
        loop {
            if fs::metadata(format!(
                "../test_vectors/circuits/test-circuits/witness_outputs/sum_test/witness{}.wtns",
                i
            ))
            .is_err()
            {
                break;
            }
            let inp: TestInputs = from_test_name("sum_test", i);
            let builder = CompilerBuilder::<Bn254>::new(inp.circuit_path.as_str().to_owned())
                .link_library("../test_vectors/circuits/libs/");
            let is_witness = builder
                .build()
                .parse()
                .unwrap()
                .to_plain_vm()
                .run(inp.input)
                .unwrap();
            assert_eq!(is_witness, inp.witness.values);
            i += 1;
        }
        assert_ne!(i, 0);
    }
}
