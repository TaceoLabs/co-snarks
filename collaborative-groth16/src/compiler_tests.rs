


#[cfg(test)]
mod compiler_tests {
    use circom_mpc_compiler::CompilerBuilder;
    use ark_bn254::Bn254;
    use tracing_test::traced_test;
    use circom_types::groth16::witness::Witness;
    use itertools::Itertools;
    use std::{fs::File, str::FromStr};
    #[traced_test]
    #[test]
    fn logs() {
        let file = "../test_vectors/circuits/multiplier2.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned()).build();
        let is_witness = builder
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("3").unwrap(),
                ark_bn254::Fr::from_str("11").unwrap(),
            ])
            .unwrap();
        assert_eq!(
            is_witness,
            vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("33").unwrap(),
                ark_bn254::Fr::from_str("3").unwrap(),
                ark_bn254::Fr::from_str("11").unwrap()
            ]
        );
        assert!(logs_contain(
            "This is a test to see whether the logging work:  33"
        ));
    }

    #[test]
    fn mul16() {
        let file = "../test_vectors/circuits/multiplier16.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned()).build();
        let is_witness = builder
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("5").unwrap(),
                ark_bn254::Fr::from_str("10").unwrap(),
                ark_bn254::Fr::from_str("2").unwrap(),
                ark_bn254::Fr::from_str("3").unwrap(),
                ark_bn254::Fr::from_str("4").unwrap(),
                ark_bn254::Fr::from_str("5").unwrap(),
                ark_bn254::Fr::from_str("6").unwrap(),
                ark_bn254::Fr::from_str("7").unwrap(),
                ark_bn254::Fr::from_str("8").unwrap(),
                ark_bn254::Fr::from_str("9").unwrap(),
                ark_bn254::Fr::from_str("10").unwrap(),
                ark_bn254::Fr::from_str("11").unwrap(),
                ark_bn254::Fr::from_str("12").unwrap(),
                ark_bn254::Fr::from_str("13").unwrap(),
                ark_bn254::Fr::from_str("14").unwrap(),
                ark_bn254::Fr::from_str("15").unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/bn254/multiplier16/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn control_flow() {
        let file = "../test_vectors/circuits/control_flow.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("1").unwrap()])
            .unwrap();
        let witness = File::open("../test_vectors/bn254/control_flow/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn functions() {
        let file = "../test_vectors/circuits/functions.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = vec![ark_bn254::Fr::from_str("5").unwrap()];
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input)
            .unwrap();
        let witness = File::open("../test_vectors/bn254/functions/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }
    #[test]
    fn bin_sum() {
        let file = "../test_vectors/circuits/binsum_caller.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = vec![
            //13
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            //12
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            //10
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input)
            .unwrap();
        let witness = File::open("../test_vectors/bn254/bin_sum/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn mimc() {
        let file = "../test_vectors/circuits/mimc_hasher.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("2").unwrap(),
                ark_bn254::Fr::from_str("3").unwrap(),
                ark_bn254::Fr::from_str("4").unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/bn254/mimc/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn pedersen() {
        let file = "../test_vectors/circuits/pedersen_hasher.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("5").unwrap()])
            .unwrap();
        let witness = File::open("../test_vectors/bn254/pedersen/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn poseidon1() {
        let file = "../test_vectors/circuits/poseidon_hasher1.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("5").unwrap()])
            .unwrap();
        let witness = File::open("../test_vectors/bn254/poseidon/poseidon1.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn poseidon2() {
        let file = "../test_vectors/circuits/poseidon_hasher2.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str("1").unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/bn254/poseidon/poseidon2.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn poseidon16() {
        let file = "../test_vectors/circuits/poseidon_hasher16.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(
                (0..16)
                    .map(|i| ark_bn254::Fr::from_str(i.to_string().as_str()).unwrap())
                    .collect_vec(),
            )
            .unwrap();
        let witness = File::open("../test_vectors/bn254/poseidon/poseidon16.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn eddsa_verify() {
        let file = "../test_vectors/circuits/eddsa_verify.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str(
                    "13277427435165878497778222415993513565335242147425444199013288855685581939618",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "13622229784656158136036771217484571176836296686641868549125388198837476602820",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2010143491207902444122668013146870263468969134090678646686512037244361350365",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "11220723668893468001994760120794694848178115379170651044669708829805665054484",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2367470421002446880004241260470975644531657398480773647535134774673409612366",
                )
                .unwrap(),
                ark_bn254::Fr::from_str("1234").unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/bn254/eddsa/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    //new ones:

    #[test]
    fn aliascheck_test1() {
        let file = "../test_vectors/circuits/test-circuits/aliascheck_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("0").unwrap(); 254])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/aliascheck_test_js/witness0.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn aliascheck_test2() {
        let file = "../test_vectors/circuits/test-circuits/aliascheck_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = [
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1", "1", "1", "1", "1", "1",
            "0", "0", "1", "0", "0", "1", "1", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0",
            "0", "0", "1", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0",
            "1", "0", "0", "1", "0", "0", "0", "0", "1", "1", "1", "0", "1", "0", "0", "1", "1",
            "1", "0", "1", "1", "0", "0", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "0",
            "1", "0", "0", "0", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0", "1", "1", "0",
            "0", "0", "0", "0", "1", "0", "1", "0", "0", "1", "0", "1", "1", "1", "0", "1", "0",
            "0", "0", "0", "1", "1", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0", "1", "1",
            "0", "0", "0", "0", "0", "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0",
            "1", "0", "0", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "0",
            "1", "1", "1", "0", "1", "1", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0",
            "0", "1", "0", "1", "1", "0", "0", "0", "1", "1", "0", "0", "1", "0", "0", "0", "0",
            "1", "1", "1", "0", "1", "0", "0", "1", "1", "1", "0", "0", "1", "1", "1", "0", "0",
            "1", "0", "0", "0", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "1",
        ];
        let f_input = input
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input)
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/aliascheck_test_js/witnessq-1.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }
    #[test]
    fn aliascheck_test3() {
        let file = "../test_vectors/circuits/test-circuits/aliascheck_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = [
            "1", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        ];
        let f_input = input
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input)
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/aliascheck_test_js/witness3.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn babyadd_tester() {
        let file = "../test_vectors/circuits/test-circuits/babyadd_tester.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str("1").unwrap(),
            ])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/babyadd_tester_js/witness.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }
    #[test]
    fn babyadd_tester2() {
        let file = "../test_vectors/circuits/test-circuits/babyadd_tester.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str(
                    "17777552123799933955779906779655732241715742912184938656739573121738514868268",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2626589144620713026669568689430873010625803728049924121243784502389097019475",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "16540640123574156134436876038791482806971768689494387082833631921987005038935",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "20819045374670962167435360035096875258406992893633759881276124905556507972311",
                )
                .unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/babyadd_tester_js/witness2.wtns"
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn babyadd_tester3() {
        let file = "../test_vectors/circuits/test-circuits/babyadd_tester.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str(
                    "17777552123799933955779906779655732241715742912184938656739573121738514868268",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2626589144620713026669568689430873010625803728049924121243784502389097019475",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "17777552123799933955779906779655732241715742912184938656739573121738514868268",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2626589144620713026669568689430873010625803728049924121243784502389097019475",
                )
                .unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/babyadd_tester_js/witness3.wtns"
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn babycheck_test() {
        let file = "../test_vectors/circuits/test-circuits/babycheck_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str("1").unwrap(),
            ])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/babycheck_test_js/witness.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn babypbk_test() {
        let file = "../test_vectors/circuits/test-circuits/babypbk_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str(
                "6605950343500658796976613741813629323754104231437122765708388642002574526725",
            )
            .unwrap()])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/babypbk_test_js/witness.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn binsub_test() {
        let file = "../test_vectors/circuits/test-circuits/binsub_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str("0").unwrap(),
            ])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/binsub_test_js/witness00.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn constants_test() {
        let file = "../test_vectors/circuits/test-circuits/constants_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("3624381080").unwrap()])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/constants_test_js/witness0.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn eddsa_test() {
        let file = "../test_vectors/circuits/test-circuits/eddsa_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = [
            "0", "0", "0", "0", "0", "0", "0", "0", "1", "0", "0", "0", "0", "0", "0", "0", "0",
            "1", "0", "0", "0", "0", "0", "0", "1", "1", "0", "0", "0", "0", "0", "0", "0", "0",
            "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0", "1", "1",
            "0", "0", "0", "0", "0", "1", "1", "1", "0", "0", "0", "0", "0", "0", "0", "0", "1",
            "0", "0", "0", "0", "1", "0", "0", "1", "0", "0", "0", "0", "0", "0", "1", "0", "0",
            "0", "1", "1", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "1", "0", "1", "1",
            "1", "1", "0", "1", "1", "0", "0", "1", "0", "1", "0", "1", "1", "0", "1", "0", "0",
            "1", "1", "1", "1", "0", "1", "1", "0", "1", "0", "1", "0", "1", "0", "1", "0", "1",
            "0", "1", "0", "1", "1", "1", "0", "0", "0", "1", "0", "0", "1", "0", "1", "0", "0",
            "0", "1", "0", "0", "1", "0", "0", "1", "1", "1", "1", "0", "1", "1", "1", "1", "1",
            "0", "0", "1", "1", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "1", "0",
            "1", "1", "1", "0", "0", "1", "1", "1", "1", "0", "1", "0", "1", "0", "0", "1", "1",
            "0", "0", "0", "0", "1", "0", "1", "1", "0", "0", "1", "1", "0", "1", "1", "1", "1",
            "0", "0", "1", "0", "1", "0", "0", "1", "0", "0", "1", "0", "1", "1", "1", "0", "1",
            "1", "1", "0", "1", "1", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "1",
            "1", "0", "1", "0", "0", "0", "0", "1", "1", "0", "1", "0", "1", "1", "0", "0", "1",
            "1", "1", "1", "1", "1", "1", "0", "0", "0", "0", "1", "1", "0", "1", "1", "0", "0",
            "1", "0", "0", "0", "0", "0", "1", "0", "0", "0", "1", "0", "0", "0", "0", "1", "0",
            "0", "1", "0", "1", "0", "1", "0", "0", "0", "1", "0", "1", "1", "1", "1", "0", "1",
            "1", "1", "0", "0", "0", "0", "1", "1", "1", "1", "0", "0", "1", "1", "1", "0", "0",
            "1", "0", "0", "0", "1", "0", "1", "0", "0", "0", "0", "1", "1", "0", "0", "0", "0",
            "0", "0", "0", "1", "0", "0", "1", "1", "0", "1", "1", "1", "1", "1", "0", "0", "1",
            "1", "1", "0", "0", "1", "0", "1", "1", "0", "0", "1", "1", "1", "0", "0", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "0", "0", "0", "0", "0", "1", "0", "0", "1", "0",
            "0", "1", "0", "0", "1", "0", "1", "0", "1", "0", "0", "1", "0", "1", "1", "0", "0",
            "0", "1", "1", "1", "1", "0", "1", "0", "0", "1", "1", "1", "0", "1", "1", "1", "0",
            "0", "1", "0", "1", "0", "0", "1", "0", "0", "1", "0", "1", "0", "1", "1", "1", "1",
            "1", "0", "1", "1", "1", "1", "0", "1", "1", "0", "1", "0", "0", "1", "1", "0", "0",
            "0", "1", "0", "1", "0", "1", "0", "1", "1", "1", "1", "1", "0", "1", "0", "0", "0",
            "0", "1", "1", "1", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0", "1", "0", "0",
            "1", "1", "1", "0", "1", "0", "0", "1", "1", "0", "1", "1", "1", "0", "1", "1", "0",
            "0", "1", "0", "0", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "0", "1", "1",
            "0", "1", "1", "0", "1", "1", "0", "0", "1", "1", "1", "1", "0", "0", "1", "0", "1",
            "0", "1", "0", "1", "0", "0", "1", "0", "0", "1", "0", "1", "1", "0", "1", "0", "1",
            "1", "1", "1", "1", "1", "0", "0", "0", "1", "1", "0", "1", "0", "1", "1", "1", "0",
            "0", "0", "0", "1", "0", "1", "0", "0", "0", "0", "1", "1", "1", "0", "0", "0", "0",
            "0", "1", "0", "1", "1", "1", "0", "1", "0", "1", "0", "0", "0", "1", "1", "0", "1",
            "0", "1", "0", "1", "1", "1", "1", "1", "1", "1", "1", "1", "0", "1", "1", "1", "1",
            "0", "0", "0", "0", "1", "1", "0", "1", "0", "1", "1", "0", "1", "1", "1", "1", "1",
            "1", "0", "0", "1", "1", "0", "1", "0", "1", "0", "0", "1", "0", "0", "0", "0", "0",
            "1", "1", "1", "1", "0", "0", "0", "0", "0", "1", "1", "1", "1", "1", "0", "0", "0",
            "0", "1", "1", "0", "0", "0", "1", "0", "0", "0", "0", "0", "1", "0", "0", "1", "1",
            "0", "0", "0", "1", "0", "0", "0", "0", "1", "1", "1", "0", "1", "1", "1", "0", "1",
            "0", "0", "1", "0", "0", "1", "1", "0", "1", "1", "0", "0", "1", "1", "1", "0", "0",
            "0", "1", "0", "1", "0", "1", "1", "0", "1", "1", "1", "1", "0", "0", "0", "1", "0",
            "0", "0", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "0", "0", "1", "0", "1",
            "0", "1", "1", "0", "1", "1", "0", "1", "0", "1", "0", "0", "1", "0", "0", "1", "0",
            "0", "1", "1", "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "0", "0", "1", "0",
            "0", "1", "1", "1", "1", "1", "1", "1", "1", "1", "0", "1", "1", "0", "0", "0", "1",
            "0", "1", "0", "1", "1", "0", "1", "0", "0", "1", "0", "0", "0", "0", "0",
        ];
        let f_input = input
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input)
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/eddsa_test_js/witness1.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }
    #[test]
    fn eddsa_test2() {
        let file = "../test_vectors/circuits/test-circuits/eddsa_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = [
            "0", "0", "0", "0", "0", "0", "0", "0", "1", "0", "0", "0", "0", "0", "0", "0", "1",
            "0", "0", "0", "0", "0", "0", "0", "1", "1", "0", "0", "0", "0", "1", "0", "0", "0",
            "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1",
            "0", "0", "0", "0", "0", "0", "0", "0", "1", "0", "0", "0", "0", "0", "0", "0", "1",
            "0", "0", "0", "0", "1", "0", "0", "1", "0", "0", "0", "0", "0", "0", "1", "0", "0",
            "0", "1", "1", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "1", "0", "1", "1",
            "1", "1", "0", "1", "1", "0", "0", "1", "0", "1", "0", "1", "1", "0", "1", "0", "0",
            "1", "1", "1", "1", "0", "1", "1", "0", "1", "0", "1", "0", "1", "0", "1", "0", "1",
            "0", "1", "0", "1", "1", "1", "0", "0", "0", "1", "0", "0", "1", "0", "1", "0", "0",
            "0", "1", "0", "0", "1", "0", "0", "1", "1", "1", "1", "0", "1", "1", "1", "1", "1",
            "0", "0", "1", "1", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "1", "0",
            "1", "1", "1", "0", "0", "1", "1", "1", "1", "0", "1", "0", "1", "0", "0", "1", "1",
            "0", "0", "0", "0", "1", "0", "1", "1", "0", "0", "1", "1", "0", "1", "1", "1", "1",
            "0", "0", "1", "0", "1", "0", "0", "1", "0", "0", "1", "0", "1", "1", "1", "0", "1",
            "1", "1", "0", "1", "1", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "1",
            "1", "0", "1", "0", "0", "0", "0", "1", "1", "0", "1", "0", "1", "1", "0", "0", "1",
            "1", "1", "1", "1", "1", "1", "0", "0", "0", "0", "1", "1", "0", "1", "1", "0", "0",
            "1", "0", "0", "0", "0", "0", "1", "0", "0", "0", "1", "0", "0", "0", "0", "1", "0",
            "0", "1", "0", "1", "0", "1", "0", "0", "0", "1", "0", "1", "1", "1", "1", "0", "1",
            "1", "1", "0", "0", "0", "0", "1", "1", "1", "1", "0", "0", "1", "1", "0", "0", "0",
            "1", "1", "0", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "1", "0", "1", "1",
            "0", "1", "1", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "1", "0", "1",
            "0", "1", "0", "1", "0", "1", "0", "0", "1", "1", "1", "0", "1", "0", "1", "0", "1",
            "1", "0", "1", "1", "1", "1", "1", "1", "1", "0", "1", "1", "1", "0", "0", "0", "1",
            "0", "1", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "0", "1", "1", "1", "1",
            "0", "1", "0", "0", "0", "1", "1", "0", "1", "1", "0", "1", "1", "1", "0", "1", "1",
            "0", "0", "1", "0", "1", "1", "0", "0", "0", "0", "0", "0", "1", "1", "0", "0", "1",
            "1", "0", "0", "1", "0", "0", "1", "1", "0", "0", "1", "1", "0", "1", "0", "0", "0",
            "0", "0", "1", "1", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0",
            "0", "1", "1", "0", "1", "0", "1", "0", "1", "0", "0", "0", "0", "1", "0", "0", "1",
            "1", "1", "1", "1", "0", "1", "1", "1", "0", "1", "0", "0", "0", "1", "0", "0", "0",
            "1", "0", "0", "1", "1", "0", "1", "0", "0", "1", "1", "0", "0", "1", "1", "0", "1",
            "1", "0", "1", "0", "1", "0", "0", "1", "1", "1", "1", "0", "1", "1", "0", "0", "1",
            "0", "0", "1", "0", "0", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1", "1", "1",
            "0", "1", "0", "1", "1", "1", "0", "1", "1", "1", "1", "0", "0", "0", "1", "0", "0",
            "1", "0", "1", "1", "0", "0", "1", "0", "1", "0", "1", "1", "0", "0", "0", "0", "1",
            "1", "1", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "1", "1", "1", "0", "0",
            "0", "1", "0", "1", "0", "0", "0", "1", "1", "1", "0", "1", "1", "0", "1", "0", "0",
            "0", "1", "0", "0", "0", "1", "0", "0", "1", "1", "1", "0", "1", "1", "1", "1", "0",
            "1", "0", "1", "0", "0", "1", "0", "0", "0", "0", "1", "1", "0", "1", "0", "1", "1",
            "1", "0", "0", "1", "0", "1", "0", "1", "0", "1", "1", "1", "0", "0", "1", "0", "0",
            "0", "0", "0", "0", "0", "1", "1", "0", "0", "0", "1", "1", "0", "1", "1", "1", "1",
            "0", "1", "1", "1", "1", "0", "1", "0", "1", "1", "0", "0", "0", "1", "1", "1", "0",
            "0", "0", "0", "1", "1", "0", "1", "1", "1", "0", "0", "1", "0", "0", "0", "0", "1",
            "0", "1", "1", "1", "1", "0", "1", "1", "1", "1", "0", "1", "0", "0", "1", "0", "0",
            "1", "0", "0", "0", "0", "0", "0", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0",
            "0", "0", "1", "1", "1", "1", "1", "1", "1", "1", "0", "1", "1", "0", "0", "1", "0",
            "0", "0", "0", "0", "1", "1", "1", "0", "1", "1", "0", "1", "1", "0", "1", "0", "1",
            "1", "0", "0", "1", "1", "1", "1", "0", "0", "0", "0", "1", "1", "1", "0", "1", "1",
            "0", "1", "0", "1", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        ];
        let f_input = input
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input)
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/eddsa_test_js/witness2.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn eddsamimc_test1() {
        let file = "../test_vectors/circuits/test-circuits/eddsamimc_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str(
                    "13277427435165878497778222415993513565335242147425444199013288855685581939618",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "13622229784656158136036771217484571176836296686641868549125388198837476602820",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "11220723668893468001994760120794694848178115379170651044669708829805665054484",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2367470421002446880004241260470975644531657398480773647535134774673409612366",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "1701898193987160140374512573986329501685719384866194117894109500242212188181",
                )
                .unwrap(),
                ark_bn254::Fr::from_str("1234").unwrap(),
            ])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/eddsamimc_test_js/witness1.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }
    #[test]
    fn eddsamimc_test2() {
        let file = "../test_vectors/circuits/test-circuits/eddsamimc_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str(
                    "13277427435165878497778222415993513565335242147425444199013288855685581939618",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "13622229784656158136036771217484571176836296686641868549125388198837476602820",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "11220723668893468001994760120794694848178115379170651044669708829805665054485",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2367470421002446880004241260470975644531657398480773647535134774673409612366",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "1701898193987160140374512573986329501685719384866194117894109500242212188181",
                )
                .unwrap(),
                ark_bn254::Fr::from_str("1234").unwrap(),
            ])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/eddsamimc_test_js/witness2.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn eddsaposeidon_test1() {
        let file = "../test_vectors/circuits/test-circuits/eddsaposeidon_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str(
                    "13277427435165878497778222415993513565335242147425444199013288855685581939618",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "13622229784656158136036771217484571176836296686641868549125388198837476602820",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2010143491207902444122668013146870263468969134090678646686512037244361350365",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "11220723668893468001994760120794694848178115379170651044669708829805665054484",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2367470421002446880004241260470975644531657398480773647535134774673409612366",
                )
                .unwrap(),
                ark_bn254::Fr::from_str("1234").unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/eddsaposeidon_test_js/witness1.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }
    #[test]
    fn eddsaposeidon_test2() {
        let file = "../test_vectors/circuits/test-circuits/eddsaposeidon_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str(
                    "13277427435165878497778222415993513565335242147425444199013288855685581939618",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "13622229784656158136036771217484571176836296686641868549125388198837476602820",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2010143491207902444122668013146870263468969134090678646686512037244361350365",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "11220723668893468001994760120794694848178115379170651044669708829805665054485",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2367470421002446880004241260470975644531657398480773647535134774673409612366",
                )
                .unwrap(),
                ark_bn254::Fr::from_str("1234").unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/eddsaposeidon_test_js/witness2.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn edwards2montgomery() {
        let file = "../test_vectors/circuits/test-circuits/edwards2montgomery.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str(
                    "5299619240641551281634865583518297030282874472190772894086521144482721001553",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "16950150798460657717958625567821834550301663161624707787222815936182638968203",
                )
                .unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/edwards2montgomery_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn escalarmul_test() {
        let file = "../test_vectors/circuits/test-circuits/escalarmul_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("31").unwrap()])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/escalarmul_test_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn escalarmul_test_min() {
        let file = "../test_vectors/circuits/test-circuits/escalarmul_test_min.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = [
            "1", "1", "0", "1", "1", "1", "0", "0", "1", "1", "0", "1", "0", "0", "1", "1", "0",
            "1", "1", "1", "0", "0", "1", "1", "1", "0", "0", "0", "0", "1", "0", "1", "0", "1",
            "1", "1", "1", "0", "1", "0", "1", "0", "0", "0", "0", "1", "0", "1", "1", "0", "1",
            "1", "1", "1", "1", "1", "0", "1", "0", "1", "0", "0", "0", "0", "1", "0", "0", "0",
            "1", "1", "1", "0", "0", "1", "0", "1", "1", "0", "1", "0", "1", "0", "1", "1", "1",
            "0", "0", "1", "1", "0", "0", "0", "1", "0", "0", "1", "1", "1", "0", "0", "0", "0",
            "0", "1", "1", "0", "0", "0", "1", "1", "0", "0", "1", "1", "0", "1", "0", "0", "1",
            "0", "1", "1", "1", "0", "0", "1", "0", "0", "1", "0", "0", "0", "0", "1", "0", "0",
            "0", "1", "1", "1", "0", "1", "0", "1", "0", "1", "1", "1", "0", "1", "0", "1", "1",
            "0", "1", "1", "1", "0", "1", "1", "0", "1", "1", "1", "1", "1", "0", "0", "0", "1",
            "1", "0", "0", "1", "1", "0", "1", "1", "0", "1", "1", "1", "0", "0", "0", "0", "0",
            "1", "0", "1", "0", "0", "1", "1", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0",
            "1", "1", "1", "0", "0", "0", "0", "0", "1", "1", "1", "0", "1", "0", "1", "1", "1",
            "0", "1", "0", "1", "1", "0", "1", "0", "0", "0", "0", "1", "0", "0", "0", "1", "1",
            "1", "0", "1", "1", "0", "0", "1", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1",
            "0",
        ];
        let f_input = input
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input)
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/escalarmul_test_min_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn escalarmulany_test() {
        let file = "../test_vectors/circuits/test-circuits/escalarmulany_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str(
                    "5299619240641551281634865583518297030282874472190772894086521144482721001553",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "16950150798460657717958625567821834550301663161624707787222815936182638968203",
                )
                .unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/escalarmulany_test_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }
    #[test]
    fn escalarmulany_test2() {
        let file = "../test_vectors/circuits/test-circuits/escalarmulany_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str(
                    "2736030358979909402780800718157159386076813972158567259200215660948447373041",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "5299619240641551281634865583518297030282874472190772894086521144482721001553",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "16950150798460657717958625567821834550301663161624707787222815936182638968203",
                )
                .unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/escalarmulany_test_js/witness2.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn escalarmulfix_test() {
        let file = "../test_vectors/circuits/test-circuits/escalarmulfix_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/escalarmulfix_test_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn escalarmulw4table_test() {
        let file = "../test_vectors/circuits/test-circuits/escalarmulw4table_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("1").unwrap()])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/escalarmulw4table_test_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn escalarmulw4table_test3() {
        let file = "../test_vectors/circuits/test-circuits/escalarmulw4table_test3.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("1").unwrap()])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/escalarmulw4table_test3_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn greatereqthan() {
        let file = "../test_vectors/circuits/test-circuits/greatereqthan.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_5 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_6 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_7 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_8 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_2 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let input_3 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("133").unwrap(),
        ];
        let input_4 = vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_5 = vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let input_6 = vec![
            ark_bn254::Fr::from_str("333").unwrap(),
            ark_bn254::Fr::from_str("444").unwrap(),
        ];
        let input_7 = vec![
            ark_bn254::Fr::from_str("555").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_8 = vec![
            ark_bn254::Fr::from_str("661").unwrap(),
            ark_bn254::Fr::from_str("660").unwrap(),
        ];
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_3)
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_4)
            .unwrap();
        let is_witness_5 = builder_5
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_5)
            .unwrap();
        let is_witness_6 = builder_6
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_6)
            .unwrap();
        let is_witness_7 = builder_7
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_7)
            .unwrap();
        let is_witness_8 = builder_8
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_8)
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan_js/witness0_0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan_js/witness0_1.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan_js/witness0_133.wtns",
        )
        .unwrap();
        let witness_4 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan_js/witness1_0.wtns",
        )
        .unwrap();
        let witness_5 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan_js/witness1_1.wtns",
        )
        .unwrap();
        let witness_6 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan_js/witness333_444.wtns",
        )
        .unwrap();
        let witness_7 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan_js/witness555_0.wtns",
        )
        .unwrap();
        let witness_8 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greatereqthan_js/witness661_660.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_5).unwrap();
        assert_eq!(is_witness_5, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_6).unwrap();
        assert_eq!(is_witness_6, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_7).unwrap();
        assert_eq!(is_witness_7, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_8).unwrap();
        assert_eq!(is_witness_8, should_witness.values);
    }

    #[test]
    fn greaterthan() {
        let file = "../test_vectors/circuits/test-circuits/greaterthan.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_5 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_2 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("444").unwrap(),
        ];
        let input_3 = vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let input_4 = vec![
            ark_bn254::Fr::from_str("333").unwrap(),
            ark_bn254::Fr::from_str("444").unwrap(),
        ];
        let input_5 = vec![
            ark_bn254::Fr::from_str("555").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_3)
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_4)
            .unwrap();
        let is_witness_5 = builder_5
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_5)
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greaterthan_js/witness0_0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greaterthan_js/witness0_444.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greaterthan_js/witness1_1.wtns",
        )
        .unwrap();
        let witness_4 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/greaterthan_js/witness333_444.wtns",
        )
        .unwrap();
        let witness_5 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/greaterthan_js/witness555_0.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_5).unwrap();
        assert_eq!(is_witness_5, should_witness.values);
    }

    #[test]
    fn isequal() {
        let file = "../test_vectors/circuits/test-circuits/isequal.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("111").unwrap(),
                ark_bn254::Fr::from_str("222").unwrap(),
            ])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("444").unwrap(),
                ark_bn254::Fr::from_str("444").unwrap(),
            ])
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/isequal_js/witness111_222.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/isequal_js/witness444_444.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn iszero() {
        let file = "../test_vectors/circuits/test-circuits/iszero.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("0").unwrap()])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("111").unwrap()])
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/iszero_js/witness0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/iszero_js/witness111.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn lesseqthan() {
        let file = "../test_vectors/circuits/test-circuits/lesseqthan.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_5 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_2 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let input_3 = vec![
            ark_bn254::Fr::from_str("333").unwrap(),
            ark_bn254::Fr::from_str("333").unwrap(),
        ];
        let input_4 = vec![
            ark_bn254::Fr::from_str("555").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_5 = vec![
            ark_bn254::Fr::from_str("661").unwrap(),
            ark_bn254::Fr::from_str("660").unwrap(),
        ];
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_3)
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_4)
            .unwrap();
        let is_witness_5 = builder_5
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_5)
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/lesseqthan_js/witness0_0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/lesseqthan_js/witness0_1.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/lesseqthan_js/witness333_333.wtns",
    )
    .unwrap();
        let witness_4 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/lesseqthan_js/witness555_0.wtns",
    )
    .unwrap();
        let witness_5 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/lesseqthan_js/witness661_660.wtns",
    )
    .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_5).unwrap();
        assert_eq!(is_witness_5, should_witness.values);
    }

    #[test]
    fn lessthan() {
        let file = "../test_vectors/circuits/test-circuits/lessthan.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_5 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_6 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_7 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_2 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let input_3 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("444").unwrap(),
        ];
        let input_4 = vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let input_5 = vec![
            ark_bn254::Fr::from_str("333").unwrap(),
            ark_bn254::Fr::from_str("444").unwrap(),
        ];
        let input_6 = vec![
            ark_bn254::Fr::from_str("661").unwrap(),
            ark_bn254::Fr::from_str("660").unwrap(),
        ];
        let input_7 = vec![
            ark_bn254::Fr::from_str("1902").unwrap(),
            ark_bn254::Fr::from_str("1909").unwrap(),
        ];
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_3)
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_4)
            .unwrap();
        let is_witness_5 = builder_5
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_5)
            .unwrap();
        let is_witness_6 = builder_6
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_6)
            .unwrap();
        let is_witness_7 = builder_7
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_7)
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/lessthan_js/witness0_0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/lessthan_js/witness0_1.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/lessthan_js/witness0_444.wtns",
        )
        .unwrap();
        let witness_4 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/lessthan_js/witness1_1.wtns",
        )
        .unwrap();
        let witness_5 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/lessthan_js/witness333_444.wtns",
    )
    .unwrap();
        let witness_6 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/lessthan_js/witness661_660.wtns",
    )
    .unwrap();
        let witness_7 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/lessthan_js/witness1902_1909.wtns",
    )
    .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_5).unwrap();
        assert_eq!(is_witness_5, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_6).unwrap();
        assert_eq!(is_witness_6, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_7).unwrap();
        assert_eq!(is_witness_7, should_witness.values);
    }

    #[test]
    fn mimc_sponge_hash_test() {
        let file = "../test_vectors/circuits/test-circuits/mimc_sponge_hash_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("2").unwrap(),
                ark_bn254::Fr::from_str("0").unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/mimc_sponge_hash_test_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn mimc_sponge_test() {
        let file = "../test_vectors/circuits/test-circuits/mimc_sponge_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("2").unwrap(),
                ark_bn254::Fr::from_str("3").unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/mimc_sponge_test_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn mimc_test() {
        let file = "../test_vectors/circuits/test-circuits/mimc_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("2").unwrap(),
            ])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mimc_test_js/witness.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn montgomery2edwards() {
        let file = "../test_vectors/circuits/test-circuits/montgomery2edwards.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str(
                    "7117928050407583618111176421555214756675765419608405867398403713213306743542",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "14577268218881899420966779687690205425227431577728659819975198491127179315626",
                )
                .unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/montgomery2edwards_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn montgomeryadd() {
        let file = "../test_vectors/circuits/test-circuits/montgomeryadd.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str(
                    "9100101664623603210404406531442675454232253730068772788857137348928737865001",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2001496619702126385410643647111889571349877104328461789861384191044657552597",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "8429015691535519290020541809040432060914528754647555246465794825755548892308",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "17195795546199479698049280986533217912895387703604249182353056528831670208959",
                )
                .unwrap(),
            ])
            .unwrap();
        let witness = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/montgomeryadd_js/witness.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn montgomerydouble() {
        let file = "../test_vectors/circuits/test-circuits/montgomerydouble.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str(
                    "9100101664623603210404406531442675454232253730068772788857137348928737865001",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "2001496619702126385410643647111889571349877104328461789861384191044657552597",
                )
                .unwrap(),
            ])
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/montgomerydouble_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn mux1_1() {
        let file = "../test_vectors/circuits/test-circuits/mux1_1.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("0").unwrap()])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("1").unwrap()])
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux1_1_js/witness0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux1_1_js/witness1.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn mux2_1() {
        let file = "../test_vectors/circuits/test-circuits/mux2_1.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("0").unwrap()])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("1").unwrap()])
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("2").unwrap()])
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("3").unwrap()])
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux2_1_js/witness0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux2_1_js/witness1.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux2_1_js/witness2.wtns",
        )
        .unwrap();
        let witness_4 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux2_1_js/witness3.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
    }

    #[test]
    fn mux3_1() {
        let file = "../test_vectors/circuits/test-circuits/mux3_1.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_5 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_6 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = vec![ark_bn254::Fr::from_str("0").unwrap()];
        let input_2 = vec![ark_bn254::Fr::from_str("1").unwrap()];
        let input_3 = vec![ark_bn254::Fr::from_str("2").unwrap()];
        let input_4 = vec![ark_bn254::Fr::from_str("3").unwrap()];
        let input_5 = vec![ark_bn254::Fr::from_str("5").unwrap()];
        let input_6 = vec![ark_bn254::Fr::from_str("6").unwrap()];

        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_3)
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_4)
            .unwrap();
        let is_witness_5 = builder_5
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_5)
            .unwrap();
        let is_witness_6 = builder_6
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_6)
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux3_1_js/witness0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux3_1_js/witness1.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux3_1_js/witness2.wtns",
        )
        .unwrap();
        let witness_4 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux3_1_js/witness3.wtns",
        )
        .unwrap();
        let witness_5 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux3_1_js/witness5.wtns",
        )
        .unwrap();
        let witness_6 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux3_1_js/witness6.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_5).unwrap();
        assert_eq!(is_witness_5, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_6).unwrap();
        assert_eq!(is_witness_6, should_witness.values);
    }

    #[test]
    fn mux4_1() {
        let file = "../test_vectors/circuits/test-circuits/mux4_1.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_5 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_6 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_7 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_8 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = vec![ark_bn254::Fr::from_str("0").unwrap()];
        let input_2 = vec![ark_bn254::Fr::from_str("1").unwrap()];
        let input_3 = vec![ark_bn254::Fr::from_str("2").unwrap()];
        let input_4 = vec![ark_bn254::Fr::from_str("3").unwrap()];
        let input_5 = vec![ark_bn254::Fr::from_str("7").unwrap()];
        let input_6 = vec![ark_bn254::Fr::from_str("12").unwrap()];
        let input_7 = vec![ark_bn254::Fr::from_str("13").unwrap()];
        let input_8 = vec![ark_bn254::Fr::from_str("15").unwrap()];
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_3)
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_4)
            .unwrap();
        let is_witness_5 = builder_5
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_5)
            .unwrap();
        let is_witness_6 = builder_6
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_6)
            .unwrap();
        let is_witness_7 = builder_7
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_7)
            .unwrap();
        let is_witness_8 = builder_8
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_8)
            .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1_js/witness0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1_js/witness1.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1_js/witness2.wtns",
        )
        .unwrap();
        let witness_4 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1_js/witness3.wtns",
        )
        .unwrap();
        let witness_5 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1_js/witness7.wtns",
        )
        .unwrap();
        let witness_6 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1_js/witness12.wtns",
        )
        .unwrap();
        let witness_7 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1_js/witness13.wtns",
        )
        .unwrap();
        let witness_8 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/mux4_1_js/witness15.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_5).unwrap();
        assert_eq!(is_witness_5, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_6).unwrap();
        assert_eq!(is_witness_6, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_7).unwrap();
        assert_eq!(is_witness_7, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_8).unwrap();
        assert_eq!(is_witness_8, should_witness.values);
    }

    #[test]
    fn pedersen2_test() {
        let file = "../test_vectors/circuits/test-circuits/pedersen2_test.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("0").unwrap()])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str(
                "14474011154664524427946373126085988481658748083205070504932198000989141204991",
            )
            .unwrap()])
            .unwrap();

        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/pedersen2_test_js/witness0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/pedersen2_test_js/witness1.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn pedersen_test() {
        // need to recheck the inputs here after TODO is fixed (if it fails then)
        let file = "../test_vectors/circuits/test-circuits/pedersen_test.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_5 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = vec![
            ark_bn254::Fr::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            )
            .unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let input_2 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_3 = vec![
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let input_4 = vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
        ];
        let input_5 = vec![
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("7").unwrap(),
        ];
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_3)
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_4)
            .unwrap();
        let is_witness_5 = builder_5
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(input_5)
            .unwrap();
        let witness_1 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/pedersen_test_js/witness-11.wtns",
    )
    .unwrap();
        let witness_2 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/pedersen_test_js/witness00.wtns",
    )
    .unwrap();
        let witness_3 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/pedersen_test_js/witness01.wtns",
            )
    .unwrap();
        let witness_4 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/pedersen_test_js/witness10.wtns",
    )
    .unwrap();
        let witness_5 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/pedersen_test_js/witness37.wtns",
    )
    .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_5).unwrap();
        assert_eq!(is_witness_5, should_witness.values);
    }

    #[test]
    fn pointbits_loopback() {
        let file = "../test_vectors/circuits/test-circuits/pointbits_loopback.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str(
                    "5299619240641551281634865583518297030282874472190772894086521144482721001553",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "16950150798460657717958625567821834550301663161624707787222815936182638968203",
                )
                .unwrap(),
            ])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str("1").unwrap(),
            ])
            .unwrap();

        let witness_1 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/pointbits_loopback_js/witness0.wtns",
    )
    .unwrap();
        let witness_2 = File::open(
        "../test_vectors/circuits/test-circuits/witness_outputs/pointbits_loopback_js/witness1.wtns",
    )
    .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn poseidon3_test() {
        let file = "../test_vectors/circuits/test-circuits/poseidon3_test.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("2").unwrap(),
            ])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("3").unwrap(),
                ark_bn254::Fr::from_str("4").unwrap(),
            ])
            .unwrap();

        let witness_1 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/poseidon3_test_js/witness12.wtns",
)
.unwrap();
        let witness_2 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/poseidon3_test_js/witness34.wtns",
)
.unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn poseidon6_test() {
        let file = "../test_vectors/circuits/test-circuits/poseidon6_test.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("2").unwrap(),
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str("0").unwrap(),
                ark_bn254::Fr::from_str("0").unwrap(),
            ])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("3").unwrap(),
                ark_bn254::Fr::from_str("4").unwrap(),
                ark_bn254::Fr::from_str("5").unwrap(),
                ark_bn254::Fr::from_str("10").unwrap(),
                ark_bn254::Fr::from_str("23").unwrap(),
            ])
            .unwrap();

        let witness_1 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/poseidon6_test_js/witness1-2-0-0-0.wtns",
    )
    .unwrap();
        let witness_2 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/poseidon6_test_js/witness3-4-5-10-23.wtns",
    )
    .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn poseidonex_test() {
        let file = "../test_vectors/circuits/test-circuits/poseidonex_test.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
            "17",
        ];
        let f_input = input
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input)
            .unwrap();
        let witness = File::open("../test_vectors/circuits/test-circuits/witness_outputs/poseidonex_test_js/witness.wtns").unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }

    #[test]
    fn sha256_2_test() {
        let file = "../test_vectors/circuits/test-circuits/sha256_2_test.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("1").unwrap(),
                ark_bn254::Fr::from_str("2").unwrap(),
            ])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![
                ark_bn254::Fr::from_str("13").unwrap(),
                ark_bn254::Fr::from_str("94").unwrap(),
            ])
            .unwrap();

        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sha256_2_test_js/witness.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sha256_2_test_js/witness2.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn sha256_test448() {
        let file = "../test_vectors/circuits/test-circuits/sha256_test448.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = [
            "0", "1", "1", "0", "0", "0", "0", "1", "0", "1", "1", "0", "0", "0", "1", "0", "0",
            "1", "1", "0", "0", "0", "1", "1", "0", "1", "1", "0", "0", "1", "0", "0", "0", "1",
            "1", "0", "0", "0", "1", "0", "0", "1", "1", "0", "0", "0", "1", "1", "0", "1", "1",
            "0", "0", "1", "0", "0", "0", "1", "1", "0", "0", "1", "0", "1", "0", "1", "1", "0",
            "0", "0", "1", "1", "0", "1", "1", "0", "0", "1", "0", "0", "0", "1", "1", "0", "0",
            "1", "0", "1", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1",
            "0", "0", "0", "1", "1", "0", "0", "1", "0", "1", "0", "1", "1", "0", "0", "1", "1",
            "0", "0", "1", "1", "0", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1", "0", "1",
            "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "1", "0",
            "1", "1", "0", "1", "0", "0", "0", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1",
            "1", "0", "0", "1", "1", "1", "0", "1", "1", "0", "1", "0", "0", "0", "0", "1", "1",
            "0", "1", "0", "0", "1", "0", "1", "1", "0", "0", "1", "1", "1", "0", "1", "1", "0",
            "1", "0", "0", "0", "0", "1", "1", "0", "1", "0", "0", "1", "0", "1", "1", "0", "1",
            "0", "1", "0", "0", "1", "1", "0", "1", "0", "0", "0", "0", "1", "1", "0", "1", "0",
            "0", "1", "0", "1", "1", "0", "1", "0", "1", "0", "0", "1", "1", "0", "1", "0", "1",
            "1", "0", "1", "1", "0", "1", "0", "0", "1", "0", "1", "1", "0", "1", "0", "1", "0",
            "0", "1", "1", "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0", "0", "0",
            "1", "1", "0", "1", "0", "1", "0", "0", "1", "1", "0", "1", "0", "1", "1", "0", "1",
            "1", "0", "1", "1", "0", "0", "0", "1", "1", "0", "1", "1", "0", "1", "0", "1", "1",
            "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0", "0", "0", "1", "1", "0",
            "1", "1", "0", "1", "0", "1", "1", "0", "1", "1", "1", "0", "0", "1", "1", "0", "1",
            "1", "0", "0", "0", "1", "1", "0", "1", "1", "0", "1", "0", "1", "1", "0", "1", "1",
            "1", "0", "0", "1", "1", "0", "1", "1", "1", "1", "0", "1", "1", "0", "1", "1", "0",
            "1", "0", "1", "1", "0", "1", "1", "1", "0", "0", "1", "1", "0", "1", "1", "1", "1",
            "0", "1", "1", "1", "0", "0", "0", "0", "0", "1", "1", "0", "1", "1", "1", "0", "0",
            "1", "1", "0", "1", "1", "1", "1", "0", "1", "1", "1", "0", "0", "0", "0", "0", "1",
            "1", "1", "0", "0", "0", "1",
        ];
        let f_input_1 = input_1
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let input_2 = [
            "0", "1", "1", "0", "0", "1", "0", "1", "0", "1", "1", "1", "0", "0", "1", "0", "0",
            "1", "1", "0", "0", "0", "0", "1", "0", "1", "1", "1", "1", "0", "1", "0", "0", "1",
            "1", "0", "0", "1", "0", "1", "0", "1", "1", "1", "0", "0", "0", "1", "0", "1", "1",
            "1", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1", "0", "1", "0", "1", "1", "1",
            "0", "1", "1", "1", "0", "1", "1", "0", "0", "0", "0", "1", "0", "1", "1", "0", "1",
            "0", "0", "0", "0", "1", "1", "0", "1", "0", "1", "0", "0", "1", "1", "1", "0", "1",
            "0", "0", "0", "1", "1", "0", "0", "0", "0", "1", "0", "1", "1", "1", "0", "0", "1",
            "1", "0", "1", "1", "0", "0", "1", "0", "0", "0", "1", "1", "1", "0", "0", "1", "1",
            "0", "1", "1", "0", "0", "1", "0", "0", "0", "1", "1", "0", "0", "1", "1", "0", "0",
            "1", "1", "0", "0", "1", "1", "1", "0", "1", "1", "0", "0", "0", "0", "1", "0", "1",
            "1", "0", "0", "1", "0", "0", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1",
            "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0", "1", "0", "1", "1", "0",
            "1", "0", "0", "1", "0", "1", "1", "0", "1", "0", "1", "1", "0", "1", "1", "1", "0",
            "1", "0", "0", "0", "1", "1", "1", "0", "0", "1", "1", "0", "1", "1", "0", "0", "1",
            "1", "1", "0", "1", "1", "0", "1", "0", "0", "0", "0", "1", "1", "1", "1", "0", "0",
            "1", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "0", "0", "1", "1", "1",
            "0", "1", "1", "1", "0", "0", "1", "1", "0", "1", "1", "0", "1", "0", "1", "0", "0",
            "1", "1", "1", "0", "1", "0", "0", "0", "1", "1", "1", "0", "1", "0", "1", "0", "1",
            "1", "0", "1", "0", "1", "1", "0", "1", "1", "1", "0", "1", "0", "0", "0", "1", "1",
            "1", "0", "1", "1", "1", "0", "1", "1", "1", "0", "0", "1", "0", "0", "1", "1", "1",
            "0", "1", "0", "0", "0", "1", "1", "1", "1", "0", "1", "0", "0", "1", "1", "1", "0",
            "1", "1", "1", "0", "1", "1", "0", "1", "0", "1", "0", "0", "1", "1", "0", "1", "0",
            "1", "1", "0", "1", "1", "0", "1", "0", "0", "1", "0", "1", "1", "1", "0", "0", "1",
            "0", "0", "1", "1", "1", "0", "1", "1", "1", "0", "1", "1", "0", "1", "0", "0", "0",
            "0", "1", "1", "1", "0", "0", "1", "0", "0", "1", "1", "1", "0", "1", "1", "1", "0",
            "1", "1", "0", "1", "0", "0", "0", "0", "1", "1", "1", "0", "1", "1", "1", "0", "1",
            "1", "1", "0", "1", "1", "1",
        ];
        let f_input_2 = input_2
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_2)
            .unwrap();

        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sha256_test448_js/witness.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sha256_test448_js/witness2.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn sha256_test512() {
        let file = "../test_vectors/circuits/test-circuits/sha256_test512.circom";
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_1 = [
            "0", "0", "0", "0", "0", "0", "0", "1", "0", "0", "0", "0", "0", "0", "1", "0", "0",
            "0", "0", "0", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "0", "0", "0", "0",
            "0", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "1", "1", "0", "0", "0", "0",
            "0", "0", "1", "1", "1", "0", "0", "0", "0", "1", "0", "0", "0", "0", "0", "0", "0",
            "1", "0", "0", "1", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "1",
            "0", "1", "1", "0", "0", "0", "0", "1", "1", "0", "0", "0", "0", "0", "0", "1", "1",
            "0", "1", "0", "0", "0", "0", "1", "1", "1", "0", "0", "0", "0", "0", "1", "1", "1",
            "1", "0", "0", "0", "1", "0", "0", "0", "0", "0", "0", "0", "1", "0", "0", "0", "1",
            "0", "0", "0", "1", "0", "0", "1", "0", "0", "0", "0", "1", "0", "0", "1", "1", "0",
            "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "1", "0", "0",
            "0", "1", "0", "1", "1", "0", "0", "0", "0", "1", "0", "1", "1", "1", "0", "0", "0",
            "1", "1", "0", "0", "0", "0", "0", "0", "1", "1", "0", "0", "1", "0", "0", "0", "1",
            "1", "0", "1", "0", "0", "0", "0", "1", "1", "0", "1", "1", "0", "0", "0", "1", "1",
            "1", "0", "0", "0", "0", "0", "1", "1", "1", "0", "1", "0", "0", "0", "1", "1", "1",
            "1", "0", "0", "0", "0", "1", "1", "1", "1", "1", "0", "0", "1", "0", "0", "0", "0",
            "0", "0", "0", "1", "0", "0", "0", "0", "1", "0", "0", "1", "0", "0", "0", "1", "0",
            "0", "0", "1", "0", "0", "0", "1", "1", "0", "0", "1", "0", "0", "1", "0", "0", "0",
            "0", "1", "0", "0", "1", "0", "1", "0", "0", "1", "0", "0", "1", "1", "0", "0", "0",
            "1", "0", "0", "1", "1", "1", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "1",
            "0", "1", "0", "0", "1", "0", "0", "1", "0", "1", "0", "1", "0", "0", "0", "1", "0",
            "1", "0", "1", "1", "0", "0", "1", "0", "1", "1", "0", "0", "0", "0", "1", "0", "1",
            "1", "0", "1", "0", "0", "1", "0", "1", "1", "1", "0", "0", "0", "1", "0", "1", "1",
            "1", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "0", "1", "1", "0", "0", "0",
            "1", "0", "0", "1", "1", "0", "0", "1", "0", "0", "0", "1", "1", "0", "0", "1", "1",
            "0", "0", "1", "1", "0", "1", "0", "0", "0", "0", "1", "1", "0", "1", "0", "1", "0",
            "0", "1", "1", "0", "1", "1", "0", "0", "0", "1", "1", "0", "1", "1", "1", "0", "0",
            "1", "1", "1", "0", "0", "0", "0", "0", "1", "1", "1", "0", "0", "1", "0", "0", "1",
            "1", "1", "0", "1", "0", "0", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1", "1",
            "1", "1", "0", "0", "0", "0", "1", "1", "1", "1", "0", "1", "0", "0", "1", "1", "1",
            "1", "1", "0", "0", "0", "1", "1", "1", "1", "1", "1", "0", "1", "0", "0", "0", "0",
            "0", "0",
        ];
        let f_input_1 = input_1
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let input_2 = [
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1", "1", "0", "1", "0",
            "0", "0", "1", "1", "0", "1", "0", "0", "0", "1", "0", "0", "1", "1", "1", "0", "0",
            "1", "1", "0", "1", "0", "0", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1", "0",
            "0", "1", "1", "1", "0", "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0",
            "1", "0", "0", "0", "0", "1", "1", "1", "0", "1", "0", "1", "1", "0", "0", "0", "0",
            "0", "1", "0", "1", "0", "0", "0", "1", "1", "1", "1", "1", "0", "0", "1", "1", "1",
            "0", "0", "1", "0", "1", "0", "1", "0", "0", "1", "1", "0", "1", "1", "0", "1", "1",
            "0", "1", "1", "0", "0", "0", "0", "1", "1", "1", "1", "0", "1", "0", "0", "0", "0",
            "1", "1", "0", "1", "1", "1", "0", "1", "1", "1", "1", "0", "1", "0", "1", "0", "1",
            "1", "1", "1", "0", "1", "1", "1", "0", "0", "0", "0", "0", "1", "0", "0", "0", "0",
            "0", "1", "0", "0", "0", "1", "0", "0", "0", "1", "1", "1", "1", "0", "0", "0", "1",
            "0", "1", "0", "1", "1", "0", "0", "1", "1", "1", "0", "0", "0", "0", "1", "0", "0",
            "0", "1", "0", "1", "0", "1", "0", "1", "0", "0", "1", "0", "0", "1", "0", "1", "1",
            "1", "1", "1", "0", "1", "1", "0", "1", "1", "0", "0", "0", "1", "1", "1", "1", "0",
            "0", "1", "1", "0", "0", "0", "0", "1", "1", "0", "1", "0", "0", "1", "0", "0", "1",
            "1", "1", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "1", "1", "0", "1",
            "1", "0", "1", "1", "1", "0", "1", "0", "1", "1", "0", "0", "0", "1", "1", "1", "1",
            "1", "0", "1", "0", "1", "0", "0", "1", "1", "1", "0", "0", "0", "0", "1", "1", "1",
            "1", "0", "1", "1", "1", "0", "1", "1", "1", "1", "1", "0", "1", "1", "0", "0", "0",
            "0", "1", "0", "0", "0", "0", "0", "0", "1", "0", "1", "0", "1", "0", "0", "1", "0",
            "0", "0", "1", "0", "0", "0", "1", "0", "1", "1", "1", "1", "0", "0", "1", "1", "1",
            "1", "0", "0", "0", "1", "0", "0", "1", "0", "0", "1", "0", "1", "0", "1", "0", "1",
            "1", "0", "0", "1", "1", "0", "0", "0", "1", "1", "0", "1", "1", "1", "0", "0", "0",
            "0", "0", "1", "1", "1", "1", "1", "0", "1", "1", "0", "0", "0", "1", "0", "1", "0",
            "1", "0", "0", "1", "0", "1", "1", "1", "1", "0", "1", "0", "0", "1", "0", "0", "1",
            "0", "1", "1", "0", "0", "0", "1", "1", "0", "1", "1", "1", "1", "1", "0", "1", "1",
            "0", "0", "1", "0", "1", "1", "1", "1", "0", "1", "1", "0", "0", "0", "1", "1", "1",
            "0", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0", "1", "0", "1", "1", "1", "1",
            "1", "1", "1", "1", "0", "0", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "1",
            "0", "0", "1", "0", "0", "1", "0", "0", "1", "1", "0", "0", "0", "1", "1", "0", "0",
            "1", "1",
        ];
        let f_input_2 = input_2
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_2)
            .unwrap();

        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sha256_test512_js/witness.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sha256_test512_js/witness2.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
    }

    #[test]
    fn sign_test() {
        let file = "../test_vectors/circuits/test-circuits/sign_test.circom";
        let builder_0 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_4 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input_0 = [
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        ];
        let input_1 = [
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1", "1", "1", "1", "1", "1", "0",
            "0", "1", "0", "0", "1", "1", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0", "0",
            "0", "1", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "1",
            "0", "0", "1", "0", "0", "0", "0", "1", "1", "1", "0", "1", "0", "0", "1", "1", "1",
            "0", "1", "1", "0", "0", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "0", "1",
            "0", "0", "0", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0", "1", "1", "0", "0",
            "0", "0", "0", "1", "0", "1", "0", "0", "1", "0", "1", "1", "1", "0", "1", "0", "0",
            "0", "0", "1", "1", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0", "1", "1", "0",
            "0", "0", "0", "0", "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0", "1",
            "0", "0", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "0", "1",
            "1", "1", "0", "1", "1", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0", "0",
            "1", "0", "1", "1", "0", "0", "0", "1", "1", "0", "0", "1", "0", "0", "0", "0", "1",
            "1", "1", "0", "1", "0", "0", "1", "1", "1", "0", "0", "1", "1", "1", "0", "0", "1",
            "0", "0", "0", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "1", "0",
        ];
        let input_2 = [
            "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1", "1", "1", "1", "1", "1",
            "0", "0", "1", "0", "0", "1", "1", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0",
            "0", "0", "1", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0",
            "1", "0", "0", "1", "0", "0", "0", "0", "1", "1", "1", "0", "1", "0", "0", "1", "1",
            "1", "0", "1", "1", "0", "0", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "0",
            "1", "0", "0", "0", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0", "1", "1", "0",
            "0", "0", "0", "0", "1", "0", "1", "0", "0", "1", "0", "1", "1", "1", "0", "1", "0",
            "0", "0", "0", "1", "1", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0", "1", "1",
            "0", "0", "0", "0", "0", "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0",
            "1", "0", "0", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "0",
            "1", "1", "1", "0", "1", "1", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0",
            "0", "1", "0", "1", "1", "0", "0", "0", "1", "1", "0", "0", "1", "0", "0", "0", "0",
            "1", "1", "1", "0", "1", "0", "0", "1", "1", "1", "0", "0", "1", "1", "1", "0", "0",
            "1", "0", "0", "0", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "1",
        ];
        let input_3 = [
            "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1", "1", "1", "1", "1", "1",
            "0", "0", "1", "0", "0", "1", "1", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0",
            "0", "0", "1", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0",
            "1", "0", "0", "1", "0", "0", "0", "0", "1", "1", "1", "0", "1", "0", "0", "1", "1",
            "1", "0", "1", "1", "0", "0", "1", "1", "1", "1", "0", "0", "0", "0", "1", "0", "0",
            "1", "0", "0", "0", "0", "1", "0", "1", "1", "1", "1", "1", "0", "0", "1", "1", "0",
            "0", "0", "0", "0", "1", "0", "1", "0", "0", "1", "0", "1", "1", "1", "0", "1", "0",
            "0", "0", "0", "1", "1", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0", "1", "1",
            "0", "0", "0", "0", "0", "0", "1", "0", "1", "1", "0", "1", "1", "0", "1", "1", "0",
            "1", "0", "0", "0", "1", "0", "0", "0", "0", "0", "1", "0", "1", "0", "0", "0", "0",
            "1", "1", "1", "0", "1", "1", "0", "0", "1", "0", "1", "0", "0", "0", "0", "0", "0",
            "0", "1", "0", "1", "1", "0", "0", "0", "1", "1", "0", "0", "1", "0", "0", "0", "0",
            "1", "1", "1", "0", "1", "0", "0", "1", "1", "1", "0", "0", "1", "1", "1", "0", "0",
            "1", "0", "0", "0", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "1", "1",
        ];
        let input_4 = [
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1",
        ];
        let f_input_0 = input_0
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_1 = input_1
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_2 = input_2
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_3 = input_3
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_4 = input_4
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness_0 = builder_0
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_0)
            .unwrap();
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_3)
            .unwrap();
        let is_witness_4 = builder_4
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_4)
            .unwrap();

        let witness_0 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sign_test_js/witness0.wtns",
        )
        .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sign_test_js/witness1.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sign_test_js/witness2.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sign_test_js/witness3.wtns",
        )
        .unwrap();
        let witness_4 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sign_test_js/witness4.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_0).unwrap();
        assert_eq!(is_witness_0, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_4).unwrap();
        assert_eq!(is_witness_4, should_witness.values);
    }

    #[test]
    // need to recheck the inputs here after TODO is fixed (if it fails then)
    fn smtprocessor10_test() {
        let file = "../test_vectors/circuits/test-circuits/smtprocessor10_test.circom";
        let builder_0 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");

        let input_0 = [
            "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1", "111",
            "222",
        ];
        let input_1 = [
            "1",
            "0",
            "9308772482099879945566979599408036177864352098141198065063141880905857869998",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "111",
            "222",
            "0",
            "333",
            "444",
            "111",
            "222",
        ];
        let input_2 = [
            "1",
            "1",
            "1288560299535560961253537358119722684041344245980076865013927406034193350532",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "333",
            "444",
            "0",
            "111",
            "222",
        ];
        let input_3 = [
            "1",
            "1",
            "12549289627350776599881360848479894769581529188188467455798610052916592066756",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "1",
            "333",
            "444",
        ];

        let f_input_0 = input_0
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_1 = input_1
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_2 = input_2
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_3 = input_3
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();

        let is_witness_0 = builder_0
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_0)
            .unwrap();
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_3)
            .unwrap();

        let witness_0 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/smtprocessor10_test_js/witness0.wtns",
    )
    .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/smtprocessor10_test_js/witness1.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/smtprocessor10_test_js/witness2.wtns",
)
.unwrap();
        let witness_3 = File::open(
"../test_vectors/circuits/test-circuits/witness_outputs/smtprocessor10_test_js/witness3.wtns",
)
.unwrap();

        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_0).unwrap();
        assert_eq!(is_witness_0, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
    }

    #[test]
    // need to recheck the inputs here after TODO is fixed (if it fails then)
    fn smtverifier10_test() {
        let file = "../test_vectors/circuits/test-circuits/smtverifier10_test.circom";
        let builder_0 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");

        let input_0 = [
            "1",
            "0",
            "16797818670491194348249868563697804441293516695295768428725464454437473025192",
            "3175708756784007584835495801424747224482504115070783937148492422993448606467",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "7",
            "77",
        ];
        let input_1 = [
            "1",
            "0",
            "16797818670491194348249868563697804441293516695295768428725464454437473025192",
            "7623680454338960526645764969964785413027269598530557012829785131842723566171",
            "0",
            "0",
            "13191375861488098868464420135513191848618403718287355402776643336503305836023",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "8",
            "88",
        ];
        let input_2 = [
            "1",
            "1",
            "16797818670491194348249868563697804441293516695295768428725464454437473025192",
            "7623680454338960526645764969964785413027269598530557012829785131842723566171",
            "0",
            "0",
            "8199520123371559548495425428157097842501569495702004037304582533739096128775",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "32",
            "3232",
            "0",
            "16",
            "0",
        ];
        let input_3 = [
            "1",
            "0",
            "5216840757456074114667429562829614408627554131513854271234366250812983764603",
            "0",
            "0",
            "14629197953112535783367739911834726338546021277736603169291721034393042119291",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "17195092312975762537892237130737365903429674363577646686847513978084990105579",
            "19650379996168153643111744440707177573540245771926102415571667548153444658179",
        ];

        let f_input_0 = input_0
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_1 = input_1
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_2 = input_2
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let f_input_3 = input_3
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();

        let is_witness_0 = builder_0
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_0)
            .unwrap();
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_1)
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_2)
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input_3)
            .unwrap();

        let witness_0 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/smtverifier10_test_js/witness0.wtns",
    )
    .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/smtverifier10_test_js/witness1.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
    "../test_vectors/circuits/test-circuits/witness_outputs/smtverifier10_test_js/witness2.wtns",
)
.unwrap();
        let witness_3 = File::open(
"../test_vectors/circuits/test-circuits/witness_outputs/smtverifier10_test_js/witness3.wtns",
)
.unwrap();

        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_0).unwrap();
        assert_eq!(is_witness_0, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
    }

    #[test]
    fn sum_test() {
        let file = "../test_vectors/circuits/test-circuits/sum_test.circom";
        let builder_0 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_1 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_2 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let builder_3 = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let is_witness_0 = builder_0
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("111").unwrap(),ark_bn254::Fr::from_str("222").unwrap()])
            .unwrap();
        let is_witness_1 = builder_1
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("123").unwrap(),ark_bn254::Fr::from_str("423").unwrap()])
            .unwrap();
        let is_witness_2 = builder_2
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("14354353").unwrap(),ark_bn254::Fr::from_str("4225233").unwrap()])
            .unwrap();
        let is_witness_3 = builder_3
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(vec![ark_bn254::Fr::from_str("14354353").unwrap(),ark_bn254::Fr::from_str("14354353").unwrap()])
            .unwrap();
        let witness_0 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sum_test_js/witness3.wtns",
        )
        .unwrap();
        let witness_1 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sum_test_js/witness0.wtns",
        )
        .unwrap();
        let witness_2 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sum_test_js/witness1.wtns",
        )
        .unwrap();
        let witness_3 = File::open(
            "../test_vectors/circuits/test-circuits/witness_outputs/sum_test_js/witness2.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_0).unwrap();
        assert_eq!(is_witness_0, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_1).unwrap();
        assert_eq!(is_witness_1, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_2).unwrap();
        assert_eq!(is_witness_2, should_witness.values);
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness_3).unwrap();
        assert_eq!(is_witness_3, should_witness.values);
    }
    #[ignore]
    #[test]
    fn ml_breast() {
        let file = "test_vectors/circuits/test-circuits/witness_outputs/breast_logreg_linear/circuit.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = vec![
            "42074870000000000",
            "-954683800000000000",
            "91977060000000000",
            "-272534459999999968",
            "187505640000000000",
            "584074600000000000",
            "406279290000000000",
            "462226640000000000",
            "372727270000000000",
            "211036230000000000",
            "-287705959999999968",
            "-759061170000000000",
            "-261932810000000000",
            "-452377480000000000",
            "-681408710000000000",
            "-297203110000000000",
            "-728636360000000000",
            "-398749760000000000",
            "-376709630000000000",
            "-633915120000000000",
            "241551050000000000",
            "-716950960000000000",
            "336620350000000000",
            "-98604010000000000",
            "202271680000000000",
            "238583110000000000",
            "137220450000000000",
            "824054980000000000",
            "196924900000000000",
            "-162272070000000000",
            "1",
            "-2",
            "1",
            "-5",
            "1",
            "-2",
            "-2",
            "0",
            "-1",
            "0",
            "-1",
            "2",
            "-2",
            "-2",
            "4",
            "-1",
            "0",
            "0",
            "1",
            "0",
            "0",
            "-1",
            "-1",
            "0",
            "-5",
            "1",
            "2",
            "0",
            "0",
            "-1",
            "-16",
            "-132250645000000021",
            "2",
        ];
        let f_input = input
            .into_iter()
            .map(|f| ark_bn254::Fr::from_str(f).unwrap())
            .collect();
        let is_witness = builder
            .build()
            .parse()
            .unwrap()
            .to_plain_vm()
            .run(f_input)
            .unwrap();
        let witness = File::open(
            "test_vectors/circuits/test-circuits/witness_outputs/breast_logreg_linear/witness.wtns",
        )
        .unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        assert_eq!(is_witness, should_witness.values);
    }
}
