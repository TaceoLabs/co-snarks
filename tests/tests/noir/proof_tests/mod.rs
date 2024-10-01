mod plain;
// mod rep3;

macro_rules! add_plain_proof_test {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_plain_ $name >]() {
                let program = std::fs::read_to_string(format!(
                    "../test_vectors/noir/{}/kat/{}.json",
                $name, $name))
                .unwrap();
                let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
                    .expect("failed to parse program artifact");
                let should_witness =
                    std::fs::read(format!("../test_vectors/noir/{}/kat/{}.gz", $name, $name)).unwrap();
                let should_witness =
                    WitnessStack::<FieldElement>::try_from(should_witness.as_slice()).unwrap();
                let proof = format!("../test_vectors/noir/kat/{}/Prover.toml", $name);
                let solver =
                    PlainCoSolver::init_plain_driver(program_artifact, prover_toml).unwrap();
                let is_witness = solver.solve().unwrap();
                let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
                assert_eq!(is_witness, should_witness);
            }
        }
    };
}
