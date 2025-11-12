use ark_bn254::{Fq, Fr, G1Affine};
use co_acvm::{PlainAcvmSolver, mpc::NoirWitnessExtensionProtocol};
use co_builder::{
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::Bn254G1,
    types::{big_field::BigField, big_group::BigGroup, field_ct::FieldCT},
};
use mpc_core::gadgets::field_from_hex_string;
use num_traits::identities::One;

type TestEntry = (
    u8,     // max_num_bits
    u8,     // with_edge_cases
    String, // masking_scalar as hex string
    Vec<(
        (String, String, u8), // Input point as hex string coordinates and flag for infinity
        String,               // Scalar as hex string
    )>,
    (String, String, u8), // Expected result point as hex string coordinates and flag for infinity
);

struct TestData<T: NoirWitnessExtensionProtocol<Fr>> {
    expected_result: G1Affine,
    points: Vec<BigGroup<Fr, T>>,
    scalars: Vec<FieldCT<Fr>>,
    with_edge_cases: bool,
    max_num_bits: usize,
    masking_scalar: FieldCT<Fr>,
}

impl<T: NoirWitnessExtensionProtocol<Fr>> TestData<T> {
    fn from_test_entry(
        entry: TestEntry,
        builder: &mut GenericUltraCircuitBuilder<Bn254G1, T>,
        driver: &mut T,
    ) -> Self {
        let (
            max_num_bits,
            with_edge_cases,
            masking_scalar_hex,
            point_scalar_pairs,
            expected_result_hex,
        ) = entry;

        let masking_scalar = field_from_hex_string::<Fr>(&masking_scalar_hex).unwrap();
        let masking_scalar = if with_edge_cases == 0 {
            FieldCT::from(Fr::one())
        } else {
            FieldCT::from_witness(masking_scalar.into(), builder)
        };

        let mut points = Vec::new();
        let mut scalars = Vec::new();

        for ((px_hex, py_hex, is_infinity), scalar_hex) in point_scalar_pairs {
            let point_x = BigField::from_witness_other_acvm_type(
                &field_from_hex_string::<Fq>(&px_hex).unwrap().into(),
                driver,
                builder,
            )
            .unwrap();
            let point_y = BigField::from_witness_other_acvm_type(
                &field_from_hex_string::<Fq>(&py_hex).unwrap().into(),
                driver,
                builder,
            )
            .unwrap();
            let point = if is_infinity == 1 {
                BigGroup::point_at_infinity()
            } else {
                BigGroup::new(point_x, point_y)
            };
            points.push(point);

            let scalar = FieldCT::from_witness(
                field_from_hex_string::<Fr>(&scalar_hex).unwrap().into(),
                builder,
            );
            scalars.push(scalar);
        }

        let (result_x_hex, result_y_hex, result_is_infinity) = expected_result_hex;
        let expected_result = if result_is_infinity == 1 {
            G1Affine::identity()
        } else {
            G1Affine::new(
                field_from_hex_string::<Fq>(&result_x_hex).unwrap(),
                field_from_hex_string::<Fq>(&result_y_hex).unwrap(),
            )
        };

        Self {
            expected_result,
            points,
            scalars,
            with_edge_cases: with_edge_cases == 1,
            max_num_bits: max_num_bits as usize,
            masking_scalar,
        }
    }

    fn from_test_entries(
        entries: Vec<TestEntry>,
        builder: &mut GenericUltraCircuitBuilder<Bn254G1, T>,
        driver: &mut T,
    ) -> Vec<Self> {
        entries
            .into_iter()
            .map(|entry| Self::from_test_entry(entry, builder, driver))
            .collect()
    }

    fn get_from_file(
        test_file: &str,
        builder: &mut GenericUltraCircuitBuilder<Bn254G1, T>,
        driver: &mut T,
    ) -> Vec<Self> {
        let test_entries: Vec<TestEntry> =
            serde_json::from_str(std::fs::read_to_string(test_file).unwrap().as_str()).unwrap();
        Self::from_test_entries(test_entries, builder, driver)
    }
}

fn run_test<T: NoirWitnessExtensionProtocol<Fr>>(
    test_data: TestData<T>,
    builder: &mut GenericUltraCircuitBuilder<Bn254G1, T>,
    driver: &mut T,
) {
    let TestData {
        points,
        scalars,
        with_edge_cases,
        max_num_bits,
        masking_scalar,
        expected_result,
    } = test_data;

    tracing::info!(
        "Running big group batch_mul test with {} points",
        points.len()
    );
    let result = BigGroup::batch_mul(
        &points,
        &scalars,
        max_num_bits,
        with_edge_cases,
        &masking_scalar,
        builder,
        driver,
    )
    .unwrap();

    let result_affine = result.to_affine(builder, driver).unwrap();
    assert_eq!(result_affine, expected_result);
}

fn run_tests<T: NoirWitnessExtensionProtocol<Fr>>(test_file: &str, driver: &mut T) {
    // TODO CESAR: size hint?
    let mut builder = GenericUltraCircuitBuilder::<Bn254G1, T>::new(100);
    let test_data_list = TestData::get_from_file(test_file, &mut builder, driver);

    for test_data in test_data_list {
        run_test(test_data, &mut builder, driver);
    }
}

#[test]
fn test_big_group_consistency_plaindriver() {
    const TEST_FILE: &str = "tests/test_data/big_group_consistency";
    tracing_subscriber::fmt().init();
    let mut driver = PlainAcvmSolver::<Fr>::new();
    run_tests(TEST_FILE, &mut driver);
}

#[test]
fn test_big_group_edge_case_equivalence_plaindriver() {
    const TEST_FILE: &str = "tests/test_data/big_group_consistency";
    tracing_subscriber::fmt().init();
    let mut driver = PlainAcvmSolver::<Fr>::new();
    let mut builder = GenericUltraCircuitBuilder::<Bn254G1, _>::new(10);
    let test_data = TestData::get_from_file(TEST_FILE, &mut builder, &mut driver);
    test_data.into_iter().for_each(|mut data| {
        data.with_edge_cases = true;
        data.masking_scalar = FieldCT::from(Fr::one());
        run_test(data, &mut builder, &mut driver);
    });
}
