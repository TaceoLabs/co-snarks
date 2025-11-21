use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use co_acvm::{PlainAcvmSolver, Rep3AcvmSolver, mpc::NoirWitnessExtensionProtocol};
use co_builder::{
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::Bn254G1,
    types::{big_field::BigField, big_group::BigGroup, field_ct::FieldCT},
};
use itertools::izip;
use mpc_core::{
    gadgets::field_from_hex_string,
    protocols::rep3::{Rep3PrimeFieldShare, conversion::A2BType, share_field_element},
};
use mpc_net::local::LocalNetwork;
use num_traits::identities::One;
use rand::{SeedableRng, rngs::StdRng};

type Plain = PlainAcvmSolver<Fr>;
type Rep3 = Rep3AcvmSolver<'static, Fr, LocalNetwork>;

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

type SharedTestEntry<T, Q> = (u8, bool, T, Vec<((Q, Q, bool), T)>, G1Affine);

const SEED: u64 = 42;

struct TestData<T: NoirWitnessExtensionProtocol<Fr>> {
    expected_result: G1Affine,
    points: Vec<BigGroup<Fr, T>>,
    scalars: Vec<FieldCT<Fr>>,
    with_edge_cases: bool,
    max_num_bits: usize,
    masking_scalar: FieldCT<Fr>,
}

impl<T: NoirWitnessExtensionProtocol<Fr>> TestData<T> {
    fn random(
        num_points: usize,
        max_num_bits: usize,
        with_edge_cases: bool,
        masking_scalar: FieldCT<Fr>,
        builder: &mut GenericUltraCircuitBuilder<Bn254G1, T>,
        driver: &mut T,
    ) -> Self {
        let mut rng = StdRng::seed_from_u64(SEED);

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let mut expected_result = G1Affine::identity();

        for _ in 0..num_points {
            let point = G1Affine::rand(&mut rng);
            let scalar = Fr::rand(&mut rng);

            expected_result = (expected_result + point * scalar).into_affine();

            points.push(BigGroup::new(
                BigField::from_witness_other_acvm_type(&point.x.into(), driver, builder).unwrap(),
                BigField::from_witness_other_acvm_type(&point.y.into(), driver, builder).unwrap(),
            ));
            scalars.push(FieldCT::from_witness(scalar.into(), builder));
        }

        Self {
            expected_result,
            points,
            scalars,
            with_edge_cases,
            max_num_bits,
            masking_scalar,
        }
    }

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

impl TestData<Plain> {
    fn share(
        &self,
        plain_builder: &mut GenericUltraCircuitBuilder<Bn254G1, Plain>,
        plain_driver: &mut Plain,
    ) -> Vec<SharedTestEntry<Rep3PrimeFieldShare<Fr>, Rep3PrimeFieldShare<Fq>>> {
        let mut rng = &mut rand::thread_rng();

        let points = self
            .points
            .iter()
            .map(|p| p.to_affine(plain_builder, plain_driver).unwrap())
            .collect::<Vec<G1Affine>>();

        let scalars = self
            .scalars
            .iter()
            .map(|s| s.get_value(plain_builder, plain_driver))
            .collect::<Vec<Fr>>();

        let masking_scalar = self.masking_scalar.get_value(plain_builder, plain_driver);

        let point_bfs = points
            .iter()
            .map(|p| {
                if let Some((x, y)) = p.xy() {
                    let x_shares = share_field_element::<Fq, _>(x, &mut rng);
                    let y_shares = share_field_element::<Fq, _>(y, &mut rng);
                    (x_shares, y_shares, false)
                } else {
                    (Default::default(), Default::default(), true)
                }
            })
            .collect::<Vec<_>>();
        let point_bfs = point_bfs.into_iter().fold(
            vec![Vec::new(), Vec::new(), Vec::new()],
            |mut acc, shares| {
                for (i, item) in acc.iter_mut().enumerate().take(3) {
                    item.push((shares.0[i], shares.1[i], shares.2));
                }
                acc
            },
        );

        let scalar_cts = scalars
            .iter()
            .map(|s| share_field_element::<Fr, _>(*s, &mut rng))
            .collect::<Vec<_>>();
        let scalar_cts = (0..3)
            .map(|i| {
                scalar_cts
                    .iter()
                    .map(|shares| shares[i])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let masking_scalar_shares = share_field_element::<Fr, _>(masking_scalar, &mut rng);

        (0..3)
            .map(|i| {
                (
                    self.max_num_bits as u8,
                    self.with_edge_cases,
                    masking_scalar_shares[i],
                    izip!(point_bfs[i].iter(), scalar_cts[i].iter())
                        .map(|(point_share, scalar_share)| {
                            ((point_share.0, point_share.1, point_share.2), *scalar_share)
                        })
                        .collect::<Vec<_>>(),
                    self.expected_result,
                )
            })
            .collect::<Vec<_>>()
    }
}

impl TestData<Rep3> {
    fn random_shared_test_entries(
        num_points: usize,
        max_num_bits: usize,
        with_edge_cases: bool,
        masking_scalar: FieldCT<Fr>,
    ) -> Vec<SharedTestEntry<Rep3PrimeFieldShare<Fr>, Rep3PrimeFieldShare<Fq>>> {
        let plain_builder = &mut GenericUltraCircuitBuilder::<Bn254G1, Plain>::new(100);
        let plain_driver = &mut Plain::new();
        let plain_data = TestData::<Plain>::random(
            num_points,
            max_num_bits,
            with_edge_cases,
            masking_scalar,
            plain_builder,
            plain_driver,
        );
        plain_data.share(plain_builder, plain_driver)
    }

    fn from_shared_test_entry(
        entry: SharedTestEntry<Rep3PrimeFieldShare<Fr>, Rep3PrimeFieldShare<Fq>>,
        builder: &mut GenericUltraCircuitBuilder<Bn254G1, Rep3>,
        driver: &mut Rep3,
    ) -> Self {
        let (
            max_num_bits,
            with_edge_cases,
            _masking_scalar_share,
            point_scalar_pairs,
            expected_result,
        ) = entry;

        let masking_scalar = FieldCT::from(Fr::ONE); // TODO CESAR: Placeholder, will be replaced by the share

        let mut points = Vec::new();
        let mut scalars = Vec::new();

        for ((px_share, py_share, is_infinity), scalar_share) in point_scalar_pairs {
            let point_x =
                BigField::from_witness_other_acvm_type(&px_share.into(), driver, builder).unwrap();
            let point_y =
                BigField::from_witness_other_acvm_type(&py_share.into(), driver, builder).unwrap();
            let point = if is_infinity {
                BigGroup::point_at_infinity()
            } else {
                BigGroup::new(point_x, point_y)
            };
            points.push(point);

            let scalar = FieldCT::from_witness(scalar_share.into(), builder);
            scalars.push(scalar);
        }

        Self {
            expected_result,
            points,
            scalars,
            with_edge_cases,
            max_num_bits: max_num_bits as usize,
            masking_scalar,
        }
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
fn test_batch_mul_plaindriver() {
    for num_points in [1, 5, 10, 20] {
        let mut driver = PlainAcvmSolver::<Fr>::new();
        let mut builder = GenericUltraCircuitBuilder::<Bn254G1, _>::new(10);
        tracing::info!("Testing batch_mul with {} points", num_points);
        let test_data = TestData::random(
            num_points,
            0,
            false,
            FieldCT::from(Fr::ONE),
            &mut builder,
            &mut driver,
        );
        run_test(test_data, &mut builder, &mut driver);
    }
}

#[test]
fn test_batch_mul_rep3_driver() {
    for num_points in [1] {
        let shared_entries =
            TestData::random_shared_test_entries(num_points, 0, false, FieldCT::from(Fr::ONE));

        println!(
            "Starting batch_mul test with {} points using Rep3 driver",
            num_points
        );
        let nets_1 = LocalNetwork::new_3_parties();
        let nets_2 = LocalNetwork::new_3_parties();

        let mut threads = Vec::new();
        for (test_data, net_1, net_2) in izip!(
            shared_entries.into_iter(),
            nets_1.into_iter(),
            nets_2.into_iter(),
        ) {
            threads.push(std::thread::spawn(move || {
                let net_1b = Box::leak(Box::new(net_1));
                let net_2b = Box::leak(Box::new(net_2));
                let mut builder = GenericUltraCircuitBuilder::<Bn254G1, Rep3>::new(0);
                let mut driver = Rep3::new(net_1b, net_2b, A2BType::Direct).unwrap();
                let test_data =
                    TestData::from_shared_test_entry(test_data, &mut builder, &mut driver);
                run_test(test_data, &mut builder, &mut driver);
            }));
        }

        for handle in threads {
            handle.join().unwrap();
            println!("Finished Rep3 batch_mul test with {} points", num_points);
        }
    }
}

#[test]
fn test_batch_mul_consistency_plaindriver() {
    const TEST_FILE: &str = "tests/test_data/batch_mul";
    let mut driver = PlainAcvmSolver::<Fr>::new();
    run_tests(TEST_FILE, &mut driver);
}

#[test]
fn test_batch_mul_edge_case_equivalence_plaindriver() {
    const TEST_FILE: &str = "tests/test_data/batch_mul";
    let mut driver = PlainAcvmSolver::<Fr>::new();
    let mut builder = GenericUltraCircuitBuilder::<Bn254G1, _>::new(10);
    let test_data = TestData::get_from_file(TEST_FILE, &mut builder, &mut driver);
    test_data.into_iter().for_each(|mut data| {
        data.with_edge_cases = true;
        data.masking_scalar = FieldCT::from(Fr::one());
        run_test(data, &mut builder, &mut driver);
    });
}

#[test]
fn test_batch_mul_edge_case_set_plaindriver() {
    const TEST_FILE: &str = "tests/test_data/batch_mul";
    let mut driver = PlainAcvmSolver::<Fr>::new();
    let mut builder = GenericUltraCircuitBuilder::<Bn254G1, _>::new(10);
    let test_data = TestData::get_from_file(TEST_FILE, &mut builder, &mut driver);
    test_data.into_iter().for_each(|mut data| {
        data.with_edge_cases = true;
        data.masking_scalar = FieldCT::from(Fr::one());
        data.points.push(BigGroup::point_at_infinity());
        data.scalars.push(FieldCT::from(Fr::one()));
        run_test(data, &mut builder, &mut driver);
    });
}
