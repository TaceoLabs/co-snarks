use ark_bn254::Bn254;
use ark_ec::CurveGroup;
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::UniformRand;
use ark_ff::Zero;
use co_acvm::PlainAcvmSolver;
use co_builder::{
    eccvm::co_ecc_op_queue::CoECCOpQueue,
    mega_builder::MegaCircuitBuilder,
    types::{
        field_ct::FieldCT,
        goblin_types::{GoblinElement, GoblinField},
    },
};
use co_noir_common::honk_curve::bn254_fq_to_fr;

type Bn254G1 = <Bn254 as Pairing>::G1;
type G1Affine = <Bn254 as Pairing>::G1Affine;
type Fq = ark_bn254::Fq;
type Fr = ark_bn254::Fr;
type T<'a> = PlainAcvmSolver<Fr>;

#[test]
fn test_negate_goblin_element() {
    let mut rng = rand::thread_rng();
    let element = G1Affine::rand(&mut rng);

    let (x, y): (Fq, Fq) = element.xy().expect("Point should not be at infinity");
    let ((x0, x1), (y0, y1)) = (bn254_fq_to_fr(&x), bn254_fq_to_fr(&y));

    let (x, y, expected_is_infinity) =
        (-element)
            .xy()
            .map(|(x, y)| (x, y, false))
            .unwrap_or((Fq::ZERO, Fq::ZERO, true));
    let ((x0_expected, x1_expected), (y0_expected, y1_expected)) =
        (bn254_fq_to_fr(&x), bn254_fq_to_fr(&y));
    let expected_is_infinity = if expected_is_infinity {
        Fr::ONE
    } else {
        Fr::ZERO
    };

    let mut builder = MegaCircuitBuilder::<Bn254G1, T>::new(CoECCOpQueue::default());
    let mut driver = T::new();
    let goblin = GoblinElement::<Bn254G1, T>::new(
        GoblinField::new([
            FieldCT::from_witness(x0, &mut builder),
            FieldCT::from_witness(x1, &mut builder),
        ]),
        GoblinField::new([
            FieldCT::from_witness(y0, &mut builder),
            FieldCT::from_witness(y1, &mut builder),
        ]),
    );

    let result = goblin.neg(&mut builder, &mut driver);

    let GoblinElement {
        x: GoblinField {
            limbs: [x0_result, x1_result],
        },
        y: GoblinField {
            limbs: [y0_result, y1_result],
        },
        is_infinity,
    } = result.unwrap();

    assert_eq!(
        [
            x0_result,
            x1_result,
            y0_result,
            y1_result,
            is_infinity.to_field_ct(&mut driver)
        ]
        .map(|f| f.get_value(&builder, &mut driver)),
        [
            x0_expected,
            x1_expected,
            y0_expected,
            y1_expected,
            expected_is_infinity
        ]
    );
}

#[test]
fn test_batch_mul() {
    let points = vec![
        G1Affine::rand(&mut rand::thread_rng()),
        G1Affine::rand(&mut rand::thread_rng()),
        G1Affine::rand(&mut rand::thread_rng()),
    ];

    let scalars = vec![
        Fr::rand(&mut rand::thread_rng()),
        Fr::rand(&mut rand::thread_rng()),
        Fr::rand(&mut rand::thread_rng()),
    ];

    let expected_result = points
        .iter()
        .zip(scalars.iter())
        .map(|(&p, &s)| p * s)
        .fold(Bn254G1::zero(), |acc, p| acc + p);

    let (x, y, expected_is_infinity) = expected_result
        .into_affine()
        .xy()
        .map(|(x, y)| (x, y, false))
        .unwrap_or((Fq::ZERO, Fq::ZERO, true));
    let ((x0_expected, x1_expected), (y0_expected, y1_expected)) =
        (bn254_fq_to_fr(&x), bn254_fq_to_fr(&y));

    let mut builder = MegaCircuitBuilder::<Bn254G1, T>::new(CoECCOpQueue::default());
    let mut driver = T::new();
    let points = points
        .into_iter()
        .map(|point| {
            let (x, y, is_infinity) =
                point
                    .xy()
                    .map(|(x, y)| (x, y, false))
                    .unwrap_or((Fq::ZERO, Fq::ZERO, true));
            let ((x0, x1), (y0, y1)) = (bn254_fq_to_fr(&x), bn254_fq_to_fr(&y));
            if is_infinity {
                GoblinElement::point_at_infinity(&mut builder)
            } else {
                GoblinElement::<Bn254G1, T>::new(
                    GoblinField::new([
                        FieldCT::from_witness(x0, &mut builder),
                        FieldCT::from_witness(x1, &mut builder),
                    ]),
                    GoblinField::new([
                        FieldCT::from_witness(y0, &mut builder),
                        FieldCT::from_witness(y1, &mut builder),
                    ]),
                )
            }
        })
        .collect::<Vec<_>>();

    let scalars = scalars
        .into_iter()
        .map(|scalar| FieldCT::from_witness(scalar, &mut builder))
        .collect::<Vec<_>>();

    let result = GoblinElement::batch_mul(&points, &scalars, &mut builder, &mut driver).unwrap();

    let GoblinElement {
        x: GoblinField {
            limbs: [x0_result, x1_result],
        },
        y: GoblinField {
            limbs: [y0_result, y1_result],
        },
        is_infinity,
    } = result;

    assert_eq!(
        [
            x0_result,
            x1_result,
            y0_result,
            y1_result,
            is_infinity.to_field_ct(&mut driver)
        ]
        .map(|f| f.get_value(&builder, &mut driver)),
        [
            x0_expected,
            x1_expected,
            y0_expected,
            y1_expected,
            if expected_is_infinity {
                Fr::ONE
            } else {
                Fr::ZERO
            }
        ]
    );
}
