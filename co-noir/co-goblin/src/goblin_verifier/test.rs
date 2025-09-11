use std::thread;

use ark_bn254::Bn254;
use ark_ec::{pairing::Pairing, AffineRepr};
use co_acvm::{PlainAcvmSolver, Rep3AcvmSolver};
use co_builder::{eccvm::co_ecc_op_queue::CoECCOpQueue, mega_builder::MegaCircuitBuilder, types::{field_ct::FieldCT, goblin_types::{GoblinElement, GoblinField}}};
use common::{honk_curve::bn254_fq_to_fr, honk_proof::TranscriptFieldType, mpc::{plain::PlainUltraHonkDriver, rep3::Rep3UltraHonkDriver}};
use itertools::izip;
use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements, Rep3State};
use mpc_net::local::LocalNetwork;
use ark_ff::{PrimeField, UniformRand};
use ark_ff::AdditiveGroup;
use ark_ff::Field;

use crate::goblin_verifier::merge_recursive_verifier::MergeRecursiveVerifier;

type Bn254G1 = <Bn254 as Pairing>::G1;
type G1Affine = <Bn254 as Pairing>::G1Affine;
type Fq = ark_bn254::Fq;
type Fr = ark_bn254::Fr;
type T<'a> = PlainAcvmSolver<Fr>;
type D = PlainUltraHonkDriver;

#[test]
fn test_negate_goblin_element() {
    let mut rng = rand::thread_rng();
    let element = G1Affine::rand(&mut rng);

    let (x, y, is_infinity) = element.xy().map(|(x, y)| (x, y, false)).unwrap_or((Fq::ZERO, Fq::ZERO, true));
    let ((x0, x1), (y0, y1)) = (
        bn254_fq_to_fr(&x),
        bn254_fq_to_fr(&y),
    );

    let (x, y, expected_is_infinity) = (-element).xy().map(|(x, y)| (x, y, false)).unwrap_or((Fq::ZERO, Fq::ZERO, true));
    let ((x0_expected, x1_expected), (y0_expected, y1_expected)) = (
        bn254_fq_to_fr(&x),
        bn254_fq_to_fr(&y),
    );
    let expected_is_infinity = if expected_is_infinity { Fr::ONE } else { Fr::ZERO };

    let mut builder = MegaCircuitBuilder::<Bn254G1, T, D>::new(CoECCOpQueue::default());
    let mut driver = T::new();
    let goblin = GoblinElement::<Bn254G1, T>::new(
        GoblinField::new([
            FieldCT::from_witness(x0.into(), &mut builder),
            FieldCT::from_witness(y0.into(), &mut builder),
        ]),
        GoblinField::new([
            FieldCT::from_witness(x1.into(), &mut builder),
            FieldCT::from_witness(y1.into(), &mut builder),
        ]),
    );

    let result = MergeRecursiveVerifier::negate_goblin_element(&goblin, &mut builder, &mut driver, &(), &mut ());

    let GoblinElement {
        x: GoblinField { limbs: [x0_result, x1_result] },
        y: GoblinField { limbs: [y0_result, y1_result] },
        is_infinity
    } = result;

    assert_eq!(
        [x0_result, x1_result, y0_result, y1_result, is_infinity.to_field_ct(&mut driver)].map(|f| f.get_value(&builder, &mut driver)),
        [x0_expected, x1_expected, y0_expected, y1_expected, expected_is_infinity].map(|f| f.into())
    );
}