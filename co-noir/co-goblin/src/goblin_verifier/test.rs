use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use co_acvm::PlainAcvmSolver;
use co_builder::{
    eccvm::{
        co_ecc_op_queue::{
            CoECCOpQueue, CoEccvmOpsTable, CoUltraEccOpsTable, CoUltraOp, CoVMOperation,
        },
        ecc_op_queue::{EccOpCode, EccOpsTable, EccvmRowTracker},
    },
    mega_builder::MegaCircuitBuilder,
    transcript::Poseidon2Sponge,
    types::{
        field_ct::FieldCT,
        goblin_types::{GoblinElement, GoblinField},
    },
};
use common::honk_proof::TranscriptFieldType;
use itertools::{Itertools, izip, multiunzip};
use mpc_core::gadgets::field_from_hex_string;

use crate::goblin_verifier::merge_recursive_verifier::MergeRecursiveVerifier;

type Bn254G1 = <Bn254 as Pairing>::G1;
type T<'a> = PlainAcvmSolver<TranscriptFieldType>;
type Fq = ark_bn254::Fq;
type Fr = ark_bn254::Fr;
type G1Affine = <Bn254 as Pairing>::G1Affine;

type EccOpsTableTestData<T, Q> = Vec<Vec<([u8; 4], (Q, Q, u8), T, T, T)>>;
type UltraOpsTableTestData<T> = Vec<Vec<([u8; 4], T, T, T, T, T, T, u8)>>;

type EccOpQueueTestData<T, Q> = (
    (Q, Q, u8),
    EccOpsTableTestData<T, Q>,
    UltraOpsTableTestData<T>,
    [u32; 5],
);
macro_rules! to_field {
    ($x:expr) => {
        field_from_hex_string($x.as_str()).unwrap()
    };
    ($x:expr, 1) => {
        $x.into_iter().map(|s| to_field!(s)).collect::<Vec<_>>()
    };
    ($x:expr, 2) => {
        $x.into_iter().map(|s| to_field!(s, 1)).collect::<Vec<_>>()
    };
}

fn to_field_elements(test_data: EccOpQueueTestData<String, String>) -> EccOpQueueTestData<Fr, Fq> {
    let ((acc_x, acc_y, is_infinity), eccvm_ops_table, ultra_ops_table, eccvm_row_tracker) =
        test_data;

    let acc_x = to_field!(acc_x);
    let acc_y = to_field!(acc_y);

    let eccvm_ops_table: EccOpsTableTestData<Fr, Fq> = eccvm_ops_table
        .into_iter()
        .map(|row| {
            row.into_iter()
                .map(
                    |(
                        op_code,
                        (base_point_x, base_point_y, is_infinity),
                        z1,
                        z2,
                        mul_scalar_full,
                    )| {
                        let (x, y): (Fq, Fq) = (to_field!(base_point_x), to_field!(base_point_y));
                        (
                            op_code,
                            (x, y, is_infinity),
                            to_field!(z1),
                            to_field!(z2),
                            to_field!(mul_scalar_full),
                        )
                    },
                )
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let ultra_ops_table: UltraOpsTableTestData<Fr> = ultra_ops_table
        .into_iter()
        .map(|row| {
            row.into_iter()
                .map(|(op_code, x_lo, x_hi, y_lo, y_hi, z_1, z_2, is_infinity)| {
                    (
                        op_code,
                        to_field!(x_lo),
                        to_field!(x_hi),
                        to_field!(y_lo),
                        to_field!(y_hi),
                        to_field!(z_1),
                        to_field!(z_2),
                        is_infinity,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    (
        (acc_x, acc_y, is_infinity),
        eccvm_ops_table,
        ultra_ops_table,
        eccvm_row_tracker,
    )
}

fn to_ecc_op_queues(
    test_data: EccOpQueueTestData<String, String>,
) -> Vec<CoECCOpQueue<T<'static>, Bn254G1>> {
    let ((acc_x, acc_y, is_infinity), eccvm_ops_table, ultra_ops_table, eccvm_row_tracker) =
        to_field_elements(test_data);

    let accumulator = if is_infinity != 0 {
        G1Affine::identity()
    } else {
        G1Affine::new(acc_x, acc_y)
    };

    let accumulators = std::iter::repeat_n(accumulator, 3);

    let eccvm_ops_tables: [Vec<Vec<CoVMOperation<T, Bn254G1>>>; 3] = eccvm_ops_table
        .into_iter()
        .map(|row| {
            let tmp: Vec<_> = row
                .into_iter()
                .map(|(op_code, (x, y, is_infinity), z1, z2, mul_scalar_full)| {
                    let base_point = if is_infinity != 0 {
                        G1Affine::identity()
                    } else {
                        G1Affine::new(x, y)
                    };

                    let op_code = EccOpCode {
                        add: op_code[0] != 0,
                        mul: op_code[1] != 0,
                        eq: op_code[2] != 0,
                        reset: op_code[3] != 0,
                    };

                    izip!(
                        std::iter::repeat_n(base_point, 3),
                        std::iter::repeat_n(z1, 3),
                        std::iter::repeat_n(z2, 3),
                        std::iter::repeat_n(mul_scalar_full, 3)
                    )
                    .map(
                        |(base_point_share, z1_share, z2_share, mul_scalar_full_share)| {
                            CoVMOperation {
                                op_code: op_code.clone(),
                                base_point: base_point_share.into(),
                                z1: z1_share,
                                z2: z2_share,
                                mul_scalar_full: mul_scalar_full_share,
                                ..Default::default()
                            }
                        },
                    )
                    .collect_tuple()
                    .unwrap()
                })
                .collect::<Vec<(_, _, _)>>();

            multiunzip(tmp)
        })
        .fold(
            [vec![], vec![], vec![]],
            |[mut acc0, mut acc1, mut acc2], (ops0, ops1, ops2)| {
                acc0.push(ops0);
                acc1.push(ops1);
                acc2.push(ops2);
                [acc0, acc1, acc2]
            },
        );

    let eccvm_ops_tables = eccvm_ops_tables.map(|table| CoEccvmOpsTable { table });

    let ultra_ops_tables: [Vec<Vec<CoUltraOp<T, Bn254G1>>>; 3] = ultra_ops_table
        .into_iter()
        .map(|row| {
            let tmp: Vec<_> = row
                .into_iter()
                .map(|(op_code, x_lo, x_hi, y_lo, y_hi, z_1, z_2, is_infinity)| {
                    let is_infinity = if is_infinity != 0 { Fr::ONE } else { Fr::ZERO };
                    let op_code = EccOpCode {
                        add: op_code[0] != 0,
                        mul: op_code[1] != 0,
                        eq: op_code[2] != 0,
                        reset: op_code[3] != 0,
                    };

                    izip!(
                        std::iter::repeat_n(x_lo, 3),
                        std::iter::repeat_n(x_hi, 3),
                        std::iter::repeat_n(y_lo, 3),
                        std::iter::repeat_n(y_hi, 3),
                        std::iter::repeat_n(z_1, 3),
                        std::iter::repeat_n(z_2, 3),
                        std::iter::repeat_n(is_infinity, 3)
                    )
                    .map(
                        |(
                            x_lo_share,
                            x_hi_share,
                            y_lo_share,
                            y_hi_share,
                            z_1_share,
                            z_2_share,
                            is_infinity_share,
                        )| CoUltraOp {
                            op_code: op_code.clone(),
                            x_lo: x_lo_share,
                            x_hi: x_hi_share,
                            y_lo: y_lo_share,
                            y_hi: y_hi_share,
                            z_1: z_1_share,
                            z_2: z_2_share,
                            return_is_infinity: is_infinity_share,
                        },
                    )
                    .collect_tuple()
                    .unwrap()
                })
                .collect::<Vec<(_, _, _)>>();
            multiunzip(tmp)
        })
        .fold(
            [vec![], vec![], vec![]],
            |[mut acc0, mut acc1, mut acc2], (ops0, ops1, ops2)| {
                acc0.push(ops0);
                acc1.push(ops1);
                acc2.push(ops2);
                [acc0, acc1, acc2]
            },
        );
    let ultra_ops_tables = ultra_ops_tables.map(|table| CoUltraEccOpsTable {
        table: EccOpsTable { table },
    });

    let [
        cached_num_muls,
        cached_active_msm_count,
        num_transcript_rows,
        num_precompute_table_rows,
        num_msm_rows,
    ] = eccvm_row_tracker;

    let eccvm_row_tracker = EccvmRowTracker {
        cached_num_muls,
        cached_active_msm_count,
        num_transcript_rows,
        num_precompute_table_rows,
        num_msm_rows,
    };

    izip!(accumulators, eccvm_ops_tables, ultra_ops_tables)
        .map(
            |(accumulator, eccvm_ops_table, ultra_ops_table)| CoECCOpQueue {
                accumulator: accumulator.into(),
                eccvm_ops_table,
                ultra_ops_table,
                eccvm_row_tracker: eccvm_row_tracker.clone(),
                ..Default::default()
            },
        )
        .collect::<Vec<_>>()
}

#[test]
#[expect(clippy::type_complexity)]
fn test_recursive_merge_verifier() {
    let (
        fold_proof,
        merge_proof,
        ecc_op_queue,
        ((random_point_x, random_point_y, _), random_scalar),
    ): (
        Vec<String>,
        Vec<String>,
        EccOpQueueTestData<String, String>,
        ((String, String, u8), String),
    ) = serde_json::from_str(include_str!("test_data")).unwrap();

    let random_point_x = to_field!(random_point_x);
    let random_point_y = to_field!(random_point_y);
    let random_point = G1Affine::new(random_point_x, random_point_y);

    let random_scalar = to_field!(random_scalar);

    let fold_proof: Vec<Fr> = to_field!(fold_proof, 1);
    let merge_proof: Vec<Fr> = to_field!(merge_proof, 1);
    let ecc_op_queues = to_ecc_op_queues(ecc_op_queue);

    let op_queue = ecc_op_queues.into_iter().next().unwrap();
    let mut builder = MegaCircuitBuilder::<Bn254G1, T>::new(op_queue);
    let mut driver = T::new();

    let pairing_point_0_limbs: ((Fr, Fr), (Fr, Fr)) = (
        (
            to_field!("0x2fc2dd516b08651dc1f8f324982c9ffa9e".to_owned()),
            to_field!("0x83fb9ce0e8d7f201057afe910cc9".to_owned()),
        ),
        (
            to_field!("0x043a6230618dfd4e4d29c11c926cf70030".to_owned()),
            to_field!("0x19eea059152cc93a12dafc17f884f6".to_owned()),
        ),
    );
    let pairing_point_1_limbs: ((Fr, Fr), (Fr, Fr)) = (
        (
            to_field!("0x99b19f962ea18016ccae9aa03cd5bad298".to_owned()),
            to_field!("0x12196b7b77f82ea43b2e5e97949268".to_owned()),
        ),
        (
            to_field!("0x4c5c60dc5d5b6ec5c001c2c8bcf6acede8".to_owned()),
            to_field!("0x1db3a7fad58a63499515f1ca497b02".to_owned()),
        ),
    );

    let pairing_point_0 = GoblinElement::<Bn254G1, T>::new(
        GoblinField::new([
            FieldCT::from_witness(pairing_point_0_limbs.0.0, &mut builder),
            FieldCT::from_witness(pairing_point_0_limbs.0.1, &mut builder),
        ]),
        GoblinField::new([
            FieldCT::from_witness(pairing_point_0_limbs.1.0, &mut builder),
            FieldCT::from_witness(pairing_point_0_limbs.1.1, &mut builder),
        ]),
    );
    let pairing_point_1 = GoblinElement::<Bn254G1, T>::new(
        GoblinField::new([
            FieldCT::from_witness(pairing_point_1_limbs.0.0, &mut builder),
            FieldCT::from_witness(pairing_point_1_limbs.0.1, &mut builder),
        ]),
        GoblinField::new([
            FieldCT::from_witness(pairing_point_1_limbs.1.0, &mut builder),
            FieldCT::from_witness(pairing_point_1_limbs.1.1, &mut builder),
        ]),
    );

    builder.queue_ecc_no_op(&mut driver).unwrap();
    builder
        .queue_ecc_mul_accum_store(random_point.into(), random_scalar, &mut driver)
        .unwrap();
    builder.queue_ecc_eq(&mut driver).unwrap();

    for &fr in &fold_proof {
        builder.add_public_variable(fr);
    }

    let mut stdlib_merge_proof = Vec::with_capacity(merge_proof.len());
    for &fr in &merge_proof {
        stdlib_merge_proof.push(FieldCT::from_witness(fr, &mut builder));
    }

    let result = MergeRecursiveVerifier
        .verify_proof::<_, _, Poseidon2Sponge>(stdlib_merge_proof, &mut builder, &mut driver)
        .unwrap();
    assert_eq!(
        (
            result.0.get_value(&mut builder, &mut driver),
            result.1.get_value(&mut builder, &mut driver)
        ),
        (
            pairing_point_0.get_value(&mut builder, &mut driver),
            pairing_point_1.get_value(&mut builder, &mut driver)
        )
    );
}
