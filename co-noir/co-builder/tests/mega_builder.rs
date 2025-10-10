use std::thread;

use ark_bn254::Bn254;
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use co_acvm::Rep3AcvmPoint;
use co_acvm::Rep3AcvmSolver;
use co_acvm::Rep3AcvmType;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{
    eccvm::{
        co_ecc_op_queue::{
            CoECCOpQueue, CoEccvmOpsTable, CoUltraEccOpsTable, CoUltraOp, CoVMOperation,
        },
        ecc_op_queue::{EccOpCode, EccOpsTable, EccvmRowTracker},
    },
    mega_builder::MegaCircuitBuilder,
    transcript::TranscriptFieldType,
};
use itertools::{Itertools, izip, multiunzip};
use mpc_core::protocols::rep3::pointshare;
use mpc_core::{
    gadgets::field_from_hex_string,
    protocols::rep3::{conversion::A2BType, share_curve_point, share_field_element},
};
use mpc_net::local::LocalNetwork;

type Bn254G1 = <Bn254 as Pairing>::G1;
type T<'a> = Rep3AcvmSolver<'a, TranscriptFieldType, LocalNetwork>;
type Fq = ark_bn254::Fq;
type Fr = ark_bn254::Fr;
type G1Affine = <Bn254 as Pairing>::G1Affine;

type EccOpsTableTestData<T, Q> = Vec<Vec<([u8; 4], (Q, Q, u8), Q, Q, T)>>;
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
                        let (z1, z2): (Fq, Fq) = (to_field!(z1), to_field!(z2));
                        (
                            op_code,
                            (x, y, is_infinity),
                            z1,
                            z2,
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

fn to_ecc_op_queues<'a>(
    test_data: EccOpQueueTestData<String, String>,
) -> Vec<CoECCOpQueue<T<'a>, Bn254G1>> {
    let ((acc_x, acc_y, is_infinity), eccvm_ops_table, ultra_ops_table, eccvm_row_tracker) =
        to_field_elements(test_data);

    let mut rng = rand::thread_rng();

    let accumulator = if is_infinity != 0 {
        G1Affine::identity()
    } else {
        G1Affine::new(acc_x, acc_y)
    };

    let accumulators = share_curve_point(accumulator.into(), &mut rng);

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
                        share_curve_point(base_point.into(), &mut rng),
                        share_field_element(z1, &mut rng),
                        share_field_element(z2, &mut rng),
                        share_field_element(mul_scalar_full, &mut rng)
                    )
                    .map(
                        |(base_point_share, z1_share, z2_share, mul_scalar_full_share)| {
                            CoVMOperation {
                                op_code: op_code.clone(),
                                base_point: Rep3AcvmPoint::Shared(base_point_share),
                                z1: z1_share.into(),
                                z2: z2_share.into(),
                                mul_scalar_full: mul_scalar_full_share.into(),
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
                        share_field_element(x_lo, &mut rng),
                        share_field_element(x_hi, &mut rng),
                        share_field_element(y_lo, &mut rng),
                        share_field_element(y_hi, &mut rng),
                        share_field_element(z_1, &mut rng),
                        share_field_element(z_2, &mut rng),
                        share_field_element(is_infinity, &mut rng)
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
                            x_lo: x_lo_share.into(),
                            x_hi: x_hi_share.into(),
                            y_lo: y_lo_share.into(),
                            y_hi: y_hi_share.into(),
                            z_1: z_1_share.into(),
                            z_2: z_2_share.into(),
                            return_is_infinity: is_infinity_share.into(),
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
                accumulator: Rep3AcvmPoint::Shared(accumulator),
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
fn test_mega_builder_construction() {
    let (
        initial_op_queue,
        ((random_point_x, random_point_y, _), random_scalar),
        expected_op_queue,
    ): (
        EccOpQueueTestData<String, String>,
        ((String, String, u8), String),
        EccOpQueueTestData<String, String>,
    ) = serde_json::from_str(include_str!("test_data")).unwrap();

    let (
        (acc_x, acc_y, is_infinity),
        expected_eccvm_ops_table,
        expected_ultra_ops_table,
        expected_eccvm_row_tracker,
    ) = to_field_elements(expected_op_queue);

    let expected_eccvm_ops_table = expected_eccvm_ops_table
        .into_iter()
        .map(|row| {
            row.into_iter()
                .map(|(op_code, (x, y, is_infinity), z1, z2, mul_scalar_full)| {
                    let base_point = if is_infinity != 0 {
                        G1Affine::identity()
                    } else {
                        G1Affine::new(x, y)
                    };
                    (op_code, base_point, z1, z2, mul_scalar_full)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let expected_accumulator = if is_infinity != 0 {
        G1Affine::identity()
    } else {
        G1Affine::new(acc_x, acc_y)
    };

    let random_point = G1Affine::new(to_field!(random_point_x), to_field!(random_point_y));
    let random_scalar = to_field!(random_scalar);

    let rng = &mut rand::thread_rng();
    let random_point_shares = share_curve_point(random_point.into(), rng)
        .into_iter()
        .map(Rep3AcvmPoint::Shared)
        .collect::<Vec<_>>();
    let random_scalar_shares = share_field_element(random_scalar, rng)
        .into_iter()
        .map(Rep3AcvmType::Shared)
        .collect::<Vec<_>>();

    let initial_op_queues = to_ecc_op_queues(initial_op_queue);

    let nets_1 = LocalNetwork::new_3_parties();
    let nets_2 = LocalNetwork::new_3_parties();

    let mut threads = Vec::with_capacity(3);

    let builders = initial_op_queues
        .into_iter()
        .map(MegaCircuitBuilder::<Bn254G1, T>::new)
        .collect::<Vec<_>>();

    for (net_1, net_2, mut builder, random_scalar_share, random_point_share) in izip!(
        nets_1,
        nets_2,
        builders,
        random_scalar_shares,
        random_point_shares
    ) {
        let net_1b = Box::leak(Box::new(net_1));
        let net_2b = Box::leak(Box::new(net_2));
        threads.push(thread::spawn(move || {
            let mut driver = T::new(net_1b, net_2b, A2BType::Direct).unwrap();
            builder.queue_ecc_no_op(&mut driver).unwrap();
            builder
                .queue_ecc_mul_accum_store(random_point_share, random_scalar_share, &mut driver)
                .unwrap();
            builder.queue_ecc_eq(&mut driver).unwrap();

            let CoECCOpQueue {
                eccvm_ops_table,
                ultra_ops_table,
                accumulator,
                eccvm_row_tracker,
                ..
            } = builder.ecc_op_queue;

            let accumulator = match accumulator {
                Rep3AcvmPoint::Public(p) => p.into(),
                Rep3AcvmPoint::Shared(point) => match pointshare::open_point(&point, net_1b) {
                    Ok(point) => point.into_affine(),
                    Err(_) => panic!("Failed to open point"),
                },
            };
            let ecc_vm_ops_table = eccvm_ops_table
                .table
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(|op| {
                            let base_point = match op.base_point {
                                Rep3AcvmPoint::Public(p) => p.into(),
                                Rep3AcvmPoint::Shared(p) => {
                                    pointshare::open_point(&p, net_1b).unwrap().into_affine()
                                }
                            };
                            let [z1, z2]: [Fq; 2] = driver
                                .open_many_other_acvm_type::<Bn254G1>(&[op.z1, op.z2])
                                .unwrap()
                                .try_into()
                                .unwrap();
                            let mul_scalar_full: Fr = driver
                                .open_many_acvm_type(&[op.mul_scalar_full])
                                .unwrap()
                                .pop()
                                .unwrap();
                            let op_code = [
                                if op.op_code.add { 1 } else { 0 },
                                if op.op_code.mul { 1 } else { 0 },
                                if op.op_code.eq { 1 } else { 0 },
                                if op.op_code.reset { 1 } else { 0 },
                            ];
                            (op_code, base_point, z1, z2, mul_scalar_full)
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            let ultra_ops_table = {
                let table = ultra_ops_table.table.table;
                let table: Vec<Vec<_>> = table
                    .into_iter()
                    .map(|row| {
                        row.into_iter()
                            .map(|op| {
                                let [x_lo, x_hi, y_lo, y_hi, z_1, z_2, return_is_infinity]: [Fr;
                                    7] = driver
                                    .open_many_acvm_type(&[
                                        op.x_lo,
                                        op.x_hi,
                                        op.y_lo,
                                        op.y_hi,
                                        op.z_1,
                                        op.z_2,
                                        op.return_is_infinity,
                                    ])
                                    .unwrap()
                                    .try_into()
                                    .unwrap();
                                let op_code = [
                                    if op.op_code.add { 1 } else { 0 },
                                    if op.op_code.mul { 1 } else { 0 },
                                    if op.op_code.eq { 1 } else { 0 },
                                    if op.op_code.reset { 1 } else { 0 },
                                ];
                                (
                                    op_code,
                                    x_lo,
                                    x_hi,
                                    y_lo,
                                    y_hi,
                                    z_1,
                                    z_2,
                                    if return_is_infinity == Fr::ZERO { 0 } else { 1 },
                                )
                            })
                            .collect()
                    })
                    .collect();
                table
            };

            let EccvmRowTracker {
                cached_num_muls,
                cached_active_msm_count,
                num_transcript_rows,
                num_precompute_table_rows,
                num_msm_rows,
            } = eccvm_row_tracker;
            let eccvm_row_tracker = [
                cached_num_muls,
                cached_active_msm_count,
                num_transcript_rows,
                num_precompute_table_rows,
                num_msm_rows,
            ];

            (
                accumulator,
                ecc_vm_ops_table,
                ultra_ops_table,
                eccvm_row_tracker,
            )
        }));
    }

    let mut results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let (accumulator, ecc_vm_ops_table, ultra_ops_table, eccvm_row_tracker) =
        results.pop().unwrap();

    assert_eq!(accumulator, expected_accumulator);
    assert_eq!(ecc_vm_ops_table, expected_eccvm_ops_table);
    assert_eq!(ultra_ops_table, expected_ultra_ops_table);
    assert_eq!(eccvm_row_tracker, expected_eccvm_row_tracker);
}
