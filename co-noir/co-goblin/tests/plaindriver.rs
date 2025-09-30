#[cfg(test)]
mod tests {
    use ark_ec::AffineRepr;
    use ark_ec::short_weierstrass;
    use ark_ff::Zero;
    use ark_grumpkin::GrumpkinConfig;
    use co_acvm::PlainAcvmSolver;
    use co_acvm::Rep3AcvmSolver;
    use co_acvm::mpc::NoirWitnessExtensionProtocol;
    use co_builder::TranscriptFieldType;
    use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
    use co_builder::prelude::HonkCurve;
    use co_builder::prelude::SerializeF;
    use co_builder::prelude::{CrsParser, SerializeP};
    use co_goblin::eccvm::co_ecc_op_queue::CoECCOpQueue;
    use co_goblin::eccvm::co_ecc_op_queue::CoEccvmOpsTable;
    use co_goblin::eccvm::co_ecc_op_queue::CoUltraEccOpsTable;
    use co_goblin::eccvm::co_ecc_op_queue::CoUltraOp;
    use co_goblin::eccvm::co_ecc_op_queue::CoVMOperation;
    use co_goblin::eccvm::co_eccvm_prover::Eccvm;
    use co_goblin::eccvm::co_eccvm_types::construct_from_builder;
    use co_ultrahonk::prelude::ProvingKey;
    use common::mpc::plain::PlainUltraHonkDriver;
    use common::mpc::rep3::Rep3UltraHonkDriver;
    use common::transcript::Poseidon2Sponge;
    use common::transcript::Transcript;
    use goblin::prelude::ECCOpQueue;
    use goblin::prelude::EccOpCode;
    use goblin::prelude::EccvmOpsTable;
    use goblin::prelude::EccvmRowTracker;
    use goblin::prelude::UltraEccOpsTable;
    use goblin::prelude::UltraOp;
    use goblin::prelude::VMOperation;
    use itertools::Itertools;
    use itertools::izip;
    use mpc_core::protocols::rep3::Rep3State;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::{share_curve_point, share_field_element};
    use mpc_net::local::LocalNetwork;
    use rand::thread_rng;
    use std::thread;
    use std::{path::PathBuf, sync::Arc};
    use ultrahonk::prelude::ZeroKnowledge;

    type WitExtDriver<'a, F, N> = Rep3AcvmSolver<'a, F, N>;

    const ECCVM_OPS_TABLE_SIZE: usize = 15;
    const ECCVM_OPS_SUBTABLE_SIZES: [usize; ECCVM_OPS_TABLE_SIZE] =
        [292, 196, 196, 396, 2, 396, 2, 396, 2, 396, 2, 396, 2, 28, 2];
    const ULTRA_OPS_TABLE_SIZE: usize = 15;
    const ULTRA_OPS_SUBTABLE_SIZES: [usize; ULTRA_OPS_TABLE_SIZE] =
        [293, 196, 196, 396, 2, 396, 2, 396, 2, 396, 2, 396, 2, 28, 2];
    // The input for this is extracted from barretenberg into bytes (see test_vectors/noir/eccvm for a text file on how the ecc_op_queue was serialized in bb)
    fn deserialize_ecc_op_queue<P: HonkCurve<TranscriptFieldType>>(path: PathBuf) -> ECCOpQueue<P> {
        let buf = &std::fs::read(&path).unwrap();

        let mut offset = 0;
        let accumulator = P::Affine::zero(); //This is the point at infinity at this time
        let mut eccvm_ops_table = Vec::with_capacity(ECCVM_OPS_TABLE_SIZE);
        for size in ECCVM_OPS_SUBTABLE_SIZES {
            let mut tmp: Vec<VMOperation<P>> = Vec::with_capacity(size);
            for _ in 0..size {
                let op_code = buf[offset];
                let op_code = EccOpCode {
                    add: (op_code & 0b0001) != 0,
                    mul: (op_code & 0b0010) != 0,
                    eq: (op_code & 0b0100) != 0,
                    reset: (op_code & 0b1000) != 0,
                };
                offset += 1;
                let base_point = SerializeP::<P>::read_g1_element(buf, &mut offset, false);
                let z1 = SerializeF::<P::ScalarField>::read_biguint(buf, 4, &mut offset);
                let z2 = SerializeF::<P::ScalarField>::read_biguint(buf, 4, &mut offset);
                let mul_scalar_full =
                    SerializeF::<P::ScalarField>::read_field_element(buf, &mut offset);
                tmp.push(VMOperation {
                    op_code,
                    base_point,
                    z1,
                    z2,
                    mul_scalar_full,
                });
            }
            eccvm_ops_table.push(tmp);
        }
        let eccvm_ops_table = EccvmOpsTable {
            table: eccvm_ops_table,
        };
        let mut ultra_ops_table = Vec::with_capacity(ULTRA_OPS_TABLE_SIZE);
        for size in ULTRA_OPS_SUBTABLE_SIZES {
            let mut tmp: Vec<UltraOp<P>> = Vec::with_capacity(size);
            for _ in 0..size {
                let op_code = buf[offset];
                let op_code = EccOpCode {
                    add: (op_code & 0b0001) != 0,
                    mul: (op_code & 0b0010) != 0,
                    eq: (op_code & 0b0100) != 0,
                    reset: (op_code & 0b1000) != 0,
                };
                offset += 1;
                let x_lo = SerializeF::<P::ScalarField>::read_field_element(buf, &mut offset);
                let x_hi = SerializeF::<P::ScalarField>::read_field_element(buf, &mut offset);
                let y_lo = SerializeF::<P::ScalarField>::read_field_element(buf, &mut offset);
                let y_hi = SerializeF::<P::ScalarField>::read_field_element(buf, &mut offset);
                let z_1 = SerializeF::<P::ScalarField>::read_field_element(buf, &mut offset);
                let z_2 = SerializeF::<P::ScalarField>::read_field_element(buf, &mut offset);
                let return_is_infinity = buf[offset] != 0;
                offset += 1;
                tmp.push(UltraOp {
                    op_code,
                    x_lo,
                    x_hi,
                    y_lo,
                    y_hi,
                    z_1,
                    z_2,
                    return_is_infinity,
                });
            }
            ultra_ops_table.push(tmp);
        }
        let ultra_ops_table = UltraEccOpsTable {
            table: ultra_ops_table,
        };
        let cached_num_muls = SerializeF::<P::ScalarField>::read_u32(buf, &mut offset);
        let cached_active_msm_count = SerializeF::<P::ScalarField>::read_u32(buf, &mut offset);
        let num_transcript_rows = SerializeF::<P::ScalarField>::read_u32(buf, &mut offset);
        let num_precompute_table_rows = SerializeF::<P::ScalarField>::read_u32(buf, &mut offset);
        let num_msm_rows = SerializeF::<P::ScalarField>::read_u32(buf, &mut offset);
        let eccvm_row_tracker = EccvmRowTracker {
            cached_num_muls,
            cached_active_msm_count,
            num_transcript_rows,
            num_precompute_table_rows,
            num_msm_rows,
        };
        ECCOpQueue {
            accumulator,
            eccvm_ops_table,
            ultra_ops_table,
            eccvm_ops_reconstructed: Vec::new(),
            ultra_ops_reconstructed: Vec::new(),
            eccvm_row_tracker,
        }
    }

    fn co_ultra_op_from_ultra_op<C: HonkCurve<TranscriptFieldType>>(
        ultra_op: UltraOp<C>,
    ) -> Vec<CoUltraOp<WitExtDriver<'static, C::BaseField, LocalNetwork>, C>> {
        let mut rng = thread_rng();
        izip!(
        share_field_element(ultra_op.x_lo, &mut rng),
        share_field_element(ultra_op.x_hi, &mut rng),
        share_field_element(ultra_op.y_lo, &mut rng),
        share_field_element(ultra_op.y_hi, &mut rng),
        share_field_element(ultra_op.z_1, &mut rng),
        share_field_element(ultra_op.z_2, &mut rng),

    )
    .map(
        |(x_lo, x_hi, y_lo, y_hi, z_1, z_2, )| CoUltraOp {
            op_code: ultra_op.op_code.clone(),
            x_lo:
                <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
                    C::BaseField,
                >>::OtherAcvmType::<C>::from(x_lo),
            x_hi:
                <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
                    C::BaseField,
                >>::OtherAcvmType::<C>::from(x_hi),
            y_lo:
                <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
                    C::BaseField,
                >>::OtherAcvmType::<C>::from(y_lo),
            y_hi:
                <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
                    C::BaseField,
                >>::OtherAcvmType::<C>::from(y_hi),
            z_1:
                <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
                    C::BaseField,
                >>::OtherAcvmType::<C>::from(z_1),
            z_2:
                <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
                    C::BaseField,
                >>::OtherAcvmType::<C>::from(z_2),
            return_is_infinity:
               ultra_op.return_is_infinity,
        },
    ).collect_vec()
    }

    fn co_vm_operation_from_vm_operation<C: HonkCurve<TranscriptFieldType>>(
        vm_operation: VMOperation<C>,
    ) -> Vec<CoVMOperation<WitExtDriver<'static, C::BaseField, LocalNetwork>, C>> {
        let mut rng = thread_rng();
        izip!(
        share_curve_point(vm_operation.base_point.into(), &mut rng),
        share_field_element(C::BaseField::from(vm_operation.z1.clone()), &mut rng),
        share_field_element(C::BaseField::from(vm_operation.z2.clone()), &mut rng),
        share_field_element(vm_operation.mul_scalar_full, &mut rng),
    )
    .map(|(base_point, z1, z2, mul_scalar_full)| CoVMOperation {
        op_code: vm_operation.op_code.clone(),
    base_point: co_acvm::Rep3AcvmPoint::<C>::from(    base_point),
        z1: <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
            C::BaseField,
        >>::AcvmType::from(z1),
        z2: <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
            C::BaseField,
        >>::AcvmType::from(z2),
        mul_scalar_full: <co_acvm::Rep3AcvmSolver<'_, _, LocalNetwork> as co_acvm::mpc::NoirWitnessExtensionProtocol<
            C::BaseField,
        >>::OtherAcvmType::<C>::from(mul_scalar_full),
        z1_is_zero: vm_operation.z1.is_zero(),
        z2_is_zero: vm_operation.z2.is_zero(),
        base_point_is_zero: vm_operation.base_point.is_zero(),
    })
    .collect_vec()
    }

    fn ecc_op_queue_into_co_ecc_op_queue<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::BaseField>,
    >(
        queue: ECCOpQueue<C>,
    ) -> CoECCOpQueue<T, C> {
        let mut eccvm_ops_table = Vec::with_capacity(ECCVM_OPS_TABLE_SIZE);

        for (j, size) in ECCVM_OPS_SUBTABLE_SIZES.iter().enumerate() {
            let mut tmp: Vec<CoVMOperation<T, C>> = Vec::with_capacity(*size);
            for i in 0..*size {
                let vm_operation = &queue.eccvm_ops_table.table[j][i];
                let vm_op = CoVMOperation::<T, C> {
                    op_code: vm_operation.op_code.clone(),
                    base_point: T::AcvmPoint::<C>::from(vm_operation.base_point.into()),
                    z1: T::AcvmType::from(C::BaseField::from(vm_operation.z1.clone())),
                    z2: T::AcvmType::from(C::BaseField::from(vm_operation.z2.clone())),
                    mul_scalar_full: T::OtherAcvmType::from(vm_operation.mul_scalar_full),
                    z1_is_zero: vm_operation.z1.is_zero(),
                    z2_is_zero: vm_operation.z2.is_zero(),
                    base_point_is_zero: vm_operation.base_point.is_zero(),
                };
                tmp.push(vm_op);
            }
            eccvm_ops_table.push(tmp);
        }
        let eccvm_ops_table = CoEccvmOpsTable {
            table: eccvm_ops_table,
        };

        let mut ultra_ops_table = Vec::with_capacity(ULTRA_OPS_TABLE_SIZE);
        for (j, size) in ULTRA_OPS_SUBTABLE_SIZES.iter().enumerate() {
            let mut tmp: Vec<CoUltraOp<T, C>> = Vec::with_capacity(*size);
            for i in 0..*size {
                let ultra_operation = &queue.ultra_ops_table.table[j][i];
                let ultra_op = CoUltraOp::<T, C> {
                    op_code: ultra_operation.op_code.clone(),
                    x_lo: T::OtherAcvmType::from(ultra_operation.x_lo),
                    x_hi: T::OtherAcvmType::from(ultra_operation.x_hi),
                    y_lo: T::OtherAcvmType::from(ultra_operation.y_lo),
                    y_hi: T::OtherAcvmType::from(ultra_operation.y_hi),
                    z_1: T::OtherAcvmType::from(ultra_operation.z_1),
                    z_2: T::OtherAcvmType::from(ultra_operation.z_2),
                    return_is_infinity: ultra_operation.return_is_infinity,
                };
                tmp.push(ultra_op);
            }
            ultra_ops_table.push(tmp);
        }
        let ultra_ops_table = CoUltraEccOpsTable {
            table: goblin::prelude::EccOpsTable {
                table: ultra_ops_table,
            },
        };
        let accumulator = T::AcvmPoint::<C>::from(queue.accumulator.into());
        CoECCOpQueue {
            accumulator,
            eccvm_ops_table,
            ultra_ops_table,
            eccvm_ops_reconstructed: Vec::new(),
            ultra_ops_reconstructed: Vec::new(),
            eccvm_row_tracker: queue.eccvm_row_tracker,
        }
    }

    fn ecc_op_queue_into_shared_co_ecc_op_queue<C: HonkCurve<TranscriptFieldType>>(
        queue: ECCOpQueue<C>,
    ) -> [CoECCOpQueue<Rep3AcvmSolver<'static, C::BaseField, LocalNetwork>, C>; 3] {
        let mut ultra_ops_share_1 = Vec::with_capacity(ULTRA_OPS_TABLE_SIZE);
        let mut ultra_ops_share_2 = Vec::with_capacity(ULTRA_OPS_TABLE_SIZE);
        let mut ultra_ops_share_3 = Vec::with_capacity(ULTRA_OPS_TABLE_SIZE);
        for ops in queue.ultra_ops_table.table.iter() {
            let mut tmp1: Vec<_> = Vec::with_capacity(ops.len());
            let mut tmp2: Vec<_> = Vec::with_capacity(ops.len());
            let mut tmp3: Vec<_> = Vec::with_capacity(ops.len());
            for op in ops.iter() {
                let shares = co_ultra_op_from_ultra_op(op.clone());
                tmp1.push(shares[0].clone());
                tmp2.push(shares[1].clone());
                tmp3.push(shares[2].clone());
            }
            ultra_ops_share_1.push(tmp1);
            ultra_ops_share_2.push(tmp2);
            ultra_ops_share_3.push(tmp3);
        }
        let mut vm_ops_share_1 = Vec::with_capacity(ECCVM_OPS_TABLE_SIZE);
        let mut vm_ops_share_2 = Vec::with_capacity(ECCVM_OPS_TABLE_SIZE);
        let mut vm_ops_share_3 = Vec::with_capacity(ECCVM_OPS_TABLE_SIZE);
        for ops in queue.eccvm_ops_table.table.iter() {
            let mut tmp1: Vec<_> = Vec::with_capacity(ops.len());
            let mut tmp2: Vec<_> = Vec::with_capacity(ops.len());
            let mut tmp3: Vec<_> = Vec::with_capacity(ops.len());
            for op in ops.iter() {
                let shares = co_vm_operation_from_vm_operation(op.clone());
                tmp1.push(shares[0].clone());
                tmp2.push(shares[1].clone());
                tmp3.push(shares[2].clone());
            }
            vm_ops_share_1.push(tmp1);
            vm_ops_share_2.push(tmp2);
            vm_ops_share_3.push(tmp3);
        }

        let accs = share_curve_point(queue.accumulator.into(), &mut thread_rng());

        [
            CoECCOpQueue {
                accumulator: co_acvm::Rep3AcvmPoint::<C>::from(accs[0]),
                eccvm_ops_table: CoEccvmOpsTable {
                    table: vm_ops_share_1,
                },
                ultra_ops_table: CoUltraEccOpsTable {
                    table: goblin::prelude::EccOpsTable {
                        table: ultra_ops_share_1,
                    },
                },
                eccvm_ops_reconstructed: Vec::new(),
                ultra_ops_reconstructed: Vec::new(),
                eccvm_row_tracker: queue.eccvm_row_tracker.clone(),
            },
            CoECCOpQueue {
                accumulator: co_acvm::Rep3AcvmPoint::<C>::from(accs[1]),
                eccvm_ops_table: CoEccvmOpsTable {
                    table: vm_ops_share_2,
                },
                ultra_ops_table: CoUltraEccOpsTable {
                    table: goblin::prelude::EccOpsTable {
                        table: ultra_ops_share_2,
                    },
                },
                eccvm_ops_reconstructed: Vec::new(),
                ultra_ops_reconstructed: Vec::new(),
                eccvm_row_tracker: queue.eccvm_row_tracker.clone(),
            },
            CoECCOpQueue {
                accumulator: co_acvm::Rep3AcvmPoint::<C>::from(accs[2]),
                eccvm_ops_table: CoEccvmOpsTable {
                    table: vm_ops_share_3,
                },
                ultra_ops_table: CoUltraEccOpsTable {
                    table: goblin::prelude::EccOpsTable {
                        table: ultra_ops_share_3,
                    },
                },
                eccvm_ops_reconstructed: Vec::new(),
                ultra_ops_reconstructed: Vec::new(),
                eccvm_row_tracker: queue.eccvm_row_tracker,
            },
        ]
    }

    // TACEO TODO: This was tested with all the randomness set to 1 (also in bb) and then compared the proofs. By default, the ECCVM Prover has ZK enabled, so without a dedicated ECCVM Verifier it is difficult to test it. For now, you can compare it against the proof.txt in the same folder by deactivating the randomness (->F::one()) everywhere (mask() in the prover, random element in zk_data, random polys in univariate.rs and polynomial.rs)
    #[test]
    #[ignore]
    fn test_ecc_vm_prover_mpc() {
        let ecc_op_queue_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_vectors/noir/eccvm/ecc_op_queue"
        );
        const CRS_PATH_GRUMPKIN: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../co-builder/src/crs/grumpkin_g1.dat"
        );

        let path = PathBuf::from(ecc_op_queue_file);
        let queue: ECCOpQueue<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> =
            deserialize_ecc_op_queue(path);
        let co_queues = ecc_op_queue_into_shared_co_ecc_op_queue::<
            ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>,
        >(queue);
        let circuit_size = 65536;
        let prover_crs = Arc::new(
            CrsParser::<ark_grumpkin::Projective>::get_crs_g1(
                CRS_PATH_GRUMPKIN,
                circuit_size,
                ZeroKnowledge::Yes,
            )
            .unwrap(),
        );

        let nets0 = LocalNetwork::new_with_timeout(3, ark_std::time::Duration::from_secs(169));
        let nets1 = LocalNetwork::new_3_parties();
        let mut threads = Vec::with_capacity(3);

        for (net0, net1, mut queue) in
            izip!(nets0.into_iter(), nets1.into_iter(), co_queues.into_iter())
        {
            let crs = prover_crs.clone();
            let net0b = Box::leak(Box::new(net0));
            let net1b = Box::leak(Box::new(net1));

            threads.push(thread::spawn(move || {
                let mut driver = Rep3AcvmSolver::<ark_grumpkin::Fr, LocalNetwork>::new(
                    net0b,
                    net1b,
                    A2BType::default(),
                )
                .unwrap();
                let polys = construct_from_builder::<
                    short_weierstrass::Projective<GrumpkinConfig>,
                    Rep3UltraHonkDriver,
                    Rep3AcvmSolver<ark_grumpkin::Fr, LocalNetwork>,
                >(&mut queue, &mut driver)
                .unwrap();
                let mut proving_key = ProvingKey::<
                    Rep3UltraHonkDriver,
                    short_weierstrass::Projective<GrumpkinConfig>,
                    ECCVMFlavour,
                >::new(
                    circuit_size,
                    0,
                    0,
                    co_builder::prelude::PublicComponentKey::default(),
                );
                proving_key.polynomials = polys;
                let transcript = Transcript::<TranscriptFieldType, Poseidon2Sponge>::new();
                let mut state = Rep3State::new(net0b, A2BType::default()).unwrap();
                let mut prover = Eccvm::<
                    short_weierstrass::Projective<GrumpkinConfig>,
                    Poseidon2Sponge,
                    Rep3UltraHonkDriver,
                    LocalNetwork,
                >::new(net0b, &mut state);
                let (a, b) = prover
                    .construct_proof(transcript, proving_key, &crs)
                    .unwrap();
                (a, b)
            }));
        }

        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let (proofs, ipa_proofs): (Vec<_>, Vec<_>) = results.into_iter().unzip();
        let proof = proofs[0].clone();
        let ipa_proof = ipa_proofs[0].clone();
        for p in proofs.iter().skip(1) {
            assert_eq!(proof, *p);
        }
        for p in ipa_proofs.iter().skip(1) {
            assert_eq!(ipa_proof, *p);
        }
    }

    // TACEO TODO: This was tested with all the randomness set to 1 (also in bb) and then compared the proofs. By default, the ECCVM Prover has ZK enabled, so without a dedicated ECCVM Verifier it is difficult to test it. For now, you can compare it against the proof.txt in the same folder by deactivating the randomness (->F::one()) everywhere (mask() in the prover, random element in zk_data, random polys in univariate.rs and polynomial.rs)
    #[test]
    #[ignore]
    fn test_ecc_vm_prover_plaindriver() {
        let ecc_op_queue_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_vectors/noir/eccvm/ecc_op_queue"
        );
        const CRS_PATH_GRUMPKIN: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../co-builder/src/crs/grumpkin_g1.dat"
        );

        let path = PathBuf::from(ecc_op_queue_file);
        let queue: ECCOpQueue<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> =
            deserialize_ecc_op_queue(path);
        let mut co_queue = ecc_op_queue_into_co_ecc_op_queue::<
            ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>,
            PlainAcvmSolver<ark_grumpkin::Fr>,
        >(queue);
        let circuit_size = 65536;
        let prover_crs = Arc::new(
            CrsParser::<ark_grumpkin::Projective>::get_crs_g1(
                CRS_PATH_GRUMPKIN,
                circuit_size,
                ZeroKnowledge::Yes,
            )
            .unwrap(),
        );
        let mut driver = PlainAcvmSolver::new();
        let polys = construct_from_builder::<
            short_weierstrass::Projective<GrumpkinConfig>,
            PlainUltraHonkDriver,
            PlainAcvmSolver<ark_grumpkin::Fr>,
        >(&mut co_queue, &mut driver)
        .unwrap();
        let mut proving_key = ProvingKey::<
            PlainUltraHonkDriver,
            short_weierstrass::Projective<GrumpkinConfig>,
            ECCVMFlavour,
        >::new(
            circuit_size,
            0,
            0,
            co_builder::prelude::PublicComponentKey::default(),
        );
        proving_key.polynomials = polys;

        let transcript = Transcript::<TranscriptFieldType, Poseidon2Sponge>::new();

        let mut binding = ();
        let mut prover = Eccvm::<
            short_weierstrass::Projective<GrumpkinConfig>,
            Poseidon2Sponge,
            PlainUltraHonkDriver,
            _,
        >::new(&(), &mut binding);
        let (_transcript, _ipa_transcript) = prover
            .construct_proof(transcript, proving_key, &prover_crs)
            .unwrap();
    }
}
