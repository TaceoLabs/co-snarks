use ark_ec::AffineRepr;
use ark_ec::short_weierstrass;
use ark_grumpkin::GrumpkinConfig;
use co_builder::eccvm::ecc_op_queue::ECCOpQueue;
use co_builder::eccvm::ecc_op_queue::EccOpCode;
use co_builder::eccvm::ecc_op_queue::EccvmOpsTable;
use co_builder::eccvm::ecc_op_queue::EccvmRowTracker;
use co_builder::eccvm::ecc_op_queue::UltraEccOpsTable;
use co_builder::eccvm::ecc_op_queue::UltraOp;
use co_builder::eccvm::ecc_op_queue::VMOperation;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::plain::PlainUltraHonkDriver;
use co_noir_common::serialize::SerializeP;
use co_noir_common::transcript::Poseidon2Sponge;
use co_noir_common::transcript::Transcript;
use co_noir_common::types::ZeroKnowledge;
use goblin::eccvm::eccvm_prover::Eccvm;
use goblin::eccvm::eccvm_types::construct_from_builder;
use goblin::prelude::Translator;
use goblin::prelude::TranslatorBuilder;
use goblin::prelude::construct_pk_from_builder;
use noir_types::SerializeF;
use std::str::FromStr;
use std::{path::PathBuf, sync::Arc};
use ultrahonk::prelude::ProvingKey;

// The input for this is extracted from barretenberg into bytes (see test_vectors/noir/eccvm for a text file on how the ecc_op_queue was serialized in bb)
fn deserialize_ecc_op_queue<P: HonkCurve<TranscriptFieldType>>(path: PathBuf) -> ECCOpQueue<P> {
    const ECCVM_OPS_TABLE_SIZE: usize = 15;
    const ECCVM_OPS_SUBTABLE_SIZES: [usize; ECCVM_OPS_TABLE_SIZE] =
        [292, 196, 196, 396, 2, 396, 2, 396, 2, 396, 2, 396, 2, 28, 2];
    const ULTRA_OPS_TABLE_SIZE: usize = 15;
    const ULTRA_OPS_SUBTABLE_SIZES: [usize; ULTRA_OPS_TABLE_SIZE] =
        [293, 196, 196, 396, 2, 396, 2, 396, 2, 396, 2, 396, 2, 28, 2];
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

// TACEO TODO: This was tested with all the randomness set to 1 (also in bb) and then compared the proofs. By default, the ECCVM Prover has ZK enabled, so without a dedicated ECCVM Verifier it is difficult to test it. For now, you can compare it against the proof.txt in the same folder by deactivating the randomness (->F::one()) everywhere (deactivating mask() in the prover, random element in zk_data, random polys in univariate.rs and polynomial.rs)
#[test]
#[ignore]
fn test_ecc_vm_prover() {
    let ecc_op_queue_file = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test_vectors/noir/eccvm/ecc_op_queue"
    );
    const CRS_PATH_GRUMPKIN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../co-builder/src/crs/grumpkin_g1.dat"
    );

    let path = PathBuf::from(ecc_op_queue_file);
    let mut queue: ECCOpQueue<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> =
        deserialize_ecc_op_queue(path);
    let circuit_size = 65536;
    let prover_crs = Arc::new(
        CrsParser::<ark_grumpkin::Projective>::get_crs_g1(
            CRS_PATH_GRUMPKIN,
            circuit_size,
            ZeroKnowledge::Yes,
        )
        .unwrap(),
    );
    let polys = construct_from_builder::<short_weierstrass::Projective<GrumpkinConfig>>(&mut queue);
    let mut proving_key =
        ProvingKey::<short_weierstrass::Projective<GrumpkinConfig>, ECCVMFlavour>::new(
            circuit_size,
            0,
            prover_crs,
            0,
        );
    proving_key.polynomials = polys;

    let mut transcript = Transcript::<
        TranscriptFieldType,
        Poseidon2Sponge,
        PlainUltraHonkDriver,
        short_weierstrass::Projective<GrumpkinConfig>,
    >::new();

    let mut prover =
        Eccvm::<short_weierstrass::Projective<GrumpkinConfig>, Poseidon2Sponge>::default();
    let _ipa_transcript = prover
        .construct_proof(&mut transcript, proving_key)
        .unwrap();
    let _proof = transcript.get_proof();
}

// TACEO TODO: The setting (regarding randomness) is the same as for the ECCVM prover test, except that the polynomials in the oink style part don't get masked here.
#[test]
#[ignore]
fn test_translator_prover() {
    let ecc_op_queue_file = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test_vectors/noir/eccvm/ecc_op_queue"
    );
    let transcript_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test_vectors/noir/translator/transcript"
    );
    const CRS_PATH_G1: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../co-builder/src/crs/bn254_g1.dat"
    );
    let path = PathBuf::from(ecc_op_queue_file);
    let mut queue: ECCOpQueue<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> =
        deserialize_ecc_op_queue(path);
    // We need to do this as the ecc_op_queue is necessary for the translator builder and gets modified in there
    // TACEO TODO: find a nicer way to do this
    let _ = construct_from_builder::<short_weierstrass::Projective<GrumpkinConfig>>(&mut queue);

    let transcript = std::io::BufReader::new(std::fs::File::open(transcript_path).unwrap());
    let transcript: Transcript<
        TranscriptFieldType,
        Poseidon2Sponge,
        PlainUltraHonkDriver,
        ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>,
    > = bincode::deserialize_from(transcript).unwrap();

    let translation_batching_challenge_v =
        ark_bn254::Fq::from_str("333310174131141305725676434666258450925").unwrap();
    let evaluation_challenge_x =
        ark_bn254::Fq::from_str("17211194955796430769589779325535368928").unwrap();
    let mut translator_builder =
        TranslatorBuilder::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::new();
    translator_builder.feed_ecc_op_queue_into_circuit(
        translation_batching_challenge_v,
        evaluation_challenge_x,
        &mut queue,
    );
    let polys = construct_pk_from_builder::<
        ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>,
    >(translator_builder);
    let circuit_size = 1 << TranslatorFlavour::CONST_TRANSLATOR_LOG_N;
    let prover_crs = Arc::new(
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g1(
            CRS_PATH_G1,
            circuit_size,
            ZeroKnowledge::Yes,
        )
        .unwrap(),
    );
    let mut proving_key = ProvingKey::<
        ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>,
        TranslatorFlavour,
    >::new(circuit_size, 0, prover_crs, 0);
    proving_key.polynomials = polys;
    let mut prover = Translator::<
        short_weierstrass::Projective<ark_bn254::g1::Config>,
        Poseidon2Sponge,
    >::new(translation_batching_challenge_v, evaluation_challenge_x);
    let _proof = prover.construct_proof(transcript, proving_key).unwrap();
}
