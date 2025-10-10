use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::Bn254;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::prover_flavour::ProverFlavour;
use co_noir::Bn254G1;
use co_noir::HonkProof;
use co_noir::VerifyingKey;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::plain::PlainUltraHonkDriver;
use co_noir_common::mpc::rep3::Rep3UltraHonkDriver;
use co_noir_common::transcript::Poseidon2Sponge;
use co_noir_common::transcript::TranscriptHasher;
use co_noir_common::types::ZeroKnowledge;
pub use co_ultrahonk::prelude::PlainProvingKey;
use co_ultrahonk::prelude::{MPCProverFlavour, ProvingKey, Rep3CoUltraHonk, UltraHonk, Utils};
use itertools::izip;
use mpc_core::protocols::rep3;
use mpc_net::local::LocalNetwork;
use rand::{CryptoRng, Rng};
use std::{fs::File, io::BufReader, thread};

pub fn split_plain_proving_key_rep3<
    P: CurveGroup<BaseField: PrimeField>,
    R: Rng + CryptoRng,
    L: MPCProverFlavour,
>(
    proving_key: PlainProvingKey<P, L>,
    rng: &mut R,
) -> eyre::Result<[ProvingKey<Rep3UltraHonkDriver, P, L>; 3]> {
    let witness_entities = proving_key
        .polynomials
        .witness
        .iter()
        .flat_map(|el| el.iter().cloned())
        .collect::<Vec<_>>();

    let shares = rep3::share_field_elements(&witness_entities, rng);

    let mut shares = shares
        .into_iter()
        .map(|share| {
            ProvingKey::<Rep3UltraHonkDriver, P, L>::from_plain_key_and_shares(&proving_key, share)
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    // the original shares above are of type [T; 3], we just collect the into a vec to
    // create the `Rep3ProvingKey` type, if that does not fail, we are guaranteed to have 3 elements
    let share2 = shares.pop().unwrap();
    let share1 = shares.pop().unwrap();
    let share0 = shares.pop().unwrap();

    Ok([share0, share1, share2])
}

fn proof_test_rep3<H: TranscriptHasher<TranscriptFieldType>>(
    proving_key_file: &str,
    has_zk: ZeroKnowledge,
) {
    let proving_key_file = BufReader::new(File::open(proving_key_file).unwrap());

    let proving_key: ProvingKey<PlainUltraHonkDriver, Bn254G1, MegaFlavour> =
        bincode::deserialize_from(proving_key_file).unwrap();
    let dyadic_circuit_size = proving_key.circuit_size.next_power_of_two();
    let prover_crs =
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g1(
            CRS_PATH_G1,
            dyadic_circuit_size as usize,
            has_zk,
        )
        .unwrap();
    let proving_key = co_ultrahonk::key::proving_key::to_plain_pk::<_, MegaFlavour>(
        proving_key,
        prover_crs.clone(),
    );

    let mut commitments =
        <MegaFlavour as ProverFlavour>::PrecomputedEntities::<ark_bn254::G1Affine>::default();

    for (des, src) in commitments
        .iter_mut()
        .zip(proving_key.polynomials.precomputed.iter())
    {
        let comm = Utils::commit(src.as_ref(), &proving_key.crs).unwrap();
        *des = ark_bn254::G1Affine::from(comm);
    }

    let verifier_crs =
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g2::<
            Bn254,
        >(CRS_PATH_G2)
        .unwrap();
    // Create and return the VerifyingKey instance
    let verifying_key = VerifyingKey::<Bn254, MegaFlavour> {
        crs: verifier_crs,
        circuit_size: proving_key.circuit_size,
        num_public_inputs: proving_key.num_public_inputs,
        pub_inputs_offset: proving_key.pub_inputs_offset,
        commitments,
        pairing_inputs_public_input_key: proving_key.pairing_inputs_public_input_key,
    };

    let nets0 = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let pk_shares = split_plain_proving_key_rep3(proving_key, &mut rand::thread_rng())
        .expect("Failed to split proving key");

    for (net0, pk_) in izip!(nets0.into_iter(), pk_shares) {
        let prover_crs = prover_crs.clone();
        threads.push(thread::spawn(move || {
            // generate proving key and vk

            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H, MegaFlavour>::prove(&net0, pk_, &prover_crs, has_zk)
                    .unwrap();
            (proof, public_input)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let mut proofs = results
        .iter()
        .map(|(proof, _)| proof.to_owned())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let mut public_inputs = results
        .iter()
        .map(|(_, public_input)| public_input.to_owned())
        .collect::<Vec<_>>();
    let public_input = public_inputs.pop().unwrap();
    for p in public_inputs {
        assert_eq!(public_input, p);
    }

    let is_valid =
        UltraHonk::<_, H, MegaFlavour>::verify(proof, &public_input, &verifying_key, has_zk)
            .unwrap();
    assert!(is_valid);
}

#[test]
#[ignore] // This test is ignored because it requires a proving key file from lfs
fn mega_proof_test() {
    const PROVING_KEY: &str = "../test_vectors/noir/mega/serialized_proving_key";
    proof_test_rep3::<Poseidon2Sponge>(PROVING_KEY, ZeroKnowledge::No);
    proof_test_rep3::<Poseidon2Sponge>(PROVING_KEY, ZeroKnowledge::Yes);
}

// This is not the PlainDriver (in co-ultrahonk), but the plain implementation (in ultrahonk).
fn plain_test<H: TranscriptHasher<TranscriptFieldType>>(
    proving_key_file: &str,
    proof_file: &str,
    has_zk: ZeroKnowledge,
) {
    let proving_key_file = BufReader::new(File::open(proving_key_file).unwrap());
    let proving_key: ProvingKey<PlainUltraHonkDriver, Bn254G1, MegaFlavour> =
        bincode::deserialize_from(proving_key_file).unwrap();
    let dyadic_circuit_size = proving_key.circuit_size.next_power_of_two();
    let prover_crs =
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g1(
            CRS_PATH_G1,
            dyadic_circuit_size as usize,
            has_zk,
        )
        .unwrap();
    let proving_key = co_ultrahonk::key::proving_key::to_plain_pk::<_, MegaFlavour>(
        proving_key,
        prover_crs.clone(),
    );
    let mut commitments =
        <MegaFlavour as ProverFlavour>::PrecomputedEntities::<ark_bn254::G1Affine>::default();
    for (des, src) in commitments
        .iter_mut()
        .zip(proving_key.polynomials.precomputed.iter())
    {
        let comm = Utils::commit(src.as_ref(), &proving_key.crs).unwrap();
        *des = ark_bn254::G1Affine::from(comm);
    }

    let verifier_crs =
        CrsParser::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>::get_crs_g2::<
            Bn254,
        >(CRS_PATH_G2)
        .unwrap();
    // Create and return the VerifyingKey instance
    let verifying_key = VerifyingKey::<Bn254, MegaFlavour> {
        crs: verifier_crs,
        circuit_size: proving_key.circuit_size,
        num_public_inputs: proving_key.num_public_inputs,
        pub_inputs_offset: proving_key.pub_inputs_offset,
        commitments,
        pairing_inputs_public_input_key: proving_key.pairing_inputs_public_input_key,
    };

    let (proof, public_inputs) =
        UltraHonk::<_, H, MegaFlavour>::prove(proving_key, has_zk).unwrap();
    if has_zk == ZeroKnowledge::No {
        let proof_u8 = proof.to_buffer();
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::from_buffer(&read_proof_u8).unwrap();
        assert_eq!(proof, read_proof);
    }

    let is_valid =
        UltraHonk::<_, H, MegaFlavour>::verify(proof, &public_inputs, &verifying_key, has_zk)
            .unwrap();
    assert!(is_valid);
}

#[test]
#[ignore] // This test is ignored because it requires a proving key file from lfs
fn mega_plain_test() {
    const PROVING_KEY: &str = "../test_vectors/noir/mega/serialized_proving_key";
    const PROOF_FILE: &str = "../test_vectors/noir/mega/proof";

    plain_test::<Poseidon2Sponge>(PROVING_KEY, PROOF_FILE, ZeroKnowledge::No);
    plain_test::<Poseidon2Sponge>(PROVING_KEY, PROOF_FILE, ZeroKnowledge::Yes);
}
