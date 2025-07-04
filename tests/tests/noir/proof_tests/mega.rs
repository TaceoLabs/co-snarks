use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use acir::native_types::{WitnessMap, WitnessStack};
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use co_acvm::{solver::Rep3CoSolver, Rep3AcvmType};
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::prover_flavour::ProverFlavour;
use co_builder::{
    flavours::{mega_flavour::MegaFlavour, ultra_flavour::UltraFlavour},
    TranscriptFieldType,
};
use co_noir::Pairing;
use co_noir::VerifyingKey;
use co_ultrahonk::prelude::{
    CrsParser, MPCProverFlavour, PlainUltraHonkDriver, Poseidon2Sponge, ProvingKey,
    Rep3CoUltraHonk, Rep3UltraHonkDriver, TranscriptHasher, UltraHonk, Utils, ZeroKnowledge,
};
use itertools::izip;
use mpc_core::protocols::rep3;
use mpc_core::protocols::rep3::network::Rep3Network;
use rand::{CryptoRng, Rng};
use sha3::Keccak256;
use std::{fs::File, io::BufReader, sync::Arc, thread};
use tests::rep3_network::Rep3TestNetwork;

pub use co_ultrahonk::prelude::PlainProvingKey;

fn witness_map_to_witness_vector<F: PrimeField>(
    witness_map: WitnessMap<Rep3AcvmType<F>>,
) -> Vec<Rep3AcvmType<F>> {
    let mut wv = Vec::new();
    let mut index = 0;
    for (w, f) in witness_map.into_iter() {
        // ACIR uses a sparse format for WitnessMap where unused witness indices may be left unassigned.
        // To ensure that witnesses sit at the correct indices in the `WitnessVector`, we fill any indices
        // which do not exist within the `WitnessMap` with the dummy value of zero.
        while index < w.0 {
            wv.push(Rep3AcvmType::from(F::zero()));
            index += 1;
        }

        wv.push(f);
        index += 1;
    }
    wv
}

pub fn split_plain_proving_key_rep3<
    P: Pairing,
    R: Rng + CryptoRng,
    N: Rep3Network,
    L: MPCProverFlavour,
>(
    proving_key: PlainProvingKey<P, L>,
    rng: &mut R,
) -> eyre::Result<[ProvingKey<Rep3UltraHonkDriver<N>, P, L>; 3]> {
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
            ProvingKey::<Rep3UltraHonkDriver<N>, P, L>::from_plain_key_and_shares(
                &proving_key,
                share,
            )
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    // the original shares above are of type [T; 3], we just collect the into a vec to
    // create the `Rep3ProvingKey` type, if that does not fail, we are guaranteed to have 3 elements
    let share2 = shares.pop().unwrap();
    let share1 = shares.pop().unwrap();
    let share0 = shares.pop().unwrap();

    Ok([share0, share1, share2])
}

fn convert_witness_rep3<F: PrimeField>(
    mut witness_stack: WitnessStack<Rep3AcvmType<F>>,
) -> Vec<Rep3AcvmType<F>> {
    let witness_map = witness_stack
        .pop()
        .expect("Witness should be present")
        .witness;
    witness_map_to_witness_vector(witness_map)
}

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(has_zk: ZeroKnowledge) {
    let proving_key_file = format!("../test_vectors/noir/mega/serialized_proving_key");

    let proving_key_file = BufReader::new(File::open(proving_key_file).unwrap());

    let proving_key: ProvingKey<PlainUltraHonkDriver, Bn254, MegaFlavour> =
        bincode::deserialize_from(proving_key_file).unwrap();
    let dyadic_circuit_size = proving_key.circuit_size.next_power_of_two();
    let prover_crs =
        CrsParser::<Bn254>::get_crs_g1(CRS_PATH_G1, dyadic_circuit_size as usize, has_zk).unwrap();
    let proving_key = co_ultrahonk::key::proving_key::from_test_to::<_, MegaFlavour>(
        proving_key,
        prover_crs.clone(),
    );

    let test_network = Rep3TestNetwork::default();
    let mut threads = Vec::with_capacity(3);
    let pk_shares = split_plain_proving_key_rep3(proving_key, &mut rand::thread_rng())
        .expect("Failed to split proving key");

    for (net, pk_) in izip!(test_network.get_party_networks(), pk_shares) {
        let prover_crs = prover_crs.clone();
        threads.push(thread::spawn(move || {
            // generate proving key and vk

            let (proof, public_input, _) =
                Rep3CoUltraHonk::<_, _, H, MegaFlavour>::prove(net, pk_, &prover_crs, has_zk)
                    .unwrap();
            (proof, public_input)
        }));
    }

    let mut commitments =
        <MegaFlavour as ProverFlavour>::PrecomputedEntities::<ark_bn254::G1Affine>::default();

    let proving_key_file = format!("../test_vectors/noir/mega/serialized_proving_key");

    let proving_key_file = BufReader::new(File::open(proving_key_file).unwrap());

    let proving_key: ProvingKey<PlainUltraHonkDriver, Bn254, MegaFlavour> =
        bincode::deserialize_from(proving_key_file).unwrap();
    let dyadic_circuit_size = Utils::get_msb64(proving_key.circuit_size as u64);
    let prover_crs =
        CrsParser::<Bn254>::get_crs_g1(CRS_PATH_G1, dyadic_circuit_size as usize, has_zk).unwrap();
    let proving_key = co_ultrahonk::key::proving_key::from_test_to::<_, MegaFlavour>(
        proving_key,
        prover_crs.clone(),
    );

    for (des, src) in commitments
        .iter_mut()
        .zip(proving_key.polynomials.precomputed.iter())
    {
        let comm = Utils::commit(src.as_ref(), &proving_key.crs).unwrap();
        *des = ark_bn254::G1Affine::from(comm);
    }

    let verifier_crs = CrsParser::<Bn254>::get_crs_g2(CRS_PATH_G2).unwrap();
    // Create and return the VerifyingKey instance
    let verifying_key = VerifyingKey::<Bn254, MegaFlavour> {
        crs: verifier_crs,
        circuit_size: proving_key.circuit_size,
        num_public_inputs: proving_key.num_public_inputs,
        pub_inputs_offset: proving_key.pub_inputs_offset,
        commitments,
        pairing_inputs_public_input_key: proving_key.pairing_inputs_public_input_key,
    };

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
fn mega_proof_test() {
    proof_test::<Poseidon2Sponge>(ZeroKnowledge::No);
}
