//! # CoNoir:

use acir::{
    FieldElement,
    acir_field::GenericFieldElement,
    native_types::{WitnessMap, WitnessStack},
};
use ark_ff::PrimeField;
use co_acvm::pss_store::PssStore;
use co_acvm::{
    PlainAcvmSolver, Rep3AcvmSolver, ShamirAcvmSolver,
    solver::{Rep3CoSolver, partial_abi::PublicMarker},
};
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::prover_flavour::ProverFlavour;
use co_builder::{TranscriptFieldType, flavours::ultra_flavour::UltraFlavour};
use co_ultrahonk::prelude::{HonkCurve, ProverCrs};
use color_eyre::eyre::{self, Context, Result};
use mpc_core::protocols::{
    rep3::{self, conversion::A2BType, id::PartyID},
    shamir::{self, ShamirPreprocessing, ShamirPrimeFieldShare, ShamirState},
};

use mpc_net::Network;
use noirc_abi::Abi;
use noirc_artifacts::program::ProgramArtifact;
use rand::{CryptoRng, Rng};
use std::{array, collections::BTreeMap, fs::File, io::Write, path::Path, sync::Arc};

pub use ark_bn254::Bn254;
pub use ark_ec::pairing::Pairing;
pub use co_acvm::{Rep3AcvmType, ShamirAcvmType};
pub use co_ultrahonk::{
    Rep3CoBuilder, ShamirCoBuilder,
    prelude::{
        AcirFormat, CrsParser, HonkRecursion, PlainProvingKey, Polynomial, Polynomials,
        Rep3CoUltraHonk, Rep3ProvingKey, ShamirCoUltraHonk, ShamirProvingKey, UltraCircuitBuilder,
        UltraHonk, VerifyingKey, VerifyingKeyBarretenberg,
    },
};
pub use sha3::Keccak256;

#[derive(Clone, Debug)]
pub enum PubShared<F: Clone> {
    Public(F),
    Shared(F),
}

impl<F: Clone> PubShared<F> {
    pub fn from_shared(f: F) -> Self {
        Self::Shared(f)
    }

    pub fn set_public(&mut self) {
        if let Self::Shared(f) = self {
            *self = Self::Public(f.clone());
        }
    }
}

pub fn parse_input(
    input_path: impl AsRef<Path>,
    program: &ProgramArtifact,
) -> eyre::Result<BTreeMap<String, PublicMarker<FieldElement>>> {
    Rep3CoSolver::<_, ()>::partially_read_abi_bn254_fieldelement(
        input_path,
        &program.abi,
        &program.bytecode,
    )
}

/// Split a witness into REP3 shares
pub fn split_witness_rep3<F: PrimeField, R: Rng + CryptoRng>(
    witness: Vec<PubShared<F>>,
    rng: &mut R,
) -> [Vec<Rep3AcvmType<F>>; 3] {
    let mut res = array::from_fn(|_| Vec::with_capacity(witness.len()));

    for witness in witness {
        match witness {
            PubShared::Public(f) => {
                for r in res.iter_mut() {
                    r.push(Rep3AcvmType::from(f));
                }
            }
            PubShared::Shared(f) => {
                let shares = rep3::share_field_element(f, rng);
                for (r, share) in res.iter_mut().zip(shares) {
                    r.push(Rep3AcvmType::from(share));
                }
            }
        }
    }
    res
}

/// Split a witness into shamir shares
pub fn split_witness_shamir<F: PrimeField, R: Rng + CryptoRng>(
    witness: Vec<PubShared<F>>,
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Vec<Vec<ShamirAcvmType<F>>> {
    let mut res = (0..num_parties)
        .map(|_| Vec::with_capacity(witness.len()))
        .collect::<Vec<_>>();

    for witness in witness {
        match witness {
            PubShared::Public(f) => {
                for r in res.iter_mut() {
                    r.push(ShamirAcvmType::from(f));
                }
            }
            PubShared::Shared(f) => {
                let shares = shamir::share_field_element(f, degree, num_parties, rng);
                for (r, share) in res.iter_mut().zip(shares) {
                    r.push(ShamirAcvmType::from(share));
                }
            }
        }
    }
    res
}

#[allow(clippy::type_complexity)]
/// Executes the noir circuit with REP3 protocol
pub fn execute_circuit_rep3<'a, N: Network>(
    input_share: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>,
    compiled_program: ProgramArtifact,
    net0: &'a N,
    net1: &'a N,
) -> Result<(
    Vec<Rep3AcvmType<ark_bn254::Fr>>,
    PssStore<Rep3AcvmSolver<'a, ark_bn254::Fr, N>, ark_bn254::Fr>,
)> {
    let input_share = witness_to_witness_map(input_share, &compiled_program.abi)?;

    // init MPC protocol
    let rep3_vm = Rep3CoSolver::new_with_witness(net0, net1, compiled_program, input_share)
        .context("while creating VM")?;

    // execute witness generation in MPC
    let (result_witness_share, value_store) = rep3_vm
        .solve_with_output()
        .context("while running witness generation")?;

    Ok((witness_stack_to_vec_rep3(result_witness_share), value_store))
}

/// Generate a witness from REP3 input shares
pub fn generate_witness_rep3<N: Network>(
    input_share: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>,
    compiled_program: ProgramArtifact,
    net0: &N,
    net1: &N,
) -> Result<Vec<Rep3AcvmType<ark_bn254::Fr>>> {
    let (witness_stack, _) = execute_circuit_rep3(input_share, compiled_program, net0, net1)?;
    Ok(witness_stack)
}

/// Translate a REP3 shared witness to a shamir shared witness
pub fn translate_witness<P: Pairing>(
    witness_share: Vec<Rep3AcvmType<P::ScalarField>>,
    id: PartyID,
) -> Vec<ShamirAcvmType<P::ScalarField>> {
    // extract shares only
    let mut shares = vec![];
    for share in witness_share.iter() {
        if let Rep3AcvmType::Shared(value) = share {
            shares.push(value.to_owned());
        }
    }

    // Translate witness to shamir shares
    let translated_shares = ShamirState::translate_primefield_repshare_vec(shares, id);

    let mut result = Vec::with_capacity(witness_share.len());
    let mut iter = translated_shares.into_iter();
    for val in witness_share.into_iter() {
        match val {
            Rep3AcvmType::Public(value) => result.push(ShamirAcvmType::Public(value)),
            Rep3AcvmType::Shared(_) => {
                let share = iter.next().expect("enough shares");
                result.push(ShamirAcvmType::Shared(share))
            }
        }
    }
    result
}

type ShamirProverWitnessEntities<T> =
    <UltraFlavour as ProverFlavour>::ProverWitnessEntities<Polynomial<ShamirPrimeFieldShare<T>>>;

/// Translate a REP3 shared proving key to a shamir shared proving key
#[allow(clippy::complexity)]
pub fn translate_proving_key<P: Pairing>(
    proving_key: Rep3ProvingKey<P, UltraFlavour>,
    id: PartyID,
) -> Result<ShamirProvingKey<P, UltraFlavour>> {
    // extract shares
    let shares = proving_key
        .polynomials
        .witness
        .into_iter()
        .flat_map(|el| el.into_vec().into_iter())
        .collect::<Vec<_>>();

    // Translate witness to shamir shares
    let translated_shares = ShamirState::translate_primefield_repshare_vec(shares, id);

    if translated_shares.len()
        != UltraFlavour::PROVER_WITNESS_ENTITIES_SIZE * proving_key.circuit_size as usize
    {
        eyre::bail!("Invalid number of shares translated");
    };

    let mut chunks = translated_shares.chunks_exact(proving_key.circuit_size as usize);
    let translated_shares = array::from_fn(|_| {
        Polynomial::new(chunks.next().expect("Length already checked").to_vec())
    });

    let polynomials = Polynomials {
        witness: ShamirProverWitnessEntities::<_> {
            elements: translated_shares,
        },
        precomputed: proving_key.polynomials.precomputed,
    };
    let result = ShamirProvingKey {
        polynomials,
        circuit_size: proving_key.circuit_size,
        public_inputs: proving_key.public_inputs,
        num_public_inputs: proving_key.num_public_inputs,
        pub_inputs_offset: proving_key.pub_inputs_offset,
        memory_read_records: proving_key.memory_read_records,
        memory_write_records: proving_key.memory_write_records,
        memory_records_shared: BTreeMap::new(),
        final_active_wire_idx: proving_key.final_active_wire_idx,
        phantom: std::marker::PhantomData,
        active_region_data: proving_key.active_region_data,
        pairing_inputs_public_input_key: proving_key.pairing_inputs_public_input_key,
    };

    Ok(result)
}

/// Compute the circuit size that is needed to load the prover crs
pub fn compute_circuit_size<P: HonkCurve<TranscriptFieldType>>(
    constraint_system: &AcirFormat<P::ScalarField>,
    recursive: bool,
) -> Result<usize> {
    UltraCircuitBuilder::<P>::circuit_size(
        constraint_system,
        recursive,
        0,
        HonkRecursion::UltraHonk,
        &mut PlainAcvmSolver::new(),
    )
}

/// Generate a REP3 shared proving key
pub fn generate_proving_key_rep3<N: Network>(
    constraint_system: &AcirFormat<ark_bn254::Fr>,
    witness_share: Vec<Rep3AcvmType<ark_bn254::Fr>>,
    recursive: bool,
    net0: &N,
    net1: &N,
) -> Result<Rep3ProvingKey<Bn254, UltraFlavour>> {
    let id = PartyID::try_from(net0.id())?;
    let mut driver = Rep3AcvmSolver::new(net0, net1, A2BType::default())?;
    // create the circuit
    let builder = Rep3CoBuilder::create_circuit(
        constraint_system,
        recursive,
        0,
        witness_share,
        HonkRecursion::UltraHonk,
        &mut driver,
    )?;
    // generate pk
    Ok(Rep3ProvingKey::create(id, builder, &mut driver)?)
}

/// Generate a shamir shared proving key
#[allow(clippy::complexity)]
pub fn generate_proving_key_shamir<N: Network>(
    num_parties: usize,
    threshold: usize,
    constraint_system: &AcirFormat<ark_bn254::Fr>,
    witness_share: Vec<ShamirAcvmType<ark_bn254::Fr>>,
    recursive: bool,
    net: &N,
) -> Result<ShamirProvingKey<Bn254, UltraFlavour>> {
    let id = net.id();
    // We have to handle precomputation on the fly, so amount is 0 initially
    let preprocessing = ShamirPreprocessing::new(num_parties, threshold, 0, net)?;
    let state = ShamirState::from(preprocessing);
    let mut driver = ShamirAcvmSolver::new(net, state);
    // create the circuit
    let builder = ShamirCoBuilder::create_circuit(
        constraint_system,
        recursive,
        0,
        witness_share,
        HonkRecursion::UltraHonk,
        &mut driver,
    )?;
    // generate pk
    Ok(ShamirProvingKey::create(id, builder, &mut driver)?)
}

/// Generate a plain proving key
pub fn generate_proving_key_plain<P: HonkCurve<TranscriptFieldType>>(
    constraint_system: &AcirFormat<P::ScalarField>,
    witness: Vec<P::ScalarField>,
    prover_crs: Arc<ProverCrs<P>>,
    recursive: bool,
) -> Result<PlainProvingKey<P, UltraFlavour>> {
    let mut driver = PlainAcvmSolver::new();
    let builder = UltraCircuitBuilder::create_circuit(
        constraint_system,
        recursive,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &mut driver,
    )?;
    Ok(PlainProvingKey::create::<PlainAcvmSolver<_>>(
        builder,
        prover_crs,
        &mut driver,
    )?)
}

/// Generate a verification key
pub fn generate_vk<P: HonkCurve<TranscriptFieldType>>(
    constraint_system: &AcirFormat<P::ScalarField>,
    prover_crs: Arc<ProverCrs<P>>,
    verifier_crs: P::G2Affine,
    recursive: bool,
) -> Result<VerifyingKey<P, UltraFlavour>> {
    let mut driver = PlainAcvmSolver::new();
    let circuit = UltraCircuitBuilder::<P>::create_circuit(
        constraint_system,
        recursive,
        0,
        vec![],
        HonkRecursion::UltraHonk,
        &mut driver,
    )?;

    Ok(VerifyingKey::create(
        circuit,
        prover_crs,
        verifier_crs,
        &mut driver,
    )?)
}

/// Generate a barretenberg verification key
pub fn generate_vk_barretenberg<P: HonkCurve<TranscriptFieldType>>(
    constraint_system: &AcirFormat<P::ScalarField>,
    prover_crs: Arc<ProverCrs<P>>,
    recursive: bool,
) -> Result<VerifyingKeyBarretenberg<P, UltraFlavour>> {
    let mut driver = PlainAcvmSolver::new();
    let circuit = UltraCircuitBuilder::create_circuit(
        constraint_system,
        recursive,
        0,
        vec![],
        HonkRecursion::UltraHonk,
        &mut driver,
    )?;
    Ok(circuit.create_vk_barretenberg(prover_crs, &mut driver)?)
}

/// Split a proving key into RPE3 shares
pub fn split_proving_key_rep3<P: Pairing, R: Rng + CryptoRng>(
    proving_key: PlainProvingKey<P, UltraFlavour>,
    rng: &mut R,
) -> Result<[Rep3ProvingKey<P, UltraFlavour>; 3]> {
    let witness_entities = proving_key
        .polynomials
        .witness
        .iter()
        .flat_map(|el| el.iter().cloned())
        .collect::<Vec<_>>();

    let shares = rep3::share_field_elements(&witness_entities, rng);

    let mut shares = shares
        .into_iter()
        .map(|share| Rep3ProvingKey::from_plain_key_and_shares(&proving_key, share))
        .collect::<Result<Vec<_>>>()?;
    // the original shares above are of type [T; 3], we just collect the into a vec to
    // create the `Rep3ProvingKey` type, if that does not fail, we are guaranteed to have 3 elements
    let share2 = shares.pop().unwrap();
    let share1 = shares.pop().unwrap();
    let share0 = shares.pop().unwrap();

    Ok([share0, share1, share2])
}

/// Split a proving key into shamir shares
pub fn split_proving_key_shamir<P: Pairing, R: Rng + CryptoRng>(
    proving_key: PlainProvingKey<P, UltraFlavour>,
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Result<Vec<ShamirProvingKey<P, UltraFlavour>>> {
    let witness_entities = proving_key
        .polynomials
        .witness
        .iter()
        .flat_map(|el| el.iter().cloned())
        .collect::<Vec<_>>();

    let shares = shamir::share_field_elements(&witness_entities, degree, num_parties, rng);

    shares
        .into_iter()
        .map(|share| ShamirProvingKey::from_plain_key_and_shares(&proving_key, share))
        .collect::<Result<Vec<_>>>()
}

/// Split input into REP3 shares
pub fn split_input_rep3<P: Pairing, R: Rng + CryptoRng>(
    initial_witness: BTreeMap<String, PublicMarker<GenericFieldElement<P::ScalarField>>>,
    rng: &mut R,
) -> [BTreeMap<String, Rep3AcvmType<P::ScalarField>>; 3] {
    let mut witnesses = array::from_fn(|_| BTreeMap::default());
    for (witness, v) in initial_witness.into_iter() {
        match v {
            PublicMarker::Public(v) => {
                for w in witnesses.iter_mut() {
                    w.insert(witness.to_owned(), Rep3AcvmType::Public(v.into_repr()));
                }
            }
            PublicMarker::Private(v) => {
                let shares = rep3::share_field_element(v.into_repr(), rng);
                for (w, share) in witnesses.iter_mut().zip(shares) {
                    w.insert(witness.clone(), Rep3AcvmType::Shared(share));
                }
            }
        }
    }

    witnesses
}

/// Merge multiple REP3 input shares
pub fn merge_input_shares<P: Pairing>(
    input_shares: Vec<BTreeMap<String, Rep3AcvmType<P::ScalarField>>>,
) -> Result<BTreeMap<String, Rep3AcvmType<P::ScalarField>>> {
    let mut result = BTreeMap::new();
    for input_share in input_shares.into_iter() {
        for (wit, share) in input_share.into_iter() {
            if result.contains_key(&wit) {
                eyre::bail!("Duplicate witness found in input shares");
            }
            result.insert(wit, share);
        }
    }
    Ok(result)
}

/// Parse a barretenberg verification key into a [VerifyingKey]
pub fn parse_barretenberg_vk<P>(
    vk: &[u8],
    verifier_crs: P::G2Affine,
) -> eyre::Result<VerifyingKey<P, UltraFlavour>>
where
    P: Pairing + HonkCurve<TranscriptFieldType>,
{
    let vk = VerifyingKeyBarretenberg::from_buffer(vk)
        .context("while deserializing verification key")?;
    Ok(VerifyingKey::from_barrettenberg_and_crs(vk, verifier_crs))
}

pub fn witness_to_witness_map(
    witness: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>,
    abi: &Abi,
) -> color_eyre::Result<WitnessMap<Rep3AcvmType<ark_bn254::Fr>>> {
    Rep3CoSolver::<ark_bn254::Fr, ()>::witness_map_from_string_map(witness, abi)
}

pub fn witness_stack_to_vec_rep3<F: PrimeField>(
    mut witness_stack: WitnessStack<Rep3AcvmType<F>>,
) -> Vec<Rep3AcvmType<F>> {
    let witness_map = witness_stack
        .pop()
        .expect("Witness should be present")
        .witness;

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

// This function is basically copied from Barretenberg
/// Downloads the CRS with num_points points to the crs_path.
pub fn download_g1_crs(num_points: usize, crs_path: impl AsRef<Path>) -> color_eyre::Result<()> {
    tracing::info!("Downloading CRS with {} points", num_points);
    let g1_end = num_points * 64 - 1;

    let url = "https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/flat/g1.dat";
    let command = format!("curl -s -H \"Range: bytes=0-{g1_end}\" '{url}'");
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .wrap_err("Failed to execute curl command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eyre::bail!("Could not download CRS: {}", stderr);
    }

    let data = output.stdout;
    let mut file = File::create(crs_path).wrap_err("Failed to create CRS file")?;
    file.write_all(&data)
        .wrap_err("Failed to write data to CRS file")?;

    if data.len() < (g1_end + 1) {
        eyre::bail!(
            "Downloaded CRS is incomplete: expected {} bytes, got {} bytes",
            g1_end + 1,
            data.len()
        );
    }

    Ok(())
}
