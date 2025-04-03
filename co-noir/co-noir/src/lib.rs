//! # Example:
//!
//! ```no_run
#![doc = include_str!("../examples/co_noir_party0.rs")]
//! ```

use acir::{
    acir_field::GenericFieldElement,
    native_types::{WitnessMap, WitnessStack},
    FieldElement,
};
use ark_ff::PrimeField;
use co_acvm::pss_store::PssStore;
use co_acvm::{
    solver::{partial_abi::PublicMarker, Rep3CoSolver},
    PlainAcvmSolver, Rep3AcvmSolver, ShamirAcvmSolver,
};
use co_ultrahonk::prelude::{
    HonkCurve, HonkProof, ProverCrs, ProverWitnessEntities, TranscriptFieldType, TranscriptHasher,
    ZeroKnowledge,
};
use color_eyre::eyre::{self, eyre, Context, Result};
use mpc_core::protocols::{
    bridges::network::RepToShamirNetwork,
    rep3::{self, network::Rep3Network},
    shamir::{self, network::ShamirNetwork, ShamirPreprocessing, ShamirProtocol},
};

use noirc_abi::Abi;
use noirc_artifacts::program::ProgramArtifact;
use rand::{CryptoRng, Rng};
use std::{array, collections::BTreeMap, fs::File, io::Write, path::Path, sync::Arc};

pub use ark_bn254::Bn254;
pub use ark_ec::pairing::Pairing;
pub use co_acvm::{Rep3AcvmType, ShamirAcvmType};
pub use co_ultrahonk::{
    prelude::{
        AcirFormat, CrsParser, HonkRecursion, PlainProvingKey, Polynomial, Polynomials,
        Poseidon2Sponge, Rep3CoUltraHonk, Rep3ProvingKey, ShamirCoUltraHonk, ShamirProvingKey,
        UltraCircuitBuilder, UltraHonk, Utils, VerifyingKey, VerifyingKeyBarretenberg,
        PROVER_WITNESS_ENTITIES_SIZE,
    },
    Rep3CoBuilder, ShamirCoBuilder,
};
pub use mpc_core::protocols::{
    rep3::{id::PartyID, network::Rep3MpcNet},
    shamir::network::ShamirMpcNet,
};
pub use mpc_net::config::{Address, NetworkConfig, NetworkParty, ParseAddressError};
pub use sha3::Keccak256;

/// State with a rep3 proving key
pub struct Rep3ProvingKeyState {
    net: Rep3MpcNet,
    /// The proving key
    proving_key: Rep3ProvingKey<Bn254, Rep3MpcNet>,
}

impl Rep3ProvingKeyState {
    /// Translate the rep3 proving key into a shamir proving key
    pub fn translate(self) -> eyre::Result<ShamirProvingKeyState> {
        let (proving_key, net) = translate_proving_key(self.proving_key, self.net)?;
        Ok(ShamirProvingKeyState {
            proving_key,
            threshold: 1,
            net,
        })
    }

    /// Generate a proof with the given [TranscriptHasher]
    pub fn prove<H: TranscriptHasher<TranscriptFieldType>>(
        self,
        prover_crs: &ProverCrs<Bn254>,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<HonkProof<ark_bn254::Fr>> {
        let (proof, _net) =
            Rep3CoUltraHonk::<_, _, H>::prove(self.net, self.proving_key, prover_crs, has_zk)?;
        Ok(proof)
    }
}

/// State with a shamir proving key
pub struct ShamirProvingKeyState {
    net: ShamirMpcNet,
    threshold: usize,
    /// The proving key
    pub proving_key: ShamirProvingKey<Bn254, ShamirMpcNet>,
}

impl ShamirProvingKeyState {
    /// Generate a proof with the given [TranscriptHasher]
    pub fn prove<H: TranscriptHasher<TranscriptFieldType>>(
        self,
        prover_crs: &ProverCrs<Bn254>,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<HonkProof<ark_bn254::Fr>> {
        let (proof, _net) = ShamirCoUltraHonk::<_, _, H>::prove(
            self.net,
            self.threshold,
            self.proving_key,
            prover_crs,
            has_zk,
        )?;
        Ok(proof)
    }
}

/// State with a rep3 shared witness
pub struct Rep3SharedWitnessState {
    net: Rep3MpcNet,
    /// The shared witness
    pub witness: Vec<Rep3AcvmType<ark_bn254::Fr>>,
}

impl Rep3SharedWitnessState {
    /// Create a new [Rep3SharedWitnessState ]
    pub fn new(net: Rep3MpcNet, witness: Vec<Rep3AcvmType<ark_bn254::Fr>>) -> Self {
        Self { net, witness }
    }

    /// Translate the rep3 shared witness into a shamir shared witness
    pub fn translate(self) -> eyre::Result<ShamirSharedWitnessState> {
        let (witness, net) =
            translate_witness::<Bn254, Rep3MpcNet, ShamirMpcNet>(self.witness, self.net)?;
        Ok(ShamirSharedWitnessState {
            witness,
            threshold: 1,
            net,
        })
    }

    /// Generate the proving key and advance to the next state
    pub fn generate_proving_key(
        self,
        constraint_system: &AcirFormat<ark_bn254::Fr>,
        recursive: bool,
    ) -> eyre::Result<Rep3ProvingKeyState> {
        let (proving_key, net) =
            generate_proving_key_rep3(self.net, constraint_system, self.witness, recursive)?;
        Ok(Rep3ProvingKeyState { net, proving_key })
    }
}

/// State with a shamir shared witness
pub struct ShamirSharedWitnessState {
    net: ShamirMpcNet,
    threshold: usize,
    /// The shared witness
    pub witness: Vec<ShamirAcvmType<ark_bn254::Fr>>,
}

impl ShamirSharedWitnessState {
    /// Create a new [ShamirSharedWitnessState ]
    pub fn new(
        net: ShamirMpcNet,
        threshold: usize,
        witness: Vec<ShamirAcvmType<ark_bn254::Fr>>,
    ) -> Self {
        Self {
            net,
            threshold,
            witness,
        }
    }

    /// Generate the proving key and advance to the next state
    pub fn generate_proving_key(
        self,
        constraint_system: &AcirFormat<ark_bn254::Fr>,
        recursive: bool,
    ) -> eyre::Result<ShamirProvingKeyState> {
        let (proving_key, net) = generate_proving_key_shamir(
            self.net,
            self.threshold,
            constraint_system,
            self.witness,
            recursive,
        )?;
        Ok(ShamirProvingKeyState {
            net,
            threshold: self.threshold,
            proving_key,
        })
    }
}

/// Initial state for the type-state pattern
pub struct CoNoirRep3 {
    net: Rep3MpcNet,
}

impl CoNoirRep3 {
    /// Create a new initial state
    pub fn new(net: Rep3MpcNet) -> Self {
        Self { net }
    }

    /// Perform the witness generation advance to the next state
    pub fn generate_witness(
        self,
        compiled_program: ProgramArtifact,
        shared_input: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>,
    ) -> eyre::Result<Rep3SharedWitnessState> {
        let (witness, net) =
            generate_witness_rep3::<Rep3MpcNet>(shared_input, compiled_program, self.net)?;
        Ok(Rep3SharedWitnessState { net, witness })
    }
}

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
        if let Self::Shared(ref mut f) = self {
            *self = Self::Public(f.clone());
        }
    }
}

pub fn parse_input(
    input_path: impl AsRef<Path>,
    program: &ProgramArtifact,
) -> eyre::Result<BTreeMap<String, PublicMarker<FieldElement>>> {
    Rep3CoSolver::<_, Rep3MpcNet>::partially_read_abi_bn254_fieldelement(
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
pub fn execute_circuit_rep3<N: Rep3Network>(
    input_share: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>,
    compiled_program: ProgramArtifact,
    net: N,
) -> Result<(
    Vec<Rep3AcvmType<ark_bn254::Fr>>,
    PssStore<Rep3AcvmSolver<ark_bn254::Fr, N>, ark_bn254::Fr>,
    N,
)> {
    let input_share = witness_to_witness_map(input_share, &compiled_program.abi)?;

    // init MPC protocol
    let rep3_vm = Rep3CoSolver::from_network_with_witness(net, compiled_program, input_share)
        .context("while creating VM")?;

    // execute witness generation in MPC
    let (result_witness_share, value_store, driver) = rep3_vm
        .solve_with_output()
        .context("while running witness generation")?;

    Ok((
        witness_stack_to_vec_rep3(result_witness_share),
        value_store,
        driver.into_network(),
    ))
}

/// Generate a witness from REP3 input shares
pub fn generate_witness_rep3<N: Rep3Network>(
    input_share: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>,
    compiled_program: ProgramArtifact,
    net: N,
) -> Result<(Vec<Rep3AcvmType<ark_bn254::Fr>>, N)> {
    let (witness_stack, _, network) = execute_circuit_rep3(input_share, compiled_program, net)?;
    Ok((witness_stack, network))
}

/// Translate a REP3 shared witness to a shamir shared witness
pub fn translate_witness<
    P: Pairing,
    NA: Rep3Network + RepToShamirNetwork<NB>,
    NB: ShamirNetwork,
>(
    witness_share: Vec<Rep3AcvmType<P::ScalarField>>,
    net: NA,
) -> Result<(Vec<ShamirAcvmType<P::ScalarField>>, NB)> {
    // extract shares only
    let mut shares = vec![];
    for share in witness_share.iter() {
        if let Rep3AcvmType::Shared(value) = share {
            shares.push(value.to_owned());
        }
    }

    let threshold = 1;
    let num_pairs = shares.len();
    let preprocessing = ShamirPreprocessing::new(threshold, net.to_shamir_net(), num_pairs)
        .context("while shamir preprocessing")?;
    let mut protocol = ShamirProtocol::from(preprocessing);

    // Translate witness to shamir shares
    let translated_shares = protocol.translate_primefield_repshare_vec(shares)?;

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

    Ok((result, protocol.network))
}

/// Translate a REP3 shared proving key to a shamir shared proving key
#[allow(clippy::complexity)]
pub fn translate_proving_key<
    P: Pairing,
    NA: Rep3Network + RepToShamirNetwork<NB>,
    NB: ShamirNetwork,
>(
    proving_key: Rep3ProvingKey<P, NA>,
    net: NA,
) -> Result<(ShamirProvingKey<P, NB>, NB)> {
    // extract shares
    let shares = proving_key
        .polynomials
        .witness
        .into_iter()
        .flat_map(|el| el.into_vec().into_iter())
        .collect::<Vec<_>>();

    let threshold = 1;
    let num_pairs = shares.len();
    let preprocessing = ShamirPreprocessing::new(threshold, net.to_shamir_net(), num_pairs)
        .context("while shamir preprocessing")?;
    let mut protocol = ShamirProtocol::from(preprocessing);

    // Translate witness to shamir shares
    let translated_shares = protocol.translate_primefield_repshare_vec(shares)?;

    if translated_shares.len() != PROVER_WITNESS_ENTITIES_SIZE * proving_key.circuit_size as usize {
        return Err(eyre!("Invalid number of shares translated"));
    };

    let mut chunks = translated_shares.chunks_exact(proving_key.circuit_size as usize);
    let translated_shares = array::from_fn(|_| {
        Polynomial::new(chunks.next().expect("Length already checked").to_vec())
    });

    let polynomials = Polynomials {
        witness: ProverWitnessEntities {
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
        contains_pairing_point_accumulator: proving_key.contains_pairing_point_accumulator,
        pairing_point_accumulator_public_input_indices: proving_key
            .pairing_point_accumulator_public_input_indices,
        active_region_data: proving_key.active_region_data,
    };

    Ok((result, protocol.network))
}

/// Compute the circuit size that is needed to load the prover crs
pub fn compute_circuit_size<P: Pairing>(
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
pub fn generate_proving_key_rep3<N: Rep3Network>(
    net: N,
    constraint_system: &AcirFormat<ark_bn254::Fr>,
    witness_share: Vec<Rep3AcvmType<ark_bn254::Fr>>,
    recursive: bool,
) -> Result<(Rep3ProvingKey<Bn254, N>, N)> {
    let id = net.get_id();
    let mut driver = Rep3AcvmSolver::new(net);
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
    let proving_key = Rep3ProvingKey::create(id, builder, &mut driver)?;

    Ok((proving_key, driver.into_network()))
}

/// Generate a shamir shared proving key
#[allow(clippy::complexity)]
pub fn generate_proving_key_shamir<N: ShamirNetwork>(
    net: N,
    threshold: usize,
    constraint_system: &AcirFormat<ark_bn254::Fr>,
    witness_share: Vec<ShamirAcvmType<ark_bn254::Fr>>,
    recursive: bool,
) -> Result<(ShamirProvingKey<Bn254, N>, N)> {
    let id = net.get_id();
    // We have to handle precomputation on the fly, so amount is 0 initially
    let preprocessing = ShamirPreprocessing::new(threshold, net, 0)?;
    let protocol = ShamirProtocol::from(preprocessing);
    let mut driver = ShamirAcvmSolver::new(protocol);
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
    let proving_key = ShamirProvingKey::create(id, builder, &mut driver)?;

    Ok((proving_key, driver.into_network()))
}

/// Generate a plain proving key
pub fn generate_proving_key_plain<P: Pairing>(
    constraint_system: &AcirFormat<P::ScalarField>,
    witness: Vec<P::ScalarField>,
    prover_crs: Arc<ProverCrs<P>>,
    recursive: bool,
) -> Result<PlainProvingKey<P>> {
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
pub fn generate_vk<P: Pairing>(
    constraint_system: &AcirFormat<P::ScalarField>,
    prover_crs: Arc<ProverCrs<P>>,
    verifier_crs: P::G2Affine,
    recursive: bool,
) -> Result<VerifyingKey<P>> {
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
pub fn generate_vk_barretenberg<P: Pairing>(
    constraint_system: &AcirFormat<P::ScalarField>,
    prover_crs: Arc<ProverCrs<P>>,
    recursive: bool,
) -> Result<VerifyingKeyBarretenberg<P>> {
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
pub fn split_proving_key_rep3<P: Pairing, R: Rng + CryptoRng, N: Rep3Network>(
    proving_key: PlainProvingKey<P>,
    rng: &mut R,
) -> Result<[Rep3ProvingKey<P, N>; 3]> {
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
pub fn split_proving_key_shamir<P: Pairing, R: Rng + CryptoRng, N: ShamirNetwork>(
    proving_key: PlainProvingKey<P>,
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Result<Vec<ShamirProvingKey<P, N>>> {
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
pub fn split_input_rep3<P: Pairing, N: Rep3Network, R: Rng + CryptoRng>(
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
                return Err(eyre!("Duplicate witness found in input shares"));
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
) -> eyre::Result<VerifyingKey<P>>
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
    Rep3CoSolver::<ark_bn254::Fr, Rep3MpcNet>::witness_map_from_string_map(witness, abi)
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
    let command = format!("curl -s -H \"Range: bytes=0-{}\" '{}'", g1_end, url);
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .wrap_err("Failed to execute curl command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(eyre!("Could not download CRS: {}", stderr));
    }

    let data = output.stdout;
    let mut file = File::create(crs_path).wrap_err("Failed to create CRS file")?;
    file.write_all(&data)
        .wrap_err("Failed to write data to CRS file")?;

    if data.len() < (g1_end + 1) {
        return Err(eyre!(
            "Downloaded CRS is incomplete: expected {} bytes, got {} bytes",
            g1_end + 1,
            data.len()
        ));
    }

    Ok(())
}
