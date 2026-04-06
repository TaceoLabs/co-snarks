//! # co-spdz-noir
//!
//! Top-level integration crate for 2-party SPDZ collaborative Noir proving.
//!
//! By default, MAC verification is enabled (malicious security).
//! Pass `semi_honest: true` to disable MAC checks for better performance.

use co_builder::keys::proving_key::ProvingKeyTrait;
use co_builder::prelude::{AcirFormat, GenericUltraCircuitBuilder, HonkRecursion};
use co_noir_common::constants::PAIRING_POINT_ACCUMULATOR_SIZE;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::keys::proving_key::ProvingKey;
use co_noir_common::keys::verification_key::VerifyingKeyBarretenberg;
use co_noir_common::transcript::TranscriptHasher;
use co_noir_common::types::ZeroKnowledge;
use co_spdz_acvm::solver::SpdzAcvmSolver;
use co_spdz_acvm::types::SpdzAcvmType;
use co_spdz_ultrahonk::driver::SpdzUltraHonkDriver;
use co_ultrahonk::prelude::CoUltraHonk;
use mpc_core::MpcState;
use mpc_net::Network;
use noir_types::HonkProof;
use spdz_core::preprocessing::SpdzPreprocessing;
use spdz_core::SpdzState;

pub type SpdzProvingKey<P> = ProvingKey<SpdzUltraHonkDriver, P>;
pub type SpdzCoUltraHonk<P, H> = CoUltraHonk<SpdzUltraHonkDriver, P, H>;
pub type SpdzCoBuilder<'a, P, N> = GenericUltraCircuitBuilder<
    P,
    SpdzAcvmSolver<'a, <P as ark_ec::PrimeGroup>::ScalarField, N>,
>;
pub type Bn254G1 = <ark_ec::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1;

/// Generate a SPDZ shared proving key.
///
/// MAC verification is enabled by default. Pass `semi_honest: true` to disable.
pub fn generate_proving_key_spdz<N: Network>(
    preprocessing: Box<dyn SpdzPreprocessing<ark_bn254::Fr>>,
    constraint_system: &AcirFormat<ark_bn254::Fr>,
    witness_share: Vec<SpdzAcvmType<ark_bn254::Fr>>,
    net: &N,
    prover_crs: &ProverCrs<Bn254G1>,
) -> eyre::Result<SpdzProvingKey<Bn254G1>> {
    generate_proving_key_spdz_with_options(preprocessing, constraint_system, witness_share, net, prover_crs, false)
}

/// Generate a SPDZ shared proving key with explicit security mode.
pub fn generate_proving_key_spdz_with_options<N: Network>(
    preprocessing: Box<dyn SpdzPreprocessing<ark_bn254::Fr>>,
    constraint_system: &AcirFormat<ark_bn254::Fr>,
    witness_share: Vec<SpdzAcvmType<ark_bn254::Fr>>,
    net: &N,
    prover_crs: &ProverCrs<Bn254G1>,
    semi_honest: bool,
) -> eyre::Result<SpdzProvingKey<Bn254G1>> {
    let mut state = if semi_honest {
        SpdzState::new_semi_honest(net.id(), preprocessing)
    } else {
        SpdzState::new(net.id(), preprocessing)
    };
    let party_id = state.id();
    let mut driver = SpdzAcvmSolver::new(net, state);

    let crs = if constraint_system.is_recursive_verification_circuit() {
        prover_crs
    } else {
        &ProverCrs::<Bn254G1>::default()
    };

    let builder = SpdzCoBuilder::create_circuit(
        constraint_system, 0, witness_share, HonkRecursion::UltraHonk, crs, &mut driver,
    )?;

    Ok(SpdzProvingKey::create(party_id, builder, &mut driver)?)
}

/// Generate a SPDZ collaborative UltraHonk proof.
///
/// MAC verification is enabled by default. Pass `semi_honest: true` to disable.
pub fn prove_spdz<
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
>(
    net: &N,
    preprocessing: Box<dyn SpdzPreprocessing<C::ScalarField>>,
    proving_key: ProvingKey<SpdzUltraHonkDriver, C>,
    crs: &ProverCrs<C>,
    has_zk: ZeroKnowledge,
    verifying_key: &VerifyingKeyBarretenberg<C>,
) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
    prove_spdz_with_options::<C, H, N>(net, preprocessing, proving_key, crs, has_zk, verifying_key, false)
}

/// Generate a SPDZ collaborative UltraHonk proof with explicit security mode.
pub fn prove_spdz_with_options<
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
>(
    net: &N,
    preprocessing: Box<dyn SpdzPreprocessing<C::ScalarField>>,
    proving_key: ProvingKey<SpdzUltraHonkDriver, C>,
    crs: &ProverCrs<C>,
    has_zk: ZeroKnowledge,
    verifying_key: &VerifyingKeyBarretenberg<C>,
    semi_honest: bool,
) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
    let mut state = if semi_honest {
        SpdzState::new_semi_honest(net.id(), preprocessing)
    } else {
        SpdzState::new(net.id(), preprocessing)
    };
    state.set_network(net);
    let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
    let proof = SpdzCoUltraHonk::<C, H>::prove_inner(
        net, &mut state, proving_key, crs, has_zk, verifying_key,
    )?;
    let (proof, public_inputs) =
        proof.separate_proof_and_public_inputs(num_public_inputs as usize);
    Ok((proof, public_inputs))
}
