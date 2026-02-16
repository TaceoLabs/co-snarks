use std::{mem::transmute};

use ark_ff::{ PrimeField};
use ark_relations::r1cs::ConstraintMatrices;
use icicle_bn254::curve::ScalarField;
use icicle_core::{ ecntt::Projective, field::Field, ntt::{self, NTT, NTTConfig, NTTDir, ntt_inplace}, traits::MontgomeryConvertible};
use icicle_runtime::{memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice}, stream::IcicleStream};
use icicle_core::{ vec_ops::VecOps};

use crate::bridges::ArkIcicleBridge;

pub struct Proof<F: Field + VecOps<F> + NTT<F, F>, G1: Projective<ScalarField = F>, G2: Projective<ScalarField =F>> {
    /// The `A` element in `G1`.
    pub a: G1::Affine,
    /// The `B` element in `G2`.
    pub b: G2::Affine,
    /// The `C` element in `G1`.
    pub c: G1::Affine,
}

impl<F: Field + VecOps<F> + NTT<F, F>, G1: Projective<ScalarField = F>, G2: Projective<ScalarField =F>> Proof<F, G1, G2> {
    pub fn to_ark<B: ArkIcicleBridge<IcicleG1 = G1, IcicleG1Affine = G1::Affine, IcicleG2 = G2, IcicleG2Affine = G2::Affine, IcicleScalarField = F>>(&self) -> ark_groth16::Proof<B::ArkPairing> {
        ark_groth16::Proof {
            a: B::icicle_to_ark_g1(self.a),
            b: B::icicle_to_ark_g2(self.b),
            c: B::icicle_to_ark_g1(self.c),
        }
    }
}

pub struct VerifyingKey<F: Field + VecOps<F> + NTT<F, F>, G1: Projective<ScalarField = F>, G2: Projective<ScalarField =F>> {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: G1::Affine,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: G2::Affine,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: G2::Affine,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: G2::Affine,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is
    /// the generator of `E::G1`.
    pub gamma_abc_g1: DeviceVec<G1::Affine>,
}

// TODO CESAR: So many copies, but is it bad?
impl<F: Field + VecOps<F> + NTT<F, F>, G1: Projective<ScalarField = F>, G2: Projective<ScalarField =F>> Clone for VerifyingKey<F, G1, G2> {
    fn clone(&self) -> Self {
        let mut copy_gamma_abc_g1 = DeviceVec::device_malloc(self.gamma_abc_g1.len()).expect("Failed to allocate device vector");
        copy_gamma_abc_g1.copy(&self.gamma_abc_g1).unwrap();
        Self {
            alpha_g1: self.alpha_g1,
            beta_g2: self.beta_g2,
            gamma_g2: self.gamma_g2,
            delta_g2: self.delta_g2,
            gamma_abc_g1: copy_gamma_abc_g1,
        }
    }
}

pub struct ProvingKey<F: Field + VecOps<F> + NTT<F, F>, G1: Projective<ScalarField = F>, G2: Projective<ScalarField =F>> {
    /// The underlying verification key.
    pub vk: VerifyingKey<F, G1, G2>,
    /// The element `beta * G` in `E::G1`.
    pub beta_g1: G1::Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: G1::Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: DeviceVec<G1::Affine>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: DeviceVec<G1::Affine>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: DeviceVec<G2::Affine>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: DeviceVec<G1::Affine>,
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: DeviceVec<G1::Affine>,
}

impl<F: Field + VecOps<F> + NTT<F, F>, G1: Projective<ScalarField = F>, G2: Projective<ScalarField =F>> ProvingKey<F, G1, G2> {
    pub fn from_ark<B: ArkIcicleBridge<IcicleG1 = G1, IcicleG1Affine = G1::Affine, IcicleG2 = G2, IcicleG2Affine = G2::Affine, IcicleScalarField = F>>(pk: &ark_groth16::ProvingKey<B::ArkPairing>) -> Self {
        let alpha_g1 = B::ark_to_icicle_g1(&pk.vk.alpha_g1);
        let beta_g2 = B::ark_to_icicle_g2(&pk.vk.beta_g2);
        let gamma_g2 = B::ark_to_icicle_g2(&pk.vk.gamma_g2);
        let delta_g2 = B::ark_to_icicle_g2(&pk.vk.delta_g2);
        let gamma_abc_g1 = DeviceVec::from_host_slice(&pk.vk.gamma_abc_g1.iter().map(B::ark_to_icicle_g1).collect::<Vec<_>>());

        let beta_g1 = B::ark_to_icicle_g1(&pk.beta_g1);
        let delta_g1 = B::ark_to_icicle_g1(&pk.delta_g1);
        let a_query = DeviceVec::from_host_slice(&pk.a_query.iter().map(B::ark_to_icicle_g1).collect::<Vec<_>>());
        let b_g1_query = DeviceVec::from_host_slice(&pk.b_g1_query.iter().map(B::ark_to_icicle_g1).collect::<Vec<_>>());
        let b_g2_query = DeviceVec::from_host_slice(&pk.b_g2_query.iter().map(B::ark_to_icicle_g2).collect::<Vec<_>>());
        let h_query = DeviceVec::from_host_slice(&pk.h_query.iter().map(B::ark_to_icicle_g1).collect::<Vec<_>>());
        let l_query = DeviceVec::from_host_slice(&pk.l_query.iter().map(B::ark_to_icicle_g1).collect::<Vec<_>>());

        Self {
            vk: VerifyingKey {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            },
            beta_g1,
            delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        }
    }
}

pub struct DeviceMatrices<F: Field> {
    /// The number of variables that are "public instances" to the constraint
    /// system.
    pub num_instance_variables: usize,
    /// The number of variables that are "private witnesses" to the constraint
    /// system.
    pub num_witness_variables: usize,
    /// The number of constraints in the constraint system.
    pub num_constraints: usize,

    pub a: DeviceMatrix<F>,
    pub b: DeviceMatrix<F>,
    pub c: DeviceMatrix<F>,
}

impl<F: Field + VecOps<F> + NTT<F, F>> DeviceMatrices<F> {
    pub fn from_constraint_matrices<B: ArkIcicleBridge<IcicleScalarField = F>>(
        constraint_matrices: &ConstraintMatrices<B::ArkScalarField>
    ) -> Self {
        let ConstraintMatrices { a, b, c, num_instance_variables, num_witness_variables, num_constraints, .. } = constraint_matrices;
        let (num_instance_variables, num_witness_variables, num_constraints) = (*num_instance_variables, *num_witness_variables, *num_constraints);
        let rows = num_constraints;
        let cols = num_instance_variables + num_witness_variables;

        let size = rows * cols;

        let mut dense_a = vec![F::zero(); size];
        for (i, row) in a.iter().enumerate() {
            for (col, j) in row.iter() {
                dense_a[i * cols + j] = B::ark_to_icicle_scalar(col);
            }
        }

        let a = DeviceVec::from_host_slice(&dense_a);
        let a = DeviceMatrix { data: a, cols: cols as u32, rows: rows as u32 };

        let mut dense_b = vec![F::zero(); size];
        for (i, row) in b.iter().enumerate() {
            for (col, j) in row.iter() {
                dense_b[i * cols + j] = B::ark_to_icicle_scalar(col);
            }
        }
        let b = DeviceVec::from_host_slice(&dense_b);
        let b = DeviceMatrix { data: b, cols: cols as u32, rows: rows as u32 };

        let mut dense_c = vec![F::zero(); size];
        for (i, row) in c.iter().enumerate() {
            for (col, j) in row.iter() {
                dense_c[i * cols + j] = B::ark_to_icicle_scalar(col);
            }
        }
        let c = DeviceVec::from_host_slice(&dense_c);
        let c = DeviceMatrix { data: c, cols: cols as u32, rows: rows as u32 };

        Self { a, b, c, num_instance_variables, num_witness_variables, num_constraints }
    }
}

pub struct DeviceMatrix<F: Field> {
    pub(crate) data: DeviceVec<F>,
    pub(crate) cols: u32,
    pub(crate) rows: u32,
}

// TODO CESAR: Compute batch of ntts
pub fn fft_inplace<F: Field + NTT<F, F>>(input: &mut DeviceSlice<F>) -> eyre::Result<()> {

    // TODO CESAR: Handle better
    ntt::initialize_domain(
        ntt::get_root_of_unity::<ScalarField>(
            input.len().try_into().unwrap()
        ).unwrap(),
        &ntt::NTTInitDomainConfig::default(),
    )
    .unwrap();

    let ntt_config = NTTConfig::<F>::default();
    ntt_inplace(input, NTTDir::kForward, &ntt_config)?;
    Ok(())
}

// TODO CESAR: Compute batch of ntts
pub fn ifft_inplace<F: Field + NTT<F, F>>(input: &mut DeviceSlice<F>) -> eyre::Result<()> {
    // TODO CESAR: Handle better
    ntt::initialize_domain(
        ntt::get_root_of_unity::<ScalarField>(
            input.len().try_into().unwrap(),
        ).unwrap(),
        &ntt::NTTInitDomainConfig::default(),
    )
    .unwrap();

    let ntt_config = NTTConfig::<F>::default();
    ntt_inplace(input, NTTDir::kInverse, &ntt_config)?;
    Ok(())
}