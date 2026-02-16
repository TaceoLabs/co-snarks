
use core::num;
use std::ops::{Index, IndexMut};

use ark_ff::{FftField, One};
use ark_groth16::r1cs_to_qap::evaluate_constraint;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, domain};
use ark_relations::r1cs::{ConstraintMatrices, Matrix};
use eyre::Result;
use icicle_core::{ecntt::Projective, ntt::NTT, vec_ops::VecOps, field::Field, pairing::Pairing};
use icicle_runtime::{Device, memory::{DeviceSlice, DeviceVec}};
use mpc_core::MpcState;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use tracing::instrument;

use crate::{bridges::transmute_ark_to_icicle_scalar, gpu_utils::{DeviceMatrices, DeviceMatrix, fft_inplace}, mpc::CircomGroth16Prover};

use super::root_of_unity_for_groth16;

macro_rules! rayon_join {
    ($t1: expr, $t2: expr, $t3: expr) => {{
        let ((x, y), z) = rayon::join(|| rayon::join($t1, $t2), $t3);
        (x, y, z)
    }};
}
/// This trait is used to convert the secret-shared witness into a secret-shared QAP witness as part of a collaborative Groth16 proof.
/// Refer to <https://docs.rs/ark-groth16/latest/ark_groth16/r1cs_to_qap/trait.R1CSToQAP.html> for more details on the plain version.
/// We do not implement the other methods of the arkworks trait, as we do not need them during proof generation.
pub trait R1CSToQAP {
    /// Computes a QAP witness corresponding to the R1CS witness defined by `private_witness`, using the provided `ConstraintMatrices`.
    /// The provided `driver` is used to perform the necessary operations on the secret-shared witness.
    fn witness_map_from_matrices<F: Field + VecOps<F> + NTT<F, F>, G1: Projective<ScalarField = F>, G2: Projective<ScalarField =F>, T: CircomGroth16Prover<F>>(
        state: &mut T::State,
        matrices: &DeviceMatrices<F>,
        public_inputs: &DeviceSlice<F>,
        private_witness: &T::DeviceShares,
    ) -> Result<DeviceVec<F>>;
}

// fn evaluate_constraint_half_share<F: Field + VecOps<F> + NTT<F, F>, T: CircomGroth16Prover<F>>(
//     id: <T::State as MpcState>::PartyID,
//     domain_size: usize,
//     matrix: &DeviceMatrix<F>,
//     public_inputs: &DeviceSlice<F>,
//     private_witness: &T::DeviceShares,
// ) -> T::DeviceHalfShares {
//     let mut result = matrix
//         .par_iter()
//         .with_min_len(256)
//         .map(|x| T::evaluate_constraint_half_share(id, x, public_inputs, private_witness))
//         .collect::<Vec<_>>();
//     result.resize(domain_size, T::ArithmeticHalfShare::default());
//     result
// }

// /// Implements the witness map used by snarkjs. The arkworks witness map calculates the
// /// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
// /// coefficients domain. snarkjs instead precomputes the Lagrange form of the powers of tau bases
// /// in a domain twice as large and the witness map is computed as the odd coefficients of (AB-C)
// /// in that domain. This serves as HZ when computing the C proof element.
// ///
// /// Based on <https://github.com/arkworks-rs/circom-compat/>.
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[instrument(level = "debug", name = "witness map from matrices", skip_all)]
    fn witness_map_from_matrices<F: Field + VecOps<F> + NTT<F, F>, G1: Projective<ScalarField = F>, G2: Projective<ScalarField =F>, T: CircomGroth16Prover<F>>(
        state: &mut T::State,
        matrices: &DeviceMatrices<F>,
        public_inputs: &DeviceSlice<F>,
        private_witness: &T::DeviceShares,
    ) -> Result<DeviceVec<F>> {
        let DeviceMatrices { a, b, c, num_constraints, num_instance_variables, .. } = matrices;
        let (num_constraints, num_inputs) = (*num_constraints, *num_instance_variables);
        let power = num_constraints + num_inputs;
        // TODO CESAR: We dont need the domain
        let mut domain =
            GeneralEvaluationDomain::<ark_bn254::Fr>::new(power)
                .ok_or(eyre::eyre!("Polynomial Degree too large"))?;
        let domain_size = 1 << power;
        let id = state.id();

        // TODO CESAR: Redo as threads or async somehow

        // Computation of the roots of unity
        // TODO CESAR: Can we push this to the GPU
        // TODO CESAR: Hardcoded for bn254
        let root_of_unity = root_of_unity_for_groth16(power, &mut domain);
        let root_of_unity = transmute_ark_to_icicle_scalar(root_of_unity);
        let mut roots = Vec::with_capacity(domain_size);
        let mut c = F::one();
        for _ in 0..domain_size {
            roots.push(c);
            c = c * root_of_unity;
        }
        let roots_to_power_domain = DeviceVec::from_host_slice(&roots);

        // Computation of a
        let mut a = T::evaluate_constraints(
            id,
            domain_size,
            a,
            public_inputs,
            private_witness,
        );

        let promoted_public = T::promote_to_trivial_shares(id, public_inputs);
        T::copy_to_device_shares(&promoted_public, &mut a, num_constraints, num_constraints + num_inputs);


        // Computation of b
        let mut b = T::evaluate_constraints(
            id,
            domain_size,
            b,
            public_inputs,
            private_witness,
        );

        let mut c = T::local_mul_vec(&a, &b, state);

        // TODO CESAR: Redo as threads or async somehow

        // Computation of a
        T::ifft_in_place(&mut a);
        T::distribute_powers_and_mul_by_const(&mut a, &roots_to_power_domain);
        T::fft_in_place(&mut a);

        // Computation of b
        T::ifft_in_place(&mut b);
        T::distribute_powers_and_mul_by_const(&mut b, &roots_to_power_domain);
        T::fft_in_place(&mut b);

        // Computation of c
        T::ifft_in_place_hs(&mut c);
        T::distribute_powers_and_mul_by_const_hs(&mut c, &roots_to_power_domain);
        T::fft_in_place_hs(&mut c);

        let ab = T::local_mul_vec(&a, &b, state);
        let result = T::sub_vec_hs(&ab, &c, state);
        Ok(result)
    }
}