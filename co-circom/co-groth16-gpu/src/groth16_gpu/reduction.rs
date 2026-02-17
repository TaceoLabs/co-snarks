use core::str;
use std::mem::transmute;

use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use eyre::Result;
use icicle_core::{
    ntt::{NTT, NTTDomain},
    traits::{Arithmetic, FieldImpl, MontgomeryConvertible},
    vec_ops::{VecOps, VecOpsConfig, sub_scalars},
};
use icicle_runtime::{
    Device,
    memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice},
    stream::{self, IcicleStream},
};
use mpc_core::MpcState;
use tracing::instrument;

use crate::mpc::CircomGroth16Prover;

/// This trait is used to convert the secret-shared witness into a secret-shared QAP witness as part of a collaborative Groth16 proof.
/// Refer to <https://docs.rs/ark-groth16/latest/ark_groth16/r1cs_to_qap/trait.R1CSToQAP.html> for more details on the plain version.
/// We do not implement the other methods of the arkworks trait, as we do not need them during proof generation.
pub trait R1CSToQAP {
    /// Computes a QAP witness corresponding to the R1CS witness defined by `private_witness`, using the provided `ConstraintMatrices`.
    /// The provided `driver` is used to perform the necessary operations on the secret-shared witness.
    fn witness_map_from_r1cs_eval<
        F: FieldImpl<Config: VecOps<F> + NTT<F, F> + NTTDomain<F>>
            + Arithmetic
            + MontgomeryConvertible,
        T: CircomGroth16Prover<F>,
    >(
        state: &mut T::State,
        eval_a: &mut T::DeviceShares,
        eval_b: &mut T::DeviceShares,
        public_inputs: &DeviceSlice<F>,
        roots_to_power_domain: &DeviceSlice<F>,
        num_constraints: usize,
        domain_size: usize,
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

/// Implements the witness map used by snarkjs. The arkworks witness map calculates the
/// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
/// coefficients domain. snarkjs instead precomputes the Lagrange form of the powers of tau bases
/// in a domain twice as large and the witness map is computed as the odd coefficients of (AB-C)
/// in that domain. This serves as HZ when computing the C proof element.
///
/// Based on <https://github.com/arkworks-rs/circom-compat/>.
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[instrument(level = "debug", name = "witness map from matrices", skip_all)]
    fn witness_map_from_r1cs_eval<
        F: FieldImpl<Config: VecOps<F> + NTT<F, F> + NTTDomain<F>>
            + Arithmetic
            + MontgomeryConvertible,
        T: CircomGroth16Prover<F>,
    >(
        state: &mut T::State,
        eval_a: &mut T::DeviceShares,
        eval_b: &mut T::DeviceShares,
        public_inputs: &DeviceSlice<F>,
        roots_to_power_domain: &DeviceSlice<F>,
        num_constraints: usize,
        domain_size: usize,
    ) -> Result<DeviceVec<F>> {
        let id = state.id();

        // Computation of a
        let promoted_public = T::promote_to_trivial_shares(id, public_inputs);
        T::copy_to_device_shares(&promoted_public, eval_a, num_constraints, domain_size);

        let mut stream_c = IcicleStream::create().unwrap();
        let mut c = T::local_mul_vec(eval_a, eval_b, state, &stream_c);

        // Computation of a
        let mut stream_a = IcicleStream::create().unwrap();
        T::ifft_in_place(eval_a, &stream_a);
        T::distribute_powers_and_mul_by_const(eval_a, roots_to_power_domain, &stream_a);
        T::fft_in_place(eval_a, &stream_a);

        // Computation of b
        let mut stream_b = IcicleStream::create().unwrap();
        T::ifft_in_place(eval_b, &stream_b);
        T::distribute_powers_and_mul_by_const(eval_b, roots_to_power_domain, &stream_b);
        T::fft_in_place(eval_b, &stream_b);

        // Computation of c
        T::ifft_in_place_hs(&mut c, &stream_c);
        T::distribute_powers_and_mul_by_const_hs(&mut c, roots_to_power_domain, &stream_c);
        T::fft_in_place_hs(&mut c, &stream_c);

        stream_a.synchronize().unwrap();
        stream_b.synchronize().unwrap();
        let ab = T::local_mul_vec(eval_a, eval_b, state, &stream_a);

        let mut result = DeviceVec::device_malloc_async(ab.len(), &stream_c)
            .expect("Failed to allocate device vector");

        let mut cfg = VecOpsConfig::default();
        cfg.stream_handle = *stream_c;
        cfg.is_async = true;
        sub_scalars(&ab, &c, result.as_mut_slice(), &cfg).unwrap();
        stream_c.synchronize().unwrap();

        stream_a.destroy().unwrap();
        stream_b.destroy().unwrap();
        stream_c.destroy().unwrap();

        Ok(result)
    }
}
