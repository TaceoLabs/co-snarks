use std::cmp::max;

use super::NoirUltraHonkProver;
use ark_ec::pairing::Pairing;
use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ff::Field;
use ark_ff::UniformRand;
use num_traits::Zero;
use rand::thread_rng;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
const MIN_ELEMENTS_PER_THREAD: usize = 16;

pub struct PlainUltraHonkDriver;

impl<P: Pairing> NoirUltraHonkProver<P> for PlainUltraHonkDriver {
    type ArithmeticShare = P::ScalarField;
    type PointShare = P::G1;
    type PartyID = usize;

    fn rand(&mut self) -> std::io::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn get_party_id(&self) -> Self::PartyID {
        0
    }

    fn sub(&self, a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a - b
    }

    fn add(&self, a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a + b
    }

    fn neg(&mut self, a: Self::ArithmeticShare) -> Self::ArithmeticShare {
        -a
    }

    fn mul_with_public(
        &self,
        public: <P as Pairing>::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        shared * public
    }

    fn mul_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn add_with_public(
        &self,
        public: <P as Pairing>::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        shared + public
    }

    fn promote_to_trivial_share(
        _id: Self::PartyID,
        public_value: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        public_value
    }

    fn promote_to_trivial_shares(
        _id: Self::PartyID,
        public_values: &[<P as Pairing>::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values.to_vec()
    }

    fn open_point(&mut self, a: Self::PointShare) -> std::io::Result<<P as Pairing>::G1> {
        Ok(a)
    }

    fn open_point_many(
        &mut self,
        a: &[Self::PointShare],
    ) -> std::io::Result<Vec<<P as Pairing>::G1>> {
        Ok(a.to_vec())
    }

    fn open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<<P as Pairing>::ScalarField>> {
        Ok(a.to_vec())
    }

    fn mul_open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<<P as Pairing>::ScalarField>> {
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn inv_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        let mut res = Vec::with_capacity(a.len());

        for a in a {
            if a.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Cannot invert zero",
                ));
            }
            res.push(a.inverse().unwrap());
        }

        Ok(res)
    }

    fn inv_many_in_place_leaking_zeros(
        &mut self,
        a: &mut [Self::ArithmeticShare],
    ) -> std::io::Result<()> {
        for a in a.iter_mut() {
            if !a.is_zero() {
                a.inverse_in_place().unwrap();
            }
        }
        Ok(())
    }

    fn inv_many_in_place(&mut self, a: &mut [Self::ArithmeticShare]) -> std::io::Result<()> {
        for a in a.iter_mut() {
            if a.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Cannot invert zero",
                ));
            }
            a.inverse_in_place().unwrap();
        }
        Ok(())
    }

    fn msm_public_points(
        points: &[<P as Pairing>::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare {
        P::G1::msm_unchecked(points, scalars)
    }

    fn eval_poly(
        &mut self,
        coeffs: &[Self::ArithmeticShare],
        point: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        if point.is_zero() {
            return coeffs[0];
        }

        let num_cpus_available = rayon::current_num_threads();
        let num_coeffs = coeffs.len();
        let num_elem_per_thread = max(num_coeffs / num_cpus_available, MIN_ELEMENTS_PER_THREAD);

        let result = coeffs
            .par_chunks(num_elem_per_thread)
            .enumerate()
            .map(|(i, chunk)| {
                let mut thread_result = chunk
                    .iter()
                    .rfold(<P as Pairing>::ScalarField::zero(), move |result, coeff| {
                        result * point + *coeff
                    });

                thread_result *= point.pow([(i * num_elem_per_thread) as u64]);
                thread_result
            })
            .sum();
        result
    }
}
