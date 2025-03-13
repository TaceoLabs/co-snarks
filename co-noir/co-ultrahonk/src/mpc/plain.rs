use super::NoirUltraHonkProver;
use ark_ec::pairing::Pairing;
use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ff::Field;
use ark_ff::UniformRand;
use ark_poly::DenseUVPolynomial;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use num_traits::Zero;
use rand::thread_rng;
use rayon::prelude::*;

pub struct PlainUltraHonkDriver;

impl<P: Pairing> NoirUltraHonkProver<P> for PlainUltraHonkDriver {
    type ArithmeticShare = P::ScalarField;
    type PointShare = P::G1;
    type PartyID = usize;

    fn debug(ele: Self::ArithmeticShare) -> String {
        if ele.is_zero() {
            "0".to_string()
        } else {
            ele.to_string()
        }
    }

    fn add_assign_public_half_share(
        share: &mut P::ScalarField,
        public: P::ScalarField,
        _: Self::PartyID,
    ) {
        *share += public
    }

    fn mul_with_public_to_half_share(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> P::ScalarField {
        <Self as NoirUltraHonkProver<P>>::mul_with_public(public, shared)
    }

    fn rand(&mut self) -> std::io::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        Ok(Self::ArithmeticShare::rand(&mut rng))
    }

    fn get_party_id(&self) -> Self::PartyID {
        0
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a - b
    }

    fn sub_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        debug_assert_eq!(a.len(), b.len());
        a.par_iter_mut().zip(b.par_iter()).for_each(|(a, b)| {
            *a -= b;
        })
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a + b
    }

    fn add_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        *a += b;
    }

    fn add_assign_public(
        a: &mut Self::ArithmeticShare,
        b: <P as Pairing>::ScalarField,
        _id: Self::PartyID,
    ) {
        *a += b;
    }

    fn neg(a: Self::ArithmeticShare) -> Self::ArithmeticShare {
        -a
    }

    fn mul_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        shared * public
    }

    fn mul_assign_with_public(shared: &mut Self::ArithmeticShare, public: P::ScalarField) {
        *shared *= public;
    }

    fn local_mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> Vec<P::ScalarField> {
        debug_assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect()
    }

    fn reshare(&mut self, a: Vec<P::ScalarField>) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        Ok(a)
    }

    fn mul_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        debug_assert_eq!(a.len(), b.len());
        Ok(a.iter().zip(b.iter()).map(|(a, b)| *a * b).collect())
    }

    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        _id: Self::PartyID,
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

    fn open_point_and_field(
        &mut self,
        a: Self::PointShare,
        b: Self::ArithmeticShare,
    ) -> std::io::Result<(<P as Pairing>::G1, <P as Pairing>::ScalarField)> {
        Ok((a, b))
    }

    fn mul_open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<<P as Pairing>::ScalarField>> {
        debug_assert_eq!(a.len(), b.len());
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

    fn msm_public_points(
        points: &[<P as Pairing>::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare {
        P::G1::msm_unchecked(points, scalars)
    }

    fn eval_poly(coeffs: &[Self::ArithmeticShare], point: P::ScalarField) -> Self::ArithmeticShare {
        // TACEO TODO: here we clone...
        let poly = DensePolynomial::from_coefficients_slice(coeffs);
        poly.evaluate(&point)
    }

    fn fft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.fft(data)
    }

    fn ifft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(data)
    }
}
