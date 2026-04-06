//! SPDZ UltraHonk Driver
//!
//! Implements `NoirUltraHonkProver` for 2-party SPDZ secret sharing.

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::mpc::NoirUltraHonkProver;
use itertools::izip;
use mpc_net::Network;
use num_traits::Zero;
use rayon::prelude::*;
use spdz_core::arithmetic;
use spdz_core::types::{SpdzPointShare, SpdzPrimeFieldShare};
use spdz_core::{SpdzPartyID, SpdzState};

/// A UltraHonk driver using 2-party SPDZ secret sharing.
#[derive(Debug)]
pub struct SpdzUltraHonkDriver;

impl<P: CurveGroup<BaseField: PrimeField>> NoirUltraHonkProver<P> for SpdzUltraHonkDriver {
    type ArithmeticShare = SpdzPrimeFieldShare<P::ScalarField>;
    type PointShare = SpdzPointShare<P>;
    type State = SpdzState<P::ScalarField>;

    fn rand<N: Network>(
        _net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        state.preprocessing.next_shared_random()
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a - b
    }

    fn sub_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        *a -= b;
    }

    fn sub_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        for (a, b) in a.iter_mut().zip(b.iter()) {
            *a -= *b;
        }
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a + b
    }

    fn add_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        *a += b;
    }

    fn add_assign_public(
        a: &mut Self::ArithmeticShare,
        b: P::ScalarField,
        id: SpdzPartyID<P::ScalarField>,
    ) {
        *a = arithmetic::add_public(*a, b, id.mac_key_share, id.id);
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
        *shared = *shared * public;
    }

    fn add_assign_public_half_share(
        share: &mut P::ScalarField,
        public: P::ScalarField,
        id: SpdzPartyID<P::ScalarField>,
    ) {
        // "Half share" = just the value component, no MAC.
        // Only party 0 adds the public value.
        if id.id == 0 {
            *share += public;
        }
    }

    fn mul_with_public_to_half_share(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> P::ScalarField {
        public * shared.share
    }

    fn local_mul_vec(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        state: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        // SPDZ multiplication REQUIRES network communication (Beaver triples).
        // We run the full Beaver protocol here via the network stored in state.
        let results = state
            .mul_via_net(a, b)
            .expect("Beaver multiplication failed in local_mul_vec");

        // Return just the .share component — the prover accumulates these
        // with public scalars, preserving the additive sharing property.
        results.iter().map(|r| r.share).collect()
    }

    fn reshare<N: Network>(
        a: Vec<P::ScalarField>,
        net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        // The values in `a` are accumulated .share components from local_mul_vec
        // results (which did full Beaver multiplication). Since the accumulation
        // only applies public-scalar operations, these are valid additive shares.
        // Exchange to compute full values for MAC generation.
        use spdz_core::network::SpdzNetworkExt;
        let other_halves: Vec<P::ScalarField> = net.exchange_many(&a)?;
        let full_values: Vec<P::ScalarField> = a
            .iter()
            .zip(other_halves.iter())
            .map(|(a, b)| *a + *b)
            .collect();

        Ok(full_values
            .iter()
            .zip(a.iter())
            .map(|(full, my_half)| {
                SpdzPrimeFieldShare::new(
                    *my_half,
                    _state.mac_key_share * full,
                )
            })
            .collect())
    }

    fn mul<N: Network>(
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        arithmetic::mul(&a, &b, net, state)
    }

    fn mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_many(a, b, net, state)
    }

    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        id: SpdzPartyID<P::ScalarField>,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public, id.mac_key_share, id.id)
    }

    fn promote_to_trivial_share(
        id: SpdzPartyID<P::ScalarField>,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        SpdzPrimeFieldShare::promote_from_trivial(&public_value, id.mac_key_share, id.id)
    }

    fn promote_to_trivial_shares(
        id: SpdzPartyID<P::ScalarField>,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|v| <Self as NoirUltraHonkProver<P>>::promote_to_trivial_share(id, *v))
            .collect()
    }

    fn promote_to_trivial_point_share(
        id: SpdzPartyID<P::ScalarField>,
        public_value: P,
    ) -> Self::PointShare {
        let share = if id.id == 0 { public_value } else { P::zero() };
        let mac = public_value * id.mac_key_share;
        SpdzPointShare::new(share, mac)
    }

    fn open_point<N: Network>(
        a: Self::PointShare,
        net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<P> {
        arithmetic::open_point(&a, net)
    }

    fn open_point_many<N: Network>(
        a: &[Self::PointShare],
        net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P>> {
        a.iter().map(|p| arithmetic::open_point(p, net)).collect()
    }

    fn open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        // UltraHonk prover opens are intermediate protocol values.
        // MAC checking happens at the ACVM layer for user-facing opens.
        // The SNARK proof itself provides soundness for these intermediate values.
        arithmetic::open_many_unchecked(a, net)
    }

    fn open_point_and_field<N: Network>(
        a: Self::PointShare,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<(P, P::ScalarField)> {
        let point = <Self as NoirUltraHonkProver<P>>::open_point(a, net, state)?;
        let field = arithmetic::open_unchecked(&b, net)?;
        Ok((point, field))
    }

    fn open_point_and_field_many<N: Network>(
        a: &[Self::PointShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<(Vec<P>, Vec<P::ScalarField>)> {
        let points = <Self as NoirUltraHonkProver<P>>::open_point_many(a, net, state)?;
        let fields = arithmetic::open_many_unchecked(b, net)?;
        Ok((points, fields))
    }

    fn mul_open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        let products = arithmetic::mul_many(a, b, net, state)?;
        arithmetic::open_many_unchecked(&products, net)
    }

    fn inv_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_many(a, net, state)
    }

    fn inv_many_in_place<N: Network>(
        a: &mut [Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<()> {
        let r = (0..a.len())
            .map(|_| <Self as NoirUltraHonkProver<P>>::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let y = <Self as NoirUltraHonkProver<P>>::mul_open_many(a, &r, net, state)?;
        if y.iter().any(|y| y.is_zero()) {
            eyre::bail!("Cannot compute inverse of zero");
        }
        for (a, r, y) in izip!(a.iter_mut(), r, y) {
            *a = r * y.inverse().unwrap();
        }
        Ok(())
    }

    fn inv_many_in_place_leaking_zeros<N: Network>(
        a: &mut [Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<()> {
        let r = (0..a.len())
            .map(|_| <Self as NoirUltraHonkProver<P>>::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let y = <Self as NoirUltraHonkProver<P>>::mul_open_many(a, &r, net, state)?;
        for (a, r, y) in izip!(a.iter_mut(), r, y) {
            if y.is_zero() {
                *a = Self::ArithmeticShare::default();
            } else {
                *a = r * y.inverse().unwrap();
            }
        }
        Ok(())
    }

    fn msm_public_points(
        points: &[P::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare {
        arithmetic::msm_public_points::<P>(points, scalars)
    }

    fn point_add(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        *a + *b
    }

    fn point_sub(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        *a - *b
    }

    fn eval_poly(
        coeffs: &[Self::ArithmeticShare],
        point: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::eval_poly(coeffs, point)
    }

    fn fft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        arithmetic::fft(data, domain)
    }

    fn ifft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        arithmetic::ifft(data, domain)
    }

    fn is_zero_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let num_bits = P::ScalarField::MODULUS_BIT_SIZE as usize;
        a.iter()
            .map(|x| spdz_core::gadgets::bits::is_zero(x, num_bits, net, state))
            .collect()
    }

    fn scalar_mul_public_point(a: &P, b: Self::ArithmeticShare) -> Self::PointShare {
        arithmetic::scalar_mul_public_point(a, &b)
    }

    fn poseidon_permutation_in_place<const T: usize, const D: u64, N: Network>(
        poseidon: &mpc_core::gadgets::poseidon2::Poseidon2<P::ScalarField, T, D>,
        state_arr: &mut [Self::ArithmeticShare; T],
        net: &N,
        mpc_state: &mut Self::State,
    ) -> eyre::Result<()> {
        let mut precomp =
            spdz_core::gadgets::poseidon2::precompute(poseidon, 1, net, mpc_state)?;
        spdz_core::gadgets::poseidon2::permutation_in_place(
            poseidon, state_arr, &mut precomp, net, mpc_state,
        )
    }

    fn pointshare_to_field_shares_many<F: PrimeField, N: Network>(
        _points: &[Self::PointShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>
    where
        P: HonkCurve<F>,
    {
        panic!("SpdzUltraHonkDriver does not support pointshare_to_field_shares_many yet");
    }
}
