use ark_ec::CurveGroup;
use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_core::MpcState;
use mpc_net::Network;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

pub mod plain;
pub mod rep3;
pub mod shamir;

/// This trait represents the operations used during UltraHonk proof generation
pub trait NoirUltraHonkProver<P: CurveGroup>: Send + Sized + std::fmt::Debug {
    /// The arithmetic share type
    type ArithmeticShare: CanonicalSerialize
        + CanonicalDeserialize
        + Copy
        + Clone
        + Default
        + Send
        + Sync
        + PartialEq
        + std::fmt::Debug
        + 'static;

    /// The G1 point share type
    type PointShare: std::fmt::Debug + Send + 'static + Clone + Default + Copy;
    /// Internal state of used MPC protocol
    type State: MpcState + Send;

    fn debug(_: Self::ArithmeticShare) -> String {
        panic!("not implemented for real protocol");
    }

    /// Generate a share of a random value. The value is thereby unknown to anyone.
    fn rand<N: Network>(net: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare>;

    /// Subtract the share b from the share a: \[c\] = \[a\] - \[b\]
    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare;

    // Subtract two shares: \[c\] = \[a\] - \[b\] and stores the result in \[a\].
    fn sub_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare);

    /// Elementwise subtraction of share b from the share a: \[c\] = \[a\] - \[b\]
    fn sub_many(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> Vec<Self::ArithmeticShare> {
        a.iter()
            .zip(b.iter())
            .map(|(a, b)| Self::sub(*a, *b))
            .collect()
    }

    /// Elementwise subtraction of share b from the share a: \[c\] = \[a\] - \[b\] and stores it
    /// into \[a\].
    fn sub_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]);

    /// Add two shares: \[c\] = \[a\] + \[b\]
    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare;

    /// Elementwise addition of two shares: \[c\] = \[a\] + \[b\]
    fn add_many(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> Vec<Self::ArithmeticShare> {
        a.iter()
            .zip(b.iter())
            .map(|(a, b)| Self::add(*a, *b))
            .collect()
    }

    /// Add two shares: \[c\] = \[a\] + \[b\] and stores the result in \[a\].
    fn add_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare);

    /// Elementwise addition of two shares: \[c\] = \[a\] + \[b\] and stores the result in \[a\].
    fn add_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        for (a, b) in a.iter_mut().zip(b.iter()) {
            Self::add_assign(a, *b);
        }
    }

    /// Adds a public value to a share: \[c\] = \[a\] + b and stores the result in \[a\].
    fn add_assign_public(
        a: &mut Self::ArithmeticShare,
        b: P::ScalarField,
        id: <Self::State as MpcState>::PartyID,
    );

    /// Elementwise addition of a public value to a share: \[c\] = \[a\] + b and stores the result in \[a\].
    fn add_assign_public_many(
        a: &mut [Self::ArithmeticShare],
        b: &[P::ScalarField],
        id: <Self::State as MpcState>::PartyID,
    ) {
        a.par_iter_mut().zip(b.par_iter()).for_each(|(a, b)| {
            Self::add_assign_public(a, *b, id);
        })
    }

    /// Elementwise addition of a public value to a share: \[c\] = a + \[b\].
    fn add_with_public_many(
        public: &[P::ScalarField],
        shared: &[Self::ArithmeticShare],
        id: <Self::State as MpcState>::PartyID,
    ) -> Vec<Self::ArithmeticShare> {
        public
            .iter()
            .zip(shared.iter())
            .map(|(a, b)| Self::add_with_public(*a, *b, id))
            .collect()
    }

    /// Elementwise addition of a public value to a share: \[c\] = a + \[b\], where a is provided
    /// as an iterator.
    fn add_with_public_many_iter(
        public: impl Iterator<Item = P::ScalarField>,
        shared: &[Self::ArithmeticShare],
        id: <Self::State as MpcState>::PartyID,
    ) -> Vec<Self::ArithmeticShare> {
        public
            .zip(shared.iter())
            .map(|(a, b)| Self::add_with_public(a, *b, id))
            .collect()
    }

    /// Negates a shared value: \[b\] = -\[a\].
    fn neg(a: Self::ArithmeticShare) -> Self::ArithmeticShare;

    /// Negates a shared value in-place: \[b\] = -\[a\] and stores the result in \[a\].
    fn neg_assign(a: &mut Self::ArithmeticShare) {
        *a = Self::neg(*a);
    }

    /// Negates shared values in-place: \[b\] = -\[a\].
    fn neg_many(a: &mut [Self::ArithmeticShare]) {
        for a in a.iter_mut() {
            *a = Self::neg(*a);
        }
    }

    /// Multiply a share b by a public value a: c = a * \[b\].
    fn mul_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    /// Multiply a share b by a public value a: c = \[a\] * b and stores the result in \[a\];
    fn mul_assign_with_public(shared: &mut Self::ArithmeticShare, public: P::ScalarField);

    /// Elementwise multiplication a share b by a public value a: c = a * \[b\].
    fn mul_with_public_many(
        public: &[P::ScalarField],
        shared: &[Self::ArithmeticShare],
    ) -> Vec<Self::ArithmeticShare> {
        debug_assert_eq!(public.len(), shared.len());
        public
            .iter()
            .zip(shared.iter())
            .map(|(public, shared)| Self::mul_with_public(*public, *shared))
            .collect()
    }

    fn add_assign_public_half_share(
        share: &mut P::ScalarField,
        public: P::ScalarField,
        id: <Self::State as MpcState>::PartyID,
    );

    fn mul_with_public_to_half_share(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> P::ScalarField;

    /// Elementwise multiplication a share b by a public value a: c = \[a\] * b and stores the
    /// result in \[a\].
    fn mul_assign_with_public_many(
        shared: &mut [Self::ArithmeticShare],
        public: &[P::ScalarField],
    ) {
        debug_assert_eq!(public.len(), shared.len());
        public
            .par_iter()
            .zip(shared.par_iter_mut())
            .for_each(|(public, shared)| {
                Self::mul_assign_with_public(shared, *public);
            });
    }

    /// Scales all elements in-place in \[a\] by the provided scale, by multiplying every share with the
    /// public scalar.
    fn scale_many_in_place(shared: &mut [Self::ArithmeticShare], scale: P::ScalarField) {
        for shared in shared.iter_mut() {
            Self::mul_assign_with_public(shared, scale);
        }
    }

    /// Scales all elements in-place in \[a\] by the provided scale, by multiplying every share with the
    /// public scalar.
    fn scale_many(
        shared: &[Self::ArithmeticShare],
        scale: P::ScalarField,
    ) -> Vec<Self::ArithmeticShare> {
        shared
            .iter()
            .map(|share| Self::mul_with_public(scale, *share))
            .collect()
    }

    /// Adds a public scalar to all elements in \[a\].
    fn add_scalar(
        shared: &[Self::ArithmeticShare],
        scalar: P::ScalarField,
        id: <Self::State as MpcState>::PartyID,
    ) -> Vec<Self::ArithmeticShare> {
        shared
            .iter()
            .map(|share| Self::add_with_public(scalar, *share, id))
            .collect()
    }

    /// Adds a public scalar to all elements in-place.
    fn add_scalar_in_place(
        shared: &mut [Self::ArithmeticShare],
        scalar: P::ScalarField,
        id: <Self::State as MpcState>::PartyID,
    ) {
        for x in shared.iter_mut() {
            Self::add_assign_public(x, scalar, id);
        }
    }

    fn local_mul_vec(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        state: &mut Self::State,
    ) -> Vec<P::ScalarField>;

    /// Restores the original sharing after doing a non-linear operation.
    fn reshare<N: Network>(
        a: Vec<P::ScalarField>,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Multiply two shares: \[c\] = \[a\] * \[b\]. Requires network communication.
    fn mul<N: Network>(
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare>;

    /// Multiply two shares: \[c\] = \[a\] * \[b\]. Requires network communication.
    fn mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Add a public value a to the share b: \[c\] = a + \[b\]
    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        id: <Self::State as MpcState>::PartyID,
    ) -> Self::ArithmeticShare;

    /// Transforms a public value into a shared value: \[a\] = a.
    fn promote_to_trivial_share(
        id: <Self::State as MpcState>::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare;

    /// Elementwise transformation of a vector of public values into a vector of shared values: \[a_i\] = a_i.
    fn promote_to_trivial_shares(
        id: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare>;

    fn promote_to_trivial_point_share(
        id: <Self::State as MpcState>::PartyID,
        public_value: P,
    ) -> Self::PointShare;

    /// Reconstructs a shared point: A = Open(\[A\]).
    fn open_point<N: Network>(
        a: Self::PointShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<P>;

    /// Reconstructs many shared points: A = Open(\[A\]).
    fn open_point_many<N: Network>(
        a: &[Self::PointShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P>>;

    /// Reconstructs many shared values: a = Open(\[a\]).
    fn open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>>;

    /// Reconstructs a shared point and a field element: (a,b) = Open(\[(a,b)\])
    fn open_point_and_field<N: Network>(
        a: Self::PointShare,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<(P, P::ScalarField)>;

    /// Reconstructs slices of shared points and field elements: (A,B) = Open(\[(A,B)\])
    fn open_point_and_field_many<N: Network>(
        a: &[Self::PointShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<(Vec<P>, Vec<P::ScalarField>)>;

    /// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
    fn mul_open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>>;

    /// Computes the inverse of many shared values: \[b\] = \[a\] ^ -1. Requires network communication.
    fn inv_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Computes the inverse of many shared values: \[a\] = \[a\] ^ -1. Requires network communication.
    /// This function ignores the case of one share to be zero and maps it to zero.
    fn inv_many_in_place<N: Network>(
        a: &mut [Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<()>;

    /// Computes the inverse of many shared values: \[a\] = \[a\] ^ -1. Requires network communication.
    /// This function ignores the case of one share to be zero and maps it to zero.
    fn inv_many_in_place_leaking_zeros<N: Network>(
        a: &mut [Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<()>;

    /// Inverts an ACVM-type and returns a share of zero if the input is zero: \[c\] = \[secret\]^(-1) if secret != 0 else \[c\] = 0.
    fn inverse_or_zero_many_in_place<N: Network>(
        net: &N,
        state: &mut Self::State,
        a: &mut [Self::ArithmeticShare],
    ) -> eyre::Result<()>;

    /// Perform msm between `points` and `scalars`
    fn msm_public_points(
        points: &[P::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare;

    /// Adds two shared points: \[c\] = \[a\] + \[b\].
    fn point_add(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare;

    /// Subs two shared points: \[c\] = \[a\] - \[b\].
    fn point_sub(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare;

    /// Evaluates shared polynomials at one point
    fn eval_poly(coeffs: &[Self::ArithmeticShare], point: P::ScalarField) -> Self::ArithmeticShare;

    /// Computes the FFT of a vector of shared field elements.
    fn fft<D: EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare>;

    /// Computes the inverse FFT of a vector of shared field elements.
    fn ifft<D: EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare>;

    /// Checks which of the shared values are zero. Returns a share of 1 if the value is zero, and a share of 0 otherwise.
    fn is_zero_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>;

    /// Multiplies a shared point by a public scalar: \[C\] = a * \[B\].
    fn scalar_mul_public_point(a: &P, b: Self::ArithmeticShare) -> Self::PointShare;
}
