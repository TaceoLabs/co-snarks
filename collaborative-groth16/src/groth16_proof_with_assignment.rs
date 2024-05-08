// TODO move this file

use crate::groth16::CollaborativeGroth16;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_groth16::{Proof, ProvingKey};
use ark_std::{end_timer, start_timer};
use color_eyre::eyre::Result;
use mpc_core::traits::{
    EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};

type FieldShare<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShare;
type FieldShareSlice<'a, T, C> = <T as PrimeFieldMpcProtocol<
    <<C as CurveGroup>::Affine as AffineRepr>::ScalarField,
>>::FieldShareSlice<'a>;
type PointShare<T, C> = <T as EcMpcProtocol<C>>::PointShare;

impl<T, P: Pairing> CollaborativeGroth16<T, P> where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>
{
}
