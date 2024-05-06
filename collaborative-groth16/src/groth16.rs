use std::marker::PhantomData;

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::Result as R1CSResult;
use circom_types::groth16::witness::Witness;
use color_eyre::eyre::Result;
use mpc_core::{
    protocols::aby3::{self, network::Aby3MpcNet, share::Aby3PointShare, Aby3Protocol},
    traits::{EcMpcProtocol, FFTProvider, PrimeFieldMpcProtocol},
};
use mpc_net::config::NetworkConfig;
use rand::{CryptoRng, Rng};

use crate::circuit::Circuit;
pub type Aby3CollaborativeGroth16<P> =
    CollaborativeGroth16<Aby3Protocol<<P as Pairing>::ScalarField, Aby3MpcNet>, P>;

pub struct SharedWitness<T, F: PrimeField>
where
    T: PrimeFieldMpcProtocol<F>,
{
    //this will be a VecShareType
    pub values: Vec<<T as PrimeFieldMpcProtocol<F>>::FieldShare>,
}

pub struct SharedVerifyingKey<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + EcMpcProtocol<P::G1>
        + EcMpcProtocol<P::G2>
        + FFTProvider<P::ScalarField>,
{
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: <T as EcMpcProtocol<P::G1>>::PointShare,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: <T as EcMpcProtocol<P::G2>>::PointShare,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: <T as EcMpcProtocol<P::G2>>::PointShare,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: <T as EcMpcProtocol<P::G2>>::PointShare,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is the generator of `E::G1`.
    pub gamma_abc_g1: Vec<<T as EcMpcProtocol<P::G1>>::PointShare>,
}

pub struct SharedProvingKey<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + EcMpcProtocol<P::G1>
        + EcMpcProtocol<P::G2>
        + FFTProvider<P::ScalarField>,
{
    /// The underlying verification key.
    pub vk: SharedVerifyingKey<T, P>,
    pub beta_g1: <T as EcMpcProtocol<P::G1>>::PointShare,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: <T as EcMpcProtocol<P::G1>>::PointShare,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: Vec<<T as EcMpcProtocol<P::G1>>::PointShare>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: Vec<<T as EcMpcProtocol<P::G1>>::PointShare>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: Vec<<T as EcMpcProtocol<P::G2>>::PointShare>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: Vec<<T as EcMpcProtocol<P::G1>>::PointShare>,
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: Vec<<T as EcMpcProtocol<P::G1>>::PointShare>,
    phantom_data_p: PhantomData<P>,
}

pub struct CollaborativeGroth16<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + EcMpcProtocol<P::G1>
        + EcMpcProtocol<P::G2>
        + FFTProvider<P::ScalarField>,
{
    _driver: T,
    phantom_data: PhantomData<P>,
}
//Aby3Protocol<<P as Pairing>::ScalarField, Aby3MpcNet

impl<T, P: Pairing> CollaborativeGroth16<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + EcMpcProtocol<P::G1>
        + EcMpcProtocol<P::G2>
        + FFTProvider<P::ScalarField>,
{
    pub fn new(driver: T) -> Self {
        Self {
            _driver: driver,
            phantom_data: PhantomData,
        }
    }
    pub fn prove(&self, _pk: &ProvingKey<P>, _circuit: Circuit<P>) -> Proof<P> {
        todo!()
    }

    pub fn verify(
        &self,
        pvk: &PreparedVerifyingKey<P>,
        proof: &Proof<P>,
        public_inputs: &[P::ScalarField],
    ) -> R1CSResult<bool> {
        Groth16::<P>::verify_proof(pvk, proof, public_inputs)
    }
}

impl<P: Pairing> Aby3CollaborativeGroth16<P> {
    pub fn with_network_config(config: NetworkConfig) -> Result<Self> {
        let mpc_net = Aby3MpcNet::new(config)?;
        let driver = Aby3Protocol::<P::ScalarField, Aby3MpcNet>::new(mpc_net)?;
        Ok(CollaborativeGroth16::new(driver))
    }
}

impl<P: Pairing> SharedProvingKey<Aby3Protocol<P::ScalarField, Aby3MpcNet>, P> {
    pub fn share_aby3<R: Rng + CryptoRng>(pk: &ProvingKey<P>, rng: &mut R) -> [Self; 3] {
        let [vk1, vk2, vk3] = SharedVerifyingKey::share_aby3(&pk.vk, rng);
        let [beta1, beta2, beta3] = aby3::utils::share_curve_point(P::G1::from(pk.beta_g1), rng);
        let [delta1, delta2, delta3] =
            aby3::utils::share_curve_point(P::G1::from(pk.delta_g1), rng);
        let [a_query1, a_query2, a_query3] = share_vec::<P::G1, P::G1Affine, _>(&pk.a_query, rng);
        let [b_g1_query1, b_g1_query2, b_g1_query3] =
            share_vec::<P::G1, P::G1Affine, _>(&pk.b_g1_query, rng);
        let [b_g2_query1, b_g2_query2, b_g2_query3] =
            share_vec::<P::G2, P::G2Affine, _>(&pk.b_g2_query, rng);
        let [h_query1, h_query2, h_query3] = share_vec::<P::G1, P::G1Affine, _>(&pk.h_query, rng);
        let [l_query1, l_query2, l_query3] = share_vec::<P::G1, P::G1Affine, _>(&pk.l_query, rng);

        let pk1 = Self {
            vk: vk1,
            beta_g1: beta1,
            delta_g1: delta1,
            a_query: a_query1,
            b_g1_query: b_g1_query1,
            b_g2_query: b_g2_query1,
            h_query: h_query1,
            l_query: l_query1,
            phantom_data_p: PhantomData,
        };
        let pk2 = Self {
            vk: vk2,
            beta_g1: beta2,
            delta_g1: delta2,
            a_query: a_query2,
            b_g1_query: b_g1_query2,
            b_g2_query: b_g2_query2,
            h_query: h_query2,
            l_query: l_query2,
            phantom_data_p: PhantomData,
        };
        let pk3 = Self {
            vk: vk3,
            beta_g1: beta3,
            delta_g1: delta3,
            a_query: a_query3,
            b_g1_query: b_g1_query3,
            b_g2_query: b_g2_query3,
            h_query: h_query3,
            l_query: l_query3,
            phantom_data_p: PhantomData,
        };
        [pk1, pk2, pk3]
    }
}

impl<F: PrimeField> SharedWitness<Aby3Protocol<F, Aby3MpcNet>, F> {
    pub fn share_aby3<R: Rng + CryptoRng>(_witness: &Witness<F>, _rng: &mut R) -> [Self; 3] {
        todo!()
    }
}
//TODO THIS WILL BE REMOVED AS SOON AS WE HAVE THE VECSHARE TYPE
//===============DELETE ME ===============
fn share_vec<C: CurveGroup, S, R: Rng + CryptoRng>(
    to_share: &[S],
    rng: &mut R,
) -> [Vec<Aby3PointShare<C>>; 3]
where
    C: From<S>,
    S: Copy,
{
    let mut share1 = Vec::with_capacity(to_share.len());
    let mut share2 = Vec::with_capacity(to_share.len());
    let mut share3 = Vec::with_capacity(to_share.len());
    for p in to_share {
        let [s1, s2, s3] = aby3::utils::share_curve_point(C::from(*p), rng);
        share1.push(s1);
        share2.push(s2);
        share3.push(s3);
    }
    [share1, share2, share3]
}
//========================================

impl<P: Pairing> SharedVerifyingKey<Aby3Protocol<P::ScalarField, Aby3MpcNet>, P> {
    pub fn share_aby3<R: Rng + CryptoRng>(vk: &VerifyingKey<P>, rng: &mut R) -> [Self; 3] {
        let [alpha1, alpha2, alpha3] =
            aby3::utils::share_curve_point(P::G1::from(vk.alpha_g1), rng);
        let [beta1, beta2, beta3] = aby3::utils::share_curve_point(P::G2::from(vk.beta_g2), rng);
        let [gamma1, gamma2, gamma3] =
            aby3::utils::share_curve_point(P::G2::from(vk.gamma_g2), rng);
        let [delta1, delta2, delta3] =
            aby3::utils::share_curve_point(P::G2::from(vk.delta_g2), rng);
        let [gamma_abc1, gamma_abc2, gamma_abc3] =
            share_vec::<P::G1, P::G1Affine, _>(&vk.gamma_abc_g1, rng);
        let vk1 = Self {
            alpha_g1: alpha1,
            beta_g2: beta1,
            gamma_g2: gamma1,
            delta_g2: delta1,
            gamma_abc_g1: gamma_abc1,
        };
        let vk2 = Self {
            alpha_g1: alpha2,
            beta_g2: beta2,
            gamma_g2: gamma2,
            delta_g2: delta2,
            gamma_abc_g1: gamma_abc2,
        };
        let vk3 = Self {
            alpha_g1: alpha3,
            beta_g2: beta3,
            gamma_g2: gamma3,
            delta_g2: delta3,
            gamma_abc_g1: gamma_abc3,
        };
        [vk1, vk2, vk3]
    }
}
