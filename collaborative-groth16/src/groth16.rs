use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::Result as R1CSResult;
use color_eyre::eyre::Result;
use mpc_core::{
    protocols::aby3::{network::Aby3MpcNet, Aby3Protocol},
    traits::{EcMpcProtocol, FFTProvider, PrimeFieldMpcProtocol},
};
use mpc_net::config::NetworkConfig;

use crate::circuit::Circuit;
pub type Aby3CollaborativeGroth16<P> =
    CollaborativeGroth16<Aby3Protocol<<P as Pairing>::ScalarField, Aby3MpcNet>, P>;

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
