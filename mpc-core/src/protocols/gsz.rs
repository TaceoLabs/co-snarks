use self::network::GSZNetwork;
use ark_ff::PrimeField;
use eyre::Report;
use std::marker::PhantomData;

pub mod fieldshare;
pub mod network;
pub mod pointshare;

pub struct GSZProtocol<F: PrimeField, N: GSZNetwork> {
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: GSZNetwork> GSZProtocol<F, N> {
    pub fn new(network: N) -> Result<Self, Report> {
        Ok(Self {
            network,
            field: PhantomData,
        })
    }
}
