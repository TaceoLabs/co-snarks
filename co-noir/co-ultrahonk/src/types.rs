use ark_ec::pairing::Pairing;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::marker::PhantomData;
use ultrahonk::ProverCrs;

pub struct ProvingKey<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) crs: ProverCrs<P>,
    pub(crate) circuit_size: u32,
    pub(crate) public_inputs: Vec<P::ScalarField>,
    pub(crate) num_public_inputs: u32,
    pub(crate) pub_inputs_offset: u32,
    // pub(crate) polynomials: Polynomials<P::ScalarField>,
    pub(crate) memory_read_records: Vec<u32>,
    pub(crate) memory_write_records: Vec<u32>,
    pub(crate) phantom_data: PhantomData<T>,
}
