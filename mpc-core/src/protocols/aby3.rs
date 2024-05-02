use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use eyre::{bail, Report};
use mpc_net::config::NetworkConfig;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use crate::traits::{EcMpcProtocol, FFTProvider, PrimeFieldMpcProtocol};
pub use share::Aby3PrimeFieldShare;

use self::{network::Aby3Network, share::Aby3PointShare};

pub mod id;
pub mod network;
pub mod share;

pub struct Aby3Protocol<F> {
    rngs: Aby3CorrelatedRng,
    network: network::Aby3MpcNet,
    field: PhantomData<F>,
}

impl<F: PrimeField> Aby3Protocol<F> {
    pub fn new(config: NetworkConfig) -> Result<Self, Report> {
        let mut network = network::Aby3MpcNet::new(config)?;
        let seed1: [u8; 32] = rand::thread_rng().gen();
        network.send_bytes(network.id().next_id(), seed1.to_vec().into())?;
        let seed2_bytes = network.recv_bytes(network.id().prev_id())?;
        if seed2_bytes.len() != 32 {
            bail!("Received seed is not 32 bytes long");
        }
        let seed2 = {
            let mut buf = [0u8; 32];
            buf[..].copy_from_slice(&seed2_bytes[..]);
            buf
        };
        Ok(Self {
            network,
            rngs: Aby3CorrelatedRng::new(seed1, seed2),
            field: PhantomData,
        })
    }
}

impl<F: PrimeField> PrimeFieldMpcProtocol<F> for Aby3Protocol<F> {
    type FieldShare = Aby3PrimeFieldShare<F>;
    type FieldShareSlice = ();
    type FieldShareVec = ();

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a - b
    }

    fn mul(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        let local_a = a * b + self.rngs.masking_field_element::<F>();
        self.network.send_next(local_a).unwrap();
        let local_b = self.network.recv_prev().unwrap();
        Self::FieldShare {
            a: local_a,
            b: local_b,
        }
    }

    fn inv(&mut self, _a: &Self::FieldShare) -> Self::FieldShare {
        todo!()
    }

    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare {
        -a
    }

    fn rand(&mut self) -> Self::FieldShare {
        let (a, b) = self.rngs.random_fes();
        Self::FieldShare { a, b }
    }
}

impl<C: CurveGroup> EcMpcProtocol<C> for Aby3Protocol<C::ScalarField> {
    type PointShare = Aby3PointShare<C>;

    fn add_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        a + b
    }

    fn sub_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        a - b
    }

    fn scalar_mul_public_point(&mut self, a: &C, b: &Self::FieldShare) -> Self::PointShare {
        Self::PointShare {
            a: a.mul(b.a),
            b: a.mul(b.b),
        }
    }

    fn scalar_mul_public_scalar(
        &mut self,
        a: &Self::PointShare,
        b: &<C>::ScalarField,
    ) -> Self::PointShare {
        Self::PointShare {
            a: a.a * b,
            b: a.b * b,
        }
    }

    fn scalar_mul(&mut self, a: &Self::PointShare, b: &Self::FieldShare) -> Self::PointShare {
        todo!("Full MPC protocol to compute secret point times secret scalar")
    }
}

impl<F: PrimeField> FFTProvider<F> for Aby3Protocol<F> {
    fn fft(&mut self, data: &[Self::FieldShare]) -> Vec<Self::FieldShare> {
        todo!()
    }

    fn ifft(&mut self, data: &[Self::FieldShare]) -> Vec<Self::FieldShare> {
        todo!()
    }
}

struct Aby3CorrelatedRng {
    rng1: ChaCha12Rng,
    rng2: ChaCha12Rng,
}

impl Aby3CorrelatedRng {
    pub fn new(seed1: [u8; 32], seed2: [u8; 32]) -> Self {
        let rng1 = ChaCha12Rng::from_seed(seed1);
        let rng2 = ChaCha12Rng::from_seed(seed2);
        Self { rng1, rng2 }
    }

    pub fn masking_field_element<F: PrimeField>(&mut self) -> F {
        let (a, b) = self.random_fes::<F>();
        a - b
    }
    pub fn random_fes<F: PrimeField>(&mut self) -> (F, F) {
        let a = F::rand(&mut self.rng1);
        let b = F::rand(&mut self.rng2);
        (a, b)
    }
}
