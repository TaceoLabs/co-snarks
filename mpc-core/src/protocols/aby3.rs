use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use eyre::{bail, Report};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use crate::traits::{EcMpcProtocol, FFTProvider, PrimeFieldMpcProtocol};
pub use share::Aby3PrimeFieldShare;

use self::{
    network::Aby3Network,
    share::{Aby3PointShare, Aby3PrimeFieldShareSlice, Aby3PrimeFieldShareVec},
};

pub mod id;
pub mod network;
pub mod share;

type IoResult<T> = std::io::Result<T>;

pub mod utils {
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use rand::{CryptoRng, Rng};

    use super::{share::Aby3PointShare, Aby3PrimeFieldShare};

    pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
        val: F,
        rng: &mut R,
    ) -> [Aby3PrimeFieldShare<F>; 3] {
        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = val - a - b;
        let share1 = Aby3PrimeFieldShare::new(a, b);
        let share2 = Aby3PrimeFieldShare::new(b, c);
        let share3 = Aby3PrimeFieldShare::new(c, a);
        [share1, share2, share3]
    }

    pub fn combine_field_element<F: PrimeField>(
        share1: Aby3PrimeFieldShare<F>,
        share2: Aby3PrimeFieldShare<F>,
        share3: Aby3PrimeFieldShare<F>,
    ) -> F {
        share1.a + share2.a + share3.a
    }

    pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
        val: C,
        rng: &mut R,
    ) -> [Aby3PointShare<C>; 3] {
        let a = C::rand(rng);
        let b = C::rand(rng);
        let c = val - a - b;
        let share1 = Aby3PointShare::new(a, b);
        let share2 = Aby3PointShare::new(b, c);
        let share3 = Aby3PointShare::new(c, a);
        [share1, share2, share3]
    }

    pub fn combine_curve_point<C: CurveGroup>(
        share1: Aby3PointShare<C>,
        share2: Aby3PointShare<C>,
        share3: Aby3PointShare<C>,
    ) -> C {
        share1.a + share2.a + share3.a
    }
}

pub struct Aby3Protocol<F: PrimeField, N: Aby3Network<F>> {
    rngs: Aby3CorrelatedRng,
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: Aby3Network<F>> Aby3Protocol<F, N> {
    pub fn new(mut network: N) -> Result<Self, Report> {
        let seed1: [u8; 32] = rand::thread_rng().gen();
        let seed2_bytes = network.send_and_receive_seed(seed1.to_vec().into())?;
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

impl<'a, F: PrimeField, N: Aby3Network<F>> PrimeFieldMpcProtocol<'a, F> for Aby3Protocol<F, N> {
    type FieldShare = Aby3PrimeFieldShare<F>;
    type FieldShareSlice = Aby3PrimeFieldShareSlice<'a, F>;
    type FieldShareVec = Aby3PrimeFieldShareVec<F>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a - b
    }

    fn mul(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> IoResult<Self::FieldShare> {
        let local_a = a * b + self.rngs.masking_field_element::<F>();
        self.network.send_next(local_a)?;
        let local_b = self.network.recv_prev()?;
        Ok(Self::FieldShare {
            a: local_a,
            b: local_b,
        })
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

impl<'a, C: CurveGroup, N: Aby3Network<C::ScalarField>> EcMpcProtocol<'a, C>
    for Aby3Protocol<C::ScalarField, N>
{
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

    fn scalar_mul(&mut self, _a: &Self::PointShare, _b: &Self::FieldShare) -> Self::PointShare {
        todo!("Full MPC protocol to compute secret point times secret scalar")
    }
}

impl<'a, F: PrimeField, N: Aby3Network<F>> FFTProvider<'a, F> for Aby3Protocol<F, N> {
    fn fft<D: EvaluationDomain<F>>(
        &mut self,
        _data: &Self::FieldShareSlice,
        _domain: &D,
    ) -> Vec<Self::FieldShare> {
        todo!()
    }

    fn ifft<D: EvaluationDomain<F>>(
        &mut self,
        _data: &Self::FieldShareSlice,
        _domain: &D,
    ) -> Vec<Self::FieldShare> {
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
