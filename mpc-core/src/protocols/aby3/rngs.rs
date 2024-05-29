use crate::RngType;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use rand::{Rng, SeedableRng};

pub(crate) struct Aby3CorrelatedRng {
    rng1: RngType,
    rng2: RngType,
}

impl Aby3CorrelatedRng {
    pub fn new(seed1: [u8; crate::SEED_SIZE], seed2: [u8; crate::SEED_SIZE]) -> Self {
        let rng1 = RngType::from_seed(seed1);
        let rng2 = RngType::from_seed(seed2);
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

    pub fn masking_ec_element<C: CurveGroup>(&mut self) -> C {
        let (a, b) = self.random_ecs::<C>();
        a - b
    }

    pub fn random_ecs<C: CurveGroup>(&mut self) -> (C, C) {
        let a = C::rand(&mut self.rng1);
        let b = C::rand(&mut self.rng2);
        (a, b)
    }

    pub fn random_biguint<F: PrimeField>(&mut self) -> (BigUint, BigUint) {
        let limbsize = (F::MODULUS_BIT_SIZE + 31) / 32;
        let a = BigUint::new((0..limbsize).map(|_| self.rng1.gen()).collect());
        let b = BigUint::new((0..limbsize).map(|_| self.rng2.gen()).collect());
        (a, b)
    }
}
