use crate::RngType;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use rand::{Rng, SeedableRng};

pub(crate) struct Aby3CorrelatedRng {
    pub(crate) rand: Aby3Rand,
    pub(crate) bitcomp1: Aby3RandBitComp,
    pub(crate) bitcomp2: Aby3RandBitComp,
}

impl Aby3CorrelatedRng {
    pub fn new(rand: Aby3Rand, bitcomp1: Aby3RandBitComp, bitcomp2: Aby3RandBitComp) -> Self {
        Self {
            rand,
            bitcomp1,
            bitcomp2,
        }
    }
}

pub(crate) struct Aby3Rand {
    rng1: RngType,
    rng2: RngType,
}

impl Aby3Rand {
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

    pub fn random_seeds(&mut self) -> ([u8; crate::SEED_SIZE], [u8; crate::SEED_SIZE]) {
        let seed1 = self.rng1.gen();
        let seed2 = self.rng2.gen();
        (seed1, seed2)
    }
}

/// This struct is responsible for creating random shares for the Binary to Arithmetic conversion. The approach is the following: for a final sharing x = x1 + x2 + x3, we want to have random values x2, x3 and subtract these from the original value x using a binary circuit to get the share x1. Hence, we need to sample random x2 and x3 and share them amongst the parties. One RandBitComp struct is responsible for either sampling x2 or x3. For sampling x2, parties 1 and 2 will get x2 in plain (since this is the final share of x), so they need to have a PRF key from all parties. party 3, however, will not get x2 in plain and must thus only be able to sample its shares of x2, requiring two PRF keys.
pub(crate) struct Aby3RandBitComp {
    rng1: RngType,
    rng2: RngType,
    rng3: Option<RngType>,
}

impl Aby3RandBitComp {
    pub fn new_2keys(rng1: [u8; crate::SEED_SIZE], rng2: [u8; crate::SEED_SIZE]) -> Self {
        Self {
            rng1: RngType::from_seed(rng1),
            rng2: RngType::from_seed(rng2),
            rng3: None,
        }
    }

    pub fn new_3keys(
        rng1: [u8; crate::SEED_SIZE],
        rng2: [u8; crate::SEED_SIZE],
        rng3: [u8; crate::SEED_SIZE],
    ) -> Self {
        Self {
            rng1: RngType::from_seed(rng1),
            rng2: RngType::from_seed(rng2),
            rng3: Some(RngType::from_seed(rng3)),
        }
    }

    pub fn random_fes_3keys<F: PrimeField>(&mut self) -> (F, F, F) {
        let a = F::rand(&mut self.rng1);
        let b = F::rand(&mut self.rng2);
        let c = if let Some(rng3) = &mut self.rng3 {
            F::rand(rng3)
        } else {
            unreachable!()
        };
        (a, b, c)
    }
}
