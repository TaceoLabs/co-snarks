use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_noir_common::polynomials::polynomial::Polynomial;

use co_noir_common::mpc::NoirUltraHonkProver;
pub struct ProverMemory<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) w_4: Polynomial<T::ArithmeticShare>, // column 3
    pub(crate) z_perm: Polynomial<T::ArithmeticShare>, // column 4
    pub(crate) lookup_inverses: Polynomial<T::ArithmeticShare>, // column 5
    pub(crate) calldata_inverses: Polynomial<T::ArithmeticShare>,
    pub(crate) secondary_calldata_inverses: Polynomial<T::ArithmeticShare>,
    pub(crate) return_data_inverses: Polynomial<T::ArithmeticShare>,
    pub(crate) public_input_delta: P::ScalarField,
    pub(crate) challenges: Challenges<P::ScalarField>,
}

pub(crate) struct Challenges<F: PrimeField> {
    pub(crate) eta_1: F,
    pub(crate) eta_2: F,
    pub(crate) eta_3: F,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) alphas: Vec<F>,
}

impl<F: PrimeField> Default for Challenges<F> {
    fn default() -> Self {
        Self {
            eta_1: Default::default(),
            eta_2: Default::default(),
            eta_3: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
            alphas: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for ProverMemory<T, P> {
    fn default() -> Self {
        Self {
            w_4: Default::default(),
            z_perm: Default::default(),
            lookup_inverses: Default::default(),
            calldata_inverses: Default::default(),
            secondary_calldata_inverses: Default::default(),
            return_data_inverses: Default::default(),
            public_input_delta: Default::default(),
            challenges: Default::default(),
        }
    }
}
