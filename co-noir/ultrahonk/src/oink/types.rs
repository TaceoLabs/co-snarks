use crate::plain_prover_flavour::PlainProverFlavour;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_builder::prelude::Polynomial;

pub(crate) struct ProverMemory<P: CurveGroup, L: PlainProverFlavour> {
    /// column 3
    pub(crate) w_4: Polynomial<P::ScalarField>,
    /// column 4
    pub(crate) z_perm: Polynomial<P::ScalarField>,
    /// column 5
    pub(crate) lookup_inverses: Polynomial<P::ScalarField>,
    pub(crate) calldata_inverses: Polynomial<P::ScalarField>,
    pub(crate) secondary_calldata_inverses: Polynomial<P::ScalarField>,
    pub(crate) return_data_inverses: Polynomial<P::ScalarField>,
    pub(crate) public_input_delta: P::ScalarField,
    pub(crate) challenges: Challenges<P::ScalarField, L>,
}

pub(crate) struct VerifierMemory<P: CurveGroup, L: PlainProverFlavour> {
    pub(crate) public_input_delta: P::ScalarField,
    pub(crate) witness_commitments: L::WitnessEntities<P::Affine>,
    pub(crate) challenges: Challenges<P::ScalarField, L>,
}

pub(crate) struct Challenges<F: PrimeField, L: PlainProverFlavour> {
    pub(crate) eta_1: F,
    pub(crate) eta_2: F,
    pub(crate) eta_3: F,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) alphas: L::Alphas<F>,
}

impl<F: PrimeField, L: PlainProverFlavour> Default for Challenges<F, L> {
    fn default() -> Self {
        Self {
            eta_1: Default::default(),
            eta_2: Default::default(),
            eta_3: Default::default(),
            beta: Default::default(),
            gamma: Default::default(),
            alphas: L::Alphas::default(),
        }
    }
}

impl<P: CurveGroup, L: PlainProverFlavour> Default for ProverMemory<P, L> {
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

impl<P: CurveGroup, L: PlainProverFlavour> Default for VerifierMemory<P, L> {
    fn default() -> Self {
        Self {
            public_input_delta: Default::default(),
            witness_commitments: Default::default(),
            challenges: Default::default(),
        }
    }
}
