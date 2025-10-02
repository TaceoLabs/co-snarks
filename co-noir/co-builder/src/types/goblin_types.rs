use crate::types::field_ct::BoolCT;
use crate::types::field_ct::FieldCT;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;

pub struct GoblinElement<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) x: GoblinField<P::ScalarField>,
    pub(crate) y: GoblinField<P::ScalarField>,
    is_infinity: BoolCT<P, T>,
}
impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> GoblinElement<P, T> {
    pub(crate) fn new(x: GoblinField<P::ScalarField>, y: GoblinField<P::ScalarField>) -> Self {
        Self {
            x,
            y,
            is_infinity: BoolCT::default(),
        }
    }
}
impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> GoblinElement<P, T> {
    pub(crate) fn set_point_at_infinity(&mut self, is_infinity: BoolCT<P, T>) {
        self.is_infinity = is_infinity;
    }
}

pub struct GoblinField<F: PrimeField> {
    pub(crate) limbs: [FieldCT<F>; 2],
}
impl<F: PrimeField> GoblinField<F> {
    pub(crate) fn new(limbs: [FieldCT<F>; 2]) -> Self {
        Self { limbs }
    }
}
