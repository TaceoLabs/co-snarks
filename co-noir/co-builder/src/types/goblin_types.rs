use crate::mega_builder::MegaCircuitBuilder;
use crate::types::field_ct::BoolCT;
use crate::types::field_ct::FieldCT;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use common::honk_curve::HonkCurve;
use common::honk_proof::TranscriptFieldType;
use common::mpc::NoirUltraHonkProver;

pub struct GoblinElement<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub x: GoblinField<P::ScalarField>,
    pub y: GoblinField<P::ScalarField>,
    is_infinity: BoolCT<P, T>,
}
impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> GoblinElement<P, T> {
    pub fn new(x: GoblinField<P::ScalarField>, y: GoblinField<P::ScalarField>) -> Self {
        Self {
            x,
            y,
            is_infinity: BoolCT::default(),
        }
    }
    pub fn neg(&self) -> GoblinElement<P, T> {
        // TODO CESAR: How to negate a Goblin element
        unimplemented!()
    }
}
impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> Clone for GoblinElement<P, T> {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            is_infinity: self.is_infinity.clone(),
        }
    }
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> GoblinElement<P, T> {
    pub fn set_point_at_infinity(&mut self, is_infinity: BoolCT<P, T>) {
        self.is_infinity = is_infinity;
    }
}

#[derive(Clone)]
pub struct GoblinField<F: PrimeField> {
    pub limbs: [FieldCT<F>; 2],
}
impl<F: PrimeField> GoblinField<F> {
    pub fn new(limbs: [FieldCT<F>; 2]) -> Self {
        Self { limbs }
    }
}

impl GoblinField<TranscriptFieldType> {
    pub fn get_value<
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        D: NoirUltraHonkProver<P, ArithmeticShare = T::ArithmeticShare>,
    >(
        &self,
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
    ) -> T::AcvmType {
        let x = self.limbs[0].get_value(builder, driver);
        let y = self.limbs[1].get_value(builder, driver);
        let tmp = driver.mul_with_public(P::ScalarField::from(2u64).pow(&[136]), y);
        driver.add(x, tmp)
    }

    pub fn one<
        P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        D: NoirUltraHonkProver<P, ArithmeticShare = T::ArithmeticShare>,
    >(
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
    ) -> Self {
        Self {
            // TODO CESAR: Verify this is correct
            limbs: [
                FieldCT::from_witness(P::ScalarField::one().into(), builder),
                FieldCT::from_witness(P::ScalarField::one().into(), builder),
            ],
        }
    }
}
impl<
    P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
> GoblinElement<P, T>
{
    pub fn get_value<D: NoirUltraHonkProver<P, ArithmeticShare = T::ArithmeticShare>>(
        &self,
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
    ) -> (T::AcvmType, T::AcvmType, T::AcvmType) {
        let x = self.x.get_value(builder, driver);
        let y = self.y.get_value(builder, driver);
        let is_infinity = self.is_infinity.get_value(driver);
        (x, y, is_infinity)
    }

    pub fn one<D: NoirUltraHonkProver<P, ArithmeticShare = T::ArithmeticShare>>(
        builder: &mut MegaCircuitBuilder<P, T, D>,
        driver: &mut T,
    ) -> Self {
        Self {
            x: GoblinField::one(builder, driver),
            y: GoblinField::one(builder, driver),
            is_infinity: BoolCT::default(),
        }
    }
}
