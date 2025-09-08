use ark_ec::CurveGroup;
use co_acvm::mpc::NoirWitnessExtensionProtocol;

use crate::types::types::{
    AddQuad, AddTriple, MulQuad, PolyTriple, Poseidon2ExternalGate, Poseidon2InternalGate,
    RangeList,
};

#[expect(private_interfaces)]
pub trait GenericBuilder<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    type TraceBlock;
    fn get_poseidon2_external_mut(&mut self) -> &mut Self::TraceBlock;
    fn get_poseidon2_internal_mut(&mut self) -> &mut Self::TraceBlock;

    fn create_add_gate(&mut self, inp: &AddTriple<P::ScalarField>);
    fn create_big_add_gate(&mut self, inp: &AddQuad<P::ScalarField>, include_next_gate_w_4: bool);
    fn create_poseidon2_external_gate(&mut self, inp: &Poseidon2ExternalGate);
    fn create_poseidon2_internal_gate(&mut self, inp: &Poseidon2InternalGate);
    fn create_big_mul_gate(&mut self, inp: &MulQuad<P::ScalarField>);
    fn create_poly_gate(&mut self, inp: &PolyTriple<P::ScalarField>);
    fn create_bool_gate(&mut self, variable_index: u32);
    fn create_dummy_gate(block: &mut Self::TraceBlock, a: u32, b: u32, c: u32, d: u32);
    fn create_new_range_constraint(&mut self, variable_index: u32, target_range: u64);
    fn create_dummy_constraints(&mut self, variable_index: &[u32]);

    fn zero_idx(&self) -> u32;

    fn get_variable(&self, index: usize) -> T::AcvmType;
    fn add_variable(&mut self, value: T::AcvmType) -> u32;
    fn update_variable(&mut self, index: usize, value: T::AcvmType);

    fn get_new_tag(&mut self) -> u32;
    fn create_tag(&mut self, tag_index: u32, tau_index: u32) -> u32;
    fn assign_tag(&mut self, variable_index: u32, tag: u32);

    fn create_range_list(&mut self, target_range: u64) -> RangeList;
    fn decompose_into_default_range(
        &mut self,
        driver: &mut T,
        variable_index: u32,
        num_bits: u64,
        decompose: Option<&[T::ArithmeticShare]>, // If already decomposed, values are here
        target_range_bitnum: u64,
    ) -> eyre::Result<Vec<u32>>;

    fn check_selector_length_consistency(&self);

    fn assert_if_has_witness(&self, input: bool);
    fn assert_equal_constant(&mut self, a_idx: usize, b: P::ScalarField);
    fn assert_equal(&mut self, a_idx: usize, b_idx: usize);
}
