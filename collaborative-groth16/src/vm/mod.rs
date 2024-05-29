use ark_ff::PrimeField;
use mpc_core::traits::{CircomWitnessExtensionProtocol, PrimeFieldMpcProtocol};

pub mod compiler;
pub mod mpc_vm;
mod op_codes;
pub mod plain_vm;
mod stack;

//this is just for the time being
pub struct PlainDriver {}

impl<F: PrimeField> PrimeFieldMpcProtocol<F> for PlainDriver {
    type FieldShare = ();

    type FieldShareVec = Vec<()>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        todo!()
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        todo!()
    }

    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        todo!()
    }

    fn sub_assign_vec(&mut self, a: &mut Self::FieldShareVec, b: &Self::FieldShareVec) {
        todo!()
    }

    fn mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare> {
        todo!()
    }

    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        todo!()
    }

    fn inv(&mut self, a: &Self::FieldShare) -> std::io::Result<Self::FieldShare> {
        todo!()
    }

    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare {
        todo!()
    }

    fn rand(&mut self) -> std::io::Result<Self::FieldShare> {
        todo!()
    }

    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F> {
        todo!()
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareVec,
        b: &Self::FieldShareVec,
    ) -> std::io::Result<Self::FieldShareVec> {
        todo!()
    }

    fn promote_to_trivial_share(&self, public_values: &[F]) -> Self::FieldShareVec {
        todo!()
    }

    fn distribute_powers_and_mul_by_const(&mut self, coeffs: &mut Self::FieldShareVec, g: F, c: F) {
        todo!()
    }

    fn evaluate_constraint(
        &mut self,
        lhs: &[(F, usize)],
        public_inputs: &[F],
        private_witness: &Self::FieldShareVec,
    ) -> Self::FieldShare {
        todo!()
    }

    fn clone_from_slice(
        &self,
        dst: &mut Self::FieldShareVec,
        src: &Self::FieldShareVec,
        dst_offset: usize,
        src_offset: usize,
        len: usize,
    ) {
        todo!()
    }

    fn print(&self, to_print: &Self::FieldShareVec) {
        todo!()
    }
}

impl<F: PrimeField> CircomWitnessExtensionProtocol<F> for PlainDriver {
    type VmType = F;

    fn vm_add(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        a + b
    }

    fn vm_sub(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        a - b
    }

    fn vm_mul(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        Ok(a * b)
    }

    fn vm_neg(&mut self, a: Self::VmType) -> Self::VmType {
        -a
    }

    fn vm_div(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        todo!()
    }

    fn vm_int_div(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        todo!()
    }

    fn is_zero(&self, a: Self::VmType) -> bool {
        todo!()
    }

    fn vm_lt(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn vm_le(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn vm_gt(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn vm_ge(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn vm_eq(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn vm_neq(&mut self, a: Self::VmType, b: Self::VmType) -> Self::VmType {
        todo!()
    }

    fn vm_shift_r(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        todo!()
    }

    fn vm_shift_l(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        todo!()
    }

    fn vm_bool_and(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        todo!()
    }

    fn vm_bit_xor(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        todo!()
    }

    fn vm_bit_or(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        todo!()
    }

    fn vm_bit_and(&mut self, a: Self::VmType, b: Self::VmType) -> std::io::Result<Self::VmType> {
        todo!()
    }

    fn to_index(&self, a: Self::VmType) -> F {
        todo!()
    }
}
