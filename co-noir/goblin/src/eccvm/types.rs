#![expect(unused)]
use ark_ec::CurveGroup;
use co_builder::HonkProofResult;
use co_builder::{
    TranscriptFieldType,
    prelude::{Polynomial, ProverCrs},
};
use ultrahonk::{
    plain_prover_flavour::PlainProverFlavour,
    prelude::{
        AllEntities, RelationParameters, SmallSubgroupIPAProver, Transcript, TranscriptHasher,
    },
};

pub(crate) struct ProverMemory<P: CurveGroup, L: PlainProverFlavour> {
    pub(crate) polys: AllEntities<Vec<P::ScalarField>, L>,
    pub(crate) relation_parameters: RelationParameters<P::ScalarField, L>,
}

pub(crate) struct TranslationData<P: CurveGroup> {
    // M(X) whose Lagrange coefficients are given by (m_0 || m_1 || ... || m_{NUM_TRANSLATION_EVALUATIONS-1} || 0 || ... || 0)
    pub concatenated_polynomial_lagrange: Polynomial<P::ScalarField>,

    // M(X) + Z_H(X) * R(X), where R(X) is a random polynomial of length = WITNESS_MASKING_TERM_LENGTH
    pub masked_concatenated_polynomial: Polynomial<P::ScalarField>,
}
impl<P: CurveGroup> TranslationData<P> {
    pub(crate) fn new<H: TranscriptHasher<TranscriptFieldType>>(
        translation_polynomials: &[&Polynomial<P::ScalarField>],
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
    ) -> Self {
        todo!()
    }

    pub fn compute_small_ipa_prover<
        H: TranscriptHasher<TranscriptFieldType>,
        // R: rand::Rng + rand::CryptoRng,
    >(
        &mut self,
        evaluation_challenge_x: P::ScalarField,
        batching_challenge_v: P::ScalarField,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<SmallSubgroupIPAProver<P>> {
        todo!()
    }
}

// use std::array::IntoIter;
// use std::collections::VecDeque;

// pub struct VMOperation<P: CurveGroup> {
//     pub op_code: EccOpCode,
//     pub base_point: <CycleGroup as CycleGroupTrait>::AffineElement,
//     pub z1: BigUint,
//     pub z2: BigUint,
//     pub mul_scalar_full: <CycleGroup as CycleGroupTrait>::SubgroupField,
// }

// impl<CycleGroup> PartialEq for VMOperation<CycleGroup>
// where
//     CycleGroup: CycleGroupTrait,
//     <CycleGroup as CycleGroupTrait>::AffineElement: PartialEq,
//     <CycleGroup as CycleGroupTrait>::SubgroupField: PartialEq,
// {
//     fn eq(&self, other: &Self) -> bool {
//         self.op_code == other.op_code
//             && self.base_point == other.base_point
//             && self.z1 == other.z1
//             && self.z2 == other.z2
//             && self.mul_scalar_full == other.mul_scalar_full
//     }
// }

// impl<CycleGroup> Eq for VMOperation<CycleGroup>
// where
//     CycleGroup: CycleGroupTrait,
//     <CycleGroup as CycleGroupTrait>::AffineElement: Eq,
//     <CycleGroup as CycleGroupTrait>::SubgroupField: Eq,
// {
// }

// pub struct ECCOpQueue {
//     point_at_infinity: Point,
//     accumulator: Point,
//     eccvm_ops_table: EccvmOpsTable,
//     ultra_ops_table: UltraEccOpsTable,
//     eccvm_ops_reconstructed: Vec<ECCVMOperation>,
//     ultra_ops_reconstructed: Vec<UltraOp>,
//     eccvm_row_tracker: EccvmRowTracker,
// }

// impl ECCOpQueue {
//     pub fn new() -> Self {
//         let mut queue = Self {
//             point_at_infinity: Point::default(),
//             accumulator: Point::default(),
//             eccvm_ops_table: EccvmOpsTable::new(),
//             ultra_ops_table: UltraEccOpsTable::new(),
//             eccvm_ops_reconstructed: Vec::new(),
//             ultra_ops_reconstructed: Vec::new(),
//             eccvm_row_tracker: EccvmRowTracker::new(),
//         };
//         queue.initialize_new_subtable();
//         queue
//     }

//     pub fn initialize_new_subtable(&mut self) {
//         self.eccvm_ops_table.create_new_subtable();
//         self.ultra_ops_table.create_new_subtable();
//     }

//     pub fn construct_ultra_ops_table_columns(&self) -> [Polynomial<Fr>; ULTRA_TABLE_WIDTH] {
//         self.ultra_ops_table.construct_table_columns()
//     }

//     pub fn construct_previous_ultra_ops_table_columns(
//         &self,
//     ) -> [Polynomial<Fr>; ULTRA_TABLE_WIDTH] {
//         self.ultra_ops_table.construct_previous_table_columns()
//     }

//     pub fn construct_current_ultra_ops_subtable_columns(
//         &self,
//     ) -> [Polynomial<Fr>; ULTRA_TABLE_WIDTH] {
//         self.ultra_ops_table
//             .construct_current_ultra_ops_subtable_columns()
//     }

//     pub fn construct_full_eccvm_ops_table(&mut self) {
//         self.eccvm_ops_reconstructed = self.eccvm_ops_table.get_reconstructed();
//     }

//     pub fn construct_full_ultra_ops_table(&mut self) {
//         self.ultra_ops_reconstructed = self.ultra_ops_table.get_reconstructed();
//     }

//     pub fn get_ultra_ops_table_num_rows(&self) -> usize {
//         self.ultra_ops_table.ultra_table_size()
//     }

//     pub fn get_current_ultra_ops_subtable_num_rows(&self) -> usize {
//         self.ultra_ops_table.current_ultra_subtable_size()
//     }

//     pub fn get_eccvm_ops(&mut self) -> &Vec<ECCVMOperation> {
//         if self.eccvm_ops_reconstructed.is_empty() {
//             self.construct_full_eccvm_ops_table();
//         }
//         &self.eccvm_ops_reconstructed
//     }

//     pub fn get_ultra_ops(&mut self) -> &Vec<UltraOp> {
//         if self.ultra_ops_reconstructed.is_empty() {
//             self.construct_full_ultra_ops_table();
//         }
//         &self.ultra_ops_reconstructed
//     }

//     pub fn get_num_msm_rows(&self) -> usize {
//         self.eccvm_row_tracker.get_num_msm_rows()
//     }

//     pub fn get_num_rows(&self) -> usize {
//         self.eccvm_row_tracker.get_num_rows()
//     }

//     pub fn get_number_of_muls(&self) -> u32 {
//         self.eccvm_row_tracker.get_number_of_muls()
//     }

//     pub fn set_eccvm_ops_for_fuzzing(&mut self, eccvm_ops_in: Vec<ECCVMOperation>) {
//         self.eccvm_ops_reconstructed = eccvm_ops_in;
//     }

//     pub fn add_erroneous_equality_op_for_testing(&mut self) {
//         let op_code = EccOpCode {
//             eq: true,
//             reset: true,
//         };
//         self.append_eccvm_op(ECCVMOperation {
//             op_code,
//             base_point: Point::random_element(),
//             ..Default::default()
//         });
//     }

//     pub fn empty_row_for_testing(&mut self) {
//         self.append_eccvm_op(ECCVMOperation {
//             base_point: self.point_at_infinity,
//             ..Default::default()
//         });
//     }

//     pub fn get_accumulator(&self) -> Point {
//         self.accumulator
//     }

//     pub fn add_accumulate(&mut self, to_add: &Point) -> UltraOp {
//         self.accumulator = self.accumulator + to_add;
//         let op_code = EccOpCode {
//             add: true,
//             ..Default::default()
//         };
//         self.append_eccvm_op(ECCVMOperation {
//             op_code,
//             base_point: *to_add,
//             ..Default::default()
//         });
//         self.construct_and_populate_ultra_ops(op_code, to_add, &Fr::zero())
//     }

//     pub fn mul_accumulate(&mut self, to_mul: &Point, scalar: &Fr) -> UltraOp {
//         self.accumulator = self.accumulator + to_mul * scalar;
//         let op_code = EccOpCode {
//             mul: true,
//             ..Default::default()
//         };
//         let ultra_op = self.construct_and_populate_ultra_ops(op_code, to_mul, scalar);
//         self.append_eccvm_op(ECCVMOperation {
//             op_code,
//             base_point: *to_mul,
//             z1: ultra_op.z_1,
//             z2: ultra_op.z_2,
//             mul_scalar_full: *scalar,
//         });
//         ultra_op
//     }

//     pub fn no_op_ultra_only(&mut self) -> UltraOp {
//         let op_code = EccOpCode::default();
//         self.construct_and_populate_ultra_ops(op_code, &self.accumulator, &Fr::zero())
//     }

//     pub fn eq_and_reset(&mut self) -> UltraOp {
//         let expected = self.accumulator;
//         self.accumulator.self_set_infinity();
//         let op_code = EccOpCode {
//             eq: true,
//             reset: true,
//         };
//         self.append_eccvm_op(ECCVMOperation {
//             op_code,
//             base_point: expected,
//             ..Default::default()
//         });
//         self.construct_and_populate_ultra_ops(op_code, &expected, &Fr::zero())
//     }

//     fn append_eccvm_op(&mut self, op: ECCVMOperation) {
//         self.eccvm_row_tracker.update_cached_msms(&op);
//         self.eccvm_ops_table.push(op);
//     }

//     fn construct_and_populate_ultra_ops(
//         &mut self,
//         op_code: EccOpCode,
//         point: &Point,
//         scalar: &Fr,
//     ) -> UltraOp {
//         let mut ultra_op = UltraOp::default();
//         ultra_op.op_code = op_code;
//         let chunk_size = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION;
//         let x_256 = uint256_t::from(point.x);
//         let y_256 = uint256_t::from(point.y);
//         ultra_op.return_is_infinity = point.is_point_at_infinity();
//         if point.is_point_at_infinity() {
//             ultra_op.x_lo = Fr::zero();
//             ultra_op.x_hi = Fr::zero();
//             ultra_op.y_lo = Fr::zero();
//             ultra_op.y_hi = Fr::zero();
//         } else {
//             ultra_op.x_lo = Fr::from(x_256.slice(0, chunk_size));
//             ultra_op.x_hi = Fr::from(x_256.slice(chunk_size, chunk_size * 2));
//             ultra_op.y_lo = Fr::from(y_256.slice(0, chunk_size));
//             ultra_op.y_hi = Fr::from(y_256.slice(chunk_size, chunk_size * 2));
//         }
//         let converted = scalar.from_montgomery_form();
//         let converted_u256 = uint256_t::from(*scalar);
//         if converted_u256.get_msb() <= 128 {
//             ultra_op.z_1 = *scalar;
//             ultra_op.z_2 = Fr::zero();
//         } else {
//             let (z_1, z_2) = Fr::split_into_endomorphism_scalars(&converted);
//             ultra_op.z_1 = z_1.to_montgomery_form();
//             ultra_op.z_2 = z_2.to_montgomery_form();
//         }
//         self.ultra_ops_table.push(ultra_op.clone());
//         ultra_op
//     }
// }
