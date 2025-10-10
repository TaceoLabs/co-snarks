use crate::mpc_prover_flavour::SharedUnivariateTrait;
use ark_ec::CurveGroup;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prover_flavour::Flavour;
use co_builder::prover_flavour::ProverFlavour;
use ultrahonk::plain_prover_flavour::UnivariateTrait;

pub(crate) type WitnessEntitiesBatch<T, L> = <L as ProverFlavour>::WitnessEntities<Vec<T>>;
pub(crate) type PrecomputedEntitiesBatch<T, L> = <L as ProverFlavour>::PrecomputedEntities<Vec<T>>;
pub(crate) type ShiftedWitnessEntitiesBatch<T, L> =
    <L as ProverFlavour>::ShiftedWitnessEntities<Vec<T>>;

use crate::{mpc_prover_flavour::MPCProverFlavour, types::AllEntities};
use co_noir_common::mpc::NoirUltraHonkProver;

pub(crate) type Shared<T, P, L> = <L as MPCProverFlavour>::ProverUnivariateShared<T, P>;
pub(crate) type Public<P, L> = <L as MPCProverFlavour>::ProverUnivariatePublic<P>;

#[derive(Default)]
pub struct AllEntitiesBatch<T, P, L>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    L: MPCProverFlavour,
{
    pub(crate) witness: WitnessEntitiesBatch<T::ArithmeticShare, L>,
    pub(crate) precomputed: PrecomputedEntitiesBatch<P::ScalarField, L>,
    pub(crate) shifted_witness: ShiftedWitnessEntitiesBatch<T::ArithmeticShare, L>,
}

#[derive(Default)]
pub(crate) struct SumCheckDataForRelation<T, P, L>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    L: MPCProverFlavour,
{
    pub(crate) can_skip: bool,
    pub(crate) all_entities: AllEntitiesBatch<T, P, L>,
    pub(crate) scaling_factors: Vec<P::ScalarField>,
}

pub trait AllEntitiesBatchRelationsTrait<T, P, L>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    L: MPCProverFlavour,
{
    fn new() -> Self;
    fn fold_and_filter(
        &mut self,
        entity: AllEntities<Shared<T, P, L>, Public<P, L>, L>,
        scaling_factor: P::ScalarField,
    );
}

impl<T, P, L> SumCheckDataForRelation<T, P, L>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
    L: MPCProverFlavour,
{
    pub(crate) fn new() -> Self {
        Self {
            can_skip: true,
            all_entities: AllEntitiesBatch::new(),
            scaling_factors: vec![],
        }
    }
}

impl<T, P, L> AllEntitiesBatch<T, P, L>
where
    P: CurveGroup,
    T: NoirUltraHonkProver<P>,
    L: MPCProverFlavour,
{
    pub fn new() -> Self {
        let witness = WitnessEntitiesBatch::<T::ArithmeticShare, L>::new();
        let precomputed = PrecomputedEntitiesBatch::<P::ScalarField, L>::new();
        let shifted_witness = ShiftedWitnessEntitiesBatch::<T::ArithmeticShare, L>::new();
        Self {
            witness,
            precomputed,
            shifted_witness,
        }
    }

    pub fn from_elements(
        shared_elements: Vec<Vec<T::ArithmeticShare>>,
        public_elements: Vec<Vec<P::ScalarField>>,
    ) -> Self {
        let precomputed = public_elements;
        let mut witness = shared_elements;
        let shifted_witness = witness.split_off(L::WITNESS_ENTITIES_SIZE);

        AllEntitiesBatch {
            precomputed: L::PrecomputedEntities::from_elements(precomputed),
            witness: L::WitnessEntities::from_elements(witness),
            shifted_witness: L::ShiftedWitnessEntities::from_elements(shifted_witness),
        }
    }

    pub fn add_w_l(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.witness
            .w_l_mut()
            .extend(entity.witness.w_l().evaluations_as_ref())
    }

    pub fn add_w_r(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.witness
            .w_r_mut()
            .extend(entity.witness.w_r().evaluations_as_ref())
    }

    pub fn add_w_o(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.witness
            .w_o_mut()
            .extend(entity.witness.w_o().evaluations_as_ref())
    }

    pub fn add_w_4(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.witness
            .w_4_mut()
            .extend(entity.witness.w_4().evaluations_as_ref())
    }

    pub fn add_z_perm(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.witness
            .z_perm_mut()
            .extend(entity.witness.z_perm().evaluations_as_ref())
    }

    pub fn add_lookup_read_tags(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.witness
            .lookup_read_tags_mut()
            .extend(entity.witness.lookup_read_tags().evaluations_as_ref())
    }

    pub fn add_lookup_inverses(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.witness
            .lookup_inverses_mut()
            .extend(entity.witness.lookup_inverses().evaluations_as_ref())
    }

    pub fn add_lookup_read_counts(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        self.witness
            .lookup_read_counts_mut()
            .extend(entity.witness.lookup_read_counts().evaluations_as_ref())
    }

    pub fn add_q_m(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_m_mut()
            .extend(entity.precomputed.q_m().evaluations_as_ref())
    }

    pub fn add_q_l(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_l_mut()
            .extend(entity.precomputed.q_l().evaluations_as_ref())
    }

    pub fn add_q_r(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_r_mut()
            .extend(entity.precomputed.q_r().evaluations_as_ref())
    }

    pub fn add_q_o(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_o_mut()
            .extend(entity.precomputed.q_o().evaluations_as_ref())
    }

    pub fn add_q_4(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_4_mut()
            .extend(entity.precomputed.q_4().evaluations_as_ref())
    }

    pub fn add_q_c(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_c_mut()
            .extend(entity.precomputed.q_c().evaluations_as_ref())
    }

    pub fn add_table_1(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .table_1_mut()
            .extend(entity.precomputed.table_1().evaluations_as_ref())
    }

    pub fn add_table_2(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .table_2_mut()
            .extend(entity.precomputed.table_2().evaluations_as_ref())
    }
    pub fn add_table_3(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .table_3_mut()
            .extend(entity.precomputed.table_3().evaluations_as_ref())
    }
    pub fn add_table_4(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .table_4_mut()
            .extend(entity.precomputed.table_4().evaluations_as_ref())
    }

    pub fn add_sigma_1(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .sigma_1_mut()
            .extend(entity.precomputed.sigma_1().evaluations_as_ref())
    }

    pub fn add_sigma_2(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .sigma_2_mut()
            .extend(entity.precomputed.sigma_2().evaluations_as_ref())
    }
    pub fn add_sigma_3(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .sigma_3_mut()
            .extend(entity.precomputed.sigma_3().evaluations_as_ref())
    }
    pub fn add_sigma_4(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .sigma_4_mut()
            .extend(entity.precomputed.sigma_4().evaluations_as_ref())
    }

    pub fn add_id_1(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .id_1_mut()
            .extend(entity.precomputed.id_1().evaluations_as_ref())
    }

    pub fn add_id_2(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .id_2_mut()
            .extend(entity.precomputed.id_2().evaluations_as_ref())
    }
    pub fn add_id_3(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .id_3_mut()
            .extend(entity.precomputed.id_3().evaluations_as_ref())
    }
    pub fn add_id_4(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .id_4_mut()
            .extend(entity.precomputed.id_4().evaluations_as_ref())
    }

    pub fn add_q_arith(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_arith_mut()
            .extend(entity.precomputed.q_arith().evaluations_as_ref())
    }

    pub fn add_q_aux(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_aux_mut()
            .extend(entity.precomputed.q_aux().evaluations_as_ref())
    }

    pub fn add_q_delta_range(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_delta_range_mut()
            .extend(entity.precomputed.q_delta_range().evaluations_as_ref())
    }

    pub fn add_q_elliptic(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_elliptic_mut()
            .extend(entity.precomputed.q_elliptic().evaluations_as_ref())
    }

    pub fn add_q_lookup(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .q_lookup_mut()
            .extend(entity.precomputed.q_lookup().evaluations_as_ref())
    }

    pub fn add_q_poseidon2_external(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        self.precomputed.q_poseidon2_external_mut().extend(
            entity
                .precomputed
                .q_poseidon2_external()
                .evaluations_as_ref(),
        )
    }

    pub fn add_q_poseidon2_internal(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        self.precomputed.q_poseidon2_internal_mut().extend(
            entity
                .precomputed
                .q_poseidon2_internal()
                .evaluations_as_ref(),
        )
    }

    pub fn add_lagrange_last(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .lagrange_last_mut()
            .extend(entity.precomputed.lagrange_last().evaluations_as_ref())
    }

    pub fn add_lagrange_first(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.precomputed
            .lagrange_first_mut()
            .extend(entity.precomputed.lagrange_first().evaluations_as_ref())
    }

    pub fn add_shifted_w_l(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.shifted_witness
            .w_l_mut()
            .extend(entity.shifted_witness.w_l().evaluations_as_ref())
    }

    pub fn add_shifted_w_r(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.shifted_witness
            .w_r_mut()
            .extend(entity.shifted_witness.w_r().evaluations_as_ref())
    }

    pub fn add_shifted_w_o(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.shifted_witness
            .w_o_mut()
            .extend(entity.shifted_witness.w_o().evaluations_as_ref())
    }

    pub fn add_shifted_w_4(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.shifted_witness
            .w_4_mut()
            .extend(entity.shifted_witness.w_4().evaluations_as_ref())
    }

    pub fn add_shifted_z_perm(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        self.shifted_witness
            .z_perm_mut()
            .extend(entity.shifted_witness.z_perm().evaluations_as_ref())
    }

    pub fn add_calldata(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .calldata_mut()
            .extend(entity.witness.calldata().evaluations_as_ref())
    }
    pub fn add_calldata_read_tags(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .calldata_read_tags_mut()
            .extend(entity.witness.calldata_read_tags().evaluations_as_ref())
    }
    pub fn add_calldata_read_counts(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .calldata_read_counts_mut()
            .extend(entity.witness.calldata_read_counts().evaluations_as_ref())
    }
    pub fn add_calldata_inverses(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .calldata_inverses_mut()
            .extend(entity.witness.calldata_inverses().evaluations_as_ref())
    }
    pub fn add_secondary_calldata(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .secondary_calldata_mut()
            .extend(entity.witness.secondary_calldata().evaluations_as_ref())
    }
    pub fn add_secondary_calldata_read_tags(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness.secondary_calldata_read_tags_mut().extend(
            entity
                .witness
                .secondary_calldata_read_tags()
                .evaluations_as_ref(),
        )
    }
    pub fn add_secondary_calldata_read_counts(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness.secondary_calldata_read_counts_mut().extend(
            entity
                .witness
                .secondary_calldata_read_counts()
                .evaluations_as_ref(),
        )
    }
    pub fn add_secondary_calldata_inverses(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness.secondary_calldata_inverses_mut().extend(
            entity
                .witness
                .secondary_calldata_inverses()
                .evaluations_as_ref(),
        )
    }
    pub fn add_return_data(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .return_data_mut()
            .extend(entity.witness.return_data().evaluations_as_ref())
    }
    pub fn add_return_data_read_tags(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .return_data_read_tags_mut()
            .extend(entity.witness.return_data_read_tags().evaluations_as_ref())
    }
    pub fn add_return_data_read_counts(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness.return_data_read_counts_mut().extend(
            entity
                .witness
                .return_data_read_counts()
                .evaluations_as_ref(),
        )
    }
    pub fn add_return_data_inverses(
        &mut self,
        entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>,
    ) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .return_data_inverses_mut()
            .extend(entity.witness.return_data_inverses().evaluations_as_ref())
    }

    pub fn add_q_busread(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.precomputed
            .q_busread_mut()
            .extend(entity.precomputed.q_busread().evaluations_as_ref())
    }
    pub fn add_databus_id(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.precomputed
            .databus_id_mut()
            .extend(entity.precomputed.databus_id().evaluations_as_ref())
    }
    pub fn add_ecc_op_wire_1(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .ecc_op_wire_1_mut()
            .extend(entity.witness.ecc_op_wire_1().evaluations_as_ref())
    }
    pub fn add_ecc_op_wire_2(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .ecc_op_wire_2_mut()
            .extend(entity.witness.ecc_op_wire_2().evaluations_as_ref())
    }
    pub fn add_ecc_op_wire_3(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .ecc_op_wire_3_mut()
            .extend(entity.witness.ecc_op_wire_3().evaluations_as_ref())
    }
    pub fn add_ecc_op_wire_4(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.witness
            .ecc_op_wire_4_mut()
            .extend(entity.witness.ecc_op_wire_4().evaluations_as_ref())
    }
    pub fn add_lagrange_ecc_op(&mut self, entity: &AllEntities<Shared<T, P, L>, Public<P, L>, L>) {
        if L::FLAVOUR == Flavour::Ultra {
            panic!("This should not be called with the UltraFlavor");
        }
        self.precomputed
            .lagrange_ecc_op_mut()
            .extend(entity.precomputed.lagrange_ecc_op().evaluations_as_ref())
    }
}

impl<T, P> AllEntitiesBatch<T, P, ECCVMFlavour>
where
    P: CurveGroup,
    T: NoirUltraHonkProver<P>,
{
    pub fn add_lagrange_second(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.precomputed
            .lagrange_second_mut()
            .extend(entity.precomputed.lagrange_second().evaluations_as_ref())
    }
    pub fn add_transcript_mul_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.transcript_mul_shift_mut().extend(
            entity
                .shifted_witness
                .transcript_mul_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_msm_count_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .transcript_msm_count_shift_mut()
            .extend(
                entity
                    .shifted_witness
                    .transcript_msm_count_shift()
                    .evaluations_as_ref(),
            )
    }
    pub fn add_precompute_scalar_sum_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .precompute_scalar_sum_shift_mut()
            .extend(
                entity
                    .shifted_witness
                    .precompute_scalar_sum_shift()
                    .evaluations_as_ref(),
            )
    }
    pub fn add_precompute_s1hi_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.precompute_s1hi_shift_mut().extend(
            entity
                .shifted_witness
                .precompute_s1hi_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_precompute_dx_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.precompute_dx_shift_mut().extend(
            entity
                .shifted_witness
                .precompute_dx_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_precompute_dy_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.precompute_dy_shift_mut().extend(
            entity
                .shifted_witness
                .precompute_dy_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_precompute_tx_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.precompute_tx_shift_mut().extend(
            entity
                .shifted_witness
                .precompute_tx_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_precompute_ty_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.precompute_ty_shift_mut().extend(
            entity
                .shifted_witness
                .precompute_ty_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_msm_transition_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.msm_transition_shift_mut().extend(
            entity
                .shifted_witness
                .msm_transition_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_msm_add_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .msm_add_shift_mut()
            .extend(entity.shifted_witness.msm_add_shift().evaluations_as_ref())
    }
    pub fn add_msm_double_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.msm_double_shift_mut().extend(
            entity
                .shifted_witness
                .msm_double_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_msm_skew_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .msm_skew_shift_mut()
            .extend(entity.shifted_witness.msm_skew_shift().evaluations_as_ref())
    }
    pub fn add_msm_accumulator_x_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.msm_accumulator_x_shift_mut().extend(
            entity
                .shifted_witness
                .msm_accumulator_x_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_msm_accumulator_y_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.msm_accumulator_y_shift_mut().extend(
            entity
                .shifted_witness
                .msm_accumulator_y_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_msm_count_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.msm_count_shift_mut().extend(
            entity
                .shifted_witness
                .msm_count_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_msm_round_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.msm_round_shift_mut().extend(
            entity
                .shifted_witness
                .msm_round_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_msm_add1_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .msm_add1_shift_mut()
            .extend(entity.shifted_witness.msm_add1_shift().evaluations_as_ref())
    }
    pub fn add_msm_pc_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .msm_pc_shift_mut()
            .extend(entity.shifted_witness.msm_pc_shift().evaluations_as_ref())
    }
    pub fn add_precompute_pc_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.precompute_pc_shift_mut().extend(
            entity
                .shifted_witness
                .precompute_pc_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_pc_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.transcript_pc_shift_mut().extend(
            entity
                .shifted_witness
                .transcript_pc_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_precompute_round_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.precompute_round_shift_mut().extend(
            entity
                .shifted_witness
                .precompute_round_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_precompute_select_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness.precompute_select_shift_mut().extend(
            entity
                .shifted_witness
                .precompute_select_shift()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_accumulator_empty_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .transcript_accumulator_empty_shift_mut()
            .extend(
                entity
                    .shifted_witness
                    .transcript_accumulator_empty_shift()
                    .evaluations_as_ref(),
            )
    }
    pub fn add_transcript_accumulator_x_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .transcript_accumulator_x_shift_mut()
            .extend(
                entity
                    .shifted_witness
                    .transcript_accumulator_x_shift()
                    .evaluations_as_ref(),
            )
    }
    pub fn add_transcript_accumulator_y_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .transcript_accumulator_y_shift_mut()
            .extend(
                entity
                    .shifted_witness
                    .transcript_accumulator_y_shift()
                    .evaluations_as_ref(),
            )
    }
    pub fn add_z_perm_shift(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.shifted_witness
            .z_perm_shift_mut()
            .extend(entity.shifted_witness.z_perm_shift().evaluations_as_ref())
    }
    pub fn add_transcript_add(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_add_mut()
            .extend(entity.witness.transcript_add().evaluations_as_ref())
    }
    pub fn add_transcript_eq(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_eq_mut()
            .extend(entity.witness.transcript_eq().evaluations_as_ref())
    }
    pub fn add_transcript_msm_transition(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_msm_transition_mut().extend(
            entity
                .witness
                .transcript_msm_transition()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_px(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_px_mut()
            .extend(entity.witness.transcript_px().evaluations_as_ref())
    }
    pub fn add_transcript_py(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_py_mut()
            .extend(entity.witness.transcript_py().evaluations_as_ref())
    }
    pub fn add_transcript_z1(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_z1_mut()
            .extend(entity.witness.transcript_z1().evaluations_as_ref())
    }
    pub fn add_transcript_z2(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_z2_mut()
            .extend(entity.witness.transcript_z2().evaluations_as_ref())
    }
    pub fn add_transcript_z1zero(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_z1zero_mut()
            .extend(entity.witness.transcript_z1zero().evaluations_as_ref())
    }
    pub fn add_transcript_z2zero(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_z2zero_mut()
            .extend(entity.witness.transcript_z2zero().evaluations_as_ref())
    }
    pub fn add_transcript_op(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_op_mut()
            .extend(entity.witness.transcript_op().evaluations_as_ref())
    }
    pub fn add_transcript_msm_x(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_msm_x_mut()
            .extend(entity.witness.transcript_msm_x().evaluations_as_ref())
    }
    pub fn add_transcript_msm_y(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_msm_y_mut()
            .extend(entity.witness.transcript_msm_y().evaluations_as_ref())
    }
    pub fn add_precompute_point_transition(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.precompute_point_transition_mut().extend(
            entity
                .witness
                .precompute_point_transition()
                .evaluations_as_ref(),
        )
    }
    pub fn add_precompute_s1lo(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_s1lo_mut()
            .extend(entity.witness.precompute_s1lo().evaluations_as_ref())
    }
    pub fn add_precompute_s2hi(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_s2hi_mut()
            .extend(entity.witness.precompute_s2hi().evaluations_as_ref())
    }
    pub fn add_precompute_s2lo(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_s2lo_mut()
            .extend(entity.witness.precompute_s2lo().evaluations_as_ref())
    }
    pub fn add_precompute_s3hi(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_s3hi_mut()
            .extend(entity.witness.precompute_s3hi().evaluations_as_ref())
    }
    pub fn add_precompute_s3lo(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_s3lo_mut()
            .extend(entity.witness.precompute_s3lo().evaluations_as_ref())
    }
    pub fn add_precompute_s4hi(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_s4hi_mut()
            .extend(entity.witness.precompute_s4hi().evaluations_as_ref())
    }
    pub fn add_precompute_s4lo(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_s4lo_mut()
            .extend(entity.witness.precompute_s4lo().evaluations_as_ref())
    }
    pub fn add_precompute_skew(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_skew_mut()
            .extend(entity.witness.precompute_skew().evaluations_as_ref())
    }
    pub fn add_msm_size_of_msm(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_size_of_msm_mut()
            .extend(entity.witness.msm_size_of_msm().evaluations_as_ref())
    }
    pub fn add_msm_add2(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_add2_mut()
            .extend(entity.witness.msm_add2().evaluations_as_ref())
    }
    pub fn add_msm_add3(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_add3_mut()
            .extend(entity.witness.msm_add3().evaluations_as_ref())
    }
    pub fn add_msm_add4(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_add4_mut()
            .extend(entity.witness.msm_add4().evaluations_as_ref())
    }
    pub fn add_msm_x1(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_x1_mut()
            .extend(entity.witness.msm_x1().evaluations_as_ref())
    }
    pub fn add_msm_y1(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_y1_mut()
            .extend(entity.witness.msm_y1().evaluations_as_ref())
    }
    pub fn add_msm_x2(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_x2_mut()
            .extend(entity.witness.msm_x2().evaluations_as_ref())
    }
    pub fn add_msm_y2(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_y2_mut()
            .extend(entity.witness.msm_y2().evaluations_as_ref())
    }
    pub fn add_msm_x3(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_x3_mut()
            .extend(entity.witness.msm_x3().evaluations_as_ref())
    }
    pub fn add_msm_y3(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_y3_mut()
            .extend(entity.witness.msm_y3().evaluations_as_ref())
    }
    pub fn add_msm_x4(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_x4_mut()
            .extend(entity.witness.msm_x4().evaluations_as_ref())
    }
    pub fn add_msm_y4(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_y4_mut()
            .extend(entity.witness.msm_y4().evaluations_as_ref())
    }
    pub fn add_msm_collision_x1(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_collision_x1_mut()
            .extend(entity.witness.msm_collision_x1().evaluations_as_ref())
    }
    pub fn add_msm_collision_x2(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_collision_x2_mut()
            .extend(entity.witness.msm_collision_x2().evaluations_as_ref())
    }
    pub fn add_msm_collision_x3(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_collision_x3_mut()
            .extend(entity.witness.msm_collision_x3().evaluations_as_ref())
    }
    pub fn add_msm_collision_x4(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_collision_x4_mut()
            .extend(entity.witness.msm_collision_x4().evaluations_as_ref())
    }
    pub fn add_msm_lambda1(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_lambda1_mut()
            .extend(entity.witness.msm_lambda1().evaluations_as_ref())
    }
    pub fn add_msm_lambda2(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_lambda2_mut()
            .extend(entity.witness.msm_lambda2().evaluations_as_ref())
    }
    pub fn add_msm_lambda3(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_lambda3_mut()
            .extend(entity.witness.msm_lambda3().evaluations_as_ref())
    }
    pub fn add_msm_lambda4(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_lambda4_mut()
            .extend(entity.witness.msm_lambda4().evaluations_as_ref())
    }
    pub fn add_msm_slice1(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_slice1_mut()
            .extend(entity.witness.msm_slice1().evaluations_as_ref())
    }
    pub fn add_msm_slice2(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_slice2_mut()
            .extend(entity.witness.msm_slice2().evaluations_as_ref())
    }
    pub fn add_msm_slice3(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_slice3_mut()
            .extend(entity.witness.msm_slice3().evaluations_as_ref())
    }
    pub fn add_msm_slice4(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_slice4_mut()
            .extend(entity.witness.msm_slice4().evaluations_as_ref())
    }
    pub fn add_transcript_reset_accumulator(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_reset_accumulator_mut().extend(
            entity
                .witness
                .transcript_reset_accumulator()
                .evaluations_as_ref(),
        )
    }
    pub fn add_lookup_read_counts_0(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .lookup_read_counts_0_mut()
            .extend(entity.witness.lookup_read_counts_0().evaluations_as_ref())
    }
    pub fn add_lookup_read_counts_1(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .lookup_read_counts_1_mut()
            .extend(entity.witness.lookup_read_counts_1().evaluations_as_ref())
    }
    pub fn add_transcript_base_infinity(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_base_infinity_mut().extend(
            entity
                .witness
                .transcript_base_infinity()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_base_x_inverse(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_base_x_inverse_mut().extend(
            entity
                .witness
                .transcript_base_x_inverse()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_base_y_inverse(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_base_y_inverse_mut().extend(
            entity
                .witness
                .transcript_base_y_inverse()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_add_x_equal(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_add_x_equal_mut()
            .extend(entity.witness.transcript_add_x_equal().evaluations_as_ref())
    }
    pub fn add_transcript_add_y_equal(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_add_y_equal_mut()
            .extend(entity.witness.transcript_add_y_equal().evaluations_as_ref())
    }
    pub fn add_transcript_add_lambda(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_add_lambda_mut()
            .extend(entity.witness.transcript_add_lambda().evaluations_as_ref())
    }
    pub fn add_transcript_msm_intermediate_x(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_msm_intermediate_x_mut().extend(
            entity
                .witness
                .transcript_msm_intermediate_x()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_msm_intermediate_y(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_msm_intermediate_y_mut().extend(
            entity
                .witness
                .transcript_msm_intermediate_y()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_msm_infinity(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_msm_infinity_mut().extend(
            entity
                .witness
                .transcript_msm_infinity()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_msm_x_inverse(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_msm_x_inverse_mut().extend(
            entity
                .witness
                .transcript_msm_x_inverse()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_msm_count_zero_at_transition(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_msm_count_zero_at_transition_mut()
            .extend(
                entity
                    .witness
                    .transcript_msm_count_zero_at_transition()
                    .evaluations_as_ref(),
            )
    }
    pub fn add_transcript_msm_count_at_transition_inverse(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_msm_count_at_transition_inverse_mut()
            .extend(
                entity
                    .witness
                    .transcript_msm_count_at_transition_inverse()
                    .evaluations_as_ref(),
            )
    }
    pub fn add_transcript_mul(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_mul_mut()
            .extend(entity.witness.transcript_mul().evaluations_as_ref())
    }
    pub fn add_transcript_msm_count(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_msm_count_mut()
            .extend(entity.witness.transcript_msm_count().evaluations_as_ref())
    }
    pub fn add_precompute_scalar_sum(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_scalar_sum_mut()
            .extend(entity.witness.precompute_scalar_sum().evaluations_as_ref())
    }
    pub fn add_precompute_s1hi(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_s1hi_mut()
            .extend(entity.witness.precompute_s1hi().evaluations_as_ref())
    }
    pub fn add_precompute_dx(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_dx_mut()
            .extend(entity.witness.precompute_dx().evaluations_as_ref())
    }
    pub fn add_precompute_dy(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_dy_mut()
            .extend(entity.witness.precompute_dy().evaluations_as_ref())
    }
    pub fn add_precompute_tx(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_tx_mut()
            .extend(entity.witness.precompute_tx().evaluations_as_ref())
    }
    pub fn add_precompute_ty(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_ty_mut()
            .extend(entity.witness.precompute_ty().evaluations_as_ref())
    }
    pub fn add_msm_transition(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_transition_mut()
            .extend(entity.witness.msm_transition().evaluations_as_ref())
    }
    pub fn add_msm_add(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_add_mut()
            .extend(entity.witness.msm_add().evaluations_as_ref())
    }
    pub fn add_msm_double(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_double_mut()
            .extend(entity.witness.msm_double().evaluations_as_ref())
    }
    pub fn add_msm_skew(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_skew_mut()
            .extend(entity.witness.msm_skew().evaluations_as_ref())
    }
    pub fn add_msm_accumulator_x(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_accumulator_x_mut()
            .extend(entity.witness.msm_accumulator_x().evaluations_as_ref())
    }
    pub fn add_msm_accumulator_y(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_accumulator_y_mut()
            .extend(entity.witness.msm_accumulator_y().evaluations_as_ref())
    }
    pub fn add_msm_count(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_count_mut()
            .extend(entity.witness.msm_count().evaluations_as_ref())
    }
    pub fn add_msm_round(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_round_mut()
            .extend(entity.witness.msm_round().evaluations_as_ref())
    }
    pub fn add_msm_add1(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_add1_mut()
            .extend(entity.witness.msm_add1().evaluations_as_ref())
    }
    pub fn add_msm_pc(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .msm_pc_mut()
            .extend(entity.witness.msm_pc().evaluations_as_ref())
    }
    pub fn add_precompute_pc(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_pc_mut()
            .extend(entity.witness.precompute_pc().evaluations_as_ref())
    }
    pub fn add_transcript_pc(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .transcript_pc_mut()
            .extend(entity.witness.transcript_pc().evaluations_as_ref())
    }
    pub fn add_precompute_round(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_round_mut()
            .extend(entity.witness.precompute_round().evaluations_as_ref())
    }
    pub fn add_precompute_select(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness
            .precompute_select_mut()
            .extend(entity.witness.precompute_select().evaluations_as_ref())
    }
    pub fn add_transcript_accumulator_empty(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_accumulator_empty_mut().extend(
            entity
                .witness
                .transcript_accumulator_empty()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_accumulator_x(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_accumulator_x_mut().extend(
            entity
                .witness
                .transcript_accumulator_x()
                .evaluations_as_ref(),
        )
    }
    pub fn add_transcript_accumulator_y(
        &mut self,
        entity: &AllEntities<Shared<T, P, ECCVMFlavour>, Public<P, ECCVMFlavour>, ECCVMFlavour>,
    ) {
        self.witness.transcript_accumulator_y_mut().extend(
            entity
                .witness
                .transcript_accumulator_y()
                .evaluations_as_ref(),
        )
    }
}
