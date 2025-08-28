use crate::mpc_prover_flavour::SharedUnivariateTrait;
use ark_ec::CurveGroup;
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
use common::mpc::NoirUltraHonkProver;

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
