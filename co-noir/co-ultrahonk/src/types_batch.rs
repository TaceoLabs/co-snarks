use ark_ec::pairing::Pairing;
use co_builder::{
    prelude::{HonkCurve, PrecomputedEntities},
    TranscriptFieldType,
};
use ultrahonk::prelude::{ShiftedWitnessEntities, Univariate, WitnessEntities};

pub(crate) type WitnessEntitiesBatch<T> = WitnessEntities<Vec<T>>;
pub(crate) type PrecomputedEntitiesBatch<T> = PrecomputedEntities<Vec<T>>;
pub(crate) type ShiftedWitnessEntitiesBatch<T> = ShiftedWitnessEntities<Vec<T>>;

use crate::{
    co_decider::{
        relations::{
            auxiliary_relation::AuxiliaryRelation,
            delta_range_constraint_relation::DeltaRangeConstraintRelation,
            elliptic_relation::EllipticRelation, logderiv_lookup_relation::LogDerivLookupRelation,
            permutation_relation::UltraPermutationRelation,
            poseidon2_external_relation::Poseidon2ExternalRelation,
            poseidon2_internal_relation::Poseidon2InternalRelation,
            ultra_arithmetic_relation::UltraArithmeticRelation, Relation as _,
        },
        types::MAX_PARTIAL_RELATION_LENGTH,
        univariates::SharedUnivariate,
    },
    mpc::NoirUltraHonkProver,
    types::AllEntities,
};

type Shared<T, P> = SharedUnivariate<T, P, MAX_PARTIAL_RELATION_LENGTH>;
type Public<P> = Univariate<<P as Pairing>::ScalarField, MAX_PARTIAL_RELATION_LENGTH>;

#[derive(Default)]
pub struct AllEntitiesBatch<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    pub(crate) witness: WitnessEntitiesBatch<T::ArithmeticShare>,
    pub(crate) precomputed: PrecomputedEntitiesBatch<P::ScalarField>,
    pub(crate) shifted_witness: ShiftedWitnessEntitiesBatch<T::ArithmeticShare>,
}

#[derive(Default)]
pub struct SumCheckDataForRelation<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    pub(crate) can_skip: bool,
    pub all_entites: AllEntitiesBatch<T, P>,
    pub scaling_factors: Vec<P::ScalarField>,
}

#[derive(Default)]
pub struct AllEntitiesBatchRelations<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    pub ultra_arith: SumCheckDataForRelation<T, P>,
    pub ultra_perm: SumCheckDataForRelation<T, P>,
    pub delta_range: SumCheckDataForRelation<T, P>,
    pub elliptic: SumCheckDataForRelation<T, P>,
    pub auxiliary: SumCheckDataForRelation<T, P>,
    pub log_lookup: SumCheckDataForRelation<T, P>,
    pub poseidon_ext: SumCheckDataForRelation<T, P>,
    pub poseidon_int: SumCheckDataForRelation<T, P>,
}

impl<T, P> SumCheckDataForRelation<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: Pairing,
{
    fn new() -> Self {
        Self {
            can_skip: true,
            all_entites: AllEntitiesBatch::new(),
            scaling_factors: vec![],
        }
    }
}

impl<T, P> AllEntitiesBatchRelations<T, P>
where
    P: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<P>,
{
    pub fn new() -> Self {
        Self {
            ultra_arith: SumCheckDataForRelation::new(),
            ultra_perm: SumCheckDataForRelation::new(),
            delta_range: SumCheckDataForRelation::new(),
            log_lookup: SumCheckDataForRelation::new(),
            elliptic: SumCheckDataForRelation::new(),
            auxiliary: SumCheckDataForRelation::new(),
            poseidon_ext: SumCheckDataForRelation::new(),
            poseidon_int: SumCheckDataForRelation::new(),
        }
    }

    pub fn fold_and_filter(
        &mut self,
        entity: AllEntities<Shared<T, P>, Public<P>>,
        scaling_factor: P::ScalarField,
    ) {
        // 0xThemis TODO - for all (?) accumulator we don't need all 7 elements. Can we remove
        // somehow skip those to decrease work even further?
        // e.g. UltraArith only has
        //
        // pub(crate) r0: SharedUnivariate<T, P, 6>,
        // pub(crate) r1: SharedUnivariate<T, P, 5>,
        //
        // Can we somehow only add 5/6 elements?

        UltraArithmeticRelation::add_edge(&entity, scaling_factor, &mut self.ultra_arith);
        UltraPermutationRelation::add_edge(&entity, scaling_factor, &mut self.ultra_perm);
        DeltaRangeConstraintRelation::add_edge(&entity, scaling_factor, &mut self.delta_range);

        EllipticRelation::add_edge(&entity, scaling_factor, &mut self.elliptic);
        AuxiliaryRelation::add_edge(&entity, scaling_factor, &mut self.auxiliary);
        LogDerivLookupRelation::add_edge(&entity, scaling_factor, &mut self.log_lookup);

        Poseidon2ExternalRelation::add_edge(&entity, scaling_factor, &mut self.poseidon_ext);
        Poseidon2InternalRelation::add_edge(&entity, scaling_factor, &mut self.poseidon_int);
    }
}

impl<T, P> AllEntitiesBatch<T, P>
where
    P: Pairing,
    T: NoirUltraHonkProver<P>,
{
    pub fn new() -> Self {
        let witness = WitnessEntitiesBatch::<T::ArithmeticShare>::new();
        let precomputed = PrecomputedEntitiesBatch::<P::ScalarField>::new();
        let shifted_witness = ShiftedWitnessEntitiesBatch::<T::ArithmeticShare>::new();
        Self {
            witness,
            precomputed,
            shifted_witness,
        }
    }

    pub fn add_w_l(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .w_l_mut()
            .extend(entity.witness.w_l().evaluations)
    }

    pub fn add_w_r(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .w_r_mut()
            .extend(entity.witness.w_r().evaluations)
    }

    pub fn add_w_o(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .w_o_mut()
            .extend(entity.witness.w_o().evaluations)
    }

    pub fn add_w_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .w_4_mut()
            .extend(entity.witness.w_4().evaluations)
    }

    pub fn add_z_perm(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .z_perm_mut()
            .extend(entity.witness.z_perm().evaluations)
    }

    pub fn add_lookup_read_tags(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .lookup_read_tags_mut()
            .extend(entity.witness.lookup_read_tags().evaluations)
    }

    pub fn add_lookup_inverses(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .lookup_inverses_mut()
            .extend(entity.witness.lookup_inverses().evaluations)
    }

    pub fn add_lookup_read_counts(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .lookup_read_counts_mut()
            .extend(entity.witness.lookup_read_counts().evaluations)
    }

    pub fn add_q_m(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_m_mut()
            .extend(entity.precomputed.q_m().evaluations)
    }

    pub fn add_q_l(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_l_mut()
            .extend(entity.precomputed.q_l().evaluations)
    }

    pub fn add_q_r(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_r_mut()
            .extend(entity.precomputed.q_r().evaluations)
    }

    pub fn add_q_o(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_o_mut()
            .extend(entity.precomputed.q_o().evaluations)
    }

    pub fn add_q_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_4_mut()
            .extend(entity.precomputed.q_4().evaluations)
    }

    pub fn add_q_c(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_c_mut()
            .extend(entity.precomputed.q_c().evaluations)
    }

    pub fn add_table_1(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .table_1_mut()
            .extend(entity.precomputed.table_1().evaluations)
    }

    pub fn add_table_2(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .table_2_mut()
            .extend(entity.precomputed.table_2().evaluations)
    }
    pub fn add_table_3(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .table_3_mut()
            .extend(entity.precomputed.table_3().evaluations)
    }
    pub fn add_table_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .table_4_mut()
            .extend(entity.precomputed.table_4().evaluations)
    }

    pub fn add_sigma_1(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .sigma_1_mut()
            .extend(entity.precomputed.sigma_1().evaluations)
    }

    pub fn add_sigma_2(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .sigma_2_mut()
            .extend(entity.precomputed.sigma_2().evaluations)
    }
    pub fn add_sigma_3(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .sigma_3_mut()
            .extend(entity.precomputed.sigma_3().evaluations)
    }
    pub fn add_sigma_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .sigma_4_mut()
            .extend(entity.precomputed.sigma_4().evaluations)
    }

    pub fn add_id_1(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .id_1_mut()
            .extend(entity.precomputed.id_1().evaluations)
    }

    pub fn add_id_2(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .id_2_mut()
            .extend(entity.precomputed.id_2().evaluations)
    }
    pub fn add_id_3(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .id_3_mut()
            .extend(entity.precomputed.id_3().evaluations)
    }
    pub fn add_id_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .id_4_mut()
            .extend(entity.precomputed.id_4().evaluations)
    }

    pub fn add_q_arith(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_arith_mut()
            .extend(entity.precomputed.q_arith().evaluations)
    }

    pub fn add_q_aux(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_aux_mut()
            .extend(entity.precomputed.q_aux().evaluations)
    }

    pub fn add_q_delta_range(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_delta_range_mut()
            .extend(entity.precomputed.q_delta_range().evaluations)
    }

    pub fn add_q_elliptic(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_elliptic_mut()
            .extend(entity.precomputed.q_elliptic().evaluations)
    }

    pub fn add_q_lookup(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_lookup_mut()
            .extend(entity.precomputed.q_lookup().evaluations)
    }

    pub fn add_q_poseidon2_external(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_poseidon2_external_mut()
            .extend(entity.precomputed.q_poseidon2_external().evaluations)
    }

    pub fn add_q_poseidon2_internal(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_poseidon2_internal_mut()
            .extend(entity.precomputed.q_poseidon2_internal().evaluations)
    }

    pub fn add_lagrange_last(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .lagrange_last_mut()
            .extend(entity.precomputed.lagrange_last().evaluations)
    }

    pub fn add_lagrange_first(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .lagrange_first_mut()
            .extend(entity.precomputed.lagrange_first().evaluations)
    }

    pub fn add_shifted_w_l(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .w_l_mut()
            .extend(entity.shifted_witness.w_l().evaluations)
    }

    pub fn add_shifted_w_r(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .w_r_mut()
            .extend(entity.shifted_witness.w_r().evaluations)
    }

    pub fn add_shifted_w_o(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .w_o_mut()
            .extend(entity.shifted_witness.w_o().evaluations)
    }

    pub fn add_shifted_w_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .w_4_mut()
            .extend(entity.shifted_witness.w_4().evaluations)
    }

    pub fn add_shifted_z_perm(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .z_perm_mut()
            .extend(entity.shifted_witness.z_perm().evaluations)
    }
}
