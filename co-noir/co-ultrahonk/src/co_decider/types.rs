use crate::{
    mpc_prover_flavour::MPCProverFlavour,
    types::{AllEntities, Polynomials},
    types_batch::AllEntitiesBatch,
};
use ark_ec::CurveGroup;
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::{
    polynomials::polynomial_flavours::PrecomputedEntitiesFlavour, prover_flavour::Flavour,
};
use common::mpc::NoirUltraHonkProver;
use itertools::izip;
use std::iter;

pub struct ProverMemory<T: NoirUltraHonkProver<P>, P: CurveGroup, L: MPCProverFlavour> {
    pub polys: AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
    pub relation_parameters: RelationParameters<P::ScalarField, L>,
}

pub(crate) type ProverUnivariates<T, P, L> = AllEntities<
    <L as MPCProverFlavour>::ProverUnivariateShared<T, P>,
    <L as MPCProverFlavour>::ProverUnivariatePublic<P>,
    L,
>;

pub(crate) type ProverUnivariatesBatch<T, P, L> = AllEntitiesBatch<T, P, L>;
pub(crate) type PartiallyEvaluatePolys<T, P, L> = AllEntities<
    Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare>,
    Vec<<P as PrimeGroup>::ScalarField>,
    L,
>;
pub(crate) type ClaimedEvaluations<F, L> = AllEntities<F, F, L>;

pub struct RelationParameters<F: PrimeField, L: MPCProverFlavour> {
    pub eta_1: F,
    pub eta_2: F,
    pub eta_3: F,
    pub beta: F,
    pub gamma: F,
    pub public_input_delta: F,
    pub alphas: L::Alphas<F>,
    pub gate_challenges: Vec<F>,
    pub lookup_grand_product_delta: F,
    pub beta_sqr: F,
    pub beta_cube: F,
    pub eccvm_set_permutation_delta: F,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup, L: MPCProverFlavour> ProverMemory<T, P, L> {
    pub(crate) fn from_memory_and_polynomials(
        prover_memory: crate::co_oink::types::ProverMemory<T, P, L>,
        polynomials: Polynomials<T::ArithmeticShare, P::ScalarField, L>,
    ) -> Self {
        let relation_parameters = RelationParameters {
            eta_1: prover_memory.challenges.eta_1,
            eta_2: prover_memory.challenges.eta_2,
            eta_3: prover_memory.challenges.eta_3,
            beta: prover_memory.challenges.beta,
            gamma: prover_memory.challenges.gamma,
            public_input_delta: prover_memory.public_input_delta,
            alphas: prover_memory.challenges.alphas,
            gate_challenges: Default::default(),
            lookup_grand_product_delta: Default::default(),
            beta_sqr: Default::default(),
            beta_cube: Default::default(),
            eccvm_set_permutation_delta: Default::default(),
        };

        let mut memory = AllEntities::<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>::default();

        // TACEO TODO Barretenberg uses the same memory for the shifted polynomials as for the non-shifted ones

        // Missing lookups
        *memory.witness.lookup_inverses_mut() = prover_memory.lookup_inverses.into_vec();
        *memory.witness.lookup_read_counts_mut() =
            polynomials.witness.lookup_read_counts().as_ref().to_vec();
        *memory.witness.lookup_read_tags_mut() =
            polynomials.witness.lookup_read_tags().as_ref().to_vec();
        if L::FLAVOUR == Flavour::Mega {
            for (des, src) in izip!(
                memory.witness.iter_mut().skip(L::WITNESS_ECC_OP_WIRE_1),
                polynomials.witness.iter().skip(L::ECC_OP_WIRE_1).take(7)
            ) {
                *des = src.as_ref().to_vec();
            }

            *memory.witness.calldata_inverses_mut() = prover_memory.calldata_inverses.into_vec();

            for (des, src) in izip!(
                memory
                    .witness
                    .iter_mut()
                    .skip(L::WITNESS_SECONDARY_CALLDATA),
                polynomials
                    .witness
                    .iter()
                    .skip(L::SECONDARY_CALLDATA)
                    .take(3)
            ) {
                *des = src.as_ref().to_vec();
            }

            *memory.witness.secondary_calldata_inverses_mut() =
                prover_memory.secondary_calldata_inverses.into_vec();

            for (des, src) in izip!(
                memory.witness.iter_mut().skip(L::WITNESS_RETURN_DATA),
                polynomials.witness.iter().skip(L::RETURN_DATA).take(3)
            ) {
                *des = src.as_ref().to_vec();
            }

            *memory.witness.return_data_inverses_mut() =
                prover_memory.return_data_inverses.into_vec();
        }

        // Shift the witnesses
        for (des_shifted, des, src) in izip!(
            memory.shifted_witness.iter_mut(),
            memory.witness.to_be_shifted_mut(),
            polynomials
                .witness
                .into_wires()
                .take(3)
                .chain(iter::once(prover_memory.w_4))
                .chain(iter::once(prover_memory.z_perm)),
        ) {
            // TACEO TODO use same memory to prevent copying?
            *des_shifted = src.shifted().to_vec();
            *des = src.into_vec();
        }

        // Copy precomputed polynomials
        for (des, src) in izip!(
            memory.precomputed.iter_mut(),
            polynomials.precomputed.into_iter()
        ) {
            *des = src.into_vec();
        }

        Self {
            polys: memory,
            relation_parameters,
        }
    }
}
