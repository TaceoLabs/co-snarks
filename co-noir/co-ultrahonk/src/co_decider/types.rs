use crate::{
    mpc::NoirUltraHonkProver,
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
use itertools::izip;
use std::iter;

pub(crate) struct ProverMemory<T: NoirUltraHonkProver<P>, P: CurveGroup, L: MPCProverFlavour> {
    pub(crate) polys: AllEntities<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, L>,
    pub(crate) relation_parameters: RelationParameters<P::ScalarField, L>,
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
    pub(crate) eta_1: F,
    pub(crate) eta_2: F,
    pub(crate) eta_3: F,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) public_input_delta: F,
    pub(crate) alphas: L::Alphas<F>,
    pub(crate) gate_challenges: Vec<F>,
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
                memory
                    .witness
                    .iter_mut()
                    .skip(L::WITNESS_ECC_OP_WIRE_1.expect("ECC_OP_WIRE_1 is not set")),
                polynomials
                    .witness
                    .iter()
                    .skip(L::ECC_OP_WIRE_1.expect("ECC_OP_WIRE_1 is not set"))
                    .take(7)
            ) {
                *des = src.as_ref().to_vec();
            }

            *memory.witness.calldata_inverses_mut() = prover_memory.calldata_inverses.into_vec();

            for (des, src) in izip!(
                memory
                    .witness
                    .iter_mut()
                    .skip(L::WITNESS_SECONDARY_CALLDATA.expect("SECONDARY_CALLDATA is not set")),
                polynomials
                    .witness
                    .iter()
                    .skip(L::SECONDARY_CALLDATA.expect("SECONDARY_CALLDATA is not set"))
                    .take(3)
            ) {
                *des = src.as_ref().to_vec();
            }

            *memory.witness.secondary_calldata_inverses_mut() =
                prover_memory.secondary_calldata_inverses.into_vec();

            for (des, src) in izip!(
                memory
                    .witness
                    .iter_mut()
                    .skip(L::WITNESS_RETURN_DATA.expect("RETURN_DATA is not set")),
                polynomials
                    .witness
                    .iter()
                    .skip(L::RETURN_DATA.expect("RETURN_DATA is not set"))
                    .take(3)
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
