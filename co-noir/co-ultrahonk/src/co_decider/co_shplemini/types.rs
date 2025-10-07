use crate::mpc_prover_flavour::MPCProverFlavour;
use std::fmt::Debug;

pub(crate) struct PolyF<
    'a,
    Shared: Default + Clone + Debug + std::marker::Sync,
    Public: Default + Clone + Debug + std::marker::Sync,
    L: MPCProverFlavour,
> {
    pub(crate) precomputed: &'a L::PrecomputedEntities<Public>,
    pub(crate) witness: &'a L::WitnessEntities<Shared>,
}
