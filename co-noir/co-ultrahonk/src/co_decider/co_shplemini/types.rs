use crate::mpc_prover_flavour::MPCProverFlavour;

pub(crate) struct PolyF<
    'a,
    Shared: Default + std::marker::Sync,
    Public: Default + Clone + std::marker::Sync,
    L: MPCProverFlavour,
> {
    pub(crate) precomputed: &'a L::PrecomputedEntities<Public>,
    pub(crate) witness: &'a L::WitnessEntities<Shared>,
}

pub(crate) struct PolyG<'a, T: Default> {
    pub(crate) wires: &'a [T; 5],
}

impl<Shared: Default> PolyG<'_, Shared> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Shared> {
        self.wires.iter()
    }
}
