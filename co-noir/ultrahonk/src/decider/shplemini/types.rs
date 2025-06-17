use crate::plain_prover_flavour::PlainProverFlavour;

pub(crate) struct PolyF<'a, T: Default, L: PlainProverFlavour> {
    pub(crate) precomputed: &'a L::PrecomputedEntity<T>,
    pub(crate) witness: &'a L::WitnessEntity<T>,
}

pub(crate) struct PolyG<'a, T: Default> {
    pub(crate) wires: &'a [T; 5],
}

pub(crate) struct PolyGShift<'a, T: Default, L: PlainProverFlavour> {
    pub(crate) wires: &'a L::ShiftedWitnessEntity<T>,
}

impl<T: Default, L: PlainProverFlavour> PolyF<'_, T, L> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.precomputed.iter().chain(self.witness.iter())
    }
}

impl<T: Default> PolyG<'_, T> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.wires.iter()
    }
}

impl<T: Default, L: PlainProverFlavour> PolyGShift<'_, T, L> {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.wires.iter()
    }
}
